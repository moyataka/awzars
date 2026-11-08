"""Offline enrollment lifecycle using a temporary profile and a pseudo-terminal."""

import errno
import os
from pathlib import Path
import pty
import select
import signal
import subprocess
import sys
import tempfile
import time
import unittest


BINARY = str(Path(sys.argv.pop(1)).resolve())
CONFIG = '''[profiles.work]
mcp_readonly_accessible = true
role_arn = "arn:aws:iam::111111111111:role/Source"
lock_ai_markers = ["AWZARS_MCP_TEST_AI"]
[profiles.work.azure]
tenant_id = "11111111-2222-3333-4444-aaaaaaaaaaaa"
app_id_uri = "https://signin.aws.amazon.com/saml"
[profiles.work.read_only.targets.workload]
role_arn = "arn:aws:iam::123456789012:role/Workload"
region = "ap-southeast-1"
capabilities = ["s3-list-buckets", "ec2-describe-instances"]
'''


class EnrollmentTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.configuration = self.root / "config.toml"
        self.configuration.write_text(CONFIG)
        self.environment = dict(os.environ)
        self.environment.pop("AWZARS_MCP_TEST_AI", None)
        self.environment.update(XDG_RUNTIME_DIR=str(self.root),
                                AWZARS_SESSION_ID="mcp_enrollment_test",
                                TOKIO_WORKER_THREADS="2", TERM="xterm")
        self.command = [BINARY, "--config-dir", str(self.root), "--profile", "work"]

    def terminal(self, arguments, answers=(), environment=None, capture=False,
                 before_answer=None):
        reader, writer = os.pipe() if capture else (None, None)
        child, master = pty.fork()
        if child == 0:
            if capture:
                os.close(reader)
                os.dup2(writer, 1)
                os.close(writer)
            os.execve(BINARY, self.command + arguments, environment or self.environment)
        if capture:
            os.close(writer)
            if capture == "broken":
                os.close(reader)
                reader = None
        output = bytearray()
        private = bytearray()
        pending = list(answers)
        cursor = 0
        deadline = time.monotonic() + 20
        status = None
        try:
            while time.monotonic() < deadline:
                if select.select([master], [], [], 0.05)[0]:
                    try:
                        chunk = os.read(master, 4096)
                    except OSError as error:
                        if error.errno != errno.EIO:
                            raise
                        chunk = b""
                    output.extend(chunk)
                if reader is not None and select.select([reader], [], [], 0)[0]:
                    private.extend(os.read(reader, 4096))
                if pending and pending[0][0] in output[cursor:]:
                    prompt, answer = pending.pop(0)
                    cursor = output.index(prompt, cursor) + len(prompt)
                    if before_answer is not None:
                        before_answer()
                        before_answer = None
                    os.write(master, answer + b"\n")
                exited, candidate = os.waitpid(child, os.WNOHANG)
                if exited:
                    status = (os.WEXITSTATUS(candidate) if os.WIFEXITED(candidate)
                              else -os.WTERMSIG(candidate))
                    break
            if status is None:
                self.fail("CLI terminal operation timed out")
        finally:
            if status is None:
                os.kill(child, signal.SIGKILL)
                os.waitpid(child, 0)
            os.close(master)
            if reader is not None:
                while True:
                    chunk = os.read(reader, 4096)
                    if not chunk:
                        break
                    private.extend(chunk)
                os.close(reader)
        if capture:
            return status, bytes(output), bytes(private)
        return status, bytes(output)

    def request(self, secret, client="incident-agent", capability="s3-list-buckets"):
        environment = dict(self.environment, AWZARS_MCP_TEST_AI="1")
        return subprocess.run(
            self.command + ["read-only", "--target", "workload", "--capability",
                            capability, "--client", client],
            input=secret, capture_output=True, env=environment, timeout=20,
            check=False,
        )

    def test_enrollment_rejection_password_change_and_revocation(self):
        status, output = self.terminal(["set-password"], [
            (b"New password for", b"test-password"),
            (b"Confirm new password", b"test-password"),
        ])
        self.assertEqual(status, 0, output)
        secret_file = self.root / "client.secret"
        arguments = ["enroll-mcp", "--client", "incident-agent", "--target", "workload",
                     "--capability", "s3-list-buckets", "--secret-file", str(secret_file)]
        status, output = self.terminal(arguments, [(b"manage MCP access", b"test-password")])
        self.assertEqual(status, 0, output)
        secret = secret_file.read_bytes()
        self.assertEqual(len(secret.strip()), 43)
        self.assertEqual(secret_file.stat().st_mode & 0o777, 0o600)
        self.assertNotIn(secret.strip(), output)
        stored = self.configuration.read_text()
        self.assertIn("[profiles.work.read_only.clients.incident-agent]", stored)
        self.assertIn('secret_verifier = "$argon2id$', stored)
        self.assertNotIn(secret.strip().decode(), self.configuration.read_text())

        before = self.configuration.read_bytes()
        duplicate = self.root / "duplicate.secret"
        status, _ = self.terminal(arguments[:-1] + [str(duplicate)],
                                  [(b"manage MCP access", b"test-password")])
        self.assertEqual(status, 2)
        self.assertFalse(duplicate.exists())
        self.assertEqual(self.configuration.read_bytes(), before)
        bad_arguments = [item.replace("incident-agent", "other-agent") for item in arguments]
        status, _ = self.terminal(bad_arguments[:-1] + [str(duplicate)],
                                  [(b"manage MCP access", b"wrong-password")])
        self.assertEqual(status, 9)
        self.assertFalse(duplicate.exists())
        self.assertEqual(self.configuration.read_bytes(), before)

        for response in [self.request(b"A" * 43), self.request(secret, client="unknown"),
                         self.request(secret, capability="ec2-describe-instances")]:
            self.assertEqual(response.returncode, 12, response.stderr)
            self.assertEqual(response.stdout, b"")
            self.assertNotIn(secret.strip(), response.stderr)

        status, output = self.terminal(["set-password"], [
            (b"Current password for", b"test-password"),
            (b"New password for", b"changed-password"),
            (b"Confirm new password", b"changed-password"),
        ])
        self.assertEqual(status, 0, output)
        self.assertEqual(self.request(secret).returncode, 12)
        status, output = self.terminal(["revoke-mcp", "--client", "incident-agent"],
                                       [(b"manage MCP access", b"changed-password")])
        self.assertEqual(status, 0, output)
        self.assertEqual(self.request(secret).returncode, 12)
        self.assertNotIn("[profiles.work.read_only.clients.", self.configuration.read_text())
        self.assertEqual(secret_file.read_bytes(), secret)
        self.assertFalse(list((self.root / "awzars" / "sessions").glob("*.json")))
        self.assertFalse((self.root / "refresh-work.lock").exists())
        self.assertFalse((self.root / "chromium").exists())

    def registration_arguments(self):
        return ["enroll-mcp", "--client", "incident-agent", "--target", "workload",
                "--capability", "s3-list-buckets", "--secret-stdout"]

    def assert_no_normal_unlock_or_credentials(self):
        self.assertFalse(list((self.root / "awzars" / "sessions").glob("*.json")))
        self.assertFalse((self.root / "refresh-work.lock").exists())
        self.assertFalse((self.root / "chromium").exists())
        self.assertEqual({p.name for p in self.root.iterdir()} - {"awzars"},
                         {"config.toml", "mcp-management.lock"})
        self.assertFalse([p for p in (self.root / "awzars").rglob("*") if p.is_file()])

    def test_private_stdout_registration_and_profile_switch_lifecycle(self):
        for setting in ("", "mcp_readonly_accessible = false\n"):
            self.configuration.write_text(CONFIG.replace("mcp_readonly_accessible = true\n", setting))
            status, terminal, private = self.terminal(self.registration_arguments(), capture=True)
            self.assertEqual(status, 12, terminal)
            self.assertEqual(private, b"")
            legacy = self.registration_arguments()[:-1] + ["--secret-file", str(self.root / "legacy.secret")]
            status, terminal = self.terminal(legacy)
            self.assertEqual(status, 12, terminal)
            self.assertFalse((self.root / "legacy.secret").exists())
        status, output = self.terminal(["set-mcp-access", "--enabled", "true"],
                                      [(b"Type yes", b"yes")])
        self.assertEqual(status, 0, output)
        self.assertNotIn("[profiles.work.read_only.clients.", self.configuration.read_text())
        self.assertEqual(self.request(b"A" * 43).returncode, 12)
        status, terminal = self.terminal(self.registration_arguments())
        self.assertEqual(status, 2, terminal)  # No secret may be printed on a terminal.
        status, terminal, private = self.terminal(self.registration_arguments(),
                                                  [(b"Type yes", b"no")], capture=True)
        self.assertEqual(status, 2, terminal)
        self.assertEqual(private, b"")
        status, terminal, secret = self.terminal(self.registration_arguments(),
                                                 [(b"Type yes", b"yes")], capture=True)
        self.assertEqual(status, 0, terminal)
        self.assertRegex(secret, rb"^[A-Za-z0-9_-]{43}\n$")
        self.assertNotIn(secret.strip(), terminal)
        self.assertNotIn(secret.strip().decode(), self.configuration.read_text())
        # A fake MCP keyring is enough for this awzars-only contract check.
        keyring = {(str(self.root), "work", "incident-agent"): secret}
        original = self.configuration.read_text()
        status, terminal, private = self.terminal(self.registration_arguments(),
                                                  [(b"Type yes", b"yes")], capture=True)
        self.assertEqual(status, 2, terminal)
        self.assertEqual(private, b"")
        self.assertEqual(self.configuration.read_text(), original)
        for enabled in ("false", "true"):
            status, output = self.terminal(["set-mcp-access", "--enabled", enabled],
                                          [(b"Type yes", b"yes")])
            self.assertEqual(status, 0, output)
            if enabled == "false":
                self.assertEqual(self.request(secret).returncode, 12)
        self.assertEqual(self.configuration.read_text(), original)
        status, output = self.terminal(["revoke-mcp", "--client", "incident-agent"],
                                      [(b"Type yes", b"yes")])
        self.assertEqual(status, 0, output)
        keyring.pop((str(self.root), "work", "incident-agent"))
        status, output = self.terminal(["set-mcp-access", "--enabled", "true"],
                                      [(b"Type yes", b"yes")])
        self.assertEqual(status, 0, output)
        self.assertEqual(self.request(secret).returncode, 12)
        self.assert_no_normal_unlock_or_credentials()

    def test_password_registration_rechecks_context_and_hides_secret(self):
        status, output = self.terminal(["set-password"], [
            (b"New password for", b"test-password"),
            (b"Confirm new password", b"test-password"),
        ])
        self.assertEqual(status, 0, output)
        original = self.configuration.read_text()
        for old, new in [("mcp_readonly_accessible = true", "mcp_readonly_accessible = false"),
                         ("ap-southeast-1", "us-east-1")]:
            self.configuration.write_text(original)
            status, terminal, secret = self.terminal(
                self.registration_arguments(), [(b"manage MCP access", b"test-password")],
                capture=True, before_answer=lambda: self.configuration.write_text(original.replace(old, new)))
            self.assertEqual(status, 2, terminal)
            self.assertEqual(secret, b"")
            self.assertNotIn("[profiles.work.read_only.clients.", self.configuration.read_text())
        self.configuration.write_text(original)
        status, terminal, secret = self.terminal(
            ["-vvv"] + self.registration_arguments(), [(b"manage MCP access", b"test-password")],
            capture=True, environment=dict(self.environment, RUST_LOG="trace"))
        self.assertEqual(status, 0, terminal)
        self.assertRegex(secret, rb"^[A-Za-z0-9_-]{43}\n$")
        self.assertNotIn(secret.strip(), terminal)
        self.assertNotIn(b"test-password", terminal)
        self.assert_no_normal_unlock_or_credentials()

    def test_lost_secret_output_leaves_a_grant_and_requires_explicit_recovery(self):
        status, terminal, private = self.terminal(self.registration_arguments(),
                                                 [(b"Type yes", b"yes")], capture="broken")
        self.assertEqual(status, 2, terminal)
        self.assertEqual(private, b"")
        self.assertIn(b"Registration was saved but secret delivery failed", terminal)
        self.assertIn(b"Revoke", terminal)
        original = self.configuration.read_text()
        self.assertIn("[profiles.work.read_only.clients.incident-agent]", original)
        status, terminal, private = self.terminal(self.registration_arguments(),
                                                 [(b"Type yes", b"yes")], capture=True)
        self.assertEqual(status, 2, terminal)
        self.assertEqual(private, b"")
        self.assertEqual(self.configuration.read_text(), original)
        self.assert_no_normal_unlock_or_credentials()

    def test_ai_context_cannot_enroll_even_with_a_terminal(self):
        secret_file = self.root / "client.secret"
        status, output = self.terminal(
            ["enroll-mcp", "--client", "incident-agent", "--target", "workload",
             "--capability", "s3-list-buckets", "--secret-file", str(secret_file)],
            environment=dict(self.environment, AWZARS_MCP_TEST_AI="1"),
        )
        self.assertEqual(status, 8, output)
        self.assertFalse(secret_file.exists())
        self.assertEqual(self.configuration.read_text(), CONFIG)
        for arguments in [self.registration_arguments(),
                          ["set-mcp-access", "--enabled", "false"],
                          ["revoke-mcp", "--client", "incident-agent"]]:
            status, terminal, private = self.terminal(arguments, capture=True,
                environment=dict(self.environment, AWZARS_MCP_TEST_AI="1"))
            self.assertEqual(status, 8, terminal)
            self.assertEqual(private, b"")
            self.assertEqual(self.configuration.read_text(), CONFIG)


if __name__ == "__main__":
    unittest.main()

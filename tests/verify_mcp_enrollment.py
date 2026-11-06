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

    def terminal(self, arguments, answers=(), environment=None):
        child, master = pty.fork()
        if child == 0:
            os.execve(BINARY, self.command + arguments, environment or self.environment)
        output = bytearray()
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
                if pending and pending[0][0] in output[cursor:]:
                    prompt, answer = pending.pop(0)
                    cursor = output.index(prompt, cursor) + len(prompt)
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


if __name__ == "__main__":
    unittest.main()

"""Offline verification of the EKS example: python3 tests/verify_eks_session.py."""

import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


VERIFIER = Path(__file__).resolve().parents[1] / "examples/verify-eks-session.fish"
FISH = shutil.which("fish")
TARGET_ROLE = "arn:aws:iam::123456789012:role/ExistingWorkloadRole"

MOCK_PROGRAM = r'''#!/usr/bin/python3
import json
import os
from pathlib import Path
import subprocess
import sys

arguments = sys.argv[1:]
scenario = os.environ["MOCK_SCENARIO"]

def option(name):
    return arguments[arguments.index(name) + 1]

def record(kind, label="", attributes=None):
    with open(os.environ["MOCK_LOG"], "a") as output:
        output.write(json.dumps([kind, label, attributes]) + "\n")

def credentials(label):
    return {"AccessKeyId": "fake-key-" + label,
            "SecretAccessKey": "fake-secret-" + label,
            "SessionToken": "fake-token-" + label}

def assert_credentials(label):
    for name, field in [("AWS_ACCESS_KEY_ID", "AccessKeyId"),
                        ("AWS_SECRET_ACCESS_KEY", "SecretAccessKey"),
                        ("AWS_SESSION_TOKEN", "SessionToken"),
                        ("AWS_SECURITY_TOKEN", "SessionToken")]:
        assert os.environ[name] == credentials(label)[field], name

def fail(message):
    print(message, file=sys.stderr)
    sys.exit(1)

executable = Path(sys.argv[0]).name
if executable == "awzars":
    record("login")
    assert option("--profile") == "source-profile"
    assert "login" in arguments and "--session-policy" not in arguments
    assert all(flag in arguments for flag in ["--headless", "--remember-me", "--credential-process"])
    assert os.environ["AWS_ACCESS_KEY_ID"] == "ambient-key"
    if scenario == "login_failure":
        fail("Profile is locked")
    result = credentials("source")
    if scenario == "invalid_source":
        result.pop("SessionToken")
    print(json.dumps(result))
elif executable == "aws":
    assert "--profile" not in arguments
    assert option("--region") == "ap-southeast-1"
    assert "--no-cli-pager" in arguments
    assert os.environ["AWS_CLI_AUTO_PROMPT"] == "off"
    if arguments[:2] == ["sts", "assume-role"]:
        assert_credentials("source")
        assert option("--role-arn") == os.environ["MOCK_ROLE"]
        assert option("--role-session-name") == "awzars-eks-policy-test"
        assert option("--duration-seconds") == "900"
        assert option("--query") == "Credentials"
        policy = option("--policy")
        assert policy.startswith("file://")
        policy_path = Path(policy[len("file://"):])
        label = "denied" if policy_path.name == "deny-all.json" else "allowed"
        record("assume", label)
        statements = json.loads(policy_path.read_text())["Statement"]
        if label == "allowed":
            assert {"Effect": "Allow", "Action": "eks:DescribeCluster", "Resource": "*"} in statements
            assert {"Effect": "Deny", "NotAction": "eks:DescribeCluster", "Resource": "*"} in statements
        else:
            assert statements == [{"Effect": "Deny", "Action": "*", "Resource": "*"}]
        if scenario == "assume_failure_" + label:
            fail("AssumeRole was denied")
        result = credentials(label)
        if scenario == "invalid_credentials_" + label:
            result.pop("AccessKeyId")
        print(json.dumps(result))
    elif arguments[:2] == ["eks", "describe-cluster"]:
        label = os.environ["AWS_ACCESS_KEY_ID"].replace("fake-key-", "")
        assert_credentials(label)
        record("describe", label)
        assert option("--name") == "example-cluster"
        if label == "allowed":
            if scenario == "allow_describe_failure":
                fail("DescribeCluster was denied")
            result = {"name": "example-cluster", "endpoint": "https://example.invalid",
                      "certificateAuthority": {"data": "ZmFrZS1jYQ=="}}
            if scenario == "invalid_cluster":
                result.pop("certificateAuthority")
            print(json.dumps(result))
        else:
            if scenario == "deny_describe_allowed":
                print("example-cluster")
                sys.exit(0)
            code = "ExpiredToken" if scenario == "deny_describe_expired" else "AccessDeniedException"
            operation = "ListClusters" if scenario == "deny_describe_wrong_operation" else "DescribeCluster"
            fail("An error occurred ({}) when calling the {} operation: denied".format(code, operation))
    else:
        assert arguments == ["eks", "get-token", "--cluster-name", "example-cluster",
                             "--region", "ap-southeast-1", "--output", "json", "--no-cli-pager"]
        label = os.environ["AWS_ACCESS_KEY_ID"].replace("fake-key-", "")
        assert_credentials(label)
        record("token", label)
        print(json.dumps({"status": {"token": "private-kubernetes-token"}}))
else:
    assert executable == "kubectl"
    label = os.environ["AWS_ACCESS_KEY_ID"].replace("fake-key-", "")
    assert label in ["allowed", "denied"]
    assert_credentials(label)
    configuration_path = Path(option("--kubeconfig"))
    assert str(configuration_path) != os.environ["KUBECONFIG"]
    assert configuration_path.stat().st_mode & 0o077 == 0
    configuration = json.loads(configuration_path.read_text())
    user = configuration["users"][0]["user"]
    assert set(user) == {"exec"}
    assert set(user["exec"]) == {"apiVersion", "command", "args", "interactiveMode"}
    assert user["exec"]["interactiveMode"] == "Never"
    assert configuration["clusters"][0]["cluster"] == {
        "server": "https://example.invalid", "certificate-authority-data": "ZmFrZS1jYQ=="}
    assert option("--cache-dir") == str(configuration_path.parent / "cache")
    assert "--request-timeout=20s" in arguments
    token = subprocess.run([user["exec"]["command"], *user["exec"]["args"]],
                           text=True, stdout=subprocess.PIPE, check=True)
    assert json.loads(token.stdout)["status"]["token"] == "private-kubernetes-token"
    if "auth" in arguments:
        fail("error: unknown flag: --output (legacy kubectl has no auth whoami)")
    if arguments[-5:] == ["create", "--raw",
                          "/apis/authentication.k8s.io/v1/selfsubjectreviews", "-f", "-"]:
        request = json.load(sys.stdin)
        assert request == {"apiVersion": "authentication.k8s.io/v1", "kind": "SelfSubjectReview"}
        record("identity", label)
        if scenario == "authentication_failure_" + label:
            fail("Unable to connect to the Kubernetes server")
        if scenario == "missing_identity_api_" + label:
            fail("Error from server (NotFound): the server could not find the requested resource")
        identity = {"username": "private-user", "groups": ["system:authenticated"]}
        if scenario == "anonymous_" + label:
            identity = {"username": "system:anonymous", "groups": ["system:unauthenticated"]}
        print(json.dumps({"status": {"userInfo": identity}}))
    else:
        assert arguments[-5:] == ["create", "--raw",
                                 "/apis/authorization.k8s.io/v1/selfsubjectaccessreviews", "-f", "-"]
        request = json.load(sys.stdin)
        assert request["apiVersion"] == "authorization.k8s.io/v1"
        assert request["kind"] == "SelfSubjectAccessReview"
        attributes = request["spec"]["resourceAttributes"]
        assert attributes.pop("namespace") == "default"
        assert attributes in [
            {"verb": "list", "resource": "pods"},
            {"verb": "get", "resource": "pods", "subresource": "log"},
            {"verb": "create", "resource": "pods"},
            {"verb": "patch", "resource": "deployments", "group": "apps"},
            {"verb": "delete", "resource": "pods"},
            {"verb": "create", "resource": "pods", "subresource": "exec"}]
        record("review", label, attributes)
        if scenario == "review_failure_" + label:
            fail("Authorization review request failed")
        allowed = (attributes in [{"verb": "list", "resource": "pods"},
                                  {"verb": "get", "resource": "pods", "subresource": "log"}]
                   or scenario == "all_writes" or scenario == "writes_" + label)
        result = {"allowed": allowed, "reason": "Policy decision"}
        if scenario == "evaluation_error_" + label:
            result["evaluationError"] = "Authorization webhook unavailable"
        if scenario == "invalid_review_" + label:
            result.pop("allowed")
        print(json.dumps({"status": result}))
'''


@unittest.skipUnless(FISH and shutil.which("jq"), "Fish and jq are required")
class VerifyEksSession(unittest.TestCase):
    def test_isolation_results_and_failures(self):
        scenarios = {
            "all_writes": 3, "writes_allowed": 3, "writes_denied": 3, "reads_only": 0,
            "login_failure": 1, "invalid_source": 1,
            "allow_describe_failure": 1, "invalid_cluster": 1,
            "deny_describe_allowed": 1, "deny_describe_expired": 1,
            "deny_describe_wrong_operation": 1,
        }
        for label in ["allowed", "denied"]:
            for failure in ["assume_failure", "invalid_credentials", "authentication_failure", "missing_identity_api",
                            "anonymous", "review_failure", "evaluation_error", "invalid_review"]:
                scenarios[f"{failure}_{label}"] = 1
        for scenario, expected_status in scenarios.items():
            with self.subTest(scenario=scenario), tempfile.TemporaryDirectory(prefix="awzars-eks-mock-") as directory:
                temporary = Path(directory)
                original_config = temporary / "original-kubeconfig"
                original_config.write_text("unchanged")
                for executable in ["awzars", "aws", "kubectl"]:
                    path = temporary / executable
                    path.write_text(MOCK_PROGRAM)
                    path.chmod(0o700)
                environment = {
                    "PATH": f"{temporary}:/usr/bin:/bin", "HOME": directory, "TMPDIR": directory,
                    "MOCK_LOG": str(temporary / "events.jsonl"), "MOCK_SCENARIO": scenario,
                    "MOCK_ROLE": TARGET_ROLE, "KUBECONFIG": str(original_config),
                    "AWS_PROFILE": "normal-production-profile", "AWS_CLI_AUTO_PROMPT": "on",
                    "AWS_ACCESS_KEY_ID": "ambient-key", "AWS_SECRET_ACCESS_KEY": "ambient-secret",
                    "AWS_SESSION_TOKEN": "ambient-token", "AWS_SECURITY_TOKEN": "ambient-legacy-token",
                }
                result = subprocess.run(
                    [FISH, "--no-config", str(VERIFIER), str(temporary / "awzars"),
                     "source-profile", "ap-southeast-1", TARGET_ROLE, "example-cluster"],
                    env=environment, text=True, capture_output=True, timeout=15)
                self.assertEqual(result.returncode, expected_status, result.stdout + result.stderr)
                output = result.stdout + result.stderr
                self.assertNotIn("Traceback", output)
                for secret in ["fake-key-", "fake-secret-", "fake-token-", "private-kubernetes-token", "private-user"]:
                    self.assertNotIn(secret, output)
                self.assertEqual(original_config.read_text(), "unchanged")
                self.assertEqual(list(temporary.glob("awzars-eks-check.*")), [])
                events = [json.loads(line) for line in (temporary / "events.jsonl").read_text().splitlines()]
                if expected_status in [0, 3]:
                    self.assertIn("DescribeCluster was denied with the deny-all policy", output)
                    self.assertIn("AWS deny-all session still authenticated to Kubernetes", output)
                    self.assertEqual(sum(event[0] == "review" for event in events), 12)
                    self.assertEqual(output.count("get pods/log: yes"), 2)
                    self.assertEqual(sum(event[0] == "identity" for event in events), 2)
                if expected_status == 3:
                    self.assertIn("not a Kubernetes read-only boundary", output)
                if expected_status == 0:
                    self.assertIn("does not prove full read-only access", output)
                if scenario.startswith("deny_describe"):
                    self.assertFalse(any(event[0] == "identity" for event in events))

    def test_usage(self):
        for arguments in [[], ["binary", "profile", "region", TARGET_ROLE],
                          ["binary", "profile", "region", TARGET_ROLE, "cluster", "INVALID"],
                          ["binary", "profile", "region", TARGET_ROLE, "cluster", "default", "extra"]]:
            with self.subTest(arguments=arguments):
                result = subprocess.run([FISH, "--no-config", str(VERIFIER), *arguments],
                                        text=True, capture_output=True, timeout=5)
                self.assertEqual(result.returncode, 2, result.stdout + result.stderr)


if __name__ == "__main__":
    unittest.main()

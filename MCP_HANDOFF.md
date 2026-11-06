# Read-only MCP handoff

The MCP is a separate project. Its purpose is agent incident investigation:
approved AWS inspection, Kubernetes workload status and events, and bounded
log access. No MCP implementation belongs in the awzars repository.

## Responsibility boundary

```text
awzars
  keeps normal/source credentials internally
  authenticates the enrolled client and builds the approved session policy
  |
  | only final, policy-restricted AWS credentials (15 minutes)
  v
separate MCP
  keeps restricted AWS credentials and EKS tokens privately
  enforces approved read operations and calls AWS / Kubernetes
  |
  | read results only
  v
agent
```

Awzars owns typed construction of approved AWS session policies, final-role
issuance, source-credential protection, credential-cache separation, and
failure handling. Arbitrary JSON is not proof that a policy is read-only.
The generic session-policy option remains a separately gated interface.

The MCP owns tool authorization, request parameters and targets, Kubernetes
operation enforcement, and handling of returned data. It receives restricted
AWS sessions for its backend; agents receive tool results rather than keys
or authentication tokens. The MCP never receives awzars' normal/source
credentials through this interface. The agent does not call awzars directly.

The AWS session policy is attached by STS at issuance; the MCP receives the
credentials for that session and cannot remove or broaden its AWS policy.
These same restricted credentials may authenticate to Kubernetes with the
role's existing permissions. AWS enforces the AWS policy; the MCP enforces
the approved Kubernetes reads, as detailed below.

The existing awzars lock is the operational gate for normal credentials.
This is not a claim that an unrestricted process running as the same OS user
cannot access the user's configuration, cached credentials or keyring.
Agent tool restrictions and any stronger execution isolation are MCP/deployment
responsibilities. This is a separate deployment question, not evidence that
the proposed credential flow exposes secrets. No live credential extraction
or bypass was demonstrated in this work. Sharing an OS account alone does not
mean an agent can read another process's credentials; its tools, sandbox and
OS permissions determine which alternate access paths are available.

## Local MCP authentication

The selected deployment is the same machine and OS account. The MCP invokes
awzars as a subprocess, sends an enrolled secret through private stdin, closes
stdin, and captures credential JSON from stdout. No listening service or new
OS account is required. Authentication proves possession of the enrolled
secret; a process name, client label or shared OS identity is not proof.

Awzars checks the secret and the grant for the requested profile, target and
capability before reading source credentials. An authenticated request bypasses
the password/AI gate only for approved final-session issuance. It creates no
general unlock token and does not relax normal credential commands. Invalid
authentication or authorization returns exit code 12, with no credential output
and no fallback to the normal gate or an unrestricted session.

The normal profile lock and this enrollment are separate grants. `awzars lock`
ends the normal session unlock; `revoke-mcp` ends a client's future requests.
Enrollment secrets remain valid until revoked or invalidated by a bound setting
change. They are distinct from the AWS credentials, whose lifetime is 15 minutes.

### Enrollment and revocation

Configure the source profile and approved target first, then enroll from the
operator's own terminal. The parent directory of `--secret-file` must exist;
choose a private location accessible to the MCP and excluded from agent tools.

```sh
awzars --profile work enroll-mcp --client incident-agent \
  --target workload --capability s3-list-buckets \
  --capability eks-describe-cluster \
  --secret-file /absolute/private/mcp/awzars.secret
```

Enrollment requires a human terminal and rejects detected AI contexts. A locked
profile requires its current password; an unlocked profile requires confirmation.
Neither flow unlocks normal credentials. Awzars generates a random 256-bit secret,
writes it to a new 0600 file without overwriting existing paths, and stores only
an Argon2id verifier in the profile. The secret is never printed. If the config
save fails after file creation, the error reports that the file remains; check
the enrollment before using it. Re-enrollment requires explicit revocation.

The grant binds the profile name, Azure tenant/application, source role, current
password verifier, target role/region and configured target capabilities. Changing
these settings invalidates the enrollment. Profile edits preserve stored grants,
but changed bindings fail authentication until the operator re-enrolls the client.

```sh
awzars --profile work revoke-mcp --client incident-agent
```

Revocation uses the same operator authorization. It prevents later requests;
already authorized requests and AWS-issued sessions are not retroactively revoked.
The MCP should discard its cached sessions and remove its saved enrollment secret.

### Subprocess contract

```text
MCP -- private stdin: enrollment secret --> awzars
MCP <-- stdout: restricted credential JSON --+
agent <-- read results from MCP only
```

Invoke the trusted executable directly, without a shell:

```text
awzars --profile work read-only --target workload
       --capability eks-describe-cluster --client incident-agent
```

Stdin is the 43-character URL-safe base64 secret, optionally followed by LF or
CRLF, then EOF. Input is bounded; malformed or oversized input is rejected.
Never pass the secret in arguments or environment variables. The MCP owns the
subprocess timeout, closes stdin and treats nonzero exit as failure. Stdout is
standard AWS credential-process JSON; stderr is diagnostic text. SDK debug/trace
logging is suppressed on this authenticated path, including when verbose logging
was requested. Never forward credential stdout or the secret to the agent.

The credential issuance side is implemented in awzars; the separate MCP still
needs to integrate this contract. No production enrollment or live verification
of this authenticated path was performed as part of the implementation.

A bearer secret can be used by any process that obtains it. Protect the secret,
the MCP's session memory, trusted configuration and executable from the agent's
other tools. Same-account operation is the chosen tradeoff, not a guarantee of
isolation against unrestricted access to that account.

## Awzars consumer contract

Trusted deployment configuration fixes the awzars executable, config directory,
source profile and target alias. The caller requests a capability by name:

```text
MCP -- client + target + capability --> awzars checks secret + grant
                                  |
                          internal source session
                                  |
                      final AssumeRole + approved policy
                                  |
MCP <-- final credentials only ---+
```

Example invocation (stdout is private credential JSON, not an agent response):

```sh
awzars --profile work read-only --target workload \
  --capability s3-list-buckets --client incident-agent
```

Provide the secret on private stdin using the subprocess contract above.

The source profile must configure the existing target role, region and enabled
capabilities under `profiles.work.read_only.targets.workload`; see the README.
Initial capabilities are `s3-list-buckets`, `ec2-describe-instances` and
`eks-describe-cluster`. This is not comprehensive AWS coverage. One capability
is requested per session. Unsupported names and unconfigured targets fail
before source credentials are loaded. No caller policy, role, endpoint, region
or duration override is accepted on this command.

Awzars builds an explicit allow plus explicit denials outside the approved
action and supported scope. STS receives this policy on the final role hop,
for 900 seconds. Only validated final temporary credentials are emitted.
Source credentials may use the existing source cache; final sessions are fresh
and are never saved into that cache. Failure produces no credential output.
Without `--client`, the command requires the existing password/AI gate. The
enrolled-client path above is the only implemented exception for approved reads.
No production profile was changed or enrolled during implementation.

S3 listing reveals account-wide bucket metadata. EC2 descriptions cover the
configured region. EKS descriptions cover all clusters in the configured
region and final role's account. Narrower agent-visible targets and data are
the MCP's responsibility. The AWS role must already permit the requested read
and the source role must already be allowed to assume it.

Cache any final session only within the trusted MCP process, indexed by source,
target, capability and scope. Honor its returned expiry. Removing local
configuration or locking awzars does not revoke credentials already issued by
AWS. Refresh only through this command, never through an unrestricted fallback.
Sanitize inherited AWS, kubectl, proxy and logging environment variables; bind
executables and endpoints to trusted configuration.

## Accepted EKS limitation

AWS IAM session policies do not restrict Kubernetes permissions. In live
verification, the EKS `DescribeCluster` request succeeded with an allow policy
and failed with deny-all. Both sessions nevertheless authenticated to Kubernetes
and were authorized to list pods, create pods, patch deployments, delete pods,
and execute in pods. Only permission reviews were submitted; no workload writes
were attempted. Pod-log permission checking was added afterward and has not
yet been verified live.

For now, retain this limitation and enforce Kubernetes reads in the separate
MCP. The backend's Kubernetes identity may remain write-capable. A backend
compromise or access to its credentials can bypass application checks; the
current tradeoff does not establish cluster-enforced read-only access.

The agent's available tools and alternate access paths must match that decision:
do not also expose unrestricted `kubectl`, a shell with production credentials,
the normal kubeconfig, credential export, or token-generation tools. Merely
calling an MCP tool "read-only" does not restrict an agent's other tools.

See [EKS authentication](https://docs.aws.amazon.com/eks/latest/best-practices/identity-and-access-management.html)
and [GetCallerIdentity permissions](https://docs.aws.amazon.com/STS/latest/APIReference/API_GetCallerIdentity.html).

## Request enforcement

- Expose named tools with structured inputs, such as workload inspection,
  event inspection and pod-log retrieval. Do not expose arbitrary shell,
  AWS CLI or kubectl command strings.
- Resolve approved accounts, regions, clusters and namespaces from trusted
  configuration. Reject caller-supplied endpoints, credentials, kubeconfig,
  profile overrides, role overrides, impersonation, plugins and executable paths.
- Validate the actual request that will execute. Reject unknown parameters and
  unmapped operations rather than guessing from command names.
- Explicitly allow reviewed Kubernetes resources and subresources. Pod logs
  use `pods/log`; do not generalize that permission to `pods/*` or other proxies.
- Reject create, patch, update, delete, execution, attach, port-forward, proxy,
  impersonation and credential/token export through the agent interface.
- A `get` verb is not sufficient proof: `get nodes/proxy` can permit command
  execution. See [Kubernetes RBAC guidance](https://kubernetes.io/docs/concepts/security/rbac-good-practices/#access-to-proxy-subresource-of-nodes).
- Never retry a denied or failed restricted operation using normal credentials.
  A missing policy, incomplete authorization evaluation or unavailable service
  is an error, not evidence that a request was safely restricted.

## Returned data and incident logs

- Restrict namespaces, resources and returned fields to those approved for the
  agent. Explicit secret and credential retrieval must not be available.
- Bound log time ranges, line counts, output size, stream duration and request
  rate. Read-only operations can still disclose sensitive data or consume resources.
- Redact known sensitive fields, without promising that arbitrary application
  logs or workload definitions are secret-free.
- Treat retrieved logs, annotations and resource contents as untrusted data.
  They must not modify tool permissions, request broader credentials, supply
  commands to execute, or authorize additional actions.
- Keep authentication material out of tool responses, error messages, debug
  traces, telemetry and subprocess arguments.

## Verification before enabling agent access

Test the actual agent environment and MCP interface, not only AWS policies:

1. Approved workload inspection and logs succeed within their permitted scope.
2. Writes, execution, proxying and credential export are rejected before execution.
3. Unknown operations, extra arguments and alternate profiles/endpoints are rejected.
4. The agent's other tools cannot silently use normal production credentials.
5. Credential refresh and error handling never return or retry with source credentials.
6. Oversized requests, expired credentials and failed checks stop safely.
7. Retrieved text cannot change the allowed operations or scope.
8. Unknown/revoked clients and requests outside their grants fail before
   credential access; authorized
   read issuance never unlocks normal credential commands.

AWS session-policy enforcement has been demonstrated for S3 bucket listing and
EKS cluster description. This is not an audit of every AWS operation or proof
of Kubernetes read-only enforcement. The MCP implementation and these interface
checks remain work for the separate project.

Awzars' offline enrollment lifecycle can be checked with
`python3 tests/verify_mcp_enrollment.py /absolute/path/to/awzars`. It uses
throwaway configuration and pseudo-terminals; it does not read production
credentials, authenticate to AWS or modify the user's profiles.

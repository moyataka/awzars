# AWS operation-scoped read sessions

Awzars, not the MCP caller, decides which AWS actions enter each session policy.
The `aws-read` capability adds an exact `--aws-operation service/ApiOperation`
argument. Unknown operations, missing operation arguments and an operation paired
with a different capability are rejected. Raw IAM actions and policy JSON remain
unavailable on the approved-client path.

```text
Agent -- typed read --> MCP -- grant + exact operation --> Awzars
                                                         |
                                 pinned catalog + configured target
                                                         |
                                  final AssumeRole + 900-second policy
                                                         |
Agent <-- bounded data -- MCP <-- private final credentials
```

The target must enable `aws-read`, and the enrolled client must hold that
capability. Existing grants do not acquire it automatically. Changing a target's
bound settings invalidates its old registration. Use deliberate deregistration,
operator configuration changes and registration in the human terminal. Normal
profile password/AI locks and the default-off MCP eligibility switch are unchanged.

## Catalog provenance and exclusions

`scripts/update_aws_read_catalog.py` reads the public
[AWS service reference](https://docs.aws.amazon.com/service-authorization/latest/reference/service-reference.html),
with no AWS credentials. It pins the retrieval time and source SHA-256 digests in
`src/auth/aws/read_only/catalog.json`. Updates are explicit source changes, never
downloaded or auto-approved at credential issuance.

Every mapped IAM action must have explicit false values for write, permission
management and tagging-only annotations. Missing mappings or classifications
exclude the operation. A further conservative API-family filter and credential,
secret and stateful-operation exclusions apply to API names and IAM actions.
Names alone never approve an operation. Examples rejected include SQS message
receipt, agent/model execution, starting queries/jobs, certificate private-key
export, temporary credential retrieval and secret values. This may exclude
harmless operations too. Ordinary S3 reads exclude Object Lambda permissions.

The current snapshot contains 7,822 approved operations across 402 SDK service
interfaces. This is generated catalog coverage, not manual review or live
validation of each API. New AWS services and unclassified APIs fail closed until
an explicit catalog update. Updates require review and regression tests.

## Policy and account limits

The policy allows the mapped actions and explicitly denies every other action.
It denies a different requested region except for cataloged global services. It
denies resources in other accounts **where AWS supplies `aws:ResourceAccount`**.
This condition is not a universal account boundary: some APIs omit that key or
use caller-provided account IDs. Consumers must apply any stricter resource or
account checks required by their deployment.

AWS IAM actions can cover several API operations (for example API Gateway's
`apigateway:GET`). The session is bounded by IAM action granularity, while MCP
must still execute only the exact approved API. It is not an API-level sandbox.
The existing role must already permit the action; session policies cannot add
permissions. Every catalog policy is tested against the STS 2,048-character limit.

AWS's operation mappings omit some permissions for services acting on the caller's
behalf. Those requests may fail safely. `s3/GetObject` has one explicit reviewed
dependency: `kms:Decrypt` through S3 only, with an S3 encryption context and key
ARNs restricted to the configured account/region. Direct decryption, other
services, keys outside that scope and key writes remain explicitly denied. The
role and key policy must already permit the read. See AWS's
[S3 KMS permissions](https://docs.aws.amazon.com/AmazonS3/latest/userguide/UsingKMSEncryption.html)
and [ViaService conditions](https://docs.aws.amazon.com/kms/latest/developerguide/conditions-kms.html#conditions-kms-via-service).
Catalog descriptors list primary mapped actions; the policy builder adds this
conditioned dependency. There is no unrestricted credential fallback. Costs,
access logs and ordinary read side effects are not prevented by a read policy.

## Non-secret catalog discovery

These commands do not load profile secrets or contact AWS:

```fish
rtk proxy awzars read-catalog
rtk proxy awzars read-catalog --service dynamodb
rtk proxy awzars read-catalog --aws-operation dynamodb/Query
```

Service pages contain at most 100 operations and a `next_offset`. Descriptors
contain the service name, API name, canonical CLI command, IAM actions and global
service flag. The separate MCP consumes this catalog from its trusted awzars
executable instead of maintaining a second policy list.

Credential issuance uses the existing private pipes, with the additional argument:

```text
awzars --profile PROFILE read-only --target TARGET --client CLIENT
       --capability aws-read --aws-operation dynamodb/Query
stdin: registration secret + EOF
stdout: final credential-process JSON (private to MCP)
```

Credentials remain valid until their own expiry after issuance. Revocation and
the final grant recheck block new delivery, not already issued AWS sessions.

## Kubernetes remains separate

EKS management APIs are covered by IAM policies. Kubernetes authorization is not.
The earlier live checks showed both allow-policy and deny-all AWS sessions could
authenticate with Kubernetes write permissions. MCP must enforce its Kubernetes
get/list/log tools and keep credentials away from the agent. A shared OS account
or keyring secret alone does not isolate unrestricted local processes.

Raw port-forwarding is not read-only: arbitrary TCP traffic can mutate the
destination service. It requires a separately accepted MCP exception or a
destination that independently enforces read-only access. An AWS session policy
cannot impose that restriction.

The user accepted the separate MCP's controlled port-forwarding exception. Its
operator configuration restricts exact pods/ports, localhost listening and short
lifetimes. Awzars still issues the existing `eks-describe-cluster` session; no
new awzars capability is needed for this exception. Kubernetes RBAC and the MCP
must enforce the tunnel path independently of the AWS policy.

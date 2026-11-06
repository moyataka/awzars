#!/usr/bin/env fish

function eks_session_credential_fields
    jq -er '
        [.AccessKeyId, .SecretAccessKey, .SessionToken]
        | if all(.[]; type == "string" and length > 0)
          then .[] else error("Missing session credentials") end'
end

function assume_eks_test_session --argument-names role_arn region policy_path
    command aws sts assume-role \
        --role-arn "$role_arn" \
        --role-session-name awzars-eks-policy-test \
        --duration-seconds 900 --policy "file://$policy_path" \
        --region "$region" --query Credentials --output json --no-cli-pager \
        --cli-connect-timeout 10 --cli-read-timeout 20
end

function check_kubernetes_permissions --argument-names temporary_directory namespace label
    set -l kubectl_arguments --kubeconfig "$temporary_directory/config.json" \
        --cache-dir "$temporary_directory/cache" --request-timeout=20s
    # Older kubectl clients do not have auth whoami.
    set -l identity_review '{"apiVersion":"authentication.k8s.io/v1","kind":"SelfSubjectReview"}'
    set -l identity (printf '%s\n' "$identity_review" | command kubectl $kubectl_arguments \
        create --raw /apis/authentication.k8s.io/v1/selfsubjectreviews -f -)
    or begin
        printf 'Kubernetes identity review failed (%s); result is inconclusive.\n' "$label" >&2
        return 1
    end
    printf '%s\n' "$identity" | jq -e '
        .status.userInfo
        | (.username | type == "string" and length > 0 and . != "system:anonymous")
          and ((.groups // []) | index("system:authenticated") != null)
          and ((.groups // []) | index("system:unauthenticated") == null)' >/dev/null
    or begin
        printf 'Kubernetes did not confirm an authenticated identity (%s).\n' "$label" >&2
        return 1
    end
    printf 'Kubernetes authenticated the %s session.\n' "$label"

    set -l write_allowed false
    set -l permission_checks '[
        {"verb":"list","resource":"pods"},
        {"verb":"get","resource":"pods","subresource":"log"},
        {"verb":"create","resource":"pods"},
        {"verb":"patch","resource":"deployments","group":"apps"},
        {"verb":"delete","resource":"pods"},
        {"verb":"create","resource":"pods","subresource":"exec"}
    ]'
    for attributes in (printf '%s\n' "$permission_checks" | jq -c '.[]')
        set -l operation (printf '%s\n' "$attributes" | jq -r '
            .verb + " " + .resource
            + (if .group then "." + .group else "" end)
            + (if .subresource then "/" + .subresource else "" end)')
        set -l review (printf '%s\n' "$attributes" | jq -c --arg namespace "$namespace" '{
            apiVersion: "authorization.k8s.io/v1", kind: "SelfSubjectAccessReview",
            spec: {resourceAttributes: (. + {namespace: $namespace})}
        }')
        # These non-persistent reviews ask about permissions; they do not perform the requested operations.
        set -l permission_output (printf '%s\n' "$review" | command kubectl $kubectl_arguments \
            create --raw /apis/authorization.k8s.io/v1/selfsubjectaccessreviews -f -)
        or begin
            printf 'Kubernetes permission check failed (%s, %s); result is inconclusive.\n' "$label" "$operation" >&2
            return 1
        end
        set -l permission (printf '%s\n' "$permission_output" | jq -er '
            .status
            | if (.allowed | type) != "boolean" or ((.evaluationError // "") | length) > 0
              then error("Kubernetes authorization evaluation was incomplete")
              elif .allowed then "yes" else "no" end')
        or return 1
        printf '  %s: %s\n' "$operation" "$permission"
        if test "$permission" = yes; and not contains -- "$operation" 'list pods' 'get pods/log'
            set write_allowed true
        end
    end
    if test "$write_allowed" = true
        return 3
    end
    return 0
end

function verify_eks_session --argument-names awzars_binary profile region role_arn cluster namespace
    set -lx AWS_CLI_AUTO_PROMPT off
    set -l source_output ($awzars_binary --profile "$profile" login \
        --headless --remember-me --session-duration 900 --credential-process)
    or return 1
    set -l source_fields (printf '%s\n' "$source_output" | eks_session_credential_fields)
    or return 1
    test (count $source_fields) -eq 3
    or return 1

    set -lx AWS_ACCESS_KEY_ID $source_fields[1]
    set -lx AWS_SECRET_ACCESS_KEY $source_fields[2]
    set -lx AWS_SESSION_TOKEN $source_fields[3]
    set -lx AWS_SECURITY_TOKEN $source_fields[3]

    set -l policy_directory (path resolve (status dirname)/session-policies)
    set -l allowed_output (assume_eks_test_session "$role_arn" "$region" "$policy_directory/eks-describe-cluster.json")
    or return 1
    set -l allowed_fields (printf '%s\n' "$allowed_output" | eks_session_credential_fields)
    or return 1
    test (count $allowed_fields) -eq 3
    or return 1
    set -l denied_output (assume_eks_test_session "$role_arn" "$region" "$policy_directory/deny-all.json")
    or return 1
    set -l denied_fields (printf '%s\n' "$denied_output" | eks_session_credential_fields)
    or return 1
    test (count $denied_fields) -eq 3
    or return 1

    set AWS_ACCESS_KEY_ID $allowed_fields[1]
    set AWS_SECRET_ACCESS_KEY $allowed_fields[2]
    set AWS_SESSION_TOKEN $allowed_fields[3]
    set AWS_SECURITY_TOKEN $allowed_fields[3]
    set -l cluster_description (command aws eks describe-cluster --name "$cluster" \
        --region "$region" --output json --no-cli-pager \
        --query 'cluster.{name:name,endpoint:endpoint,certificateAuthority:certificateAuthority}' \
        --cli-connect-timeout 10 --cli-read-timeout 20)
    or begin
        printf 'EKS DescribeCluster failed with the allow policy; result is inconclusive.\n' >&2
        return 1
    end
    printf '%s\n' "$cluster_description" | jq -e --arg cluster "$cluster" '
        .name == $cluster
        and (.endpoint | type == "string" and startswith("https://"))
        and (.certificateAuthority.data | type == "string" and length > 0)' >/dev/null
    or begin
        printf 'EKS returned incomplete cluster connection information.\n' >&2
        return 1
    end
    printf 'EKS DescribeCluster succeeded with the allow policy.\n'

    umask 077
    set -l temporary_directory (mktemp -d -t awzars-eks-check.XXXXXXXX)
    or return 1
    function cleanup_eks_verification --on-event fish_exit --inherit-variable temporary_directory
        command rm -rf -- "$temporary_directory"
    end
    set -l aws_command (command --search aws)
    printf '%s\n' "$cluster_description" | jq --arg region "$region" --arg aws_command "$aws_command" '
        {
          apiVersion: "v1", kind: "Config",
          clusters: [{name: "verification", cluster: {
            server: .endpoint, "certificate-authority-data": .certificateAuthority.data
          }}],
          contexts: [{name: "verification", context: {
            cluster: "verification", user: "restricted-session"
          }}],
          "current-context": "verification",
          users: [{name: "restricted-session", user: {exec: {
            apiVersion: "client.authentication.k8s.io/v1beta1",
            command: $aws_command,
            args: ["eks", "get-token", "--cluster-name", .name,
                   "--region", $region, "--output", "json", "--no-cli-pager"],
            interactiveMode: "Never"
          }}}]
        }' >"$temporary_directory/config.json"
    or return 1

    set AWS_ACCESS_KEY_ID $denied_fields[1]
    set AWS_SECRET_ACCESS_KEY $denied_fields[2]
    set AWS_SESSION_TOKEN $denied_fields[3]
    set AWS_SECURITY_TOKEN $denied_fields[3]
    set -l describe_output (command aws eks describe-cluster --name "$cluster" \
        --region "$region" --query cluster.name --output text --no-cli-pager \
        --cli-connect-timeout 10 --cli-read-timeout 20 2>&1)
    set -l describe_status $status
    if test $describe_status -eq 0; or not string match --quiet --regex \
            '^An error occurred \((AccessDeniedException|AccessDenied)\) when calling the DescribeCluster operation:' -- $describe_output
        printf 'EKS DescribeCluster did not produce the expected denial; result is inconclusive.\n' >&2
        if test $describe_status -ne 0
            printf '%s\n' "$describe_output" >&2
        end
        return 1
    end
    printf 'EKS DescribeCluster was denied with the deny-all policy.\n'

    set AWS_ACCESS_KEY_ID $allowed_fields[1]
    set AWS_SECRET_ACCESS_KEY $allowed_fields[2]
    set AWS_SESSION_TOKEN $allowed_fields[3]
    set AWS_SECURITY_TOKEN $allowed_fields[3]
    check_kubernetes_permissions "$temporary_directory" "$namespace" 'allow-policy'
    set -l allowed_kubernetes_status $status
    if test $allowed_kubernetes_status -ne 0; and test $allowed_kubernetes_status -ne 3
        return 1
    end

    set AWS_ACCESS_KEY_ID $denied_fields[1]
    set AWS_SECRET_ACCESS_KEY $denied_fields[2]
    set AWS_SESSION_TOKEN $denied_fields[3]
    set AWS_SECURITY_TOKEN $denied_fields[3]
    check_kubernetes_permissions "$temporary_directory" "$namespace" 'deny-all'
    set -l denied_kubernetes_status $status
    if test $denied_kubernetes_status -ne 0; and test $denied_kubernetes_status -ne 3
        return 1
    end
    printf 'The AWS deny-all session still authenticated to Kubernetes.\n'
    if test $allowed_kubernetes_status -eq 3; or test $denied_kubernetes_status -eq 3
        printf 'Kubernetes reported write or execution permission in a restricted AWS session.\n'
        printf 'These credentials are not a Kubernetes read-only boundary. No workload write was attempted.\n'
        return 3
    end
    printf 'The sampled Kubernetes write permissions were denied; this does not prove full read-only access.\n'
end

if test (count $argv) -lt 5; or test (count $argv) -gt 6
    printf 'Usage: fish %s /path/to/awzars SOURCE_PROFILE REGION TARGET_ROLE_ARN CLUSTER [NAMESPACE]\n' (status filename) >&2
    exit 2
end
for executable in aws jq kubectl mktemp
    if not command --query $executable
        printf 'Required command is missing: %s\n' "$executable" >&2
        exit 2
    end
end
set -l namespace default
if test (count $argv) -eq 6
    set namespace "$argv[6]"
end
if not string match --quiet --regex '^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$' -- "$namespace"
    printf 'NAMESPACE must be a valid Kubernetes namespace name.\n' >&2
    exit 2
end
verify_eks_session "$argv[1]" "$argv[2]" "$argv[3]" "$argv[4]" "$argv[5]" "$namespace"

#!/usr/bin/env fish

function session_credential_fields
    jq -er '
        [.AccessKeyId, .SecretAccessKey, .SessionToken]
        | if all(.[]; type == "string" and length > 0)
          then .[] else error("Missing session credentials") end'
end

function verify_s3_bucket_listing --argument-names awzars_binary profile region policy_path expectation target_role_arn
    set -l session_policy_arguments
    if test -z "$target_role_arn"
        set session_policy_arguments --session-policy "$policy_path"
    end
    set -l session_output ($awzars_binary --profile "$profile" login \
        --headless --remember-me \
        $session_policy_arguments --session-duration 900 --credential-process)
    or return 1

    set -l credential_fields (printf '%s\n' "$session_output" | session_credential_fields)
    or return 1
    test (count $credential_fields) -eq 3
    or return 1

    set -lx AWS_ACCESS_KEY_ID $credential_fields[1]
    set -lx AWS_SECRET_ACCESS_KEY $credential_fields[2]
    set -lx AWS_SESSION_TOKEN $credential_fields[3]
    set -lx AWS_SECURITY_TOKEN $credential_fields[3]
    set -lx AWS_CLI_AUTO_PROMPT off

    if test -n "$target_role_arn"
        set session_output (aws sts assume-role \
            --role-arn "$target_role_arn" \
            --role-session-name awzars-session-policy-test \
            --duration-seconds 900 \
            --policy "file://$policy_path" \
            --region "$region" \
            --query Credentials --output json --no-cli-pager)
        or return 1

        set credential_fields (printf '%s\n' "$session_output" | session_credential_fields)
        or return 1
        test (count $credential_fields) -eq 3
        or return 1

        set AWS_ACCESS_KEY_ID $credential_fields[1]
        set AWS_SECRET_ACCESS_KEY $credential_fields[2]
        set AWS_SESSION_TOKEN $credential_fields[3]
        set AWS_SECURITY_TOKEN $credential_fields[3]
    end

    set -l listing_output (aws s3 ls --region "$region" --no-cli-pager 2>&1)
    set -l listing_status $status
    if test "$expectation" = allowed; and test $listing_status -eq 0
        printf 'S3 bucket listing succeeded with the allow policy.\n'
        return 0
    end
    if test "$expectation" = denied; and test $listing_status -ne 0; and \
        string match --quiet '*An error occurred (AccessDenied) when calling the ListBuckets operation:*' -- $listing_output
        printf 'The same S3 bucket listing was denied with the deny-all policy.\n'
        return 0
    end
    printf 'S3 session-policy check failed or was inconclusive (expected %s).\n' "$expectation" >&2
    if test $listing_status -eq 0
        printf 'The deny-all session unexpectedly allowed bucket listing.\n' >&2
    else
        printf '%s\n' "$listing_output" >&2
    end
    return 1
end

if test (count $argv) -lt 3; or test (count $argv) -gt 4
    printf 'Usage: fish %s /path/to/awzars SOURCE_PROFILE REGION [TARGET_ROLE_ARN]\n' (status filename) >&2
    exit 2
end
for executable in aws jq
    if not command --query $executable
        printf 'Required command is missing: %s\n' "$executable" >&2
        exit 2
    end
end
set -l target_role_arn ''
if test (count $argv) -eq 4
    if test -z "$argv[4]"
        printf 'TARGET_ROLE_ARN must not be empty when supplied.\n' >&2
        exit 2
    end
    set target_role_arn "$argv[4]"
end
set -l policy_directory (path resolve (status dirname)/session-policies)
verify_s3_bucket_listing "$argv[1]" "$argv[2]" "$argv[3]" "$policy_directory/s3-list-buckets.json" allowed "$target_role_arn"
or exit 1
verify_s3_bucket_listing "$argv[1]" "$argv[2]" "$argv[3]" "$policy_directory/deny-all.json" denied "$target_role_arn"

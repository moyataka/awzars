#!/usr/bin/env python3
"""Generate a pinned API catalog from AWS's public authorization reference.

No AWS account or credentials are used. Missing classifications or mappings,
mutating permissions, credential retrieval and known stateful reads fail closed.
"""

import argparse
import concurrent.futures
import datetime
import hashlib
import json
import pathlib
import re
import urllib.request


SOURCE = "https://servicereference.us-east-1.amazonaws.com/v1/"
PROPERTIES = ("IsWrite", "IsPermissionManagement", "IsTaggingOnly")
SENSITIVE = re.compile(
    r"credential|password|secretvalue|accesskey|token|apikey|authcode|"
    r"clientsecret|privatekey|signingcertificate|streamkey|signed.*url|sessionurl",
    re.IGNORECASE,
)
EXCLUDED_ACTIONS = {
    "sqs:ReceiveMessage",  # Changes visibility and delivery counts.
    "ssm:GetParameter",
    "ssm:GetParameters",
    "ssm:GetParametersByPath",
    "lightsail:GetInstanceAccessDetails",
    "cognito-identity:GetOpenIdToken",
    "cognito-identity:GetOpenIdTokenForDeveloperIdentity",
    "cognito-idp:GetTokensFromRefreshToken",
    "codeartifact:GetAuthorizationToken",
    "eks:AccessKubernetesApi",
    "ec2:DescribeVpnConnections",  # Includes VPN pre-shared keys.
    "glue:GetConnection",
    "glue:GetConnections",
    "cognito-idp:DescribeUserPoolClient",
    "gamelift:GetPlayerConnectionDetails",
    "appfabric:GetAppAuthorization",
    "s3:GetDataAccess",  # Returns temporary credentials, including write grants.
    "states:GetActivityTask",  # Assigns work and returns a task token.
    "wisdom:GetNextMessage",  # Conversational execution, not stored-data inspection.
}
# Names alone never grant access: these families also require every IAM mapping
# to have explicit non-mutating annotations. Other families need individual review.
READ_FAMILIES = (
    "Get", "List", "Describe", "BatchGet", "BatchDescribe", "Search", "Lookup",
    "Query", "Scan", "Head", "AdminGet", "AdminList",
)
REVIEWED_OPERATIONS = {
    "dynamodb/TransactGetItems", "logs/FilterLogEvents",
    "rds/DownloadDBLogFilePortion", "config/SelectResourceConfig",
    "config/SelectAggregateResourceConfig",
}
GLOBAL_SERVICES = {
    "account", "budgets", "ce", "cloudfront", "health", "iam", "networkmanager",
    "organizations", "route53", "route53domains", "savingsplans", "shield",
    "support", "support-app", "supportapp", "taxsettings", "waf",
}


def download(url):
    if not url.startswith(SOURCE):
        raise ValueError("Unexpected service reference URL")
    with urllib.request.urlopen(url, timeout=30) as response:
        encoded = response.read(8 * 1024 * 1024 + 1)
    if len(encoded) > 8 * 1024 * 1024:
        raise ValueError("Service reference exceeds the input limit")
    return json.loads(encoded), hashlib.sha256(encoded).hexdigest()


def exclusion(action, document):
    properties = document.get("Annotations", {}).get("Properties", {})
    if not all(properties.get(name) is False for name in PROPERTIES):
        return "mutating_or_unclassified_permission"
    if action in EXCLUDED_ACTIONS or SENSITIVE.search(action):
        return "credentials_secrets_or_stateful_read"
    return None


def operation_exclusion(identifier, permissions):
    name = identifier.split("/", 1)[1]
    if SENSITIVE.search(name) or any(
        action in EXCLUDED_ACTIONS or SENSITIVE.search(action) for action in permissions
    ):
        return "credentials_secrets_or_stateful_read"
    if not name.startswith(READ_FAMILIES) and identifier not in REVIEWED_OPERATIONS:
        return "operation_family_requires_review"
    if not identifier.startswith("s3/") and any(
        action.startswith("s3-object-lambda:") for action in permissions
    ):
        return "invokes_customer_code"
    return None


def build_catalog(references, retrieved):
    actions = {
        service + ":" + action["Name"]: action
        for service, document in references.items()
        for action in document.get("Actions", [])
    }
    operations = {}
    excluded = {}
    for service, document in sorted(references.items()):
        for operation in document.get("Operations", []):
            name = operation["Name"]
            authorized = operation.get("AuthorizedActions", [])
            required = sorted({item["Service"] + ":" + item["Name"] for item in authorized})
            reason = "missing_permission_mapping" if not required else None
            for permission in required:
                reason = reason or (
                    exclusion(permission, actions[permission])
                    if permission in actions else "missing_permission_classification"
                )
            for sdk in operation.get("SDK", []):
                if sdk.get("Package") != "Boto3":
                    continue
                sdk_service = sdk["Name"]
                method = sdk["Method"].replace("_", "-")
                identifier = sdk_service + "/" + name
                operation_reason = reason or operation_exclusion(identifier, required)
                if not (re.fullmatch(r"[a-z][a-z0-9-]{0,63}", sdk_service)
                        and re.fullmatch(r"[A-Z][A-Za-z0-9]{0,127}", name)
                        and re.fullmatch(r"[a-z][a-z0-9-]{0,127}", method)
                        and all(re.fullmatch(r"[a-z0-9-]+:[A-Za-z0-9]+", value) for value in required)):
                    excluded[identifier] = "unsupported_api_identifier"
                    operations.pop(identifier, None)
                    continue
                if operation_reason:
                    excluded[identifier] = operation_reason
                    operations.pop(identifier, None)
                    continue
                if identifier in excluded:
                    continue
                entry = {
                    "service": sdk_service,
                    "operation": name,
                    "command": method,
                    # Ordinary S3 reads must never authorize Lambda-backed access points.
                    "actions": [action for action in required if not action.startswith("s3-object-lambda:")]
                    if sdk_service == "s3" else required,
                    "global": sdk_service in GLOBAL_SERVICES or service in GLOBAL_SERVICES,
                }
                if identifier in operations and operations[identifier] != entry:
                    raise ValueError("Conflicting API-to-permission mappings: " + identifier)
                operations[identifier] = entry
    return {
        "version": 1,
        "source": SOURCE + "service-list.json",
        "retrieved_at": retrieved,
        "reference_services": len(references),
        "services": sorted({value["service"] for value in operations.values()}),
        "operations": dict(sorted(operations.items())),
        "excluded": dict(sorted(excluded.items())),
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=pathlib.Path, required=True)
    arguments = parser.parse_args()
    inventory, inventory_hash = download(SOURCE + "service-list.json")
    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as executor:
        fetched = list(executor.map(lambda item: download(item["url"]), inventory))
    references = {item["service"]: document for item, (document, _) in zip(inventory, fetched)}
    catalog = build_catalog(references, datetime.datetime.now(datetime.timezone.utc).isoformat())
    catalog["source_sha256"] = {
        "service-list": inventory_hash,
        **{item["service"]: digest for item, (_, digest) in zip(inventory, fetched)},
    }
    encoded = json.dumps(catalog, sort_keys=True, separators=(",", ":")) + "\n"
    arguments.output.parent.mkdir(parents=True, exist_ok=True)
    arguments.output.write_text(encoded)
    print(json.dumps({
        "reference_services": len(references),
        "supported_sdk_services": len(catalog["services"]),
        "read_operations": len(catalog["operations"]),
        "excluded_operations": len(catalog["excluded"]),
        "bytes": len(encoded),
    }))


if __name__ == "__main__":
    main()

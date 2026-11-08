use crate::error::{AwzarsError, Result};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, fmt, str::FromStr, sync::LazyLock};

#[derive(Deserialize)]
struct Catalog {
    retrieved_at: String,
    reference_services: usize,
    services: Vec<String>,
    operations: BTreeMap<String, OperationDescription>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OperationDescription {
    service: String,
    operation: String,
    command: String,
    actions: Vec<String>,
    global: bool,
}

static CATALOG: LazyLock<Catalog> = LazyLock::new(|| {
    serde_json::from_str(include_str!("catalog.json")).expect("validated built-in AWS read catalog")
});

#[derive(Debug, Clone)]
pub struct ApprovedAwsOperation(&'static OperationDescription);

impl FromStr for ApprovedAwsOperation {
    type Err = String;

    fn from_str(value: &str) -> std::result::Result<Self, Self::Err> {
        CATALOG.operations.get(value).map(Self).ok_or_else(|| {
            "AWS operation is absent from the approved read catalog; writes, credential retrieval and unmapped operations are unavailable".into()
        })
    }
}

impl fmt::Display for ApprovedAwsOperation {
    fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(output, "{}/{}", self.0.service, self.0.operation)
    }
}

impl ApprovedAwsOperation {
    pub(super) fn actions(&self) -> &[String] {
        &self.0.actions
    }

    pub(super) fn is_global(&self) -> bool {
        self.0.global
    }

    pub(super) fn requires_s3_decryption(&self) -> bool {
        self.0.service == "s3" && self.0.operation == "GetObject"
    }

    pub fn description(&self) -> &OperationDescription {
        self.0
    }
}

pub fn describe(
    operation: Option<&ApprovedAwsOperation>,
    service: Option<&str>,
    offset: usize,
) -> Result<serde_json::Value> {
    if let Some(operation) = operation {
        return Ok(serde_json::to_value(operation.description())?);
    }
    let catalog = &*CATALOG;
    let Some(service) = service else {
        return Ok(serde_json::json!({
            "retrieved_at": catalog.retrieved_at,
            "reference_services": catalog.reference_services,
            "supported_services": catalog.services,
            "operation_count": catalog.operations.len(),
        }));
    };
    if !catalog.services.iter().any(|known| known == service) {
        return Err(AwzarsError::Config(
            "Service has no approved operations in the pinned catalog".into(),
        ));
    }
    let available = catalog
        .operations
        .values()
        .filter(|entry| entry.service == service)
        .collect::<Vec<_>>();
    let page = available.iter().skip(offset).take(100).collect::<Vec<_>>();
    let next = (offset.saturating_add(page.len()) < available.len()).then_some(offset + page.len());
    Ok(
        serde_json::json!({"service":service, "operations":page, "next_offset":next, "total":available.len()}),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn data_reads_span_services_and_unsafe_operations_are_not_constructible() {
        for operation in [
            "s3/ListBuckets",
            "s3/GetObject",
            "dynamodb/GetItem",
            "dynamodb/Query",
            "dynamodb/Scan",
            "personalize-runtime/GetRecommendations",
            "personalize-runtime/GetPersonalizedRanking",
            "rds/DescribeDBInstances",
        ] {
            assert!(
                operation.parse::<ApprovedAwsOperation>().is_ok(),
                "{operation}"
            );
        }
        for operation in [
            "s3/PutObject",
            "s3/DeleteObject",
            "dynamodb/PutItem",
            "dynamodb/ExecuteStatement",
            "personalize/CreateCampaign",
            "secretsmanager/GetSecretValue",
            "ssm/GetParameter",
            "ecr/GetAuthorizationToken",
            "sqs/ReceiveMessage",
            "sts/AssumeRole",
            "sts/GetSessionToken",
            "s3control/GetDataAccess",
            "bedrock-agent-runtime/InvokeAgent",
            "eks-auth/AssumeRoleForPodIdentity",
            "signin/CreateOAuth2Token",
            "acm/ExportCertificate",
            "apigateway/GetApiKey",
            "glue/GetConnection",
            "ec2/DescribeVpnConnections",
            "cloudformation/DetectStackDrift",
            "logs/StartQuery",
            "s3/*",
        ] {
            assert!(
                operation.parse::<ApprovedAwsOperation>().is_err(),
                "{operation}"
            );
        }
        assert!(CATALOG.services.len() > 100);
    }

    #[test]
    fn every_advertised_operation_fits_a_bounded_sts_policy() {
        use super::super::{ApprovedSessionPolicy, ReadOnlyScope};
        let scope = ReadOnlyScope::new(
            "arn:aws:iam::123456789012:role/Example"
                .to_owned()
                .try_into()
                .unwrap(),
            "ap-southeast-1".to_owned().try_into().unwrap(),
        );
        for (name, description) in &CATALOG.operations {
            let policy =
                ApprovedSessionPolicy::for_operation(&ApprovedAwsOperation(description), &scope)
                    .unwrap_or_else(|error| panic!("{name}: {error}"));
            assert!(policy.as_str().len() <= 2048);
        }
    }

    #[test]
    fn every_catalog_entry_has_concrete_permissions_and_safe_cli_identifiers() {
        let service = regex::Regex::new(r"^[a-z][a-z0-9-]{0,63}$").unwrap();
        let command = regex::Regex::new(r"^[a-z][a-z0-9-]{0,127}$").unwrap();
        let action = regex::Regex::new(r"^[a-z0-9-]+:[A-Za-z0-9]+$").unwrap();
        for (identifier, entry) in &CATALOG.operations {
            assert_eq!(
                identifier,
                &format!("{}/{}", entry.service, entry.operation)
            );
            assert!(service.is_match(&entry.service));
            assert!(command.is_match(&entry.command));
            assert!(!entry.actions.is_empty());
            assert!(entry.actions.iter().all(|value| action.is_match(value)));
        }
    }
}

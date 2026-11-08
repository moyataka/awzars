use crate::auth::aws::read_only::{
    ApprovedSessionPolicy, ReadOnlyCapability, ReadOnlyScope, RegionName, RoleArn, TargetName,
};
use crate::error::{AwzarsError, Result};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

mod clients;
use crate::auth::mcp::McpClientName;
pub use clients::{AuthenticatedMcpRequest, McpClientGrant};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReadOnlyAccess {
    targets: BTreeMap<TargetName, ReadOnlyTarget>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    clients: BTreeMap<McpClientName, McpClientGrant>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ReadOnlyTarget {
    role_arn: RoleArn,
    region: RegionName,
    capabilities: BTreeSet<ReadOnlyCapability>,
}

/// A configured target and reviewed capability, authorized together.
#[derive(Debug)]
pub struct AuthorizedReadOnlyRequest {
    scope: ReadOnlyScope,
    policy: ApprovedSessionPolicy,
}

impl ReadOnlyAccess {
    pub(crate) fn require_capability(
        &self,
        target: &TargetName,
        capability: ReadOnlyCapability,
    ) -> Result<()> {
        let configured = self.targets.get(target).ok_or_else(|| {
            AwzarsError::Config(format!("Read-only target '{target}' is not configured"))
        })?;
        if !configured.capabilities.contains(&capability) {
            return Err(AwzarsError::Config(format!(
                "Requested read-only capability is not enabled for target '{target}'"
            )));
        }
        Ok(())
    }

    pub fn authorize_operation(
        &self,
        target: &TargetName,
        operation: &crate::auth::aws::read_only::ApprovedAwsOperation,
    ) -> Result<AuthorizedReadOnlyRequest> {
        self.require_capability(target, ReadOnlyCapability::AwsRead)?;
        let configured = &self.targets[target];
        let scope = ReadOnlyScope::new(configured.role_arn.clone(), configured.region.clone());
        let policy = ApprovedSessionPolicy::for_operation(operation, &scope)?;
        Ok(AuthorizedReadOnlyRequest { scope, policy })
    }

    pub fn authorize(
        &self,
        target: &TargetName,
        capability: ReadOnlyCapability,
    ) -> Result<AuthorizedReadOnlyRequest> {
        let configured = self.targets.get(target).ok_or_else(|| {
            AwzarsError::Config(format!("Read-only target '{target}' is not configured"))
        })?;
        if !configured.capabilities.contains(&capability) {
            return Err(AwzarsError::Config(format!(
                "Requested read-only capability is not enabled for target '{target}'"
            )));
        }
        let scope = ReadOnlyScope::new(configured.role_arn.clone(), configured.region.clone());
        let policy = capability.policy(&scope)?;
        Ok(AuthorizedReadOnlyRequest { scope, policy })
    }
}

impl AuthorizedReadOnlyRequest {
    pub fn scope(&self) -> &ReadOnlyScope {
        &self.scope
    }

    pub fn policy(&self) -> &ApprovedSessionPolicy {
        &self.policy
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const CONFIG: &str = r#"
        [targets.workload]
        role_arn = "arn:aws:iam::123456789012:role/Example"
        region = "ap-southeast-1"
        capabilities = ["s3-list-buckets"]
    "#;

    #[test]
    fn authorization_requires_both_configured_target_and_capability() {
        let access: ReadOnlyAccess = toml::from_str(CONFIG).unwrap();
        let target = "workload".parse().unwrap();
        let request = access
            .authorize(&target, ReadOnlyCapability::S3ListBuckets)
            .unwrap();
        assert_eq!(
            request.scope().role().as_str(),
            "arn:aws:iam::123456789012:role/Example"
        );
        assert!(access
            .authorize(&target, ReadOnlyCapability::EksDescribeCluster)
            .is_err());
        assert!(access
            .authorize(&"other".parse().unwrap(), ReadOnlyCapability::S3ListBuckets)
            .is_err());
    }

    #[test]
    fn config_rejects_unknown_permissions_fields_and_wildcards() {
        for invalid in [
            CONFIG.replace("s3-list-buckets", "s3:DeleteObject"),
            CONFIG.replace("role/Example", "role/*"),
            CONFIG.replace("ap-southeast-1", "*"),
            format!("{CONFIG}\npolicy = '{{}}'"),
            format!("skip_lock = true\n{CONFIG}"),
        ] {
            assert!(toml::from_str::<ReadOnlyAccess>(&invalid).is_err());
        }
    }
}

use super::ReadOnlyScope;
use crate::auth::aws::session_policy::SessionPolicy;
use crate::error::Result;
use serde::{Deserialize, Serialize};
use serde_json::json;

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, clap::ValueEnum,
)]
#[serde(rename_all = "kebab-case")]
pub enum ReadOnlyCapability {
    S3ListBuckets,
    Ec2DescribeInstances,
    EksDescribeCluster,
}

impl ReadOnlyCapability {
    pub fn policy(self, scope: &ReadOnlyScope) -> Result<ApprovedSessionPolicy> {
        match self {
            Self::S3ListBuckets => ApprovedSessionPolicy::build::<S3BucketListing>(scope),
            Self::Ec2DescribeInstances => {
                ApprovedSessionPolicy::build::<Ec2InstanceInspection>(scope)
            }
            Self::EksDescribeCluster => ApprovedSessionPolicy::build::<EksClusterInspection>(scope),
        }
    }
}

mod sealed {
    pub trait Sealed {}
}

/// Only permissions reviewed in this module can construct approved policies.
pub trait ReviewedReadPermission: sealed::Sealed {
    const ACTION: &'static str;
    const REGIONAL: bool;
    fn resource(scope: &ReadOnlyScope) -> String;
}

struct S3BucketListing;
struct Ec2InstanceInspection;
struct EksClusterInspection;

impl sealed::Sealed for S3BucketListing {}
impl sealed::Sealed for Ec2InstanceInspection {}
impl sealed::Sealed for EksClusterInspection {}

impl ReviewedReadPermission for S3BucketListing {
    const ACTION: &'static str = "s3:ListAllMyBuckets";
    const REGIONAL: bool = false;

    fn resource(_: &ReadOnlyScope) -> String {
        "*".into()
    }
}

impl ReviewedReadPermission for Ec2InstanceInspection {
    const ACTION: &'static str = "ec2:DescribeInstances";
    const REGIONAL: bool = true;

    fn resource(_: &ReadOnlyScope) -> String {
        "*".into()
    }
}

impl ReviewedReadPermission for EksClusterInspection {
    const ACTION: &'static str = "eks:DescribeCluster";
    const REGIONAL: bool = true;

    fn resource(scope: &ReadOnlyScope) -> String {
        format!(
            "arn:aws:eks:{}:{}:cluster/*",
            scope.region().as_str(),
            scope.role().account()
        )
    }
}

#[derive(Debug)]
pub struct ApprovedSessionPolicy(SessionPolicy);

impl ApprovedSessionPolicy {
    fn build<Permission: ReviewedReadPermission>(scope: &ReadOnlyScope) -> Result<Self> {
        let resource = Permission::resource(scope);
        let mut statements = vec![
            json!({"Effect":"Allow", "Action":Permission::ACTION, "Resource":resource}),
            json!({"Effect":"Deny", "NotAction":Permission::ACTION, "Resource":"*"}),
        ];
        if resource != "*" {
            statements.push(json!({
                "Effect":"Deny", "Action":Permission::ACTION, "NotResource":resource
            }));
        }
        if Permission::REGIONAL {
            statements.push(json!({
                "Effect":"Deny", "Action":Permission::ACTION, "Resource":"*",
                "Condition":{"StringNotEquals":{"aws:RequestedRegion":scope.region().as_str()}}
            }));
        }
        let document = serde_json::to_string(&json!({
            "Version":"2012-10-17", "Statement":statements
        }))?;
        SessionPolicy::parse(document).map(Self)
    }

    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::aws::read_only::{RegionName, RoleArn};

    #[test]
    fn approved_policies_have_explicit_action_resource_and_region_denials() {
        let scope = ReadOnlyScope::new(
            RoleArn::try_from("arn:aws:iam::123456789012:role/Example".to_owned()).unwrap(),
            RegionName::try_from("ap-southeast-1".to_owned()).unwrap(),
        );
        for (capability, action, resource, regional) in [
            (
                ReadOnlyCapability::S3ListBuckets,
                "s3:ListAllMyBuckets",
                "*",
                false,
            ),
            (
                ReadOnlyCapability::Ec2DescribeInstances,
                "ec2:DescribeInstances",
                "*",
                true,
            ),
            (
                ReadOnlyCapability::EksDescribeCluster,
                "eks:DescribeCluster",
                "arn:aws:eks:ap-southeast-1:123456789012:cluster/*",
                true,
            ),
        ] {
            let policy = capability.policy(&scope).unwrap();
            let document: serde_json::Value = serde_json::from_str(policy.as_str()).unwrap();
            let statements = document["Statement"].as_array().unwrap();
            assert!(statements
                .contains(&json!({"Effect":"Allow", "Action":action, "Resource":resource})));
            assert!(
                statements.contains(&json!({"Effect":"Deny", "NotAction":action, "Resource":"*"}))
            );
            assert_eq!(
                statements
                    .iter()
                    .filter(|statement| statement["Effect"] == "Allow")
                    .count(),
                1
            );
            if resource != "*" {
                assert!(statements
                    .contains(&json!({"Effect":"Deny", "Action":action, "NotResource":resource})));
            }
            if regional {
                assert!(statements.contains(&json!({
                    "Effect":"Deny", "Action":action, "Resource":"*",
                    "Condition":{"StringNotEquals":{"aws:RequestedRegion":"ap-southeast-1"}}
                })));
            }
            assert!(policy.as_str().len() <= 2048);
            assert!(!format!("{policy:?}").contains(action));
        }
    }

    #[test]
    fn arbitrary_actions_and_json_cannot_become_capabilities() {
        for value in ["s3:*", "s3:DeleteObject", "read-only", "{\"Statement\":[]}"] {
            assert!(serde_json::from_value::<ReadOnlyCapability>(json!(value)).is_err());
        }
    }
}

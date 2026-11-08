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
    AwsRead,
}

impl ReadOnlyCapability {
    pub fn policy(self, scope: &ReadOnlyScope) -> Result<ApprovedSessionPolicy> {
        match self {
            Self::S3ListBuckets => ApprovedSessionPolicy::build::<S3BucketListing>(scope),
            Self::Ec2DescribeInstances => {
                ApprovedSessionPolicy::build::<Ec2InstanceInspection>(scope)
            }
            Self::EksDescribeCluster => ApprovedSessionPolicy::build::<EksClusterInspection>(scope),
            Self::AwsRead => Err(crate::error::AwzarsError::Config(
                "aws-read requires an approved --aws-operation".into(),
            )),
        }
    }
}

mod sealed {
    pub trait Sealed {}
}

/// The fixed capabilities remain separate from the pinned operation catalog.
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
    pub(crate) fn for_operation(
        operation: &super::ApprovedAwsOperation,
        scope: &ReadOnlyScope,
    ) -> Result<Self> {
        let actions = operation.actions();
        let permitted_actions = actions
            .iter()
            .map(String::as_str)
            .chain(operation.requires_s3_decryption().then_some("kms:Decrypt"))
            .collect::<Vec<_>>();
        let mut statements = vec![
            json!({"Effect":"Allow", "Action":actions, "Resource":"*"}),
            json!({"Effect":"Deny", "NotAction":permitted_actions, "Resource":"*"}),
            json!({"Effect":"Deny", "Action":"*", "Resource":"*", "Condition":{
                "Null":{"aws:ResourceAccount":"false"},
                "StringNotEquals":{"aws:ResourceAccount":scope.role().account()}
            }}),
        ];
        if !operation.is_global() {
            statements.push(
                json!({"Effect":"Deny", "Action":permitted_actions, "Resource":"*", "Condition":{
                    "StringNotEquals":{"aws:RequestedRegion":scope.region().as_str()}
                }}),
            );
        }
        if operation.requires_s3_decryption() {
            let keys = format!(
                "arn:aws:kms:{}:{}:key/*",
                scope.region().as_str(),
                scope.role().account()
            );
            let service = format!("s3.{}.amazonaws.com", scope.region().as_str());
            statements.extend([
                json!({"Effect":"Allow", "Action":"kms:Decrypt", "Resource":keys,
                    "Condition":{"StringEquals":{"kms:ViaService":service},
                        "ArnLike":{"kms:EncryptionContext:aws:s3:arn":"arn:aws:s3:::*"}}}),
                json!({"Effect":"Deny", "Action":"kms:Decrypt", "NotResource":keys}),
                json!({"Effect":"Deny", "Action":"kms:Decrypt", "Resource":"*",
                    "Condition":{"StringNotEquals":{"kms:ViaService":service}}}),
                json!({"Effect":"Deny", "Action":"kms:Decrypt", "Resource":"*",
                    "Condition":{"ArnNotLike":{"kms:EncryptionContext:aws:s3:arn":"arn:aws:s3:::*"}}}),
            ]);
        }
        let document =
            serde_json::to_string(&json!({"Version":"2012-10-17", "Statement":statements}))?;
        SessionPolicy::parse(document).map(Self)
    }

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

    #[test]
    fn operation_policy_has_only_mapped_actions_and_explicit_region_account_denials() {
        let scope = ReadOnlyScope::new(
            RoleArn::try_from("arn:aws:iam::123456789012:role/Example".to_owned()).unwrap(),
            RegionName::try_from("ap-southeast-1".to_owned()).unwrap(),
        );
        let operation = "dynamodb/Query".parse().unwrap();
        let policy = ApprovedSessionPolicy::for_operation(&operation, &scope).unwrap();
        let document: serde_json::Value = serde_json::from_str(policy.as_str()).unwrap();
        let statements = document["Statement"].as_array().unwrap();
        assert_eq!(
            statements[0],
            json!({"Effect":"Allow","Action":["dynamodb:Query"],"Resource":"*"})
        );
        assert_eq!(
            statements[1],
            json!({"Effect":"Deny","NotAction":["dynamodb:Query"],"Resource":"*"})
        );
        assert_eq!(
            statements[2]["Condition"]["StringNotEquals"]["aws:ResourceAccount"],
            "123456789012"
        );
        assert_eq!(
            statements[2]["Condition"]["Null"]["aws:ResourceAccount"],
            "false"
        );
        assert_eq!(
            statements[3]["Condition"]["StringNotEquals"]["aws:RequestedRegion"],
            "ap-southeast-1"
        );
        assert!(ReadOnlyCapability::AwsRead.policy(&scope).is_err());
        let global = "iam/ListRoles".parse().unwrap();
        let global: serde_json::Value = serde_json::from_str(
            ApprovedSessionPolicy::for_operation(&global, &scope)
                .unwrap()
                .as_str(),
        )
        .unwrap();
        assert_eq!(global["Statement"].as_array().unwrap().len(), 3);
        let object: super::super::ApprovedAwsOperation = "s3/GetObject".parse().unwrap();
        assert!(object
            .actions()
            .iter()
            .all(|action| action.starts_with("s3:")));
    }

    #[test]
    fn object_downloads_allow_only_s3_mediated_decryption_in_the_target_scope() {
        let scope = ReadOnlyScope::new(
            RoleArn::try_from("arn:aws:iam::123456789012:role/Example".to_owned()).unwrap(),
            RegionName::try_from("ap-southeast-1".to_owned()).unwrap(),
        );
        let policy =
            ApprovedSessionPolicy::for_operation(&"s3/GetObject".parse().unwrap(), &scope).unwrap();
        let document: serde_json::Value = serde_json::from_str(policy.as_str()).unwrap();
        let statements = document["Statement"].as_array().unwrap();
        let decryption = statements
            .iter()
            .filter(|value| value["Action"] == "kms:Decrypt")
            .collect::<Vec<_>>();
        assert_eq!(decryption.len(), 4);
        assert_eq!(
            decryption[0]["Resource"],
            "arn:aws:kms:ap-southeast-1:123456789012:key/*"
        );
        assert_eq!(
            decryption[0]["Condition"]["StringEquals"]["kms:ViaService"],
            "s3.ap-southeast-1.amazonaws.com"
        );
        assert_eq!(decryption[1]["Effect"], "Deny");
        assert_eq!(decryption[1]["NotResource"], decryption[0]["Resource"]);
        assert_eq!(decryption[2]["Effect"], "Deny");
        assert_eq!(
            decryption[2]["Condition"]["StringNotEquals"]["kms:ViaService"],
            "s3.ap-southeast-1.amazonaws.com"
        );
        assert_eq!(decryption[3]["Effect"], "Deny");
        assert_eq!(
            decryption[3]["Condition"]["ArnNotLike"]["kms:EncryptionContext:aws:s3:arn"],
            "arn:aws:s3:::*"
        );
        assert!(!policy.as_str().contains("GenerateDataKey"));
        assert!(policy.as_str().len() <= 2048);
        let listing =
            ApprovedSessionPolicy::for_operation(&"s3/ListBuckets".parse().unwrap(), &scope)
                .unwrap();
        assert!(!listing.as_str().contains("kms:Decrypt"));
        assert!("kms/Decrypt"
            .parse::<super::super::ApprovedAwsOperation>()
            .is_err());
    }
}

use crate::auth::aws::arn::{IamArn, IamResource};
use serde::{Deserialize, Serialize};
use std::fmt;
use std::str::FromStr;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct RoleArn(String);

impl TryFrom<String> for RoleArn {
    type Error = String;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        let parsed = IamArn::parse(&value).ok_or("Expected an AWS IAM role ARN")?;
        if parsed.resource() != IamResource::Role
            || !parsed.is_supported_partition()
            || !value.bytes().all(|character| {
                character.is_ascii_alphanumeric() || b":/+=,.@_-".contains(&character)
            })
        {
            return Err(
                "Expected a concrete role ARN in the aws partition, without wildcards".into(),
            );
        }
        Ok(Self(value))
    }
}

impl RoleArn {
    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub(super) fn account(&self) -> &str {
        // RoleArn construction guarantees the fixed arn:aws:iam::<12 digits>: prefix.
        &self.0[13..25]
    }
}

impl From<RoleArn> for String {
    fn from(value: RoleArn) -> Self {
        value.0
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct RegionName(String);

impl TryFrom<String> for RegionName {
    type Error = String;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        let pattern =
            regex::Regex::new(r"^[a-z]{2}(?:-[a-z0-9]+)+-[0-9]+$").expect("static region pattern");
        if value.len() > 64
            || !pattern.is_match(&value)
            || value.starts_with("cn-")
            || value.starts_with("us-gov-")
            || value.contains("-iso")
        {
            return Err("Expected a concrete region in the aws partition".into());
        }
        Ok(Self(value))
    }
}

impl RegionName {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl From<RegionName> for String {
    fn from(value: RegionName) -> Self {
        value.0
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct TargetName(String);

impl TryFrom<String> for TargetName {
    type Error = String;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        if value.is_empty()
            || value.len() > 64
            || !value
                .bytes()
                .all(|character| character.is_ascii_alphanumeric() || b"_-".contains(&character))
        {
            return Err(
                "Target names must contain 1..=64 ASCII letters, digits, underscores or hyphens"
                    .into(),
            );
        }
        Ok(Self(value))
    }
}

impl FromStr for TargetName {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::try_from(value.to_owned())
    }
}

impl fmt::Display for TargetName {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

impl From<TargetName> for String {
    fn from(value: TargetName) -> Self {
        value.0
    }
}

#[derive(Debug, Clone)]
pub struct ReadOnlyScope {
    role: RoleArn,
    region: RegionName,
}

impl ReadOnlyScope {
    pub fn new(role: RoleArn, region: RegionName) -> Self {
        Self { role, region }
    }

    pub fn role(&self) -> &RoleArn {
        &self.role
    }

    pub fn region(&self) -> &RegionName {
        &self.region
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn role_scope_rejects_globs_wrong_resources_and_partitions() {
        for invalid in [
            "arn:aws:iam::123456789012:role/*",
            "arn:aws:iam::123456789012:role/Example?",
            "arn:aws:iam::123456789012:user/Example",
            "arn:aws-cn:iam::123456789012:role/Example",
            "arn:aws:iam::12345678901:role/Example",
        ] {
            assert!(RoleArn::try_from(invalid.to_owned()).is_err(), "{invalid}");
        }
        let role =
            RoleArn::try_from("arn:aws:iam::123456789012:role/team/Example".to_owned()).unwrap();
        assert_eq!(role.account(), "123456789012");
    }

    #[test]
    fn regions_and_target_names_reject_scope_injection() {
        for invalid in [
            "*",
            "us-east-1*",
            "us-east-1\n",
            "cn-north-1",
            "us-gov-west-1",
            "us-iso-east-1",
            "us-isob-east-1",
            "eu-isoe-west-1",
            "",
        ] {
            assert!(
                RegionName::try_from(invalid.to_owned()).is_err(),
                "{invalid}"
            );
        }
        assert!(RegionName::try_from("ap-southeast-1".to_owned()).is_ok());
        for invalid in ["", "../production", "*", "prod:other", "prod\n"] {
            assert!(invalid.parse::<TargetName>().is_err(), "{invalid}");
        }
        assert!("production_observe-1".parse::<TargetName>().is_ok());
    }
}

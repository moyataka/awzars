//! Approved AWS policies. This does not constrain Kubernetes authorization.

pub mod catalog;
mod issuance;
mod policy;
mod types;

pub use catalog::ApprovedAwsOperation;
pub use issuance::{issue_credentials, ReadOnlyCredentials};
pub use policy::{ApprovedSessionPolicy, ReadOnlyCapability, ReviewedReadPermission};
pub use types::{ReadOnlyScope, RegionName, RoleArn, TargetName};

pub const SESSION_DURATION_SECONDS: i32 = 900;

#[cfg(test)]
pub(crate) use issuance::tests::issue_mock;

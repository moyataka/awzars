//! Approved AWS policies. This does not constrain Kubernetes authorization.

mod issuance;
mod policy;
mod types;

pub use issuance::{issue_credentials, ReadOnlyCredentials};
pub use policy::{ApprovedSessionPolicy, ReadOnlyCapability, ReviewedReadPermission};
pub use types::{ReadOnlyScope, RegionName, RoleArn, TargetName};

pub const SESSION_DURATION_SECONDS: i32 = 900;

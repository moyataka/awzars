//! AWS authentication module

pub mod arn;
pub mod read_only;

pub mod session_policy;
pub mod sts;
#[cfg(test)]
mod test_support;

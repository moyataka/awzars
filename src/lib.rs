//! awzars: Modern Rust-based Azure AD to AWS credential federation
//!
//! This library provides functionality to:
//! - Authenticate with Azure AD via browser automation
//! - Extract SAML assertions from Azure AD responses
//! - Exchange SAML assertions for AWS credentials via STS
//! - Store credentials securely in the OS keychain
//! - Integrate with AWS CLI via the credential_process protocol

pub mod auth;
pub mod browser;
pub mod cli;
pub mod config;
pub mod credential_process;
pub mod error;
pub mod storage;
pub mod tui;
pub mod util;

pub use error::{AwzarsError, Result};

//! Azure AD configuration

use serde::{Deserialize, Serialize};

/// Azure AD configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AzureConfig {
    /// Azure AD tenant ID
    pub tenant_id: String,

    /// Azure AD app ID URI (the SAML audience)
    pub app_id_uri: String,

    /// Optional: Default role ARN to assume
    #[serde(skip_serializing_if = "Option::is_none")]
    pub default_role_arn: Option<String>,

    /// Session duration in seconds
    #[serde(default = "default_session_duration")]
    pub session_duration: i32,
}

fn default_session_duration() -> i32 {
    3600 // 1 hour
}

impl Default for AzureConfig {
    fn default() -> Self {
        Self {
            tenant_id: String::new(),
            app_id_uri: String::new(),
            default_role_arn: None,
            session_duration: 3600,
        }
    }
}

impl AzureConfig {
    /// Create a new Azure configuration
    pub fn new(tenant_id: impl Into<String>, app_id_uri: impl Into<String>) -> Self {
        Self {
            tenant_id: tenant_id.into(),
            app_id_uri: app_id_uri.into(),
            default_role_arn: None,
            session_duration: 3600,
        }
    }

    /// Get the Azure AD login URL
    pub fn login_url(&self) -> String {
        format!("https://login.microsoftonline.com/{}/saml2", self.tenant_id)
    }
}

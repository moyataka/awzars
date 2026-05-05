//! Azure login page selectors

/// Trait for selector sets
pub trait SelectorSet {
    fn selectors(&self) -> &[SelectorInfo];
}

/// Information about a selector
#[derive(Debug, Clone)]
pub struct SelectorInfo {
    pub name: &'static str,
    pub primary: &'static str,
    pub fallbacks: &'static [&'static str],
    pub description: &'static str,
}

/// Azure AD login selectors
pub struct AzureSelectors;

impl AzureSelectors {
    /// Username input field
    pub fn username_input() -> &'static str {
        "#i0116, input[name='loginfmt'], input[type='email']"
    }

    /// Password input field
    pub fn password_input() -> &'static str {
        "#i0118, input[name='passwd'], input[type='password']"
    }

    /// Submit button
    pub fn submit_button() -> &'static str {
        "#idSIButton9, input[type='submit']"
    }

    /// MFA code input
    pub fn mfa_code_input() -> &'static str {
        "#idTxtBx_SAOTCC_OTC, input[name='otc']"
    }

    /// MFA verify button
    pub fn mfa_verify_button() -> &'static str {
        "#idSubmit_SAOTCC_Continue, #idSIButton9"
    }

    /// Stay signed in "Yes" button
    pub fn stay_signed_in_yes() -> &'static str {
        "#idSIButton9, #KmsiCheckboxField"
    }

    /// Stay signed in "No" button
    pub fn stay_signed_in_no() -> &'static str {
        "#idBtn_Back"
    }

    /// Error message element
    pub fn error_message() -> &'static str {
        "#error, .error-message, [data-bind*='errorMessage']"
    }

    /// Account picker (when multiple accounts available)
    pub fn account_picker() -> &'static str {
        "#tilesHolder, .account-picker"
    }

    /// Use another account link
    pub fn use_another_account() -> &'static str {
        "#otherTileText, a[href*='login']"
    }
}

impl Default for AzureSelectors {
    fn default() -> Self {
        Self
    }
}

/// Selector versioning for handling Azure UI changes
pub mod versioning {
    /// Current selector version
    pub const CURRENT_VERSION: u32 = 1;

    /// Get selectors for a specific version
    pub fn get_selectors_for_version(version: u32) -> Vec<&'static str> {
        match version {
            1 => vec![
                "#i0116",       // username
                "#i0118",       // password
                "#idSIButton9", // submit
            ],
            _ => vec![],
        }
    }
}

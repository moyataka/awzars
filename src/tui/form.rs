//! Form types for profile editing in the TUI config manager

use super::aws_config::AwsProfileEntry;
use crate::cli::args::{
    parse_app_id_uri, parse_profile_name, parse_role_arn, parse_session_duration, parse_tenant_uuid,
};
use crate::config::{AzureConfig, Profile};
use std::collections::HashMap;

/// A single editable form field
#[derive(Debug, Clone)]
pub struct FormField {
    /// Display label
    pub label: &'static str,
    /// Current value
    pub value: String,
    /// Whether the field is optional (empty = valid)
    pub optional: bool,
    /// Whether this field is currently being inline-edited
    pub editing: bool,
    /// Cursor position within the value while editing
    pub cursor_pos: usize,
}

impl FormField {
    pub fn new(label: &'static str, value: String, optional: bool) -> Self {
        Self {
            label,
            value,
            optional,
            editing: false,
            cursor_pos: 0,
        }
    }

    pub fn start_edit(&mut self) {
        self.editing = true;
        self.cursor_pos = self.value.len();
    }

    pub fn finish_edit(&mut self) {
        self.editing = false;
    }

    pub fn cancel_edit(&mut self, original: &str) {
        self.editing = false;
        self.value = original.to_string();
        self.cursor_pos = 0;
    }

    // Text edits go through `apply(FieldOp)` in `form_ops.rs`. Lifecycle
    // transitions (start/finish/cancel edit) stay here because they touch
    // multiple fields' worth of state at once.
}

/// Toggle indices for profile form
pub const TOGGLE_REMEMBER_ME: usize = 0;
pub const TOGGLE_HEADLESS: usize = 1;
pub const TOGGLE_NO_SANDBOX: usize = 2;
pub const TOGGLE_ALLOW_INSECURE: usize = 3;
pub const TOGGLE_COUNT: usize = 4;

/// Toggle labels (indexed by TOGGLE_* constants)
const TOGGLE_LABELS: [&str; TOGGLE_COUNT] =
    ["Remember Me", "Headless", "No Sandbox", "Insecure Chrome"];

/// Form state for editing/creating a profile
pub struct ProfileForm {
    /// Field definitions in display order
    pub fields: Vec<FormField>,
    /// Toggle values: [remember_me, headless, no_sandbox, allow_insecure_remote_chrome]
    pub toggles: [Option<bool>; TOGGLE_COUNT],
    /// Index of the focused field
    pub focused: usize,
    /// Which toggle is focused (None = text field focused)
    pub toggle_focused: Option<usize>,
    /// Original profile name being edited (for rename detection)
    pub original_name: Option<String>,
    /// Stored original values for cancel
    pub original_values: Vec<String>,
    /// Stored original toggle values
    pub original_toggles: [Option<bool>; TOGGLE_COUNT],
    /// Filtered region suggestions
    pub region_suggestions: Vec<&'static str>,
    /// Selected region suggestion index
    pub region_suggestion_selected: usize,
}

/// Field indices
const IDX_NAME: usize = 0;
const IDX_TENANT: usize = 1;
const IDX_APP_URI: usize = 2;
const IDX_ROLE_ARN: usize = 3;
const IDX_DURATION: usize = 4;
pub const IDX_REGION: usize = 5;
const FIELD_COUNT: usize = 6;

impl ProfileForm {
    /// Create a form pre-populated from an existing profile
    pub fn from_profile(name: &str, profile: &Profile) -> Self {
        let fields = vec![
            FormField::new("Profile Name", name.to_string(), false),
            FormField::new("Tenant ID", profile.azure.tenant_id.clone(), false),
            FormField::new("App ID URI", profile.azure.app_id_uri.clone(), false),
            FormField::new(
                "Role ARN",
                profile.role_arn.clone().unwrap_or_default(),
                true,
            ),
            FormField::new(
                "Session Duration",
                profile.azure.session_duration.to_string(),
                false,
            ),
            FormField::new("Region", profile.region.clone().unwrap_or_default(), true),
        ];
        let original_values = fields.iter().map(|f| f.value.clone()).collect();
        let toggles = [
            profile.remember_me,
            profile.headless,
            profile.no_sandbox,
            profile.allow_insecure_remote_chrome,
        ];

        Self {
            fields,
            toggles,
            focused: 0,
            toggle_focused: None,
            original_name: Some(name.to_string()),
            original_values,
            original_toggles: toggles,
            region_suggestions: Vec::new(),
            region_suggestion_selected: 0,
        }
    }

    /// Create a form pre-filled from an existing profile, configured for
    /// creating a new profile (empty name, no original_name).
    pub fn clone_from(source_name: &str, profile: &Profile) -> Self {
        let mut form = Self::from_profile(source_name, profile);
        form.fields[IDX_NAME].value.clear();
        form.fields[IDX_NAME].cursor_pos = 0;
        form.original_name = None;
        form.original_values[IDX_NAME] = String::new();
        form
    }

    /// Create a blank form for adding a new profile
    pub fn new_empty() -> Self {
        let fields = vec![
            FormField::new("Profile Name", String::new(), false),
            FormField::new("Tenant ID", String::new(), false),
            FormField::new(
                "App ID URI",
                "https://signin.aws.amazon.com/saml".to_string(),
                false,
            ),
            FormField::new("Role ARN", String::new(), true),
            FormField::new("Session Duration", "3600".to_string(), false),
            FormField::new("Region", String::new(), true),
        ];
        let original_values = fields.iter().map(|f| f.value.clone()).collect();

        Self {
            fields,
            toggles: [None; TOGGLE_COUNT],
            focused: 0,
            toggle_focused: None,
            original_name: None,
            original_values,
            original_toggles: [None; TOGGLE_COUNT],
            region_suggestions: Vec::new(),
            region_suggestion_selected: 0,
        }
    }

    // ---- region autocomplete ----

    /// Whether the region field is currently being edited
    pub fn is_editing_region(&self) -> bool {
        self.fields.get(IDX_REGION).is_some_and(|f| f.editing)
    }

    /// Whether region suggestions are visible
    pub fn has_region_suggestions(&self) -> bool {
        !self.region_suggestions.is_empty() && self.is_editing_region()
    }

    /// Update region autocomplete suggestions
    pub fn update_region_suggestions(&mut self) {
        let query = match self.fields.get(IDX_REGION) {
            Some(f) => f.value.clone(),
            None => {
                self.region_suggestions.clear();
                return;
            }
        };
        self.region_suggestions = super::regions::filter_regions(&query);
        self.region_suggestion_selected = 0;
    }

    /// Accept the currently selected region suggestion
    pub fn accept_region_suggestion(&mut self) {
        if let Some(region) = self
            .region_suggestions
            .get(self.region_suggestion_selected)
            .copied()
        {
            if let Some(field) = self.fields.get_mut(IDX_REGION) {
                field.value = region.to_string();
                field.cursor_pos = field.value.len();
            }
            self.region_suggestions.clear();
            self.region_suggestion_selected = 0;
        }
    }

    /// Navigate region suggestions
    pub fn move_region_suggestion(&mut self, delta: i32) {
        self.region_suggestion_selected = super::form_ops::move_index(
            self.region_suggestion_selected,
            delta,
            self.region_suggestions.len(),
        );
    }

    /// Total navigable items (fields + toggles)
    pub fn total_items(&self) -> usize {
        FIELD_COUNT + TOGGLE_COUNT
    }

    /// Move focus up/down
    pub fn move_focus(&mut self, delta: i32) {
        let total = self.total_items();
        if total == 0 {
            return;
        }

        let current = if let Some(t) = self.toggle_focused {
            FIELD_COUNT as i32 + t as i32
        } else {
            self.focused as i32
        };

        let new = if delta > 0 {
            (current + delta).min((total - 1) as i32)
        } else {
            0.max(current + delta)
        };

        if new as usize >= FIELD_COUNT {
            self.toggle_focused = Some(new as usize - FIELD_COUNT);
            self.focused = FIELD_COUNT - 1;
        } else {
            self.toggle_focused = None;
            self.focused = new as usize;
        }
    }

    /// Get the currently focused field (if not on a toggle)
    pub fn focused_field(&self) -> Option<&FormField> {
        if self.toggle_focused.is_some() {
            None
        } else {
            self.fields.get(self.focused)
        }
    }

    /// Get the currently focused field mutably
    pub fn focused_field_mut(&mut self) -> Option<&mut FormField> {
        if self.toggle_focused.is_some() {
            None
        } else {
            self.fields.get_mut(self.focused)
        }
    }

    /// Check if any field is currently being edited
    pub fn is_editing(&self) -> bool {
        self.fields.iter().any(|f| f.editing)
    }

    /// Get the field that is currently being edited
    pub fn editing_field_mut(&mut self) -> Option<&mut FormField> {
        self.fields.iter_mut().find(|f| f.editing)
    }

    /// Toggle the currently focused toggle
    pub fn toggle_current(&mut self) {
        if let Some(idx) = self.toggle_focused {
            self.toggles[idx] = match self.toggles[idx] {
                None => Some(true),
                Some(true) => Some(false),
                Some(false) => None,
            };
        }
    }

    /// Get the label for a toggle index
    pub fn toggle_label(idx: usize) -> Option<&'static str> {
        TOGGLE_LABELS.get(idx).copied()
    }

    /// Validate all fields, returning list of errors (empty = valid)
    pub fn validate(&self) -> Vec<String> {
        let mut errors = Vec::new();

        // Profile name
        if let Err(e) = parse_profile_name(&self.fields[IDX_NAME].value) {
            errors.push(format!("Profile Name: {}", e));
        }

        // Tenant ID
        if let Err(e) = parse_tenant_uuid(&self.fields[IDX_TENANT].value) {
            errors.push(format!("Tenant ID: {}", e));
        }

        // App ID URI
        if let Err(e) = parse_app_id_uri(&self.fields[IDX_APP_URI].value) {
            errors.push(format!("App ID URI: {}", e));
        }

        // Role ARN (optional)
        let role_arn = &self.fields[IDX_ROLE_ARN].value;
        if !role_arn.is_empty() {
            if let Err(e) = parse_role_arn(role_arn) {
                errors.push(format!("Role ARN: {}", e));
            }
        }

        // Session duration
        if let Err(e) = parse_session_duration(&self.fields[IDX_DURATION].value) {
            errors.push(format!("Session Duration: {}", e));
        }

        // Region (optional, no strict validation)

        errors
    }

    /// Check if the form has been modified from original values
    pub fn is_dirty(&self) -> bool {
        for (i, field) in self.fields.iter().enumerate() {
            if field.value != self.original_values[i] {
                return true;
            }
        }
        if self.toggles != self.original_toggles {
            return true;
        }
        false
    }

    /// Convert form to (name, Profile). Returns Err with validation errors if invalid.
    pub fn to_profile(&self) -> Result<(String, Profile), Vec<String>> {
        let errors = self.validate();
        if !errors.is_empty() {
            return Err(errors);
        }

        let name = self.fields[IDX_NAME].value.clone();
        let role_arn_val = self.fields[IDX_ROLE_ARN].value.clone();
        let session_duration: i32 = self.fields[IDX_DURATION].value.parse().unwrap_or(3600);
        let region_val = self.fields[IDX_REGION].value.clone();

        let azure = AzureConfig {
            tenant_id: self.fields[IDX_TENANT].value.clone(),
            app_id_uri: self.fields[IDX_APP_URI].value.clone(),
            default_role_arn: if role_arn_val.is_empty() {
                None
            } else {
                Some(role_arn_val.clone())
            },
            session_duration,
        };

        let profile = Profile {
            azure,
            region: if region_val.is_empty() {
                None
            } else {
                Some(region_val)
            },
            role_arn: if role_arn_val.is_empty() {
                None
            } else {
                Some(role_arn_val)
            },
            principal_arn: None,
            remember_me: self.toggles[TOGGLE_REMEMBER_ME],
            headless: self.toggles[TOGGLE_HEADLESS],
            no_sandbox: self.toggles[TOGGLE_NO_SANDBOX],
            allow_insecure_remote_chrome: self.toggles[TOGGLE_ALLOW_INSECURE],
            // Lock state is managed by CLI commands (`set-password`, `unlock`,
            // `lock`), not by TUI editing. The save handler copies these from
            // the existing profile so an edit doesn't drop the password.
            lock_verifier: None,
            lock_ttl_hours: None,
            lock_ai_markers: None,
        };

        Ok((name, profile))
    }

    /// Format session duration for display (e.g., "3600" -> "3600s (1h)")
    pub fn format_duration(value: &str) -> String {
        match value.parse::<i32>() {
            Ok(secs) => {
                let h = secs / 3600;
                let m = (secs % 3600) / 60;
                let s = secs % 60;
                match (h, m, s) {
                    (h, 0, 0) if h > 0 => format!("{}s ({}h)", secs, h),
                    (0, m, 0) if m > 0 => format!("{}s ({}m)", secs, m),
                    (h, m, 0) if h > 0 => format!("{}s ({}h {}m)", secs, h, m),
                    _ => format!("{}s", secs),
                }
            }
            Err(_) => value.to_string(),
        }
    }

    /// Format a toggle value for display
    pub fn format_toggle(val: Option<bool>) -> &'static str {
        match val {
            Some(true) => "yes",
            Some(false) => "no",
            None => "unset",
        }
    }

    /// Backward-compatible alias
    pub fn format_remember_me(val: Option<bool>) -> &'static str {
        Self::format_toggle(val)
    }
}

// ---- AWS Profile Form ----

/// Field indices for AWS profile form
const AWS_IDX_NAME: usize = 0;
pub const AWS_IDX_REGION: usize = 1;
const AWS_IDX_OUTPUT: usize = 2;
pub const AWS_IDX_CRED_PROC: usize = 3;
pub const AWS_IDX_SOURCE_PROFILE: usize = 4;
const AWS_IDX_ROLE_ARN: usize = 5;
pub const AWS_IDX_ROLE_SESSION_NAME: usize = 6;

/// Form state for editing/creating an AWS config profile
pub struct AwsProfileForm {
    /// Field definitions in display order
    pub fields: Vec<FormField>,
    /// Index of the focused field
    pub focused: usize,
    /// Original profile name (for rename detection)
    pub original_name: Option<String>,
    /// Stored original values for cancel
    pub original_values: Vec<String>,
    /// Was this profile using awzars before editing?
    pub originally_uses_awzars: bool,
    /// Available awzars profile names for autocomplete
    pub awzars_profiles: Vec<String>,
    /// Filtered suggestions for credential_process autocomplete
    pub suggestions: Vec<String>,
    /// Selected suggestion index for credential_process
    pub suggestion_selected: usize,
    /// All AWS profile names with awzars flag for source_profile autocomplete
    pub aws_profile_names: Vec<(String, bool)>,
    /// Filtered suggestions for source_profile autocomplete (name, uses_awzars)
    pub source_suggestions: Vec<(String, bool)>,
    /// Selected suggestion index for source_profile
    pub source_suggestion_selected: usize,
    /// Whether this form is for an assume-role profile (source_profile/role_arn fields visible)
    pub is_assume_role: bool,
    /// Filtered region suggestions
    pub region_suggestions: Vec<&'static str>,
    /// Selected region suggestion index
    pub region_suggestion_selected: usize,
}

impl AwsProfileForm {
    /// Create a form pre-populated from an existing AWS profile entry
    pub fn from_entry(
        entry: &AwsProfileEntry,
        awzars_profiles: Vec<String>,
        aws_profile_names: Vec<(String, bool)>,
    ) -> Self {
        let fields = vec![
            FormField::new("Profile Name", entry.name.clone(), false),
            FormField::new("Region", entry.region.clone().unwrap_or_default(), true),
            FormField::new(
                "Output",
                entry.extra.get("output").cloned().unwrap_or_default(),
                true,
            ),
            FormField::new(
                "Credential Process",
                entry.credential_process.clone().unwrap_or_default(),
                true,
            ),
            FormField::new(
                "Source Profile",
                entry.source_profile.clone().unwrap_or_default(),
                true,
            ),
            FormField::new("Role ARN", entry.role_arn.clone().unwrap_or_default(), true),
            FormField::new(
                "Role Session Name",
                entry.role_session_name.clone().unwrap_or_default(),
                true,
            ),
        ];
        let original_values = fields.iter().map(|f| f.value.clone()).collect();

        Self {
            fields,
            focused: 0,
            original_name: Some(entry.name.clone()),
            original_values,
            originally_uses_awzars: entry.uses_awzars,
            awzars_profiles,
            suggestions: Vec::new(),
            suggestion_selected: 0,
            aws_profile_names,
            source_suggestions: Vec::new(),
            source_suggestion_selected: 0,
            is_assume_role: entry.is_assume_role(),
            region_suggestions: Vec::new(),
            region_suggestion_selected: 0,
        }
    }
    pub fn new_empty(awzars_profiles: Vec<String>, aws_profile_names: Vec<(String, bool)>) -> Self {
        let fields = vec![
            FormField::new("Profile Name", String::new(), false),
            FormField::new("Region", String::new(), true),
            FormField::new("Output", String::new(), true),
            FormField::new("Credential Process", String::new(), true),
            FormField::new("Source Profile", String::new(), true),
            FormField::new("Role ARN", String::new(), true),
            FormField::new("Role Session Name", String::new(), true),
        ];
        let original_values = fields.iter().map(|f| f.value.clone()).collect();

        Self {
            fields,
            focused: 0,
            original_name: None,
            original_values,
            originally_uses_awzars: false,
            awzars_profiles,
            suggestions: Vec::new(),
            suggestion_selected: 0,
            aws_profile_names,
            source_suggestions: Vec::new(),
            source_suggestion_selected: 0,
            is_assume_role: false,
            region_suggestions: Vec::new(),
            region_suggestion_selected: 0,
        }
    }

    /// Whether the focused field (in navigation mode) maps to the given field index.
    pub fn focused_is(&self, field_idx: usize) -> bool {
        self.visible_field_indices()
            .get(self.focused)
            .is_some_and(|&idx| idx == field_idx)
    }

    /// Whether the credential_process field is currently being edited
    pub fn is_editing_cred_proc(&self) -> bool {
        self.fields
            .get(AWS_IDX_CRED_PROC)
            .is_some_and(|f| f.editing)
    }

    /// Recompute suggestions based on current credential_process field value
    pub fn update_suggestions(&mut self) {
        let query = match self.fields.get(AWS_IDX_CRED_PROC) {
            Some(f) => f.value.clone(),
            None => {
                self.suggestions.clear();
                return;
            }
        };

        // Extract the profile name prefix from the query
        let prefix = self.extract_profile_prefix(&query);

        if prefix.is_empty() && !query.contains("awzars") {
            // No prefix and not an awzars command — show all profiles if input is empty
            if query.is_empty() {
                self.suggestions = self.awzars_profiles.clone();
            } else {
                self.suggestions.clear();
            }
        } else {
            self.suggestions = self
                .awzars_profiles
                .iter()
                .filter(|p| p.to_lowercase().starts_with(&prefix.to_lowercase()))
                .cloned()
                .collect();
        }

        self.suggestion_selected = 0;
    }

    /// Extract the profile name prefix from a credential_process value
    fn extract_profile_prefix(&self, value: &str) -> String {
        // Try to find --profile <partial> or --profile=<partial>
        let parts: Vec<&str> = value.split_whitespace().collect();
        for i in 0..parts.len() {
            if parts[i] == "--profile" {
                // Everything after --profile is the (possibly partial) profile name
                if i + 1 < parts.len() {
                    return parts[i + 1].to_string();
                }
                return String::new(); // --profile at end, no value yet
            }
            if let Some(val) = parts[i].strip_prefix("--profile=") {
                return val.to_string();
            }
        }
        // If no --profile found and value doesn't look like a command, use as prefix
        if !value.contains(' ') && !value.contains('=') {
            return value.to_string();
        }
        String::new()
    }

    /// Accept the currently selected suggestion
    pub fn accept_suggestion(&mut self) {
        if let Some(profile_name) = self.suggestions.get(self.suggestion_selected).cloned() {
            let cp = format!("awzars credential-process --profile {}", profile_name);
            if let Some(field) = self.fields.get_mut(AWS_IDX_CRED_PROC) {
                field.cursor_pos = cp.len();
                field.value = cp;
            }
            self.suggestions.clear();
            self.suggestion_selected = 0;
        }
    }

    /// Navigate suggestions up/down
    pub fn move_suggestion(&mut self, delta: i32) {
        self.suggestion_selected =
            super::form_ops::move_index(self.suggestion_selected, delta, self.suggestions.len());
    }

    /// Whether suggestions are visible
    pub fn has_suggestions(&self) -> bool {
        !self.suggestions.is_empty() && self.is_editing_cred_proc()
    }

    // ---- source_profile autocomplete ----

    /// Whether the source_profile field is currently being edited
    pub fn is_editing_source_profile(&self) -> bool {
        self.fields
            .get(AWS_IDX_SOURCE_PROFILE)
            .is_some_and(|f| f.editing)
    }

    /// Whether source_profile suggestions are visible
    pub fn has_source_suggestions(&self) -> bool {
        !self.source_suggestions.is_empty() && self.is_editing_source_profile()
    }

    /// Update source_profile autocomplete suggestions
    pub fn update_source_suggestions(&mut self) {
        let query = match self.fields.get(AWS_IDX_SOURCE_PROFILE) {
            Some(f) => f.value.clone(),
            None => {
                self.source_suggestions.clear();
                return;
            }
        };

        if query.is_empty() {
            // Show all profiles when field is empty
            self.source_suggestions = self.aws_profile_names.clone();
        } else {
            self.source_suggestions = self
                .aws_profile_names
                .iter()
                .filter(|(name, _)| name.to_lowercase().starts_with(&query.to_lowercase()))
                .cloned()
                .collect();
        }
        self.source_suggestion_selected = 0;
    }

    /// Accept the currently selected source_profile suggestion
    pub fn accept_source_suggestion(&mut self) {
        if let Some((name, _)) = self
            .source_suggestions
            .get(self.source_suggestion_selected)
            .cloned()
        {
            if let Some(field) = self.fields.get_mut(AWS_IDX_SOURCE_PROFILE) {
                field.value = name;
                field.cursor_pos = field.value.len();
            }
            self.source_suggestions.clear();
            self.source_suggestion_selected = 0;
        }
    }

    /// Navigate source_profile suggestions
    pub fn move_source_suggestion(&mut self, delta: i32) {
        self.source_suggestion_selected = super::form_ops::move_index(
            self.source_suggestion_selected,
            delta,
            self.source_suggestions.len(),
        );
    }

    // ---- region autocomplete ----

    /// Whether the region field is currently being edited
    pub fn is_editing_region(&self) -> bool {
        self.fields.get(AWS_IDX_REGION).is_some_and(|f| f.editing)
    }

    /// Whether region suggestions are visible
    pub fn has_region_suggestions(&self) -> bool {
        !self.region_suggestions.is_empty() && self.is_editing_region()
    }

    /// Update region autocomplete suggestions
    pub fn update_region_suggestions(&mut self) {
        let query = match self.fields.get(AWS_IDX_REGION) {
            Some(f) => f.value.clone(),
            None => {
                self.region_suggestions.clear();
                return;
            }
        };
        self.region_suggestions = super::regions::filter_regions(&query);
        self.region_suggestion_selected = 0;
    }

    /// Accept the currently selected region suggestion
    pub fn accept_region_suggestion(&mut self) {
        if let Some(region) = self
            .region_suggestions
            .get(self.region_suggestion_selected)
            .copied()
        {
            if let Some(field) = self.fields.get_mut(AWS_IDX_REGION) {
                field.value = region.to_string();
                field.cursor_pos = field.value.len();
            }
            self.region_suggestions.clear();
            self.region_suggestion_selected = 0;
        }
    }

    /// Navigate region suggestions
    pub fn move_region_suggestion(&mut self, delta: i32) {
        self.region_suggestion_selected = super::form_ops::move_index(
            self.region_suggestion_selected,
            delta,
            self.region_suggestions.len(),
        );
    }

    /// Field indices visible for the current profile type.
    ///
    /// Base profiles: Name, Region, Output, CredProc
    /// Assume-role profiles: Name, Region, Output, SourceProfile, RoleArn, RoleSessionName
    pub fn visible_field_indices(&self) -> &'static [usize] {
        if self.is_assume_role {
            &[
                AWS_IDX_NAME,
                AWS_IDX_REGION,
                AWS_IDX_OUTPUT,
                AWS_IDX_SOURCE_PROFILE,
                AWS_IDX_ROLE_ARN,
                AWS_IDX_ROLE_SESSION_NAME,
            ]
        } else {
            &[
                AWS_IDX_NAME,
                AWS_IDX_REGION,
                AWS_IDX_OUTPUT,
                AWS_IDX_CRED_PROC,
            ]
        }
    }

    /// Total navigable items
    pub fn total_items(&self) -> usize {
        self.visible_field_indices().len()
    }

    /// Move focus up/down
    pub fn move_focus(&mut self, delta: i32) {
        let total = self.total_items();
        if total == 0 {
            return;
        }
        let current = self.focused as i32;
        let new = if delta > 0 {
            (current + delta).min((total - 1) as i32)
        } else {
            0.max(current + delta)
        };
        self.focused = new as usize;
    }

    /// Get the currently focused field
    pub fn focused_field(&self) -> Option<&FormField> {
        self.visible_field_indices()
            .get(self.focused)
            .and_then(|&idx| self.fields.get(idx))
    }

    /// Get the currently focused field mutably
    pub fn focused_field_mut(&mut self) -> Option<&mut FormField> {
        let idx = self.visible_field_indices().get(self.focused).copied();
        match idx {
            Some(i) => self.fields.get_mut(i),
            None => None,
        }
    }

    /// Check if any field is currently being edited
    pub fn is_editing(&self) -> bool {
        self.fields.iter().any(|f| f.editing)
    }

    /// Get the field that is currently being edited
    pub fn editing_field_mut(&mut self) -> Option<&mut FormField> {
        self.fields.iter_mut().find(|f| f.editing)
    }

    /// Validate all fields
    pub fn validate(&self) -> Vec<String> {
        let mut errors = Vec::new();

        // Profile name
        if self.fields[AWS_IDX_NAME].value.is_empty() {
            errors.push("Profile Name: must not be empty".to_string());
        } else if let Err(e) = parse_profile_name(&self.fields[AWS_IDX_NAME].value) {
            errors.push(format!("Profile Name: {}", e));
        }

        errors
    }

    /// Check if the form has been modified from original values
    pub fn is_dirty(&self) -> bool {
        for (i, field) in self.fields.iter().enumerate() {
            if field.value != self.original_values[i] {
                return true;
            }
        }
        false
    }

    /// Convert form to an AwsProfileEntry. Returns Err with validation errors if invalid.
    pub fn to_entry(&self) -> Result<AwsProfileEntry, Vec<String>> {
        let errors = self.validate();
        if !errors.is_empty() {
            return Err(errors);
        }

        let name = self.fields[AWS_IDX_NAME].value.clone();
        let region_val = self.fields[AWS_IDX_REGION].value.clone();
        let output_val = self.fields[AWS_IDX_OUTPUT].value.clone();
        let cp_val = self.fields[AWS_IDX_CRED_PROC].value.clone();
        let sp_val = self.fields[AWS_IDX_SOURCE_PROFILE].value.clone();
        let ra_val = self.fields[AWS_IDX_ROLE_ARN].value.clone();
        let rsn_val = self.fields[AWS_IDX_ROLE_SESSION_NAME].value.clone();

        // source_profile and credential_process are mutually exclusive.
        let source_profile = if sp_val.is_empty() {
            None
        } else {
            Some(sp_val)
        };
        let credential_process = if source_profile.is_some() || cp_val.is_empty() {
            None
        } else {
            Some(cp_val)
        };

        let uses_awzars = credential_process
            .as_ref()
            .is_some_and(|c| c.contains("awzars"));
        let awzars_profile = credential_process
            .as_ref()
            .and_then(|c| super::aws_config::extract_awzars_profile(c));

        let mut extra = HashMap::new();
        if !output_val.is_empty() {
            extra.insert("output".to_string(), output_val);
        }

        Ok(AwsProfileEntry {
            name,
            region: if region_val.is_empty() {
                None
            } else {
                Some(region_val)
            },
            credential_process,
            uses_awzars,
            awzars_profile,
            source_profile,
            role_arn: if ra_val.is_empty() {
                None
            } else {
                Some(ra_val)
            },
            role_session_name: if rsn_val.is_empty() {
                None
            } else {
                Some(rsn_val)
            },
            extra,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_profile() -> Profile {
        Profile {
            azure: AzureConfig {
                tenant_id: "11111111-2222-3333-4444-555555555555".to_string(),
                app_id_uri: "https://signin.aws.amazon.com/saml".to_string(),
                default_role_arn: None,
                session_duration: 3600,
            },
            region: Some("us-east-1".to_string()),
            role_arn: Some("arn:aws:iam::123456789012:role/MyRole".to_string()),
            principal_arn: None,
            remember_me: Some(true),
            headless: None,
            no_sandbox: None,
            allow_insecure_remote_chrome: None,
            lock_verifier: None,
            lock_ttl_hours: None,
            lock_ai_markers: None,
        }
    }

    #[test]
    fn test_form_from_profile() {
        let form = ProfileForm::from_profile("work", &valid_profile());
        assert_eq!(form.fields[IDX_NAME].value, "work");
        assert_eq!(
            form.fields[IDX_TENANT].value,
            "11111111-2222-3333-4444-555555555555"
        );
        assert_eq!(
            form.fields[IDX_APP_URI].value,
            "https://signin.aws.amazon.com/saml"
        );
        assert_eq!(
            form.fields[IDX_ROLE_ARN].value,
            "arn:aws:iam::123456789012:role/MyRole"
        );
        assert_eq!(form.fields[IDX_DURATION].value, "3600");
        assert_eq!(form.fields[IDX_REGION].value, "us-east-1");
        assert_eq!(form.toggles[TOGGLE_REMEMBER_ME], Some(true));
        assert_eq!(form.toggles[TOGGLE_HEADLESS], None);
    }

    #[test]
    fn test_form_roundtrip() {
        let original = valid_profile();
        let form = ProfileForm::from_profile("work", &original);
        let (name, profile) = form.to_profile().expect("should be valid");
        assert_eq!(name, "work");
        assert_eq!(profile.azure.tenant_id, original.azure.tenant_id);
        assert_eq!(profile.azure.app_id_uri, original.azure.app_id_uri);
        assert_eq!(profile.role_arn, original.role_arn);
        assert_eq!(
            profile.azure.session_duration,
            original.azure.session_duration
        );
        assert_eq!(profile.region, original.region);
        assert_eq!(profile.remember_me, original.remember_me);
        assert_eq!(profile.headless, original.headless);
    }

    #[test]
    fn test_form_validation_errors() {
        let form = ProfileForm::new_empty();
        let errors = form.validate();
        assert!(!errors.is_empty()); // Empty name, tenant, app_uri
    }

    #[test]
    fn test_form_dirty_tracking() {
        let profile = valid_profile();
        let form = ProfileForm::from_profile("work", &profile);
        assert!(!form.is_dirty());
    }

    #[test]
    fn test_form_field_editing() {
        use super::super::form_ops::FieldOp;
        let mut field = FormField::new("Test", "hello".to_string(), false);
        field.start_edit();
        assert!(field.editing);
        assert_eq!(field.cursor_pos, 5);

        field.apply(FieldOp::MoveLeft);
        assert_eq!(field.cursor_pos, 4);

        field.apply(FieldOp::InsertChar('!'));
        assert_eq!(field.value, "hell!o");

        field.apply(FieldOp::DeleteBack);
        assert_eq!(field.value, "hello");

        field.finish_edit();
        assert!(!field.editing);
    }

    #[test]
    fn test_format_duration() {
        assert_eq!(ProfileForm::format_duration("3600"), "3600s (1h)");
        assert_eq!(ProfileForm::format_duration("1800"), "1800s (30m)");
        assert_eq!(ProfileForm::format_duration("900"), "900s (15m)");
        assert_eq!(ProfileForm::format_duration("5400"), "5400s (1h 30m)");
    }

    #[test]
    fn test_focus_navigation() {
        let mut form = ProfileForm::new_empty();
        assert_eq!(form.focused, 0);
        assert!(form.toggle_focused.is_none());

        form.move_focus(1);
        assert_eq!(form.focused, 1);

        form.move_focus(10); // Should clamp to last toggle
        assert_eq!(form.toggle_focused, Some(TOGGLE_ALLOW_INSECURE));

        form.move_focus(-10); // Should clamp to 0
        assert_eq!(form.focused, 0);
        assert!(form.toggle_focused.is_none());
    }

    #[test]
    fn test_toggle_cycle() {
        let mut form = ProfileForm::new_empty();
        form.toggle_focused = Some(TOGGLE_HEADLESS);

        assert_eq!(form.toggles[TOGGLE_HEADLESS], None);
        form.toggle_current();
        assert_eq!(form.toggles[TOGGLE_HEADLESS], Some(true));
        form.toggle_current();
        assert_eq!(form.toggles[TOGGLE_HEADLESS], Some(false));
        form.toggle_current();
        assert_eq!(form.toggles[TOGGLE_HEADLESS], None);
    }
}

//! AWS config (~/.aws/config) parser and writer for awzars integration

use std::collections::HashMap;
use std::path::PathBuf;

/// A single AWS profile entry from ~/.aws/config
#[derive(Debug, Clone)]
pub struct AwsProfileEntry {
    /// The AWS profile name (without the "profile " prefix)
    pub name: String,
    /// The region, if specified
    pub region: Option<String>,
    /// The credential_process command, if specified
    pub credential_process: Option<String>,
    /// Whether this profile uses awzars via credential_process
    pub uses_awzars: bool,
    /// The awzars profile name referenced in credential_process
    pub awzars_profile: Option<String>,
    /// Source profile for assume-role chains
    pub source_profile: Option<String>,
    /// Role ARN for assume-role chains
    pub role_arn: Option<String>,
    /// Role session name for assume-role chains
    pub role_session_name: Option<String>,
    /// Extra key-value pairs (output, sso_*, etc.)
    pub extra: HashMap<String, String>,
}

impl AwsProfileEntry {
    /// Whether this is an assume-role profile (has source_profile)
    pub fn is_assume_role(&self) -> bool {
        self.source_profile.is_some()
    }
}

/// AWS integration data parsed from ~/.aws/config
#[derive(Debug, Clone)]
pub struct AwsIntegrationData {
    /// All AWS profiles parsed from ~/.aws/config
    pub all_profiles: Vec<AwsProfileEntry>,
    /// Map from awzars profile name to the AWS profiles that reference it
    pub profile_map: HashMap<String, Vec<AwsProfileEntry>>,
}

impl AwsIntegrationData {
    /// Get AWS profiles referencing a specific awzars profile
    pub fn for_awzars_profile(&self, name: &str) -> &[AwsProfileEntry] {
        self.profile_map
            .get(name)
            .map(|v| v.as_slice())
            .unwrap_or(&[])
    }
}

/// Read and parse ~/.aws/config, extracting all profiles.
///
/// `path_override` substitutes for the default `~/.aws/config` when set
/// (sourced from `Config.aws_config_path`).
pub fn load_aws_integration(path_override: Option<&str>) -> AwsIntegrationData {
    let empty = AwsIntegrationData {
        all_profiles: Vec::new(),
        profile_map: HashMap::new(),
    };
    let path = match resolve_aws_config_path(path_override) {
        Some(p) => p,
        None => return empty,
    };
    let contents = match std::fs::read_to_string(&path) {
        Ok(c) => c,
        Err(_) => return empty,
    };

    let all_profiles = parse_aws_config(&contents);

    let mut profile_map: HashMap<String, Vec<AwsProfileEntry>> = HashMap::new();
    for entry in &all_profiles {
        if let Some(ref awzars_prof) = entry.awzars_profile {
            profile_map
                .entry(awzars_prof.clone())
                .or_default()
                .push(entry.clone());
        }
    }

    AwsIntegrationData {
        all_profiles,
        profile_map,
    }
}

/// Write all profiles back to the AWS config file as INI.
///
/// `path_override` substitutes for the default `~/.aws/config` when set.
///
/// On Unix the file is created with mode 0o600 and the parent directory
/// is restricted to 0o700. The file is not a secret store but it contains
/// tenant IDs, app ID URIs, and role ARNs that aid reconnaissance, so it
/// is kept private to the owning user.
///
/// Writes are atomic: contents go to a sibling `<path>.tmp` first, then are
/// renamed over the target. A crash mid-write leaves the previous AWS config
/// intact rather than truncating it.
pub fn save_aws_config(
    profiles: &[AwsProfileEntry],
    path_override: Option<&str>,
) -> std::io::Result<()> {
    let path = resolve_aws_config_path(path_override).ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "could not determine home directory for AWS config",
        )
    })?;

    // Ensure ~/.aws/ directory exists with restricted permissions.
    if let Some(parent) = path.parent() {
        // Refuse to create or chmod through a symlink. A same-UID attacker
        // who plants ~/.aws as a symlink would otherwise have us tighten
        // permissions on the target outside the home directory.
        if let Ok(meta) = std::fs::symlink_metadata(parent) {
            if meta.file_type().is_symlink() {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    format!(
                        "{} is a symlink; refusing to write through it",
                        parent.display()
                    ),
                ));
            }
        }
        std::fs::create_dir_all(parent)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700))?;
        }
    }

    // Refuse to write through a symlinked config file. Pre-existing AWS
    // configs that are intentionally symlinked elsewhere will need to be
    // de-symlinked manually; this is the safe default for a credential tool.
    if let Ok(meta) = std::fs::symlink_metadata(&path) {
        if meta.file_type().is_symlink() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                format!(
                    "{} is a symlink; refusing to write through it",
                    path.display()
                ),
            ));
        }
    }

    let mut out = String::new();
    for entry in profiles {
        let section = if entry.name == "default" {
            "[default]".to_string()
        } else {
            format!("[profile {}]", entry.name)
        };
        out.push_str(&section);
        out.push('\n');

        if let Some(ref region) = entry.region {
            out.push_str(&format!("region = {}\n", region));
        }
        if let Some(ref cp) = entry.credential_process {
            out.push_str(&format!("credential_process = {}\n", cp));
        }
        if let Some(ref sp) = entry.source_profile {
            out.push_str(&format!("source_profile = {}\n", sp));
        }
        if let Some(ref ra) = entry.role_arn {
            out.push_str(&format!("role_arn = {}\n", ra));
        }
        if let Some(ref rsn) = entry.role_session_name {
            out.push_str(&format!("role_session_name = {}\n", rsn));
        }

        // Write extra keys in sorted order for determinism
        let mut extra_keys: Vec<&String> = entry.extra.keys().collect();
        extra_keys.sort();
        for key in extra_keys {
            out.push_str(&format!("{} = {}\n", key, &entry.extra[key]));
        }

        out.push('\n');
    }

    crate::util::atomic_write(&path, out.as_bytes(), 0o600)
}

/// Resolve the effective AWS config path: override > default.
pub fn resolve_aws_config_path(override_path: Option<&str>) -> Option<PathBuf> {
    override_path
        .filter(|s| !s.is_empty())
        .map(PathBuf::from)
        .or_else(aws_config_path_default)
}

/// Get the path to ~/.aws/config, or `None` if the home directory cannot be
/// resolved.
///
/// Returns `Option` rather than a literal `~/.aws/config` fallback because
/// the OS will not expand `~` itself — falling back to that path would
/// silently create a literal `~` directory in the cwd.
fn aws_config_path_default() -> Option<PathBuf> {
    directories::BaseDirs::new().map(|bd| bd.home_dir().join(".aws").join("config"))
}

/// Parse AWS config INI content, extracting all profile entries
fn parse_aws_config(contents: &str) -> Vec<AwsProfileEntry> {
    let mut entries = Vec::new();
    let mut current_section: Option<String> = None;
    let mut current_region: Option<String> = None;
    let mut current_credential_process: Option<String> = None;
    let mut current_extra: HashMap<String, String> = HashMap::new();
    let mut current_source_profile: Option<String> = None;
    let mut current_role_arn: Option<String> = None;
    let mut current_role_session_name: Option<String> = None;

    for line in contents.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with(';') {
            continue;
        }

        if trimmed.starts_with('[') && trimmed.ends_with(']') {
            flush_section(
                &mut current_section,
                &mut current_region,
                &mut current_credential_process,
                &mut current_source_profile,
                &mut current_role_arn,
                &mut current_role_session_name,
                &mut current_extra,
                &mut entries,
            );

            let header = &trimmed[1..trimmed.len() - 1];
            current_section = Some(if header == "default" {
                "default".to_string()
            } else if let Some(name) = header.strip_prefix("profile ") {
                name.trim().to_string()
            } else {
                header.to_string()
            });
        } else if let Some((key, value)) = trimmed.split_once('=') {
            let key = key.trim();
            let value = value.trim();
            match key {
                "region" => current_region = Some(value.to_string()),
                "credential_process" => current_credential_process = Some(value.to_string()),
                "source_profile" => current_source_profile = Some(value.to_string()),
                "role_arn" => current_role_arn = Some(value.to_string()),
                "role_session_name" => current_role_session_name = Some(value.to_string()),
                _ => {
                    current_extra.insert(key.to_string(), value.to_string());
                }
            }
        }
    }

    flush_section(
        &mut current_section,
        &mut current_region,
        &mut current_credential_process,
        &mut current_source_profile,
        &mut current_role_arn,
        &mut current_role_session_name,
        &mut current_extra,
        &mut entries,
    );

    entries
}

#[allow(clippy::too_many_arguments)]
fn flush_section(
    section: &mut Option<String>,
    region: &mut Option<String>,
    credential_process: &mut Option<String>,
    source_profile: &mut Option<String>,
    role_arn: &mut Option<String>,
    role_session_name: &mut Option<String>,
    extra: &mut HashMap<String, String>,
    entries: &mut Vec<AwsProfileEntry>,
) {
    if let Some(name) = section.take() {
        let cp = credential_process.take();
        let uses_awzars = cp.as_ref().is_some_and(|c| c.contains("awzars"));
        let awzars_profile = cp.as_ref().and_then(|c| extract_awzars_profile(c));

        entries.push(AwsProfileEntry {
            name,
            region: region.take(),
            credential_process: cp,
            uses_awzars,
            awzars_profile,
            source_profile: source_profile.take(),
            role_arn: role_arn.take(),
            role_session_name: role_session_name.take(),
            extra: std::mem::take(extra),
        });
    }
    region.take();
    credential_process.take();
    source_profile.take();
    role_arn.take();
    role_session_name.take();
    extra.clear();
}

/// Extract the --profile <name> value from a credential_process command string
pub fn extract_awzars_profile(credential_process: &str) -> Option<String> {
    let parts: Vec<&str> = credential_process.split_whitespace().collect();
    for i in 0..parts.len() {
        if parts[i] == "--profile" && i + 1 < parts.len() {
            return Some(parts[i + 1].to_string());
        }
        if let Some(val) = parts[i].strip_prefix("--profile=") {
            if !val.is_empty() {
                return Some(val.to_string());
            }
        }
    }
    None
}

/// Build a credential_process command for linking an AWS profile to awzars
pub fn build_awzars_credential_process(awzars_profile: &str) -> String {
    format!("awzars credential-process --profile {}", awzars_profile)
}

/// Detect the awzars binary path from an existing credential_process string,
/// or return "awzars" as default.
pub fn detect_awzars_binary(existing: Option<&str>) -> String {
    match existing {
        Some(cp) if cp.contains("awzars") => {
            // Extract the binary path (first token)
            cp.split_whitespace().next().unwrap_or("awzars").to_string()
        }
        _ => "awzars".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_empty_config() {
        let entries = parse_aws_config("");
        assert!(entries.is_empty());
    }

    #[test]
    fn test_parse_no_awzars() {
        let contents = r#"
[profile work]
region = us-east-1
output = json
"#;
        let entries = parse_aws_config(contents);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].name, "work");
        assert_eq!(entries[0].region, Some("us-east-1".to_string()));
        assert!(!entries[0].uses_awzars);
        assert!(entries[0].credential_process.is_none());
        assert_eq!(entries[0].extra.get("output").unwrap(), "json");
    }

    #[test]
    fn test_parse_awzars_profile() {
        let contents = r#"
[profile work]
region = us-east-1
credential_process = /usr/local/bin/awzars credential-process --profile work

[profile dev]
region = eu-west-1
credential_process = awzars credential-process --profile dev
"#;
        let entries = parse_aws_config(contents);
        assert_eq!(entries.len(), 2);

        assert_eq!(entries[0].name, "work");
        assert_eq!(entries[0].region, Some("us-east-1".to_string()));
        assert!(entries[0].uses_awzars);
        assert_eq!(entries[0].awzars_profile, Some("work".to_string()));

        assert_eq!(entries[1].name, "dev");
        assert_eq!(entries[1].region, Some("eu-west-1".to_string()));
        assert!(entries[1].uses_awzars);
        assert_eq!(entries[1].awzars_profile, Some("dev".to_string()));
    }

    #[test]
    fn test_parse_default_profile() {
        let contents = r#"
[default]
region = us-east-1
credential_process = awzars credential-process --profile default
"#;
        let entries = parse_aws_config(contents);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].name, "default");
        assert!(entries[0].uses_awzars);
    }

    #[test]
    fn test_parse_mixed_profiles() {
        let contents = r#"
[profile work]
region = us-east-1
credential_process = /usr/local/bin/awzars credential-process --profile work

[profile other]
region = us-west-2
credential_process = some-other-tool provider

[profile staging]
region = ap-southeast-1
credential_process = awzars credential-process --profile staging
"#;
        let entries = parse_aws_config(contents);
        assert_eq!(entries.len(), 3);

        assert_eq!(entries[0].name, "work");
        assert!(entries[0].uses_awzars);

        assert_eq!(entries[1].name, "other");
        assert!(!entries[1].uses_awzars);

        assert_eq!(entries[2].name, "staging");
        assert!(entries[2].uses_awzars);
    }

    #[test]
    fn test_parse_extra_keys() {
        let contents = r#"
[profile sso]
region = us-east-1
output = json
sso_start_url = https://example.awsapps.com/start
sso_region = us-east-1
sso_account_id = 123456789012
sso_role_name = MyRole
"#;
        let entries = parse_aws_config(contents);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].extra.len(), 5);
        assert_eq!(
            entries[0].extra.get("sso_start_url").unwrap(),
            "https://example.awsapps.com/start"
        );
    }

    #[test]
    fn test_extract_awzars_profile() {
        assert_eq!(
            extract_awzars_profile("/usr/local/bin/awzars credential-process --profile work"),
            Some("work".to_string())
        );
        assert_eq!(
            extract_awzars_profile("awzars credential-process --profile=my-profile"),
            Some("my-profile".to_string())
        );
        assert_eq!(extract_awzars_profile("awzars credential-process"), None);
        assert_eq!(
            extract_awzars_profile("some-other-tool --profile test"),
            Some("test".to_string())
        );
    }

    #[test]
    fn test_aws_integration_data_for_profile() {
        let data = load_aws_integration(None);
        assert!(data.for_awzars_profile("nonexistent").is_empty());
    }

    #[test]
    fn test_parse_comments_and_whitespace() {
        let contents = r#"
# This is a comment
[profile work]
  region = us-east-1
  credential_process = awzars credential-process --profile work
; another comment
"#;
        let entries = parse_aws_config(contents);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].name, "work");
    }

    #[test]
    fn test_parse_profile_without_credential_process() {
        let contents = r#"
[profile manual]
region = us-west-2
output = json

[profile sso]
region = us-east-1
sso_start_url = https://example.awsapps.com/start
sso_region = us-east-1
"#;
        let entries = parse_aws_config(contents);
        assert_eq!(entries.len(), 2);
        assert!(!entries[0].uses_awzars);
        assert!(entries[0].credential_process.is_none());
        assert!(!entries[1].uses_awzars);
    }

    #[test]
    fn test_all_profiles_populated() {
        let data = load_aws_integration_from(
            r#"
[profile work]
region = us-east-1
credential_process = awzars credential-process --profile work

[profile other]
region = us-west-2
credential_process = some-other-tool provider

[profile plain]
region = eu-west-1
"#,
        );
        assert_eq!(data.all_profiles.len(), 3);
        assert_eq!(data.profile_map.len(), 1);
        assert!(data.profile_map.contains_key("work"));
    }

    #[test]
    fn test_save_and_reload() {
        let profiles = vec![
            AwsProfileEntry {
                name: "work".to_string(),
                region: Some("us-east-1".to_string()),
                credential_process: Some("awzars credential-process --profile work".to_string()),
                uses_awzars: true,
                awzars_profile: Some("work".to_string()),
                source_profile: None,
                role_arn: None,
                role_session_name: None,
                extra: HashMap::new(),
            },
            AwsProfileEntry {
                name: "other".to_string(),
                region: Some("us-west-2".to_string()),
                credential_process: None,
                uses_awzars: false,
                awzars_profile: None,
                source_profile: None,
                role_arn: None,
                role_session_name: None,
                extra: {
                    let mut m = HashMap::new();
                    m.insert("output".to_string(), "json".to_string());
                    m
                },
            },
        ];

        let serialized = format_profiles(&profiles);
        let reloaded = parse_aws_config(&serialized);

        assert_eq!(reloaded.len(), 2);
        assert_eq!(reloaded[0].name, "work");
        assert_eq!(reloaded[0].region, Some("us-east-1".to_string()));
        assert!(reloaded[0].uses_awzars);
        assert_eq!(reloaded[1].name, "other");
        assert_eq!(reloaded[1].extra.get("output").unwrap(), "json");
    }

    #[test]
    fn test_build_awzars_credential_process() {
        assert_eq!(
            build_awzars_credential_process("my-profile"),
            "awzars credential-process --profile my-profile"
        );
    }

    #[test]
    fn test_parse_assume_role_profile() {
        let contents = r#"
[profile work]
region = us-east-1
credential_process = awzars credential-process --profile work

[profile work-admin]
region = us-east-1
source_profile = work
role_arn = arn:aws:iam::123456789012:role/AdminRole
"#;
        let entries = parse_aws_config(contents);
        assert_eq!(entries.len(), 2);

        assert_eq!(entries[0].name, "work");
        assert!(entries[0].uses_awzars);
        assert!(!entries[0].is_assume_role());
        assert!(entries[0].source_profile.is_none());

        assert_eq!(entries[1].name, "work-admin");
        assert!(!entries[1].uses_awzars);
        assert!(entries[1].is_assume_role());
        assert_eq!(entries[1].source_profile, Some("work".to_string()));
        assert_eq!(
            entries[1].role_arn,
            Some("arn:aws:iam::123456789012:role/AdminRole".to_string())
        );
        assert!(entries[1].credential_process.is_none());
    }

    #[test]
    fn test_detect_awzars_binary() {
        assert_eq!(
            detect_awzars_binary(Some(
                "/usr/local/bin/awzars credential-process --profile work"
            )),
            "/usr/local/bin/awzars"
        );
        assert_eq!(detect_awzars_binary(None), "awzars");
        assert_eq!(
            detect_awzars_binary(Some("some-other-tool --profile test")),
            "awzars"
        );
    }

    fn load_aws_integration_from(contents: &str) -> AwsIntegrationData {
        let all_profiles = parse_aws_config(contents);
        let mut profile_map: HashMap<String, Vec<AwsProfileEntry>> = HashMap::new();
        for entry in &all_profiles {
            if let Some(ref awzars_prof) = entry.awzars_profile {
                profile_map
                    .entry(awzars_prof.clone())
                    .or_default()
                    .push(entry.clone());
            }
        }
        AwsIntegrationData {
            all_profiles,
            profile_map,
        }
    }

    fn format_profiles(profiles: &[AwsProfileEntry]) -> String {
        let mut out = String::new();
        for entry in profiles {
            let section = if entry.name == "default" {
                "[default]".to_string()
            } else {
                format!("[profile {}]", entry.name)
            };
            out.push_str(&section);
            out.push('\n');
            if let Some(ref region) = entry.region {
                out.push_str(&format!("region = {}\n", region));
            }
            if let Some(ref cp) = entry.credential_process {
                out.push_str(&format!("credential_process = {}\n", cp));
            }
            if let Some(ref sp) = entry.source_profile {
                out.push_str(&format!("source_profile = {}\n", sp));
            }
            if let Some(ref ra) = entry.role_arn {
                out.push_str(&format!("role_arn = {}\n", ra));
            }
            if let Some(ref rsn) = entry.role_session_name {
                out.push_str(&format!("role_session_name = {}\n", rsn));
            }
            let mut extra_keys: Vec<&String> = entry.extra.keys().collect();
            extra_keys.sort();
            for key in extra_keys {
                out.push_str(&format!("{} = {}\n", key, &entry.extra[key]));
            }
            out.push('\n');
        }
        out
    }
}

//! AWS config (~/.aws/config) parser and writer for awzars integration

mod document;

#[cfg(test)]
mod regression_tests;

use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};

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

    fn properties(&self) -> BTreeMap<String, String> {
        self.extra
            .iter()
            .map(|(name, value)| (name.clone(), value.clone()))
            .chain(
                [
                    ("region", &self.region),
                    ("credential_process", &self.credential_process),
                    ("source_profile", &self.source_profile),
                    ("role_arn", &self.role_arn),
                    ("role_session_name", &self.role_session_name),
                ]
                .into_iter()
                .filter_map(|(name, value)| {
                    value
                        .as_ref()
                        .map(|value| (name.to_string(), value.clone()))
                }),
            )
            .collect()
    }
}

/// One TUI change, applied to the AWS config file as it is when saving.
// Built once per save and only passed by reference, so the size difference
// between variants costs nothing worth boxing for.
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone)]
pub enum AwsProfileOp {
    /// Create (`before` is `None`), edit or rename (`after.name` differs from
    /// `before.name`) a profile. Only the settings that differ between
    /// `before` and `after` are written; every other setting keeps the value
    /// currently in the file.
    Upsert {
        before: Option<AwsProfileEntry>,
        after: AwsProfileEntry,
    },
    /// Remove the profile section with this name.
    Delete { name: String },
}

/// Why an AWS config save did not write the file.
#[derive(Debug)]
pub enum SaveError {
    /// Reading or writing the file failed.
    Io(std::io::Error),
    /// The profile being changed is no longer in the file.
    Missing(String),
    /// The new profile name is already used in the file.
    Exists(String),
}

impl std::fmt::Display for SaveError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(error) => error.fmt(f),
            Self::Missing(name) => write!(
                f,
                "AWS profile '{}' changed outside the TUI; reloaded",
                name
            ),
            Self::Exists(name) => write!(f, "AWS profile '{}' already exists", name),
        }
    }
}

impl std::error::Error for SaveError {}

impl From<std::io::Error> for SaveError {
    fn from(error: std::io::Error) -> Self {
        Self::Io(error)
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

/// Apply one profile change to the AWS config file as it is now, preserving
/// other sections and unchanged text byte-for-byte. Returns the settings whose
/// outside change was overridden by this one.
///
/// `path_override` substitutes for the default `~/.aws/config` when set.
///
/// On Unix the file is created with mode 0o600 and the parent directory
/// is restricted to 0o700. The file is not a secret store but it contains
/// tenant IDs, app ID URIs, and role ARNs that aid reconnaissance, so it
/// is kept private to the owning user.
///
/// Writes are atomic: contents go to a hidden temporary file in the same
/// directory first, then are renamed over the target. A crash mid-write
/// leaves the previous AWS config intact rather than truncating it.
///
/// Before a write that changes an existing file, the previous contents are
/// copied to `<path>.bak.<YYYYMMDDTHHMMSS.mmmZ>` (UTC, mode 0o600) and only
/// the newest [`BACKUP_COUNT`] such copies are kept. If the copy cannot be
/// written, the save is aborted.
pub fn save_aws_config(
    op: &AwsProfileOp,
    path_override: Option<&str>,
) -> Result<Vec<String>, SaveError> {
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
                )
                .into());
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
            )
            .into());
        }
    }

    let (contents, exists) = match std::fs::read_to_string(&path) {
        Ok(contents) => (contents, true),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => (String::new(), false),
        Err(error) => return Err(error.into()),
    };
    let (output, overridden) = document::Document::parse(&contents).apply(op)?;
    if exists && output != contents {
        backup_aws_config(&path, &contents, chrono::Utc::now())?;
    }
    crate::util::atomic_write(&path, output.as_bytes(), 0o600)?;
    Ok(overridden)
}

/// How many `<config>.bak.<timestamp>` copies `save_aws_config` keeps.
const BACKUP_COUNT: usize = 10;

/// Copy `contents` (the file as read before this save) to a new
/// `<path>.bak.<timestamp>` named after `now`, then delete all but the
/// newest [`BACKUP_COUNT`] backups of `path`.
fn backup_aws_config(
    path: &Path,
    contents: &str,
    now: chrono::DateTime<chrono::Utc>,
) -> std::io::Result<()> {
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("{} has no usable file name", path.display()),
            )
        })?;
    let stem = format!("{}.bak.{}", name, now.format("%Y%m%dT%H%M%S%.3fZ"));
    let mut backup = path.with_file_name(&stem);
    let mut clash = 0;
    while std::fs::symlink_metadata(&backup).is_ok() {
        clash += 1;
        backup = path.with_file_name(format!("{}-{}", stem, clash));
    }
    crate::util::atomic_write(&backup, contents.as_bytes(), 0o600)?;

    // Pruning is best effort: the new backup is already safely written.
    let directory = backup
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let Ok(entries) = std::fs::read_dir(directory) else {
        return Ok(());
    };
    let mut backups: Vec<_> = entries
        .filter_map(Result::ok)
        .filter(|entry| entry.file_type().is_ok_and(|kind| kind.is_file()))
        .filter_map(|entry| {
            let file_name = entry.file_name().into_string().ok()?;
            let order = backup_order(name, &file_name)?;
            Some((order, entry.path()))
        })
        .collect();
    backups.sort();
    let excess = backups.len().saturating_sub(BACKUP_COUNT);
    for (_, old) in backups.into_iter().take(excess) {
        let _ = std::fs::remove_file(old);
    }
    Ok(())
}

/// Sort key of `file_name` if it is exactly `<name>.bak.<YYYYMMDDTHHMMSS.mmmZ>`
/// with an optional `-<n>` clash suffix, as written by [`backup_aws_config`].
fn backup_order(name: &str, file_name: &str) -> Option<(String, u64)> {
    let rest = file_name.strip_prefix(name)?.strip_prefix(".bak.")?;
    let (timestamp, clash) = match rest.split_once('-') {
        Some((timestamp, clash)) => {
            if clash.is_empty() || !clash.bytes().all(|byte| byte.is_ascii_digit()) {
                return None;
            }
            (timestamp, clash.parse().ok()?)
        }
        None => (rest, 0),
    };
    let bytes = timestamp.as_bytes();
    let digits = |range: std::ops::Range<usize>| bytes[range].iter().all(u8::is_ascii_digit);
    let valid = bytes.len() == 20
        && digits(0..8)
        && bytes[8] == b'T'
        && digits(9..15)
        && bytes[15] == b'.'
        && digits(16..19)
        && bytes[19] == b'Z';
    valid.then(|| (timestamp.to_string(), clash))
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
    document::Document::parse(contents)
        .profiles()
        .map(|(name, mut properties)| {
            let credential_process = properties.remove("credential_process");
            let uses_awzars = credential_process
                .as_ref()
                .is_some_and(|value| value.contains("awzars"));
            let awzars_profile = credential_process
                .as_ref()
                .and_then(|value| extract_awzars_profile(value));
            AwsProfileEntry {
                name: name.to_string(),
                region: properties.remove("region"),
                credential_process,
                uses_awzars,
                awzars_profile,
                source_profile: properties.remove("source_profile"),
                role_arn: properties.remove("role_arn"),
                role_session_name: properties.remove("role_session_name"),
                extra: properties.into_iter().collect(),
            }
        })
        .collect()
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

        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("config");
        for after in profiles {
            let op = AwsProfileOp::Upsert {
                before: None,
                after,
            };
            assert!(save_aws_config(&op, path.to_str()).unwrap().is_empty());
        }
        let reloaded = load_aws_integration(path.to_str()).all_profiles;

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
}

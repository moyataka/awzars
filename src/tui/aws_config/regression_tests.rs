use super::{load_aws_integration, save_aws_config};
use std::path::PathBuf;

fn config_file(contents: &str) -> (tempfile::TempDir, PathBuf) {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("config");
    std::fs::write(&path, contents).unwrap();
    (directory, path)
}

#[test]
fn commented_headers_keep_profiles_separate_when_saved() {
    for comment in ["# note", "; note"] {
        let contents = format!(
            "[profile a]\nregion = us-east-1\n[profile b] {comment}\n\
             region = us-west-2\nrole_arn = arn:aws:iam::123456789012:role/B\n"
        );
        let (_directory, path) = config_file(&contents);
        let profiles = load_aws_integration(path.to_str()).all_profiles;

        assert_eq!(profiles.len(), 2);
        assert_eq!(profiles[0].name, "a");
        assert_eq!(profiles[0].region.as_deref(), Some("us-east-1"));
        assert!(profiles[0].role_arn.is_none());
        assert_eq!(profiles[1].name, "b");
        assert_eq!(profiles[1].region.as_deref(), Some("us-west-2"));

        save_aws_config(&profiles, path.to_str()).unwrap();
        let reloaded = load_aws_integration(path.to_str()).all_profiles;
        assert_eq!(reloaded.len(), 2);
        assert_eq!(reloaded[0].region.as_deref(), Some("us-east-1"));
        assert!(reloaded[0].role_arn.is_none());
        assert_eq!(reloaded[1].region.as_deref(), Some("us-west-2"));
        assert_eq!(
            reloaded[1].role_arn.as_deref(),
            Some("arn:aws:iam::123456789012:role/B")
        );
    }
}

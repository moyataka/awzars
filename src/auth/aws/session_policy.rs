use crate::error::{AwzarsError, Result};
use std::io::Read;
use std::path::Path;

const MAX_POLICY_CHARACTERS: usize = 2048;
// STS accepts U+0009/U+000A/U+000D and U+0020..U+00FF: at most two UTF-8 bytes.
const MAX_POLICY_BYTES: usize = MAX_POLICY_CHARACTERS * 2;

#[derive(Clone)]
pub struct SessionPolicy(String);

impl SessionPolicy {
    pub fn from_file(path: &Path) -> Result<Self> {
        let mut document = String::new();
        std::fs::File::open(path)
            .and_then(|file| {
                file.take((MAX_POLICY_BYTES + 1) as u64)
                    .read_to_string(&mut document)
            })
            .map_err(|error| {
                AwzarsError::Config(format!(
                    "Could not read session policy file '{}': {error}",
                    path.display()
                ))
            })?;
        Self::parse(document)
    }

    pub fn parse(document: String) -> Result<Self> {
        if document.chars().count() > MAX_POLICY_CHARACTERS {
            return Err(AwzarsError::Config(
                "Session policy exceeds the STS limit of 2048 characters (including whitespace)"
                    .into(),
            ));
        }
        if !document
            .chars()
            .all(|character| matches!(character, '\t' | '\n' | '\r' | ' '..='\u{ff}'))
        {
            return Err(AwzarsError::Config(
                "Session policy contains characters outside the STS supported range; use JSON Unicode escapes"
                    .into(),
            ));
        }
        let policy: serde_json::Value = serde_json::from_str(&document).map_err(|_| {
            AwzarsError::Config("Session policy must be a valid JSON policy document".into())
        })?;
        let has_statements = match policy.get("Statement") {
            Some(serde_json::Value::Object(statement)) => !statement.is_empty(),
            Some(serde_json::Value::Array(statements)) => {
                !statements.is_empty()
                    && statements.iter().all(|statement| {
                        statement
                            .as_object()
                            .is_some_and(|statement| !statement.is_empty())
                    })
            }
            _ => false,
        };
        if !policy.is_object() || !has_statements {
            return Err(AwzarsError::Config(
                "Session policy must contain a nonempty Statement object or array of objects"
                    .into(),
            ));
        }
        Ok(Self(document))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Debug for SessionPolicy {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SessionPolicy")
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const POLICY: &str =
        include_str!("../../../examples/session-policies/ec2-describe-instances.json");

    #[test]
    fn accepts_the_example_without_changing_its_contents() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("policy.json");
        std::fs::write(&path, POLICY).unwrap();
        assert_eq!(SessionPolicy::from_file(&path).unwrap().as_str(), POLICY);
    }

    #[test]
    fn rejects_missing_invalid_and_empty_policy_files() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("policy.json");
        assert!(SessionPolicy::from_file(&path).is_err());
        for document in [
            "",
            "not-json",
            "{}",
            "[]",
            "null",
            r#"{"Statement":[]}"#,
            r#"{"Statement":{}}"#,
            r#"{"Statement":[null]}"#,
            r#"{"Statement":[{}]}"#,
        ] {
            std::fs::write(&path, document).unwrap();
            assert!(SessionPolicy::from_file(&path).is_err(), "{document}");
        }
    }

    #[test]
    fn enforces_the_sts_character_limit_and_range() {
        let single = r#"{"Statement":{"Effect":"Deny","Action":"*","Resource":"*"}}"#;
        let at_limit = format!(
            "{single}{}",
            " ".repeat(MAX_POLICY_CHARACTERS - single.len())
        );
        assert!(SessionPolicy::parse(at_limit.clone()).is_ok());
        assert!(SessionPolicy::parse(format!("{at_limit} ")).is_err());
        assert!(SessionPolicy::parse(format!("{single}\0")).is_err());
        let latin = single.replacen('{', "{\"Id\":\"é\",", 1);
        let latin_at_limit = format!(
            "{latin}{}",
            " ".repeat(MAX_POLICY_CHARACTERS - latin.chars().count())
        );
        assert!(SessionPolicy::parse(latin_at_limit).is_ok());
        assert!(SessionPolicy::parse(single.replacen('{', "{\"Id\":\"🙂\",", 1)).is_err());
    }

    #[test]
    fn policy_contents_stay_out_of_debug_and_parse_errors() {
        let policy = SessionPolicy::parse(POLICY.into()).unwrap();
        assert!(!format!("{policy:?}").contains("DescribeInstances"));
        let error = SessionPolicy::parse("PRIVATE-POLICY-MARKER".into()).unwrap_err();
        assert!(!error.to_string().contains("PRIVATE-POLICY-MARKER"));
    }
}

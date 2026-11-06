//! Local client authentication; possession of the enrolled secret identifies the client.

use crate::auth::aws::read_only::TargetName;
use crate::error::{AwzarsError, Result};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use serde::{Deserialize, Serialize};
use std::{fmt, io::Read, str::FromStr};
use zeroize::Zeroizing;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct McpClientName(TargetName);

impl FromStr for McpClientName {
    type Err = String;

    fn from_str(value: &str) -> std::result::Result<Self, Self::Err> {
        value.parse().map(Self)
    }
}

impl fmt::Display for McpClientName {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

pub struct McpSecret(Zeroizing<String>);

impl fmt::Debug for McpSecret {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("McpSecret([REDACTED])")
    }
}

impl McpSecret {
    pub fn generate() -> Result<Self> {
        let mut bytes = Zeroizing::new([0u8; 32]);
        getrandom::fill(bytes.as_mut())
            .map_err(|_| AwzarsError::Config("Could not generate an MCP client secret".into()))?;
        Ok(Self(Zeroizing::new(URL_SAFE_NO_PAD.encode(bytes.as_ref()))))
    }

    /// The caller closes its private pipe after writing one secret and an optional newline.
    pub fn from_reader(reader: impl Read) -> Result<Self> {
        let mut input = Zeroizing::new(String::new());
        reader
            .take(46)
            .read_to_string(&mut input)
            .map_err(|_| AwzarsError::McpAuthentication)?;
        let secret = input
            .strip_suffix("\r\n")
            .or_else(|| input.strip_suffix('\n'))
            .unwrap_or(&input);
        if secret.len() != 43 {
            return Err(AwzarsError::McpAuthentication);
        }
        let decoded = Zeroizing::new(
            URL_SAFE_NO_PAD
                .decode(secret)
                .map_err(|_| AwzarsError::McpAuthentication)?,
        );
        if decoded.len() != 32 {
            return Err(AwzarsError::McpAuthentication);
        }
        Ok(Self(Zeroizing::new(secret.to_owned())))
    }

    pub(crate) fn expose(&self) -> &str {
        &self.0
    }

    pub fn verifier(&self) -> Result<McpSecretVerifier> {
        McpSecretVerifier::try_from(crate::auth::lock::hash_password(self.expose())?)
            .map_err(AwzarsError::Config)
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct McpSecretVerifier(String);

impl fmt::Debug for McpSecretVerifier {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("McpSecretVerifier([REDACTED])")
    }
}

impl TryFrom<String> for McpSecretVerifier {
    type Error = String;

    fn try_from(value: String) -> std::result::Result<Self, Self::Error> {
        let invalid = || "Invalid MCP secret verifier".to_owned();
        if value.len() > 256 {
            return Err(invalid());
        }
        let hash = argon2::password_hash::PasswordHash::new(&value).map_err(|_| invalid())?;
        if hash.algorithm.as_str() != "argon2id"
            || hash.version != Some(19)
            || hash.params.get_decimal("m") != Some(65536)
            || hash.params.get_decimal("t") != Some(3)
            || hash.params.get_decimal("p") != Some(4)
            || hash.salt.is_none()
            || hash.hash.is_none()
        {
            return Err(invalid());
        }
        Ok(Self(value))
    }
}

impl From<McpSecretVerifier> for String {
    fn from(value: McpSecretVerifier) -> Self {
        value.0
    }
}

impl McpSecretVerifier {
    pub fn verifies(&self, secret: &McpSecret) -> bool {
        crate::auth::lock::verify_password(secret.expose(), &self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secrets_are_bounded_redacted_and_verified_without_echoing_input() {
        let secret = McpSecret::generate().unwrap();
        let verifier = secret.verifier().unwrap();
        for suffix in ["", "\n", "\r\n"] {
            let input = format!("{}{suffix}", secret.expose());
            assert!(verifier.verifies(&McpSecret::from_reader(input.as_bytes()).unwrap()));
        }
        assert!(!verifier.verifies(&McpSecret::generate().unwrap()));
        assert!(!format!("{secret:?}").contains(secret.expose()));
        assert!(!format!("{verifier:?}").contains("argon2"));
        for input in [
            "PRIVATE-SECRET".to_owned(),
            "A".repeat(44),
            "!".repeat(43),
            "A".repeat(4096),
        ] {
            let error = McpSecret::from_reader(input.as_bytes())
                .unwrap_err()
                .to_string();
            assert!(!error.contains(&input));
        }
        let mut input = std::io::Cursor::new(vec![b'A'; 4096]);
        assert!(McpSecret::from_reader(&mut input).is_err());
        assert_eq!(input.position(), 46);
    }

    #[test]
    fn verifiers_reject_malformed_or_excessive_hash_parameters() {
        let verifier = String::from(McpSecret::generate().unwrap().verifier().unwrap());
        for invalid in [
            verifier.replace("m=65536", "m=999999999"),
            verifier.replace("t=3", "t=999999"),
            "PRIVATE-SECRET".into(),
        ] {
            assert_eq!(
                McpSecretVerifier::try_from(invalid).unwrap_err(),
                "Invalid MCP secret verifier"
            );
        }
    }
}

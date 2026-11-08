use super::*;
use crate::auth::mcp::{McpSecret, McpSecretVerifier};
use crate::config::Profile;
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct McpClientGrant {
    target: TargetName,
    capabilities: BTreeSet<ReadOnlyCapability>,
    secret_verifier: McpSecretVerifier,
    binding: EnrollmentBinding,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
struct EnrollmentBinding(String);

impl TryFrom<String> for EnrollmentBinding {
    type Error = String;
    fn try_from(value: String) -> std::result::Result<Self, Self::Error> {
        if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err("Invalid MCP enrollment binding".into());
        }
        Ok(Self(value))
    }
}

impl From<EnrollmentBinding> for String {
    fn from(value: EnrollmentBinding) -> Self {
        value.0
    }
}

impl EnrollmentBinding {
    fn for_profile(profile_name: &str, profile: &Profile, target: &TargetName) -> Result<Self> {
        let configured = profile
            .read_only
            .as_ref()
            .and_then(|access| access.targets.get(target))
            .ok_or(AwzarsError::McpAuthentication)?;
        let document = serde_json::to_vec(&(
            "awzars-mcp-enrollment-v1",
            profile_name,
            &profile.azure.tenant_id,
            &profile.azure.app_id_uri,
            &profile.role_arn,
            &profile.lock_verifier,
            target,
            configured,
        ))?;
        Ok(Self(
            Sha256::digest(document)
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect(),
        ))
    }
}

impl McpClientGrant {
    pub(crate) fn enroll(
        profile_name: &str,
        profile: &Profile,
        target: TargetName,
        capabilities: BTreeSet<ReadOnlyCapability>,
    ) -> Result<(Self, McpSecret)> {
        if !profile.mcp_readonly_accessible {
            return Err(AwzarsError::McpAuthentication);
        }
        let access = profile.read_only.as_ref().ok_or_else(|| {
            AwzarsError::Config("Configure read-only targets before enrolling a client".into())
        })?;
        if capabilities.is_empty() {
            return Err(AwzarsError::Config(
                "Enroll at least one approved capability".into(),
            ));
        }
        for capability in &capabilities {
            access.require_capability(&target, *capability)?;
        }
        let secret = McpSecret::generate()?;
        Ok((
            Self {
                binding: EnrollmentBinding::for_profile(profile_name, profile, &target)?,
                target,
                capabilities,
                secret_verifier: secret.verifier()?,
            },
            secret,
        ))
    }

    pub(crate) fn matches_profile(&self, profile_name: &str, profile: &Profile) -> Result<bool> {
        Ok(self.binding == EnrollmentBinding::for_profile(profile_name, profile, &self.target)?)
    }
}

pub struct AuthenticatedMcpRequest<'a> {
    profile_name: &'a str,
    profile: &'a Profile,
    request: AuthorizedReadOnlyRequest,
    client: McpClientName,
    grant: &'a McpClientGrant,
}

impl AuthenticatedMcpRequest<'_> {
    pub fn profile_name(&self) -> &str {
        self.profile_name
    }
    pub fn profile(&self) -> &Profile {
        self.profile
    }
    pub fn request(&self) -> &AuthorizedReadOnlyRequest {
        &self.request
    }

    /// Recheck the exact grant and its binding after potentially slow credential issuance.
    pub fn revalidate(&self, current: &Profile) -> Result<()> {
        let current_grant = current
            .read_only
            .as_ref()
            .and_then(|access| access.clients.get(&self.client));
        if !current.mcp_readonly_accessible
            || current_grant != Some(self.grant)
            || !self.grant.matches_profile(self.profile_name, current)?
        {
            return Err(AwzarsError::McpAuthentication);
        }
        Ok(())
    }
}

impl Profile {
    pub fn authenticate_mcp<'a>(
        &'a self,
        profile_name: &'a str,
        client: &McpClientName,
        target: &TargetName,
        capability: ReadOnlyCapability,
        secret: &McpSecret,
    ) -> Result<AuthenticatedMcpRequest<'a>> {
        self.authenticate_mcp_operation(profile_name, client, target, capability, secret, None)
    }

    pub fn authenticate_mcp_operation<'a>(
        &'a self,
        profile_name: &'a str,
        client: &McpClientName,
        target: &TargetName,
        capability: ReadOnlyCapability,
        secret: &McpSecret,
        operation: Option<&crate::auth::aws::read_only::ApprovedAwsOperation>,
    ) -> Result<AuthenticatedMcpRequest<'a>> {
        if !self.mcp_readonly_accessible {
            return Err(AwzarsError::McpAuthentication);
        }
        let access = self
            .read_only
            .as_ref()
            .ok_or(AwzarsError::McpAuthentication)?;
        let grant = access
            .clients
            .get(client)
            .ok_or(AwzarsError::McpAuthentication)?;
        if &grant.target != target
            || !grant.capabilities.contains(&capability)
            || !grant.matches_profile(profile_name, self)?
            || !grant.secret_verifier.verifies(secret)
        {
            return Err(AwzarsError::McpAuthentication);
        }
        let request = match (capability, operation) {
            (ReadOnlyCapability::AwsRead, Some(operation)) => {
                access.authorize_operation(target, operation)
            }
            (ReadOnlyCapability::AwsRead, None) | (_, Some(_)) => {
                Err(AwzarsError::McpAuthentication)
            }
            (_, None) => access.authorize(target, capability),
        }
        .map_err(|_| AwzarsError::McpAuthentication)?;
        Ok(AuthenticatedMcpRequest {
            profile_name,
            profile: self,
            request,
            client: client.clone(),
            grant,
        })
    }
}

impl ReadOnlyAccess {
    pub(crate) fn insert_client(
        &mut self,
        name: McpClientName,
        grant: McpClientGrant,
    ) -> Result<()> {
        if self.clients.contains_key(&name) {
            return Err(AwzarsError::Config(format!(
                "MCP client '{name}' already exists; revoke it before re-enrolling"
            )));
        }
        self.clients.insert(name, grant);
        Ok(())
    }

    pub(crate) fn remove_client(&mut self, name: &McpClientName) -> bool {
        self.clients.remove(name).is_some()
    }
}

#[cfg(test)]
mod tests;

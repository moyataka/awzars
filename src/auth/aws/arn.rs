#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IamResource {
    Role,
    SamlProvider,
}

#[derive(Debug, Clone, Copy)]
pub struct IamArn<'a> {
    value: &'a str,
    resource: IamResource,
}

impl<'a> IamArn<'a> {
    pub fn parse(value: &'a str) -> Option<Self> {
        let components: Vec<_> = value.splitn(6, ':').collect();
        let ["arn", "aws" | "aws-cn" | "aws-us-gov", "iam", "", account, resource] =
            components.as_slice()
        else {
            return None;
        };
        if account.len() != 12 || !account.bytes().all(|character| character.is_ascii_digit()) {
            return None;
        }
        let (kind, name) = resource.split_once('/')?;
        if name.is_empty()
            || name
                .chars()
                .any(|character| character.is_whitespace() || character.is_control())
        {
            return None;
        }
        let resource = match kind {
            "role" => IamResource::Role,
            "saml-provider" => IamResource::SamlProvider,
            _ => return None,
        };
        Some(Self { value, resource })
    }

    pub fn resource(self) -> IamResource {
        self.resource
    }

    pub fn as_str(self) -> &'a str {
        self.value
    }

    /// Sign-in always targets the commercial AWS endpoint, so only the
    /// `aws` partition is usable; `aws-cn` and `aws-us-gov` are recognised
    /// only so they can be rejected with a clear message.
    pub fn is_supported_partition(self) -> bool {
        self.value.starts_with("arn:aws:")
    }
}

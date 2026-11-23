use std::collections::BTreeMap;

/// Where Box Core gets a route's credential.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Credential {
    /// A key read from this environment variable of the Box Core process.
    Environment(String),
    /// Static keys from this profile in the operator's AWS credentials file.
    AwsProfile(String),
    /// The host's ambient identity, from the AWS SDK default credential chain.
    AwsDefaultChain,
    /// A key that a declared source's program reads at startup, by scheme and declaring plugin.
    Source(String, Option<String>),
}

impl Credential {
    /// The credential that a `secret.ref` names: an `env://` or `aws://` reference, or a
    /// reference in a scheme of `sources`.
    pub(crate) fn from_reference(
        reference: &str,
        sources: &BTreeMap<String, Option<String>>,
    ) -> Option<Self> {
        match reference.split_once("://")? {
            ("env", name) if !name.is_empty() => Some(Self::Environment(name.to_string())),
            ("aws", "") => Some(Self::AwsDefaultChain),
            ("aws", profile) => Some(Self::AwsProfile(profile.to_string())),
            (scheme, _) => sources
                .get(scheme)
                .map(|plugin| Self::Source(scheme.to_string(), plugin.clone())),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::Credential;

    #[test]
    fn from_reference_maps_each_scheme() {
        let none = BTreeMap::new();
        assert_eq!(
            Credential::from_reference("env://KEY", &none),
            Some(Credential::Environment("KEY".to_string()))
        );
        assert_eq!(
            Credential::from_reference("aws://dev", &none),
            Some(Credential::AwsProfile("dev".to_string()))
        );
        assert_eq!(
            Credential::from_reference("aws://", &none),
            Some(Credential::AwsDefaultChain)
        );
        for malformed in ["env://", "https://x", "aws", ""] {
            assert_eq!(
                Credential::from_reference(malformed, &none),
                None,
                "{malformed}"
            );
        }
    }
}

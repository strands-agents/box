use serde::Serialize;

use crate::Error;

/// The immutable context repeated on an invocation's events.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RunContext {
    pub(crate) box_version: String,
    pub(crate) os_family: OsFamily,
    pub(crate) os_version: Option<String>,
    pub(crate) build_arch: BuildArch,
    pub(crate) builtin_packs: Option<Vec<String>>,
    pub(crate) mcp_configured: Option<bool>,
    pub(crate) has_custom_packs: Option<bool>,
    pub(crate) profile_policy_present: Option<bool>,
    pub(crate) profile_hash: Option<String>,
}

/// The longest `os_version` the schema accepts.
const OS_VERSION_MAX: usize = 64;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub(crate) enum OsFamily {
    Macos,
    Linux,
    Windows,
    Other,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub(crate) enum BuildArch {
    Aarch64,
    X86_64,
    Other,
}

impl RunContext {
    /// A context with the CLI version and binary target.
    pub(crate) fn new(
        version: &str,
        os: &str,
        os_version: Option<String>,
        arch: &str,
    ) -> Result<Self, Error> {
        let components: Vec<_> = version.split('.').collect();
        if components.len() != 3
            || components.iter().any(|component| {
                !(1..=4).contains(&component.len())
                    || !component.bytes().all(|byte| byte.is_ascii_digit())
                    || (component.len() > 1 && component.starts_with('0'))
            })
        {
            return Err(Error);
        }
        Ok(Self {
            box_version: version.to_owned(),
            os_family: match os {
                "macos" => OsFamily::Macos,
                "linux" => OsFamily::Linux,
                "windows" => OsFamily::Windows,
                _ => OsFamily::Other,
            },
            os_version: os_version
                .map(|value| {
                    value
                        .trim()
                        .chars()
                        .take(OS_VERSION_MAX)
                        .collect::<String>()
                })
                .filter(|value| !value.is_empty()),
            build_arch: match arch {
                "aarch64" => BuildArch::Aarch64,
                "x86_64" => BuildArch::X86_64,
                _ => BuildArch::Other,
            },
            builtin_packs: None,
            mcp_configured: None,
            has_custom_packs: None,
            profile_policy_present: None,
            profile_hash: None,
        })
    }
}

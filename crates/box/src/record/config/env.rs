//! Which environment variable names a process may set, and which Core owns.

use std::path::Path;

use crate::EnvRefusal;
use crate::error::{BoxError, Internal};

/// Prefixes whose whole family loads code. See [`reserved_workload_environment`].
pub(super) const LOADER_HOOK_PREFIXES: [&str; 3] = ["LD_", "DYLD_", "PYTHON"];

/// The OTLP exporter family the box owns, by prefix. See [`reserved_workload_environment`].
pub(super) const OTLP_EXPORTER_PREFIX: &str = "OTEL_EXPORTER_OTLP_";

/// Exact names that make a runtime load code. See `reserved_workload_environment`.
pub(super) const LOADER_HOOKS: [&str; 10] = [
    "NODE_OPTIONS",
    "BASH_ENV",
    "ENV",
    "RUBYOPT",
    "PERL5LIB",
    "PERL5OPT",
    "GEM_PATH",
    "CLASSPATH",
    "JAVA_TOOL_OPTIONS",
    "_JAVA_OPTIONS",
];

/// Refuse an environment name the box cannot safely hand a phantom to.
pub(crate) fn checked_provisioned_name(host: &str, name: &str) -> Result<String, BoxError> {
    checked_provisioned_name_inner(host, name, true)
}

/// [`checked_provisioned_name`] without the value-presence check, for a strip-phantom route whose
/// real value the box never reads: it provisions a placeholder under `name` and strips it, so a
/// backend box with no destination token must still launch. The name itself is still validated.
pub(crate) fn checked_provisioned_name_without_value(
    host: &str,
    name: &str,
) -> Result<String, BoxError> {
    checked_provisioned_name_inner(host, name, false)
}

fn checked_provisioned_name_inner(
    host: &str,
    name: &str,
    require_value: bool,
) -> Result<String, BoxError> {
    if name.is_empty() {
        return Err(Internal::CredentialProjection(format!(
            "credential for {host} has an empty environment variable name"
        ))
        .into());
    }
    if !valid_environment_name(name) || reserved_workload_environment(name) || composed_over(name) {
        return Err(Internal::CredentialProjection(format!(
            "credential for {host} names invalid or reserved variable {name:?}"
        ))
        .into());
    }
    // Whitespace-only, not merely empty: `Bearer   ` on the wire fails at the upstream in a way an
    // operator reads as the box denying the call. It agrees with the vault's content rule.
    if require_value
        && std::env::var_os(name)
            .is_none_or(|value| value.to_str().is_none_or(|value| value.trim().is_empty()))
    {
        return Err(Internal::CredentialProjection(format!(
            "credential variable {name} is not set, or holds only whitespace"
        ))
        .into());
    }
    Ok(name.to_string())
}

/// Whether the composed environment writes `name` above every phantom, so a phantom there is lost.
fn composed_over(name: &str) -> bool {
    matches!(name, "HOME" | "PATH")
}

/// Whether a credential phantom may not claim `name`: a loader hook, or a name Core sets itself.
///
/// `HOME`, `PATH`, and `TMPDIR` are the operator's: Core supplies a default for the first two and
/// prepends the alias directory to `PATH`, and it reserves none of them.
pub(crate) fn reserved_workload_environment(name: &str) -> bool {
    loader_hook(name) || box_owned_environment(name)
}

/// Whether `name` makes a runtime load code before the workload's first line.
fn loader_hook(name: &str) -> bool {
    LOADER_HOOK_PREFIXES
        .iter()
        .any(|prefix| name.starts_with(prefix))
        || LOADER_HOOKS.contains(&name)
}

/// Whether the dynamic loader reads `name`.
fn dynamic_loader_environment(name: &str) -> bool {
    name.starts_with("LD_") || name.starts_with("DYLD_")
}

/// Whether Core sets `name` itself, so neither a credential nor a `ProcessSpec` may claim it.
fn box_owned_environment(name: &str) -> bool {
    if name.starts_with(OTLP_EXPORTER_PREFIX) {
        return true;
    }

    matches!(
        name,
        "HTTP_PROXY"
            | "HTTPS_PROXY"
            | "http_proxy"
            | "https_proxy"
            | "NO_PROXY"
            | "no_proxy"
            | "SSL_CERT_FILE"
            | "NODE_EXTRA_CA_CERTS"
            | "NODE_USE_ENV_PROXY"
            | "CODEX_CA_CERTIFICATE"
            // `botocore` reads this one and not `SSL_CERT_FILE`, and `requests` and `httpx` read
            // the next. The box sets both, so both are box-owned.
            | "AWS_CA_BUNDLE"
            | "REQUESTS_CA_BUNDLE"
            // Apple `git`'s libcurl reads this one and none of the others.
            | "GIT_SSL_CAINFO"
            | "PWD"
            | "USER"
    )
}

/// Why a process table's `env` refuses the name `name`, whatever its value.
pub(crate) fn refused_name(name: &str) -> Option<EnvRefusal> {
    if !valid_environment_name(name) {
        return Some(EnvRefusal::InvalidName);
    }
    if box_owned_environment(name) {
        return Some(EnvRefusal::SetByBox);
    }
    dynamic_loader_environment(name).then_some(EnvRefusal::LoadsCode)
}

/// Why a process table's `env` refuses `value` for the name `name`.
pub(crate) fn refused_value(name: &str, value: &str) -> Option<EnvRefusal> {
    (matches!(name, "HOME" | "TMPDIR") && !Path::new(value).is_absolute())
        .then_some(EnvRefusal::NotAbsolute)
}

/// The reason a process table states for a refused `env` entry.
pub(crate) fn refusal_reason(kind: EnvRefusal, name: &str, value: &str) -> String {
    match kind {
        EnvRefusal::InvalidName => {
            format!("`env` name {name:?} is not a valid environment-variable name")
        }
        EnvRefusal::SetByBox => {
            format!("`env` name {name:?} is set by the box itself, so a table cannot claim it")
        }
        EnvRefusal::LoadsCode => format!(
            "`env` name {name:?} is read by the dynamic loader of every program in the box, Box's \
             own aliases included, so a table cannot set it"
        ),
        EnvRefusal::NotAbsolute => format!("`env.{name}` must be an absolute path: {value:?}"),
    }
}

pub(crate) fn valid_environment_name(name: &str) -> bool {
    let mut bytes = name.bytes();
    bytes
        .next()
        .is_some_and(|byte| byte == b'_' || byte.is_ascii_alphabetic())
        && bytes.all(|byte| byte == b'_' || byte.is_ascii_alphanumeric())
}

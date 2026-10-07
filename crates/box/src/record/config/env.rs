//! Which environment variable names a process may set, and which Core owns.
//!
//! Two independent concerns ask the same question: a `ProcessSpec`'s `env` asks it of an operator's
//! own variable, and a credential's `env://` locator asks it of a phantom the box mints. Both must
//! refuse a name that makes a runtime load code, and both must refuse a name Core sets itself.

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
    // operator reads as the box denying the call. It agrees with the vault's content rule
    if std::env::var_os(name)
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

/// Whether Core sets `name` itself, so neither a credential nor a `ProcessSpec` may claim it.
///
/// `HOME`, `PATH`, and `TMPDIR` are the operator's: Core supplies a default for the first two and
/// prepends the alias directory to `PATH`, and it reserves none of them.
pub(crate) fn reserved_workload_environment(name: &str) -> bool {
    // Loader hooks first, because they are a different kind of refusal: the names below are
    // box-owned routing, while these make a runtime load code before the workload's first line.
    if LOADER_HOOK_PREFIXES
        .iter()
        .any(|prefix| name.starts_with(prefix))
        || LOADER_HOOKS.contains(&name)
    {
        return true;
    }

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

pub(crate) fn valid_environment_name(name: &str) -> bool {
    let mut bytes = name.bytes();
    bytes
        .next()
        .is_some_and(|byte| byte == b'_' || byte.is_ascii_alphabetic())
        && bytes.all(|byte| byte == b'_' || byte.is_ascii_alphanumeric())
}

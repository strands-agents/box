//! Resolving a *named* AWS profile, so `aws://<profile>` signs as the identity it names.
//!
//! **Why this exists.** `EnvAwsProvider` reads `AWS_*` from the daemon's environment and refuses a
//! named profile rather than substituting the ambient identity — an operator who names an identity
//! gets that identity or an error. That refusal was correct and complete: it left
//! `aws://<profile>` with no provider that could honour it, so every such route failed at the first
//! request. Measured 2026-08-19 with a Codex workload: `credential denied: … the ambient AWS
//! provider cannot sign as the declared profile "codex-DO-NOT-DELETE"`, which reached the workload as
//! `403 blocked by egress control` and named nothing.
//!
//! This module closes that gap behind the existing vocabulary. `aws://<profile>` was already a
//! documented spelling that `box.toml` already parses; nothing here adds an operator-facing surface.
//!
//! **Static keys only. Every other shape is refused by name.**
//!
//! `credential_process` was supported for part of one day and is now refused, because honouring it
//! means the daemon executes a program named by `~/.aws/config`. No floor defends that file, and when
//! the project is the operator's home the starter policy's own `fs:write` rule reaches it — so an
//! agent write became daemon code execution outside containment. Separately, the daemon's environment
//! is the storage for every `env://` route, so an inherited environment handed the helper every
//! opaque secret the box held. Refusing the shape removes both at once.
//!
//! A profile that assumes a role or uses SSO needs an HTTP call to STS, and this crate holds no HTTP
//! client, so those refuse with the setting that caused it rather than falling back to an identity the
//! operator did not name.

use std::path::PathBuf;

use zeroize::Zeroizing;

use crate::AwsSessionCredentials;
use crate::{CredentialError, Result};

/// Resolve `profile` from the operator's AWS configuration.
///
/// Returns the credentials the profile names, or an error naming what stopped it. Never falls back to
/// the ambient identity: that would sign as one principal while the audit record attests another.
pub(crate) fn resolve_profile(profile: &str) -> Result<AwsSessionCredentials> {
    choose(profile, profile_settings(profile)?)
}

/// Decide what a profile's settings mean, separately from finding them.
///
/// **Split out so the decision is testable without a filesystem.** This crate carries no `tempfile`
/// dev-dependency and its dependency list is deliberately six crates wide, so a test that needed one
/// would be a dependency added for a test's convenience.
fn choose(profile: &str, settings: Settings) -> Result<AwsSessionCredentials> {
    // **`credential_process` is refused, and that refusal is the security boundary.** Honouring it
    // means the daemon executes a program named by `~/.aws/config` — a file no floor defends and, when
    // the project is the operator's home, one the starter policy's own `fs:write` rule reaches. That
    // turns an operator configuration file into daemon code execution outside containment, at the
    // operator's UID, which is the outcome `box/AGENTS.md`'s "never execute a workload-named program
    // from the daemon" rule exists to prevent. The MCP spawn path carries four guards for the same
    // act — a self-defended declaring file, a refusal for an undeclared name, a `shell:spawn`
    // decision, and a cleared environment — and none of them exist here.
    //
    // A second reason, independent of any write: the daemon's own environment **is** the storage for
    // every `env://` route, so an inherited environment hands the helper every opaque secret the box
    // holds. Clearing it would fix that one and leave the exec path.
    //
    // So the shape is refused rather than guarded. Static keys need no subprocess at all.
    if let Some(command) = settings.get("credential_process") {
        return Err(CredentialError::Credential(format!(
            "AWS profile {profile:?} uses credential_process, which this box does not run: it would \
             execute {command:?} from the daemon, outside containment. Use a profile with static keys, \
             or export AWS_BEARER_TOKEN_BEDROCK and bind that instead"
        )));
    }
    // **A role-assuming or SSO shape is refused BEFORE the static keys are read, and the order is
    // the whole point.** This check sat *after* the `aws_access_key_id` branch, so a profile
    // carrying both — which is the ordinary shape, because `role_arn` needs source credentials to
    // sign the `AssumeRole` call with — resolved to the source keys and signed every request as the
    // **base user** instead of the role.
    //
    // That is a wrong-identity failure, not a missing feature. The operator named a role; the box
    // used a different principal and the audit record attested the one it used. A role is normally
    // *narrower* than the user it is assumed from, so the request went out with more authority than
    // the operator asked for, and silently.
    //
    // `source_profile` is in the list because it is what makes the pair ordinary: botocore's
    // documented self-referencing form puts `role_arn`, `source_profile = <itself>`, and the static
    // keys in one section.
    //
    // Refusing by shape mirrors `credential_process` directly above. This crate holds no HTTP
    // client, so it cannot call STS, and there is no correct answer to fall back to.
    if let Some(setting) = unsupported_setting(&settings) {
        return Err(CredentialError::Credential(format!(
            "AWS profile {profile:?} declares {setting}, so it names an identity this box cannot \
             assume: resolving it needs an STS call and this crate holds no HTTP client. Any static \
             keys in that profile are the *source* credentials for the AssumeRole, not the identity \
             you asked for, so they are refused rather than used. Use a profile whose static keys are \
             the identity itself, or export AWS_BEARER_TOKEN_BEDROCK and bind that instead"
        )));
    }
    if settings.contains_key("aws_access_key_id") {
        return static_credentials(profile, settings);
    }
    Err(CredentialError::Credential(format!(
        "AWS profile {profile:?} declares no static keys and no identity this box can resolve"
    )))
}

/// The setting that names an identity this crate cannot resolve, if the profile declares one.
///
/// **Returns the setting rather than a message fragment, because the caller now REFUSES on it** —
/// it used to build a parenthetical for an error the caller had already decided to return. That
/// difference is what let a `role_arn` profile with source keys through.
///
/// Each entry needs a call this crate cannot make: `sso_session` and `sso_start_url` need the SSO
/// token endpoints, `role_arn` and `source_profile` need `AssumeRole`, and
/// `web_identity_token_file` needs `AssumeRoleWithWebIdentity`. All are HTTP, and this crate holds
/// no HTTP client — a deliberate constraint, since its dependency list is six crates wide.
fn unsupported_setting(settings: &Settings) -> Option<&'static str> {
    [
        "sso_session",
        "sso_start_url",
        "role_arn",
        "source_profile",
        "web_identity_token_file",
    ]
    .into_iter()
    .find(|name| settings.get(*name).is_some())
}

/// Build credentials from a profile's static keys, **moving** them out of `settings`.
///
/// **`remove`, not `get().cloned()`, so no un-wiped copy is left behind.** `profile_settings` wraps the
/// file text in `Zeroizing` and says why: this crate's rule is that the daemon's memory hardening
/// "stops a read, never a copy". But `section_of` then copied each value into a plain `String` in the
/// map, and cloning from there made a *second* plain copy — so the wrapper protected the file text
/// while two unprotected copies of the secret access key sat beside it.
///
/// Taking `settings` by value and `remove`-ing each key moves the `String` straight into
/// `AwsSessionCredentials`, which implements `Zeroize` and wipes on drop. The map keeps only its
/// non-secret entries. No `Deref` laundering, and nothing to remember to wrap.
///
/// Honest framing: the same plaintext already sits in `~/.aws/credentials` at the same UID, so this is
/// doctrine consistency rather than a new disclosure path — and the doctrine in `credentials/AGENTS.md`
/// is that it is "not a reason to leave a *new* un-wiped copy on this path".
fn static_credentials(profile: &str, mut settings: Settings) -> Result<AwsSessionCredentials> {
    let mut required = |name: &str| -> Result<String> {
        settings.remove(name).ok_or_else(|| {
            CredentialError::Credential(format!(
                "AWS profile {profile:?} declares aws_access_key_id but not {name}"
            ))
        })
    };
    Ok(AwsSessionCredentials {
        access_key_id: required("aws_access_key_id")?,
        secret_access_key: required("aws_secret_access_key")?,
        session_token: settings.remove("aws_session_token"),
        // Not secret, so a move is only for consistency: the closure above holds a mutable
        // borrow, and `remove` avoids reasoning about when it ends.
        region: settings.remove("region"),
    })
}

// ═══════════════════════════════════════════════════════════════════════════════
// The AWS configuration files
// ═══════════════════════════════════════════════════════════════════════════════

/// One profile's settings, merged across both files.
type Settings = std::collections::BTreeMap<String, String>;

/// Read `profile`'s settings from `~/.aws/credentials` then `~/.aws/config`.
///
/// **The credentials file is read first and wins**, matching every AWS SDK: it is the file that holds
/// keys, and `config` holds everything else. A profile absent from both is an error naming both paths,
/// because "profile not found" without them sends an operator looking in the wrong place.
fn profile_settings(profile: &str) -> Result<Settings> {
    let credentials_path = path_from_env("AWS_SHARED_CREDENTIALS_FILE", ".aws/credentials")?;
    let config_path = path_from_env("AWS_CONFIG_FILE", ".aws/config")?;

    let mut settings = Settings::new();
    // `config` first, then `credentials` over the top, so the credentials file wins on a collision.
    for (path, section) in [
        (&config_path, format!("profile {profile}")),
        (&credentials_path, profile.to_string()),
    ] {
        // **Wiped on drop, because `~/.aws/credentials` holds a secret access key.** The crate's rule
        // is that the daemon's memory hardening "stops a read, never a copy", so a plain `String` of
        // this file would be one un-wiped copy per resolve.
        if let Ok(text) = std::fs::read_to_string(path).map(Zeroizing::new) {
            // In `credentials` the default profile has no `profile ` prefix, and in `config` a
            // non-default one does. Both spellings are tried so `aws://default` resolves too.
            for candidate in [section.as_str(), profile] {
                if let Some(found) = section_of(&text, candidate) {
                    settings.extend(found);
                    break;
                }
            }
        }
    }

    if settings.is_empty() {
        return Err(CredentialError::Credential(format!(
            "AWS profile {profile:?} is not declared in {} or {}",
            config_path.display(),
            credentials_path.display()
        )));
    }
    Ok(settings)
}

/// A path from `variable`, or `~/<fallback>`.
fn path_from_env(variable: &str, fallback: &str) -> Result<PathBuf> {
    if let Some(value) = std::env::var_os(variable).filter(|v| !v.is_empty()) {
        return Ok(PathBuf::from(value));
    }
    let home = std::env::var_os("HOME")
        .filter(|v| !v.is_empty())
        .ok_or_else(|| {
            CredentialError::Credential(format!(
                "cannot locate the AWS configuration: HOME is unset and {variable} is not set"
            ))
        })?;
    Ok(PathBuf::from(home).join(fallback))
}

/// The `key = value` pairs of one INI section, or `None` when the section is absent.
///
/// Deliberately minimal: sections in brackets, `#` and `;` comments, `key = value` with both sides
/// trimmed. Nested sub-sections — the indented form SSO uses — are skipped rather than flattened,
/// because flattening would let a sub-section's `region` masquerade as the profile's.
fn section_of(text: &str, wanted: &str) -> Option<Settings> {
    let mut inside = false;
    let mut found = Settings::new();
    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with(';') {
            continue;
        }
        if let Some(name) = trimmed
            .strip_prefix('[')
            .and_then(|rest| rest.strip_suffix(']'))
        {
            inside = name.trim() == wanted;
            continue;
        }
        // An indented line carrying no `=` is a sub-section header, not a profile setting.
        if inside && line.starts_with(char::is_whitespace) && !trimmed.contains('=') {
            continue;
        }
        if let (true, Some((key, value))) = (inside, trimmed.split_once('=')) {
            found.insert(key.trim().to_ascii_lowercase(), value.trim().to_string());
        }
    }
    inside
        .then_some(())
        .or(if found.is_empty() { None } else { Some(()) })?;
    Some(found)
}

#[cfg(test)]
#[path = "aws_profile_tests.rs"]
mod tests;

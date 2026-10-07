//! Tests for named-profile resolution.
//!
//! Every case drives the parsing and the choice directly, with no filesystem: `choose` takes a
//! `Settings` map so the decision is testable without a `tempfile` dev-dependency. This crate's
//! dependency list is deliberately six crates wide.
//!
//! There is no `credential_process` execution to test. It is refused by shape, and two cases below
//! pin that refusal — one for a profile declaring it alone, one for a profile declaring it beside
//! static keys. An earlier version of this header described a `capture` helper that ran `/bin/echo`;
//! that helper went with the feature.

use super::*;

/// A profile with static keys resolves to exactly those keys.
#[test]
fn static_keys_resolve() {
    let text = "[profile work]\n\
                aws_access_key_id = AKIAEXAMPLE\n\
                aws_secret_access_key = secretvalue\n\
                aws_session_token = tokenvalue\n\
                region = us-east-2\n";
    let settings = section_of(text, "profile work").expect("the section exists");
    let resolved = static_credentials("work", settings).expect("static keys resolve");

    assert_eq!(resolved.access_key_id, "AKIAEXAMPLE");
    assert_eq!(resolved.secret_access_key, "secretvalue");
    assert_eq!(resolved.session_token.as_deref(), Some("tokenvalue"));
    assert_eq!(resolved.region.as_deref(), Some("us-east-2"));
}

/// A key id with no secret is refused, naming the missing setting.
///
/// The alternative is signing with an empty secret, which fails at AWS as
/// `SignatureDoesNotMatch` — an opaque error for a config mistake this can name.
#[test]
fn a_key_id_without_its_secret_is_refused() {
    let settings = section_of(
        "[profile work]\naws_access_key_id = AKIAEXAMPLE\n",
        "profile work",
    )
    .expect("the section exists");
    let error = static_credentials("work", settings).expect_err("an incomplete pair is refused");
    assert!(
        error.to_string().contains("aws_secret_access_key"),
        "the message must name what is missing: {error}"
    );
}

/// **A section that is absent yields `None`, and an empty one does not masquerade as it.**
#[test]
fn an_absent_section_is_distinguishable_from_an_empty_one() {
    let text = "[profile empty]\n\n[profile full]\nregion = us-east-2\n";
    assert!(section_of(text, "profile missing").is_none());
    assert_eq!(
        section_of(text, "profile full")
            .expect("present")
            .get("region"),
        Some(&"us-east-2".to_string())
    );
}

/// Comments and case are handled the way every AWS SDK handles them.
#[test]
fn comments_are_skipped_and_keys_are_lowercased() {
    let text = "[profile work]\n\
                # a hash comment\n\
                ; a semicolon comment\n\
                AWS_Access_Key_Id = AKIAEXAMPLE\n";
    let settings = section_of(text, "profile work").expect("the section exists");
    assert_eq!(
        settings.get("aws_access_key_id"),
        Some(&"AKIAEXAMPLE".to_string()),
        "a key must match whatever case the operator wrote"
    );
}

/// A profile this crate cannot resolve is refused, and the refusal names the setting that caused it.
///
/// Asserted through `choose` rather than through the helper, because the helper's *return* stopped
/// being a message fragment and became the refusal decision itself. A test on the fragment could not
/// have caught the ordering defect below.
#[test]
fn an_sso_profile_is_refused_by_name() {
    let settings = section_of(
        "[profile work]\nsso_session = corp\nregion = us-east-2\n",
        "profile work",
    )
    .expect("the section exists");
    let error = choose("work", settings).expect_err("an SSO profile must be refused");
    assert!(
        error.to_string().contains("sso_session"),
        "the refusal must name the setting: {error}"
    );
}

/// **A role-assuming profile carrying its own source keys is refused, not resolved as the base user.**
///
/// This is the ordinary shape, not an exotic one: `role_arn` needs source credentials to sign the
/// `AssumeRole` call, and botocore documents a self-referencing form that puts `role_arn`,
/// `source_profile = <itself>`, and the static keys in one section.
///
/// The shape check used to sit *after* the `aws_access_key_id` branch, so this profile resolved to
/// the source keys and every request signed as the **base user** instead of the role. A role is
/// normally narrower than the user it is assumed from, so the box sent more authority than the
/// operator asked for, and the audit record attested the principal it used rather than the one named.
#[test]
fn a_role_profile_with_source_keys_is_refused_rather_than_signed_as_the_base_user() {
    let settings = section_of(
        "[profile work]\n\
         role_arn = arn:aws:iam::123456789012:role/Narrow\n\
         source_profile = work\n\
         aws_access_key_id = AKIAEXAMPLE\n\
         aws_secret_access_key = secretvalue\n",
        "profile work",
    )
    .expect("the section exists");

    let error = choose("work", settings)
        .expect_err("a role profile must not resolve to its source credentials");
    let message = error.to_string();
    assert!(
        message.contains("role_arn") || message.contains("source_profile"),
        "the refusal must name the setting that caused it: {message}"
    );
    assert!(
        message.contains("source"),
        "the refusal must say the static keys are the SOURCE credentials, or it reads as an \
         unimplemented feature: {message}"
    );
    assert!(
        !message.contains("AKIAEXAMPLE") && !message.contains("secretvalue"),
        "the refusal must not echo the credentials it declined to use: {message}"
    );
}

/// The paired positive: a profile whose static keys ARE the identity still resolves.
///
/// Without it, the refusal above could be satisfied by refusing every profile.
#[test]
fn a_profile_whose_static_keys_are_the_identity_still_resolves() {
    let settings = section_of(
        "[profile work]\n\
         aws_access_key_id = AKIAEXAMPLE\n\
         aws_secret_access_key = secretvalue\n",
        "profile work",
    )
    .expect("the section exists");
    let resolved = choose("work", settings).expect("plain static keys still resolve");
    assert_eq!(resolved.access_key_id, "AKIAEXAMPLE");
}

// ── credential_process is refused ────────────────────────────────────────────

/// **`credential_process` is refused, and the refusal names the command it would have run.**
///
/// Honouring it means the daemon executes a program named by `~/.aws/config`. No floor defends that
/// file, and when the project is the operator's home the starter policy's own `fs:write` rule reaches
/// it — so an agent write became daemon code execution outside containment, at the operator's UID.
/// A second reason, needing no write at all: the daemon's environment is the storage for every
/// `env://` route, so an inherited environment handed the helper every opaque secret the box held.
///
/// It was supported for part of one day. Refusing the shape removes both problems; clearing the
/// environment would have fixed only the second.
#[test]
fn a_credential_process_profile_is_refused() {
    let settings = section_of(
        "[profile work]\ncredential_process = /bin/sh -c 'echo pwned'\n",
        "profile work",
    )
    .expect("the section exists");

    let error = choose("work", settings).expect_err("credential_process must be refused");
    let message = error.to_string();
    assert!(
        message.contains("credential_process"),
        "the refusal must name the setting: {message}"
    );
    assert!(
        message.contains("outside containment"),
        "the refusal must say why, or it reads as an unimplemented feature: {message}"
    );
    // The operator needs a way forward, not just a no.
    assert!(
        message.contains("static keys") && message.contains("AWS_BEARER_TOKEN_BEDROCK"),
        "the refusal must name both working alternatives: {message}"
    );
}

/// **A profile carrying BOTH shapes is still refused, and the reason is the exec one.**
///
/// The paired case. Preferring the static keys would silently honour a profile that also asks for a
/// subprocess, so an operator who believes `credential_process` runs would be wrong about what signed
/// their request.
#[test]
fn both_shapes_present_still_refuses() {
    let settings = section_of(
        "[profile work]\n\
         aws_access_key_id = AKIAEXAMPLE\n\
         aws_secret_access_key = secretvalue\n\
         credential_process = /bin/echo hello\n",
        "profile work",
    )
    .expect("the section exists");

    assert!(
        choose("work", settings).is_err(),
        "a profile asking for a subprocess must not be silently resolved from its static keys"
    );
}

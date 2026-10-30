//! SDK provider checks in processes with isolated AWS configuration.

use std::path::PathBuf;
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

use super::SdkCredentials;

const CHILD: &str = "BOX_SDK_PROFILE_TEST";
const STATIC: &str = "aws_access_key_id = AKIASELECTED\naws_secret_access_key = selected-secret\n";

struct Fixture(PathBuf);

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn check(case: &str, settings: &str) {
    let fixture = Fixture(std::env::temp_dir().join(format!(
        "box-sdk-{}-{}-{case}",
        std::process::id(),
        SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos()
    )));
    std::fs::create_dir(&fixture.0).unwrap();
    let config = fixture.0.join("config");
    let credentials = fixture.0.join("credentials");
    std::fs::write(
        &config,
        format!(
            "[profile selected]\nregion = us-east-1\n{settings}\n\
             [profile other]\naws_access_key_id = AKIAOTHER\naws_secret_access_key = other-secret\n"
        ),
    )
    .unwrap();
    std::fs::write(&credentials, "").unwrap();
    let output = Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "sources::prototype_aws_sdk::tests::isolated_provider",
            "--nocapture",
        ])
        .env_clear()
        .env(CHILD, case)
        .env("HOME", &fixture.0)
        .env("PATH", "/usr/bin:/bin")
        .env("AWS_CONFIG_FILE", config)
        .env("AWS_SHARED_CREDENTIALS_FILE", credentials)
        .env("AWS_PROFILE", "other")
        .env("AWS_REGION", "us-east-1")
        .env("AWS_EC2_METADATA_DISABLED", "true")
        .env("AWS_ACCESS_KEY_ID", "AKIAENVIRONMENT")
        .env("AWS_SECRET_ACCESS_KEY", "environment-secret")
        .output()
        .unwrap();
    assert!(
        !String::from_utf8_lossy(&output.stdout).contains("HELPER-ERROR-SECRET")
            && !String::from_utf8_lossy(&output.stderr).contains("HELPER-ERROR-SECRET"),
        "{case}: helper stderr escaped the provider"
    );
    assert!(
        output.status.success(),
        "{case}: {}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn isolated_provider() {
    let Ok(case) = std::env::var(CHILD) else {
        return;
    };
    let selection = match case.as_str() {
        "chain" => None,
        "missing" => Some("missing".to_string()),
        _ => Some("selected".to_string()),
    };
    let provider = SdkCredentials::open(selection).unwrap();
    for _ in 0..2 {
        let result = provider.resolve();
        match case.as_str() {
            "chain" => assert_eq!(result.unwrap().access_key_id, "AKIAENVIRONMENT"),
            "static" | "helper" => {
                let credentials = result.unwrap();
                assert_eq!(credentials.access_key_id, "AKIASELECTED");
                assert_eq!(credentials.secret_access_key, "selected-secret");
            }
            _ => {
                let error = result.unwrap_err().to_string();
                assert!(!error.contains("selected-secret"));
                assert!(!error.contains("environment-secret"));
                assert!(!error.contains("HELPER-ERROR-SECRET"));
            }
        }
    }
    if case == "helper" {
        assert_eq!(
            std::fs::read_to_string(
                PathBuf::from(std::env::var_os("HOME").unwrap()).join("helper-calls")
            )
            .unwrap(),
            "xx"
        );
    }
}

#[test]
fn a_profile_whose_static_keys_are_the_identity_still_resolves() {
    check("static", STATIC);
}

#[test]
fn the_default_chain_prefers_environment_credentials() {
    check("chain", STATIC);
}

#[test]
fn an_absent_profile_does_not_fall_back_to_environment_or_another_profile() {
    check("missing", STATIC);
}

#[test]
fn a_key_id_without_its_secret_is_refused() {
    check("incomplete", "aws_access_key_id = AKIASELECTED\n");
}

#[test]
fn a_role_profile_with_source_keys_is_refused_rather_than_signed_as_the_base_user() {
    check(
        "role",
        &format!(
            "{STATIC}role_arn = arn:aws:iam::123456789012:role/Narrow\nsource_profile = missing\n"
        ),
    );
}

#[test]
fn an_incomplete_sso_profile_does_not_fall_back() {
    check("sso", "sso_session = missing\n");
}

#[cfg(unix)]
#[test]
fn a_credential_process_profile_uses_the_sdk_runner() {
    check(
        "helper",
        "credential_process = printf x >> \"$HOME/helper-calls\"; printf '%s' '{\"Version\":1,\"AccessKeyId\":\"AKIASELECTED\",\"SecretAccessKey\":\"selected-secret\"}'\n",
    );
}

#[cfg(unix)]
#[test]
fn a_failed_helper_does_not_fall_back_or_expose_stderr() {
    check(
        "failed-helper",
        "credential_process = echo HELPER-ERROR-SECRET >&2; exit 1\n",
    );
}

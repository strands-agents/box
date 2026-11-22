use crate::support::*;

#[test]
fn a_kiro_run_brings_in_the_model_but_not_the_engine_and_turns_off_updates_and_the_trust_all_question()
 {
    let host = FakeHost::new();
    host.profile()
        .with("kiro")
        .create()
        .expect("a profile")
        .write(false)
        .expect("a write");
    let settings = host.home().join(".kiro/settings");
    std::fs::create_dir_all(&settings).expect("a folder");
    std::fs::write(
        settings.join("cli.json"),
        serde_json::json!({
            "chat.agentEngine": "v2",
            "chat.defaultModel": "auto",
            "chat.enableContextUsageIndicator": true,
            "chat.defaultAgent": "team-agent",
            "mcp.loadedBefore": true,
        })
        .to_string(),
    )
    .expect("settings");
    host.launcher()
        .prepare("kiro", &host.project(), None)
        .expect("a launch");
    let copy = storage_root(&host.home().join(".strands/box"), "kiro")
        .join("agent/home/.kiro/settings/cli.json");
    let copied: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(copy).expect("read")).expect("JSON");
    assert_eq!(
        copied,
        serde_json::json!({
            "chat.defaultModel": "auto",
            "chat.enableContextUsageIndicator": true,
            "app.disableAutoupdates": true,
            "chat.disableTrustAllConfirmation": true,
        })
    );
}

#[test]
fn a_kiro_run_puts_the_box_guidance_beside_the_hosts_steering() {
    let host = FakeHost::new();
    host.profile()
        .with("kiro")
        .create()
        .expect("a profile")
        .write(false)
        .expect("a write");
    let steering = host.home().join(".kiro/steering");
    std::fs::create_dir_all(&steering).expect("a folder");
    std::fs::write(steering.join("style.md"), "Use short names.\n").expect("steering");
    host.launcher()
        .prepare("kiro", &host.project(), None)
        .expect("a launch");
    let copy =
        storage_root(&host.home().join(".strands/box"), "kiro").join("agent/home/.kiro/steering");
    let guidance = std::fs::read_to_string(copy.join("box.md")).expect("the guidance");
    assert!(
        guidance.starts_with("---\ninclusion: always\n---\n\n# You run in a box\n"),
        "{guidance}"
    );
    assert!(guidance.contains(SHELL_NOTE), "{guidance}");
    assert!(guidance.contains(OUTSIDE_FILES_NOTE), "{guidance}");
    assert!(guidance.contains(RESTART_NOTE), "{guidance}");
    assert!(guidance.contains(DNS_NOTE), "{guidance}");
    for line in [
        "`echo \"$BOX_PROFILE\"`",
        "## Programs you install",
        "[tool.jq]",
    ] {
        assert!(guidance.contains(line), "{line}: {guidance}");
    }
    assert_eq!(
        std::fs::read_to_string(copy.join("host/style.md")).expect("the host's steering"),
        "Use short names.\n"
    );
}

fn kiro(host: &FakeHost) -> Trial {
    host.trial().with("kiro").option("kiro.sign-in", "api-key")
}

#[test]
fn a_kiro_box_runs_its_runtime_from_a_host_folder_it_cannot_write() {
    let host = FakeHost::new();
    let shared = host.home().join("kiro-runtime");
    for (trial, runtime) in [
        (kiro(&host), host.home().join(".kiro-runtime")),
        (
            kiro(&host).variable("KIRO_RUNTIME_DIR", shared.display().to_string()),
            shared.clone(),
        ),
    ] {
        let generated = trial.generate().expect("a configuration");
        let file: toml::Value = toml::from_str(generated.box_toml()).expect("TOML");
        let agent = &file["agent"];
        let runtime = runtime.display().to_string();
        assert_eq!(
            agent["env"]["KIRO_RUNTIME_DIR"].as_str(),
            Some(runtime.as_str())
        );
        let home = generated.storage().join("agent/home").display().to_string();
        assert_eq!(agent["env"]["HOME"].as_str(), Some(home.as_str()));
        let filesystem = agent["filesystem"].as_table().expect("filesystem");
        for list in ["read", "exec"] {
            assert!(
                string_list(filesystem.get(list)).contains(&runtime),
                "{list}: {filesystem:?}"
            );
        }
        let tmp = generated.storage().join("agent/tmp").display().to_string();
        assert_eq!(agent["env"]["TMPDIR"].as_str(), Some(tmp.as_str()));
        let shell = agent["env"]["SHELL"].as_str().expect("SHELL");
        assert!(shell.ends_with("/box/bin/bash"), "{shell}");
        for switch in [
            "KIRO_DISABLE_TELEMETRY",
            "KIRO_DISABLE_TOOLKIT_TELEMETRY",
            "KIRO_NO_AUTO_UPDATE",
            "KIRO_NO_REMOTE_CHANGELOG",
        ] {
            assert_eq!(agent["env"][switch].as_str(), Some("1"), "{switch}");
        }
        assert_eq!(
            file["egress"]["kiro"]["secret"]["phantom_prefix"].as_str(),
            Some("ksk_")
        );
        assert_eq!(
            string_list(file["egress"]["kiro"].get("destinations")),
            [
                "management.us-east-1.kiro.dev",
                "runtime.us-east-1.kiro.dev"
            ]
        );
        assert_eq!(
            file["egress"]["kiro"]["secret"]["ref"].as_str(),
            Some("env://KIRO_API_KEY")
        );
    }
}

#[test]
fn a_kiro_box_reads_the_system_library_folders_on_linux_only() {
    let host = FakeHost::new();
    let folders = ["/lib", "/usr/lib", "/lib64", "/usr/lib64"];
    for os in ["linux", "macos"] {
        let generated = kiro(&host).os(os).generate().expect("a configuration");
        let file: toml::Value = toml::from_str(generated.box_toml()).expect("TOML");
        let read = string_list(file["agent"]["filesystem"].get("read"));
        // The box resolves links, so on a host where /lib links to usr/lib the two are one entry.
        for folder in folders {
            let Ok(resolved) = std::fs::canonicalize(folder) else {
                continue;
            };
            let resolved = resolved.display().to_string();
            assert_eq!(
                read.contains(&resolved),
                os == "linux",
                "{os} {folder}: {read:?}"
            );
        }
    }
}

#[test]
fn a_kiro_box_names_its_profile_for_the_guidance() {
    let host = FakeHost::new();
    let generated = kiro(&host).generate().expect("a configuration");
    let file: toml::Value = toml::from_str(generated.box_toml()).expect("TOML");
    let profile = profiles_root(&host.home().join(".strands/box")).join("kiro");
    assert_eq!(
        file["agent"]["env"]["BOX_PROFILE"].as_str(),
        profile.to_str()
    );
}

#[test]
fn kiro_starts_on_v3_and_skip_permissions_starts_its_chat_with_trust_all_tools() {
    let host = FakeHost::new();
    let binary = host
        .home()
        .join(".local/bin/kiro-cli")
        .display()
        .to_string();
    let command = agent_command(
        &kiro(&host)
            .agent_args(&["chat", "--no-interactive", "hi"])
            .generate()
            .expect("a configuration"),
    );
    assert_eq!(
        command,
        [
            binary.clone(),
            "--v3".into(),
            "chat".into(),
            "--no-interactive".into(),
            "hi".into()
        ]
    );
    let command = agent_command(
        &kiro(&host)
            .option("agent.skip-permissions", "true")
            .agent_args(&["--no-interactive", "hi"])
            .generate()
            .expect("a configuration"),
    );
    assert_eq!(
        command,
        [
            binary,
            "--v3".into(),
            "chat".into(),
            "--trust-all-tools".into(),
            "--no-interactive".into(),
            "hi".into()
        ]
    );
}

#[test]
fn a_kiro_login_profile_opens_the_login_hosts_with_no_credential_and_an_api_key_one_does_not() {
    let host = FakeHost::new();
    let generated = host
        .trial()
        .with("kiro")
        .generate()
        .expect("a configuration");
    let file: toml::Value = toml::from_str(generated.box_toml()).expect("TOML");
    assert!(file.get("egress").is_none(), "{}", generated.box_toml());
    for login in [
        "oidc.us-east-1.amazonaws.com",
        "management.us-east-1.kiro.dev",
        "runtime.us-east-1.kiro.dev",
    ] {
        assert!(
            generated
                .policy()
                .contains(&format!(r#"context.input.host == "{login}""#)),
            "{login}: {}",
            generated.policy()
        );
    }
    let keyed = kiro(&host).generate().expect("a configuration");
    assert!(
        !keyed.policy().contains("oidc.us-east-1.amazonaws.com"),
        "{}",
        keyed.policy()
    );
}

#[test]
fn the_next_steps_of_a_kiro_profile_name_its_key_for_both_hosts() {
    let host = FakeHost::new();
    let steps = host
        .profile()
        .with("kiro")
        .option("kiro.sign-in", "api-key")
        .create()
        .expect("a profile")
        .next_steps(false);
    assert!(
        steps.contains(
            "  1. Put the key for management.us-east-1.kiro.dev and runtime.us-east-1.kiro.dev \
             in KIRO_API_KEY.\n  2. Start Kiro CLI in the box"
        ),
        "{steps}"
    );
}

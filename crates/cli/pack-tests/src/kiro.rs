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

/// Writes a host agent whose file names a hook and an MCP server, and a `cli.json` that names it
/// as the default agent.
fn write_host_agent(host: &FakeHost) {
    let kiro_home = host.home().join(".kiro");
    std::fs::create_dir_all(kiro_home.join("agents")).expect("a folder");
    std::fs::create_dir_all(kiro_home.join("settings")).expect("a folder");
    std::fs::write(
        kiro_home.join("agents/team-agent.json"),
        serde_json::json!({
            "name": "team-agent",
            "allowedTools": ["fs_read"],
            "hooks": { "agentSpawn": [{ "command": "echo hi" }] },
            "mcpServers": { "files": { "command": "npx" } },
        })
        .to_string(),
    )
    .expect("an agent");
    std::fs::write(
        kiro_home.join("settings/cli.json"),
        serde_json::json!({
            "chat.defaultModel": "auto",
            "chat.defaultAgent": "team-agent",
        })
        .to_string(),
    )
    .expect("settings");
}

fn kiro_agent_storage(host: &FakeHost) -> std::path::PathBuf {
    storage_root(&host.home().join(".strands/box"), "kiro").join("agent/home/.kiro")
}

#[test]
fn a_kiro_run_leaves_the_hosts_agents_and_default_agent_out_unless_import_agents_is_on() {
    let host = FakeHost::new();
    host.profile()
        .with("kiro")
        .create()
        .expect("a profile")
        .write(false)
        .expect("a write");
    write_host_agent(&host);
    host.launcher()
        .prepare("kiro", &host.project(), None)
        .expect("a launch");
    let storage = kiro_agent_storage(&host);
    assert!(!storage.join("agents").exists());
    let settings = std::fs::read_to_string(storage.join("settings/cli.json")).expect("settings");
    assert!(!settings.contains("chat.defaultAgent"), "{settings}");
    assert!(settings.contains("chat.defaultModel"), "{settings}");
}

#[test]
fn a_kiro_run_with_import_agents_copies_each_agent_whole_and_keeps_the_default_agent() {
    let host = FakeHost::new();
    host.profile()
        .with("kiro")
        .option("kiro.import-agents", "true")
        .create()
        .expect("a profile")
        .write(false)
        .expect("a write");
    write_host_agent(&host);
    host.launcher()
        .prepare("kiro", &host.project(), None)
        .expect("a launch");
    let storage = kiro_agent_storage(&host);
    let agent: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(storage.join("agents/team-agent.json")).expect("the agent"),
    )
    .expect("JSON");
    assert_eq!(agent["allowedTools"], serde_json::json!(["fs_read"]));
    // A folder copy cannot drop keys: this is the trade-off that the input's warning states.
    assert!(agent.get("hooks").is_some());
    assert!(agent.get("mcpServers").is_some());
    let settings: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(storage.join("settings/cli.json")).expect("settings"),
    )
    .expect("JSON");
    assert_eq!(
        settings,
        serde_json::json!({
            "chat.defaultModel": "auto",
            "chat.defaultAgent": "team-agent",
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

/// A host with one installed legacy power, `probe-power`, that names an MCP server.
fn host_with_a_power() -> FakeHost {
    let host = FakeHost::new();
    let powers = host.home().join(".kiro/powers");
    let power = powers.join("installed/probe-power");
    std::fs::create_dir_all(power.join("steering")).expect("a folder");
    std::fs::create_dir_all(powers.join("data/probe-power")).expect("a folder");
    std::fs::create_dir_all(powers.join("registries")).expect("a folder");
    for (path, text) in [
        (
            powers.join("installed.json"),
            r#"{"installedPowers":[{"name":"probe-power"}]}"#,
        ),
        (
            power.join("POWER.md"),
            "---\nname: probe-power\ndescription: feature-probe-power\n---\n",
        ),
        (
            power.join("steering/probe.md"),
            "feature-probe-power-steering\n",
        ),
        (
            power.join("mcp.json"),
            r#"{"mcpServers":{"probe":{"command":"probe-server","env":{"KEY":"secret"}}}}"#,
        ),
        (powers.join("data/probe-power/state.json"), "{}"),
        (powers.join("registries/catalog.json"), "{}"),
    ] {
        std::fs::write(path, text).expect("a power file");
    }
    host
}

#[test]
fn import_powers_brings_in_each_powers_text_and_leaves_out_its_mcp_servers() {
    let host = host_with_a_power();
    host.profile()
        .with("kiro")
        .option("kiro.import-powers", "true")
        .create()
        .expect("a profile")
        .write(false)
        .expect("a write");
    let preview = host
        .launcher()
        .preview("kiro", &host.project())
        .expect("a preview");
    assert_eq!(
        preview.links,
        [(
            "~/.kiro/powers/installed/probe-power/mcp.json".to_string(),
            "not copied: the row's `exclude` names it".to_string()
        )]
    );
    let launch = host
        .launcher()
        .prepare("kiro", &host.project(), None)
        .expect("a launch");
    let powers =
        storage_root(&host.home().join(".strands/box"), "kiro").join("agent/home/.kiro/powers");
    assert_eq!(
        std::fs::read_to_string(powers.join("installed.json")).expect("installed.json"),
        r#"{"installedPowers":[{"name":"probe-power"}]}"#
    );
    let power = powers.join("installed/probe-power");
    assert!(power.join("POWER.md").is_file());
    assert_eq!(
        std::fs::read_to_string(power.join("steering/probe.md")).expect("the steering"),
        "feature-probe-power-steering\n"
    );
    assert!(!power.join("mcp.json").exists(), "the MCP servers stay out");
    assert!(!powers.join("data").exists(), "a server's state stays out");
    assert!(!powers.join("registries").exists());
    assert_eq!(
        launch.not_copied(),
        [(
            "~/.kiro/powers/installed/probe-power/mcp.json".to_string(),
            "the row's `exclude` names it".to_string()
        )]
    );
    std::fs::write(
        host.home()
            .join(".kiro/powers/installed/probe-power/mcp.json"),
        r#"{"mcpServers":{}}"#,
    )
    .expect("a host edit");
    host.launcher()
        .prepare("kiro", &host.project(), None)
        .expect("a second launch");
    assert!(
        !power.join("mcp.json").exists(),
        "a sync leaves the MCP servers out too"
    );
}

#[test]
fn without_import_powers_no_power_comes_in() {
    let host = host_with_a_power();
    host.profile()
        .with("kiro")
        .create()
        .expect("a profile")
        .write(false)
        .expect("a write");
    host.launcher()
        .prepare("kiro", &host.project(), None)
        .expect("a launch");
    let home = storage_root(&host.home().join(".strands/box"), "kiro").join("agent/home");
    assert!(home.join(".kiro/steering/box.md").is_file(), "the copy ran");
    assert!(!home.join(".kiro/powers").exists());
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

/// Writes Kiro's shared memory database with its WAL files, and one user's memory and settings.
fn write_host_memory(host: &FakeHost) {
    let kiro_home = host.home().join(".kiro");
    let user = kiro_home.join("identities/5e3a");
    std::fs::create_dir_all(kiro_home.join("memories")).expect("a folder");
    std::fs::create_dir_all(user.join("memories")).expect("a folder");
    std::fs::create_dir_all(user.join("settings")).expect("a folder");
    for (file, text) in [
        ("memories/memories.db", "shared"),
        ("memories/memories.db-wal", "shared wal"),
        ("memories/memories.db-shm", "shared shm"),
        ("identities/5e3a/memories/memories.db", "user"),
        (
            "identities/5e3a/settings/kiro-agent.json",
            r#"{"migrations":["deviceMemory-v1"]}"#,
        ),
    ] {
        std::fs::write(kiro_home.join(file), text).expect("a file");
    }
}

fn kiro_profile(host: &FakeHost, import_memory: Option<&str>) {
    let profile = host.profile().with("kiro");
    let profile = match import_memory {
        Some(value) => profile.option("kiro.import-memory", value),
        None => profile,
    };
    profile
        .create()
        .expect("a profile")
        .write(false)
        .expect("a write");
}

#[test]
fn a_kiro_run_leaves_the_hosts_memory_out_unless_import_memory_is_on() {
    for import_memory in [None, Some("false")] {
        let host = FakeHost::new();
        kiro_profile(&host, import_memory);
        write_host_memory(&host);
        host.launcher()
            .prepare("kiro", &host.project(), None)
            .expect("a launch");
        let storage =
            storage_root(&host.home().join(".strands/box"), "kiro").join("agent/home/.kiro");
        assert!(
            storage.join("settings/cli.json").is_file(),
            "the copies ran"
        );
        assert!(!storage.join("memories").exists(), "{import_memory:?}");
        assert!(!storage.join("identities").exists(), "{import_memory:?}");
    }
}

#[test]
fn a_kiro_run_with_import_memory_copies_the_memory_once_and_writes_nothing_back() {
    let host = FakeHost::new();
    kiro_profile(&host, Some("true"));
    write_host_memory(&host);
    host.launcher()
        .prepare("kiro", &host.project(), None)
        .expect("a launch");
    let storage = storage_root(&host.home().join(".strands/box"), "kiro").join("agent/home/.kiro");
    for (file, text) in [
        ("memories/memories.db", "shared"),
        ("memories/memories.db-wal", "shared wal"),
        ("memories/memories.db-shm", "shared shm"),
        ("identities/5e3a/memories/memories.db", "user"),
        (
            "identities/5e3a/settings/kiro-agent.json",
            r#"{"migrations":["deviceMemory-v1"]}"#,
        ),
    ] {
        assert_eq!(
            std::fs::read_to_string(storage.join(file)).expect("a copy"),
            text,
            "{file}"
        );
    }

    std::fs::write(storage.join("memories/memories.db"), "saved in the box").expect("a box edit");
    std::fs::write(
        host.home().join(".kiro/memories/memories.db"),
        "host, later",
    )
    .expect("a write");
    host.launcher()
        .prepare("kiro", &host.project(), None)
        .expect("a second launch");
    assert_eq!(
        std::fs::read_to_string(storage.join("memories/memories.db")).expect("the copy"),
        "saved in the box",
        "no sync: the box keeps its memory"
    );
    assert_eq!(
        std::fs::read_to_string(host.home().join(".kiro/memories/memories.db")).expect("host"),
        "host, later",
        "nothing goes back to the host"
    );
}

#[test]
fn mcp_import_declares_the_hosts_kiro_servers_and_keeps_their_keys_out_of_the_boxs_mcp_json() {
    let host = FakeHost::new();
    brew_program(&host, "mcp-local");
    let source = host.home().join(".kiro/settings/mcp.json");
    std::fs::create_dir_all(source.parent().expect("a parent")).expect("a folder");
    std::fs::write(
        &source,
        r#"{"mcpServers": {
            "local": {"command": "mcp-local", "args": ["--quiet"], "env": {"TOKEN": "${LOCAL_TOKEN}"}, "autoApprove": ["probe"], "timeout": 120000},
            "resting": {"command": "mcp-local", "disabled": true},
            "docs": {"url": "https://docs.example.com/mcp", "headers": {"Authorization": "Bearer ${DOCS_TOKEN}"}}}}"#,
    )
    .expect("the host's servers");
    host.profile()
        .with("kiro")
        .option("kiro.import-mcp", "true")
        .create()
        .expect("a profile")
        .write(false)
        .expect("a write");
    let launch = host
        .launcher()
        .environment(&[
            ("LOCAL_TOKEN", "local-secret"),
            ("DOCS_TOKEN", "docs-secret"),
        ])
        .prepare("kiro", &host.project(), None)
        .expect("a launch");
    let compiled: toml::Table =
        toml::from_str(&std::fs::read_to_string(launch.config()).expect("box.toml")).expect("TOML");
    let docs: toml::Value = toml::from_str(
        r#"
type = "http"
destinations = ["docs.example.com"]
[secret]
ref = "env://DOCS_TOKEN"
header = "Authorization"
prefix = "Bearer "
"#,
    )
    .expect("expected");
    assert_eq!(compiled["mcp"]["docs"], docs);
    let local = compiled["mcp"]["local"].as_table().expect("local");
    assert_eq!(local["env"]["TOKEN"].as_str(), Some("local-secret"));
    assert!(
        compiled["mcp"].get("resting").is_none(),
        "a server turned off with disabled = true gets no program, host, or key: {:?}",
        compiled["mcp"].get("resting")
    );

    let target = storage_root(&host.home().join(".strands/box"), "kiro")
        .join("agent/home/.kiro/settings/mcp.json");
    let text = std::fs::read_to_string(&target).expect("the box's mcp.json");
    for secret in ["local-secret", "docs-secret"] {
        assert!(!text.contains(secret), "{text}");
    }
    let saved: serde_json::Value = serde_json::from_str(&text).expect("JSON");
    assert_eq!(
        saved["mcpServers"]["local"]["autoApprove"],
        serde_json::json!(["probe"])
    );
    assert_eq!(
        saved["mcpServers"]["resting"]["disabled"],
        serde_json::json!(true)
    );

    host.profile()
        .with("kiro")
        .create()
        .expect("a profile")
        .write(true)
        .expect("a write");
    std::fs::remove_file(&target).expect("remove the import");
    let off = host
        .launcher()
        .prepare("kiro", &host.project(), None)
        .expect("a launch");
    let compiled: toml::Table =
        toml::from_str(&std::fs::read_to_string(off.config()).expect("box.toml")).expect("TOML");
    assert!(compiled.get("mcp").is_none(), "off by default");
    assert!(!target.exists(), "off by default writes no mcp.json");
}

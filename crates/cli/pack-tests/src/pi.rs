use crate::support::*;

#[test]
fn a_pi_run_loads_the_box_shell_with_this_runs_box_and_keeps_only_the_listed_settings() {
    let host = FakeHost::new();
    host.profile()
        .with("pi")
        .with("bedrock")
        .tools(["git"])
        .create()
        .expect("a profile")
        .write(false)
        .expect("a write");
    let instructions = host.home().join(".pi/agent/AGENTS.md");
    std::fs::create_dir_all(instructions.parent().expect("a parent")).expect("a folder");
    std::fs::write(&instructions, "Be brief.").expect("instructions");
    let compiled = |launch: &strands_box_cli::Launch| -> toml::Table {
        toml::from_str(&std::fs::read_to_string(launch.config()).expect("read")).expect("TOML")
    };
    let command = |file: &toml::Table| -> Vec<String> {
        file["agent"]["command"]
            .as_array()
            .expect("a command")
            .iter()
            .map(|part| part.as_str().expect("a string").to_string())
            .collect()
    };
    let pack = resources().join("packs/pi");
    let copy =
        storage_root(&host.home().join(".strands/box"), "pi").join("agent/agent/settings.json");

    let preview = host
        .launcher()
        .preview("pi", &host.project())
        .expect("a preview");
    assert!(
        !preview
            .parts
            .iter()
            .any(|(what, target, _)| what == "sets" && target == "agent/agent/settings.json"),
        "{:?}",
        preview.parts
    );
    let first = compiled(
        &host
            .launcher()
            .prepare("pi", &host.project(), None)
            .expect("a launch"),
    );
    let package = host
        .brew()
        .join("lib/node_modules/@earendil-works/pi-coding-agent");
    assert_eq!(
        command(&first)[..5],
        [
            host.brew()
                .join("Cellar/node/26.9.0/bin/node")
                .display()
                .to_string(),
            r#"--import=data:text/javascript,Object.defineProperty(process,"title",{get:()=>"pi",set:()=>{}})"#
                .to_string(),
            package.join("dist/bundle/cli.js").display().to_string(),
            "-e".to_string(),
            pack.join("box-shell.ts").display().to_string(),
        ]
    );
    let box_dir = first["box_dir"].as_str().expect("box_dir").to_string();
    assert_eq!(
        first["agent"]["env"]["BOX_SHELL_PATH"].as_str(),
        Some(format!("{box_dir}/bin/bash").as_str())
    );
    assert!(
        first["agent"]["filesystem"]["read"]
            .as_array()
            .expect("a list")
            .contains(&toml::Value::from(pack.display().to_string())),
        "pi reads box-shell.ts by its real path"
    );
    assert_eq!(
        std::fs::read_to_string(
            storage_root(&host.home().join(".strands/box"), "pi").join("agent/agent/AGENTS.md")
        )
        .expect("the copied instructions"),
        "Be brief."
    );
    assert!(!copy.exists(), "no host settings writes no settings copy");

    let settings = host.home().join(".pi/agent");
    std::fs::write(
        settings.join("settings.json"),
        serde_json::json!({
            "theme": "light",
            "quietStartup": true,
            "shellPath": "/opt/homebrew/bin/fish",
            "shellCommandPrefix": "source ~/.profile",
            "defaultProvider": "anthropic",
            "packages": ["npm:pi-extras"],
        })
        .to_string(),
    )
    .expect("settings");
    let second = compiled(
        &host
            .launcher()
            .prepare("pi", &host.project(), None)
            .expect("a second launch"),
    );
    let second_dir = second["box_dir"].as_str().expect("box_dir");
    assert_ne!(box_dir, second_dir);
    assert_eq!(
        second["agent"]["env"]["BOX_SHELL_PATH"].as_str(),
        Some(format!("{second_dir}/bin/bash").as_str()),
        "each run names its own box"
    );
    let saved: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&copy).expect("read")).expect("JSON");
    assert_eq!(
        saved,
        serde_json::json!({"theme": "light", "quietStartup": true})
    );
}

#[test]
fn mcp_import_declares_pis_servers_and_keeps_their_keys_out_of_its_mcp_json() {
    let host = FakeHost::new();
    let keg = brew_program(&host, "mcp-local");
    let bin = keg.join("bin").display().to_string();
    let source = host.home().join(".pi/agent/mcp.json");
    std::fs::create_dir_all(source.parent().expect("parent")).expect("directory");
    std::fs::write(
        &source,
        r#"{"autoEnableCodemode": true, "mcpServers": {
            "local": {"command": "mcp-local", "args": ["--quiet"], "env": {"TOKEN": "$LOCAL_TOKEN"}, "exposure": "direct"},
            "templated": {"command": "${MCP_BIN}/mcp-local"},
            "argued": {"command": "mcp-local", "args": ["${MCP_ARG}"]},
            "fetched": {"command": "mcp-local", "env": {"TOKEN": "!gh auth token"}},
            "docs": {"url": "https://docs.example.com/mcp", "headers": {"Authorization": "Bearer $DOCS_TOKEN"}, "description": "Docs"}}}"#,
    )
    .expect("source");
    host.profile()
        .with("pi")
        .option("pi.import-mcp", "true")
        .with("bedrock")
        .create()
        .expect("profile")
        .write(false)
        .expect("write");
    let launch = host
        .launcher()
        .environment(&[
            ("LOCAL_TOKEN", "local-secret"),
            ("DOCS_TOKEN", "docs-secret"),
            ("MCP_BIN", &bin),
            ("MCP_ARG", "arg-value"),
        ])
        .prepare("pi", &host.project(), None)
        .expect("launch");
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
    assert!(
        compiled["mcp"].get("fetched").is_none(),
        "a value that pi runs as a command is not one box can supply"
    );
    let local = compiled["mcp"]["local"].as_table().expect("local");
    assert_eq!(local["env"]["TOKEN"].as_str(), Some("local-secret"));
    let argued = compiled["mcp"]["argued"].as_table().expect("argued");
    assert_eq!(
        argued["command"],
        toml::Value::from(vec!["mcp-local", "*"]),
        "pi passes an argument as written, so box matches it as a wildcard"
    );
    assert_eq!(argued["argument_wildcards"].as_bool(), Some(true));
    assert!(
        compiled["mcp"].get("templated").is_none(),
        "pi does not fill in a variable in command, so box declares no server from it: {:?}",
        compiled["mcp"].get("templated")
    );

    let target = storage_root(&host.home().join(".strands/box"), "pi").join("agent/agent/mcp.json");
    let text = std::fs::read_to_string(&target).expect("mcp.json");
    for secret in ["local-secret", "docs-secret"] {
        assert!(!text.contains(secret), "{text}");
    }
    let saved: serde_json::Value = serde_json::from_str(&text).expect("JSON");
    assert_eq!(
        saved,
        serde_json::json!({"mcpServers": {
            "local": {"command": "mcp-local", "args": ["--quiet"], "exposure": "direct"},
            "templated": {"command": "${MCP_BIN}/mcp-local"},
            "argued": {"command": "mcp-local", "args": ["${MCP_ARG}"]},
            "fetched": {"command": "mcp-local", "env": {"TOKEN": "!gh auth token"}},
            "docs": {"url": "https://docs.example.com/mcp", "headers": {"Authorization": "Bearer $DOCS_TOKEN"}, "description": "Docs"}}})
    );

    host.profile()
        .with("pi")
        .with("bedrock")
        .create()
        .expect("profile")
        .write(true)
        .expect("write");
    std::fs::remove_file(&target).expect("remove the import");
    let off = host
        .launcher()
        .prepare("pi", &host.project(), None)
        .expect("launch");
    let compiled: toml::Table =
        toml::from_str(&std::fs::read_to_string(off.config()).expect("box.toml")).expect("TOML");
    assert!(compiled.get("mcp").is_none(), "off by default");
    assert!(!target.exists(), "off by default writes no mcp.json");
}

fn launch_command(launch: &strands_box_cli::Launch) -> Vec<String> {
    let file: toml::Table =
        toml::from_str(&std::fs::read_to_string(launch.config()).expect("read")).expect("TOML");
    file["agent"]["command"]
        .as_array()
        .expect("a command")
        .iter()
        .map(|part| part.as_str().expect("a string").to_string())
        .collect()
}

#[test]
fn a_pi_box_tells_pi_about_its_shell_and_when_a_change_takes_effect() {
    let host = FakeHost::new();
    host.profile()
        .with("pi")
        .with("bedrock")
        .tools(["git"])
        .create()
        .expect("a profile")
        .write(false)
        .expect("a write");
    let instructions = host.home().join(".pi/agent/AGENTS.md");
    std::fs::create_dir_all(instructions.parent().expect("a parent")).expect("a folder");
    std::fs::write(&instructions, "Be brief.").expect("instructions");
    let launch = host
        .launcher()
        .prepare("pi", &host.project(), None)
        .expect("a launch");
    let command = launch_command(&launch);
    let at = command
        .iter()
        .position(|arg| arg == "--append-system-prompt")
        .expect("the system prompt flag");
    let guidance = std::fs::read_to_string(&command[at + 1]).expect("the prompt file");
    assert!(guidance.contains(SHELL_NOTE), "{guidance}");
    assert!(guidance.contains(OUTSIDE_FILES_NOTE), "{guidance}");
    assert!(guidance.contains(RESTART_NOTE), "{guidance}");
    assert!(guidance.contains(DNS_NOTE), "{guidance}");
    assert_eq!(
        std::fs::read_to_string(
            storage_root(&host.home().join(".strands/box"), "pi").join("agent/agent/AGENTS.md")
        )
        .expect("the host's instructions"),
        "Be brief."
    );
}

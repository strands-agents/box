use crate::support::*;

#[test]
fn codex_imports_and_syncs_native_subagent_definitions() {
    let host = FakeHost::new();
    host.profile()
        .with("codex")
        .with("bedrock-mantle")
        .create()
        .expect("a profile")
        .write(false)
        .expect("a write");
    let source = host.home().join("custom-codex");
    let reviewer = "developer_instructions = 'review marker'";
    write(&source.join("agents/reviewer.toml"), reviewer);
    let explorer =
        "name = 'explorer'\ndescription = 'explore'\ndeveloper_instructions = 'folder marker'";
    write(&source.join("agents/explorer.toml"), explorer);
    let original = "[agents]\nmax_depth = 3\n\
         [agents.reviewer]\ndescription = 'reviewer'\nconfig_file = 'agents/reviewer.toml'\n";
    write(&source.join("config.toml"), original);
    let environment = [("CODEX_HOME", source.to_str().unwrap())];
    let launcher = host.launcher().environment(&environment);
    let private = storage_root(&host.home().join(".strands/box"), "codex").join("agent/home");
    launcher
        .prepare("codex", &host.project(), None)
        .expect("import");
    let saved = std::fs::read_to_string(private.join("config.toml")).unwrap();
    let config: toml::Value = toml::from_str(&saved).unwrap();
    let original: toml::Value = toml::from_str(original).unwrap();
    assert_eq!(config["agents"], original["agents"]);
    for (name, expected) in [("reviewer", reviewer), ("explorer", explorer)] {
        assert_eq!(
            std::fs::read_to_string(private.join(format!("agents/{name}.toml"))).unwrap(),
            expected
        );
    }
    let edited = "developer_instructions = 'host edit'";
    write(&source.join("agents/reviewer.toml"), edited);
    launcher
        .prepare("codex", &host.project(), None)
        .expect("sync");
    assert_eq!(
        std::fs::read_to_string(private.join("agents/reviewer.toml")).unwrap(),
        edited
    );
}

#[test]
fn a_codex_run_copies_the_operators_agents_file_and_rules_into_its_home() {
    let host = FakeHost::new();
    host.profile()
        .with("codex")
        .with("bedrock-mantle")
        .create()
        .expect("a profile")
        .write(false)
        .expect("a write");
    let codex = host.home().join(".codex");
    std::fs::create_dir_all(&codex).expect("a folder");
    std::fs::write(codex.join("AGENTS.md"), "host agents").expect("a file");
    std::fs::write(codex.join("auth.json"), "{}").expect("a login");
    std::fs::create_dir_all(codex.join("rules")).expect("a folder");
    std::fs::write(codex.join("rules/default.rules"), "host rules").expect("a file");
    host.launcher()
        .prepare("codex", &host.project(), None)
        .expect("a launch");
    let home = storage_root(&host.home().join(".strands/box"), "codex").join("agent/home");
    assert_eq!(
        std::fs::read_to_string(home.join("AGENTS.md")).expect("read"),
        "host agents"
    );
    assert_eq!(
        std::fs::read_to_string(home.join("rules/default.rules")).expect("read"),
        "host rules"
    );
    assert!(!home.join("auth.json").exists());
}

#[test]
fn codex_imports_its_selected_host_home_without_sharing_credentials() {
    for selection in ["empty", "custom", "ancestor"] {
        let host = FakeHost::new();
        operator_pack(
            &host,
            "direct",
            "[inputs.instructions-file]\nfrom = 'env:INSTRUCTIONS_FILE'\n\
             default = '${{ home }}/.codex/AGENTS.md'\n\
             [[storage.files]]\nsource = '${{ inputs.instructions-file }}'\n\
             target = 'home/direct.md'\noptional = true\n",
        );
        host.profile()
            .with("codex")
            .with("bedrock-mantle")
            .with("direct")
            .option("codex.import-mcp", "true")
            .option("codex.import-hooks", "true")
            .create()
            .expect("a profile")
            .write(false)
            .expect("a write");
        let source = host.home().join(if selection == "custom" {
            "custom codex"
        } else {
            ".codex"
        });
        let project = if selection == "ancestor" {
            let project = source.join("worktrees/project");
            std::fs::create_dir_all(&project).expect("a project");
            project
        } else {
            host.project()
        };
        strands_box_cli_profile::fixtures::write(
            &source.join("AGENTS.md"),
            "selected instructions",
        );
        strands_box_cli_profile::fixtures::write(
            &source.join("rules/default.rules"),
            "selected rules",
        );
        strands_box_cli_profile::fixtures::write(
            &source.join("skills/review/SKILL.md"),
            "selected skill",
        );
        strands_box_cli_profile::fixtures::write(
            &source.join("themes/night.tmTheme"),
            "selected theme",
        );
        strands_box_cli_profile::fixtures::write(
            &host.home().join(".agents/skills/shared/SKILL.md"),
            "independent skill",
        );
        strands_box_cli_profile::fixtures::write(&source.join("auth.json"), "host login");
        let script = host.home().join("hooks/check.sh");
        strands_box_cli_profile::fixtures::write(&script, "exit 0\n");
        let hooks = serde_json::json!({"hooks": {"PreToolUse": [{"hooks": [{
            "type": "command", "command": script,
        }]}]}});
        strands_box_cli_profile::fixtures::write(&source.join("hooks.json"), &hooks.to_string());
        let settings = "model = 'host-model'\n\
            api_key = 'host secret'\n[mcp_servers.docs]\nurl = 'https://docs.example.com/mcp'\n";
        strands_box_cli_profile::fixtures::write(&source.join("config.toml"), settings);
        let value = source.to_str().expect("a UTF-8 path");
        let instruction_file = source.join("AGENTS.md");
        let mut environment = vec![("CODEX_HOME", if selection == "empty" { "" } else { value })];
        environment.push(("INSTRUCTIONS_FILE", instruction_file.to_str().unwrap()));
        let launcher = host.launcher().environment(&environment);
        let preview = launcher.preview("codex", &project).expect("a preview");
        let config: toml::Value = toml::from_str(&preview.box_toml).expect("box.toml");
        let private = storage_root(&host.home().join(".strands/box"), "codex").join("agent/home");
        assert_eq!(
            config["agent"]["env"]["CODEX_HOME"].as_str(),
            private.to_str(),
            "{selection}: the agent keeps its private home"
        );
        launcher.prepare("codex", &project, None).expect("a launch");
        for (path, expected) in [
            ("AGENTS.md", "selected instructions"),
            ("direct.md", "selected instructions"),
            ("rules/default.rules", "selected rules"),
            ("skills/codex/review/SKILL.md", "selected skill"),
            ("skills/agents/shared/SKILL.md", "independent skill"),
            ("themes/night.tmTheme", "selected theme"),
        ] {
            assert_eq!(
                std::fs::read_to_string(private.join(path)).expect("a private copy"),
                expected,
                "{selection}: {path}"
            );
        }
        let saved = std::fs::read_to_string(private.join("config.toml")).expect("settings");
        let saved: toml::Value = toml::from_str(&saved).expect("TOML");
        assert_eq!(saved["model"].as_str(), Some("host-model"));
        assert_eq!(
            saved["mcp_servers"]["docs"]["url"].as_str(),
            Some("https://docs.example.com/mcp")
        );
        assert!(saved.get("api_key").is_none());
        assert!(!private.join("auth.json").exists());
        let imported: serde_json::Value = serde_json::from_str(
            &std::fs::read_to_string(private.join("hooks.json")).expect("hooks"),
        )
        .expect("JSON");
        assert_eq!(
            imported["hooks"]["PreToolUse"][0]["hooks"][0]["command"],
            format!(". {}", script.canonicalize().unwrap().display()),
            "{selection}: hooks come from the selected home"
        );
        assert_eq!(
            std::fs::read_to_string(source.join("config.toml")).unwrap(),
            settings
        );
        strands_box_cli_profile::fixtures::write(
            &source.join("themes/night.tmTheme"),
            "updated theme",
        );
        launcher
            .prepare("codex", &project, None)
            .expect("theme sync");
        assert_eq!(
            std::fs::read_to_string(private.join("themes/night.tmTheme")).unwrap(),
            "updated theme",
            "{selection}: themes follow the selected home"
        );
    }
}

#[test]
fn codex_skips_unsafe_host_homes_and_keeps_its_private_copies() {
    let host = FakeHost::new();
    host.profile()
        .with("codex")
        .with("bedrock-mantle")
        .option("codex.import-mcp", "true")
        .option("codex.import-hooks", "true")
        .create()
        .expect("a profile")
        .write(false)
        .expect("a write");
    strands_box_cli_profile::fixtures::write(
        &host.home().join(".codex/AGENTS.md"),
        "private instructions",
    );
    strands_box_cli_profile::fixtures::write(&host.home().join("hooks/check.sh"), "exit 0\n");
    strands_box_cli_profile::fixtures::write(
        &host.home().join(".codex/hooks.json"),
        r#"{"hooks":{"PreToolUse":[{"hooks":[{"type":"command","command":"~/hooks/check.sh"}]}]}}"#,
    );
    host.launcher()
        .prepare("codex", &host.project(), None)
        .expect("first launch");
    std::fs::create_dir_all(host.home().join("safe")).expect("a folder");
    strands_box_cli_profile::fixtures::write(
        &host.home().join(".codex/AGENTS.md"),
        "new host instructions",
    );
    let private = storage_root(&host.home().join(".strands/box"), "codex").join("agent/home");
    let linked = host.home().join("linked-codex");
    strands_box_cli_profile::fixtures::link(host.project().to_str().unwrap(), &linked);
    let roots = [
        PathBuf::from("relative"),
        host.home().join("safe/../.codex"),
        host.project(),
        linked,
        private.clone(),
        host.home().join(".codex/AGENTS.md"),
    ];
    for root in roots {
        let environment = [("CODEX_HOME", root.to_str().unwrap())];
        let launcher = host.launcher().environment(&environment);
        let preview = launcher
            .preview("codex", &host.project())
            .expect("skipped preview");
        let launch = launcher
            .prepare("codex", &host.project(), None)
            .expect("skipped launch");
        assert!(
            preview
                .links
                .iter()
                .any(|(_, reason)| reason.contains("CODEX_HOME")),
            "{root:?}: {:?}",
            preview.links
        );
        assert!(
            launch
                .not_copied()
                .iter()
                .any(|(_, reason)| reason.contains("CODEX_HOME")),
            "{root:?}: {:?}",
            launch.not_copied()
        );
        assert!(
            format!("{:?}", preview.mcp_unread).contains("CODEX_HOME"),
            "{root:?}: {:?}",
            preview.mcp_unread
        );
        assert_eq!(
            std::fs::read_to_string(private.join("AGENTS.md")).unwrap(),
            "private instructions"
        );
        let hooks: serde_json::Value = serde_json::from_str(
            &std::fs::read_to_string(private.join("hooks.json")).expect("hooks"),
        )
        .expect("JSON");
        assert_eq!(hooks, serde_json::json!({}), "{root:?}");
    }
}

#[test]
fn a_codex_run_imports_both_skill_roots_syncs_and_can_disable_imports() {
    let host = FakeHost::new();
    host.profile()
        .with("codex")
        .with("bedrock-mantle")
        .create()
        .expect("a profile")
        .write(false)
        .expect("a write");
    let storage =
        storage_root(&host.home().join(".strands/box"), "codex").join("agent/home/skills");
    for root in ["codex", "agents"] {
        let source = host.home().join(format!(".{root}/skills/review"));
        std::fs::create_dir_all(&source).expect("a skill folder");
        std::fs::write(source.join("SKILL.md"), root).expect("a skill");
    }
    host.launcher()
        .prepare("codex", &host.project(), None)
        .expect("default import");
    for root in ["codex", "agents"] {
        assert_eq!(
            std::fs::read_to_string(storage.join(format!("{root}/review/SKILL.md")))
                .expect("a copied skill"),
            root,
            "matching skill folders remain separate"
        );
        std::fs::write(
            host.home().join(format!(".{root}/skills/review/SKILL.md")),
            "host edit",
        )
        .expect("an edit");
    }
    host.launcher()
        .prepare("codex", &host.project(), None)
        .expect("sync");
    for root in ["codex", "agents"] {
        assert_eq!(
            std::fs::read_to_string(storage.join(format!("{root}/review/SKILL.md")))
                .expect("an updated skill"),
            "host edit"
        );
        std::fs::write(
            host.home().join(format!(".{root}/skills/review/SKILL.md")),
            "disabled edit",
        )
        .expect("an edit");
    }
    host.profile()
        .with("codex")
        .with("bedrock-mantle")
        .option("codex.import-skills", "false")
        .create()
        .expect("a profile")
        .write(true)
        .expect("a write");
    host.launcher()
        .prepare("codex", &host.project(), None)
        .expect("disabled import");
    for root in ["codex", "agents"] {
        assert_eq!(
            std::fs::read_to_string(storage.join(format!("{root}/review/SKILL.md")))
                .expect("a retained copy"),
            "host edit"
        );
    }
}

#[test]
fn codex_imports_host_preferences_preserves_saved_choices_and_supplies_no_defaults() {
    let host = FakeHost::new();
    host.profile()
        .with("codex")
        .with("bedrock-mantle")
        .create()
        .expect("profile")
        .write(false)
        .expect("write");
    let source = host.home().join(".codex/config.toml");
    let target =
        storage_root(&host.home().join(".strands/box"), "codex").join("agent/home/config.toml");
    host.launcher()
        .prepare("codex", &host.project(), None)
        .expect("no host settings");
    assert!(!target.exists(), "no host settings means no default model");
    std::fs::create_dir_all(source.parent().expect("parent")).expect("directory");
    std::fs::write(&source, "secret = \"not copied\"\n").expect("source");
    host.launcher()
        .prepare("codex", &host.project(), None)
        .expect("no host model");
    assert!(!target.exists(), "no kept values means no settings copy");

    let memory_settings = r#"version = "v1"
no_memories_if_mcp_or_web_search = true
"#;
    std::fs::write(&target, "[mcp_servers]\n[tui]\n").expect("saved settings");
    std::fs::write(
        &source,
        format!(
            "model = \"host-model\" # token in comment\n\
         model_verbosity = \"low\"\nmodel_reasoning_effort = \"low\"\npersonality = \"pragmatic\"\n\
         secret = \"not copied\"\n\
         [model_providers.private]\nexperimental_bearer_token = \"secret\"\n\
         [tui]\nanimations = false\nshow_tooltips = false\ntheme = \"night\"\n\
         secret = \"not copied\"\n[tui.keymap.composer]\nqueue = \"alt-q\"\n\
         [tui.keymap.global]\ncopy = []\n\
         [tui.presets.1]\nlabel = \"Review\"\ninput = \"Review the changes.\"\n\
         [features]\nmemories = true\nsecret = \"not copied\"\n\
         [memories]\n{memory_settings}"
        ),
    )
    .expect("host settings");
    host.launcher()
        .prepare("codex", &host.project(), None)
        .expect("import beside MCP");
    let text = std::fs::read_to_string(&target).expect("settings");
    let config: toml::Table = text.parse().expect("TOML");
    assert_eq!(config["model"].as_str(), Some("host-model"));
    assert_eq!(config["model_verbosity"].as_str(), Some("low"));
    assert_eq!(config["model_reasoning_effort"].as_str(), Some("low"));
    assert_eq!(config["personality"].as_str(), Some("pragmatic"));
    assert_eq!(config["tui"]["animations"].as_bool(), Some(false));
    assert_eq!(config["tui"]["show_tooltips"].as_bool(), Some(false));
    assert_eq!(config["tui"]["theme"].as_str(), Some("night"));
    assert_eq!(
        config["tui"]["keymap"]["composer"]["queue"].as_str(),
        Some("alt-q")
    );
    assert_eq!(
        config["tui"]["keymap"]["global"]["copy"].as_array(),
        Some(&vec![])
    );
    assert_eq!(
        config["tui"]["presets"]["1"]["label"].as_str(),
        Some("Review")
    );
    assert_eq!(
        config["tui"]["presets"]["1"]["input"].as_str(),
        Some("Review the changes.")
    );
    assert_eq!(config["features"]["memories"].as_bool(), Some(true));
    assert_eq!(
        config["memories"].as_table().expect("memory preferences"),
        &memory_settings.parse::<toml::Table>().expect("TOML")
    );
    assert!(config.get("mcp_servers").is_some());
    assert!(!text.contains("secret") && !text.contains("token"));
    assert!(config.get("model_providers").is_none());

    let saved = "# user choice\nmodel = \"saved-model\"\n\
                 model_verbosity = \"high\"\nmodel_reasoning_effort = \"high\"\npersonality = \"friendly\"\n\
                 other = true\n[tui]\ntheme = \"saved\"\n[tui.keymap]\n\
                 [tui.presets.1]\ninput = \"Explain the changes.\"\n\
                 [features]\nmemories = false\n\
                 [memories]\nno_memories_if_mcp_or_web_search = false\n";
    std::fs::write(&target, saved).expect("user edit");
    std::fs::write(
        &source,
        "model = \"changed-host-model\"\n\
         model_verbosity = \"medium\"\nmodel_reasoning_effort = \"medium\"\npersonality = \"none\"\n\
         [tui]\ntheme = \"changed\"\n[tui.keymap.composer]\nqueue = \"alt-w\"\n\
         [features]\nmemories = true\n\
         [memories]\nversion = \"v2\"\n\
         disable_on_external_context = true\n\
         [tui.presets.1]\ninput = \"Changed prompt.\"\n\
         [tui.presets.2]\ninput = \"New prompt.\"\n",
    )
    .expect("host edit");
    host.launcher()
        .prepare("codex", &host.project(), None)
        .expect("second launch");
    assert_eq!(std::fs::read_to_string(&target).expect("settings"), saved);
}

#[test]
fn codex_imports_only_each_workspaces_trust_and_preserves_saved_choices() {
    let host = FakeHost::new();
    host.profile()
        .with("codex")
        .with("bedrock-mantle")
        .create()
        .expect("profile")
        .write(false)
        .expect("write");
    let other = host.home().join("work/other.project");
    let absent = host.home().join("work/absent");
    for workspace in [&other, &absent] {
        std::fs::create_dir_all(workspace).expect("workspace");
    }
    let first = resolved(&host.project()).display().to_string();
    let second = resolved(&other).display().to_string();
    let source = host.home().join(".codex/config.toml");
    std::fs::create_dir_all(source.parent().expect("parent")).expect("directory");
    let original = format!(
        "secret = \"not copied\"\n\
         [projects.{first:?}]\ntrust_level = \"trusted\"\nsecret = \"not copied\"\n\
         [projects.{second:?}]\ntrust_level = \"untrusted\"\n\
         [projects.\"/never-selected\"]\ntrust_level = \"trusted\"\n"
    );
    std::fs::write(&source, &original).expect("host settings");
    let target =
        storage_root(&host.home().join(".strands/box"), "codex").join("agent/home/config.toml");
    std::fs::create_dir_all(target.parent().expect("parent")).expect("storage");
    std::fs::write(&target, "[mcp_servers]\n").expect("existing MCP settings");
    host.launcher()
        .prepare("codex", &host.project(), None)
        .expect("first workspace");
    let read = || -> toml::Table {
        std::fs::read_to_string(&target)
            .expect("settings")
            .parse()
            .expect("TOML")
    };
    let mut expected: toml::Table =
        format!("[mcp_servers]\n[projects.{first:?}]\ntrust_level = \"trusted\"\n")
            .parse()
            .expect("expected settings");
    assert_eq!(read(), expected);

    expected["projects"][&first]["trust_level"] = "untrusted".into();
    std::fs::write(&target, toml::to_string(&expected).expect("TOML")).expect("saved choice");
    host.launcher()
        .prepare("codex", &host.project(), None)
        .expect("preserve saved distrust");
    assert_eq!(read(), expected);
    host.launcher()
        .prepare("codex", &other, None)
        .expect("second workspace");
    expected["projects"]
        .as_table_mut()
        .expect("projects")
        .insert(
            second,
            toml::Value::Table(toml::toml! { trust_level = "untrusted" }),
        );
    assert_eq!(read(), expected);
    host.launcher()
        .prepare("codex", &absent, None)
        .expect("no host trust choice");
    assert_eq!(read(), expected);
    assert_eq!(
        std::fs::read_to_string(&source).expect("host settings"),
        original
    );
}

#[test]
fn mcp_import_keeps_codex_remote_references_and_strips_local_env_vars() {
    let host = FakeHost::new();
    brew_program(&host, "mcp-local");
    let source = host.home().join(".codex/config.toml");
    std::fs::create_dir_all(source.parent().expect("parent")).expect("directory");
    std::fs::write(
        &source,
        r#"
model = "host-model"
[mcp_servers.local]
command = "mcp-local"
args = ["literal-secret"]
env_vars = ["LOCAL_TOKEN"]
env = { PASTED = "pasted-secret" }
startup_timeout_sec = 30
[mcp_servers.bearer]
url = "https://bearer.example.com/mcp"
bearer_token_env_var = "BEARER_TOKEN"
[mcp_servers.header]
url = "https://header.example.com/mcp"
env_http_headers = { "X-Key" = "HEADER_TOKEN" }
http_headers = { "X-Client" = "codex" }
"#,
    )
    .expect("source");
    host.profile()
        .with("codex")
        .option("codex.import-mcp", "true")
        .with("bedrock-mantle")
        .create()
        .expect("profile")
        .write(false)
        .expect("write");
    host.launcher()
        .environment(&[
            ("LOCAL_TOKEN", "local-secret"),
            ("BEARER_TOKEN", "bearer-secret"),
            ("HEADER_TOKEN", "header-secret"),
        ])
        .prepare("codex", &host.project(), None)
        .expect("launch");
    let target =
        storage_root(&host.home().join(".strands/box"), "codex").join("agent/home/config.toml");
    let text = std::fs::read_to_string(&target).expect("config");
    for secret in [
        "local-secret",
        "pasted-secret",
        "bearer-secret",
        "header-secret",
    ] {
        assert!(!text.contains(secret), "{text}");
    }
    let value: toml::Value = toml::from_str(&text).expect("TOML");
    let expected: toml::Value = toml::from_str(
        r#"
model = "host-model"
[mcp_servers.local]
command = "mcp-local"
args = ["literal-secret"]
startup_timeout_sec = 30
[mcp_servers.bearer]
url = "https://bearer.example.com/mcp"
bearer_token_env_var = "BEARER_TOKEN"
[mcp_servers.header]
url = "https://header.example.com/mcp"
env_http_headers = { "X-Key" = "HEADER_TOKEN" }
http_headers = { "X-Client" = "codex" }
"#,
    )
    .expect("expected");
    assert_eq!(value, expected);
}

#[test]
fn a_codex_run_declares_the_servers_in_its_config() {
    let host = FakeHost::new();
    brew_program(&host, "mcp-notes");
    brew_program(&host, "mcp-issues");
    let codex = host.home().join(".codex");
    std::fs::create_dir_all(&codex).expect("a folder");
    std::fs::write(
        codex.join("config.toml"),
        "model = \"x\"\n[mcp_servers.notes]\ncommand = \"mcp-notes\"\n\
         [mcp_servers.issues]\ncommand = \"mcp-issues\"\n\
         env_vars = [\"BOX_TEST_TOKEN\"]\nenv = { LOG_LEVEL = \"info\" }\n\
         [mcp_servers.token]\nurl = \"https://api.example.com\"\n\
         bearer_token_env_var = \"BOX_TEST_UNSET\"\n\
         [mcp_servers.keyed]\nurl = \"https://keyed.example.com/mcp\"\n\
         bearer_token_env_var = \"HOME\"\n",
    )
    .expect("a config");
    host.profile()
        .with("codex")
        .option("codex.import-mcp", "true")
        .with("bedrock-mantle")
        .create()
        .expect("a profile")
        .write(false)
        .expect("a write");
    let preview = host
        .launcher()
        .environment(&[("BOX_TEST_TOKEN", "ghp_real")])
        .preview("codex", &host.project())
        .expect("a preview");
    assert_eq!(
        preview.mcp_servers,
        vec![
            (
                "issues".to_string(),
                "~/.codex/config.toml".to_string(),
                ", with BOX_TEST_TOKEN, LOG_LEVEL".to_string()
            ),
            (
                "notes".to_string(),
                "~/.codex/config.toml".to_string(),
                String::new()
            ),
        ]
    );
    let file: toml::Table = toml::from_str(&preview.box_toml).expect("TOML");
    assert_eq!(
        file["mcp"]["issues"]["env"],
        toml::from_str::<toml::Value>("BOX_TEST_TOKEN = \"ghp_real\"\nLOG_LEVEL = \"info\"")
            .expect("TOML"),
        "the shipped pack passes each name in env_vars"
    );
    assert_eq!(
        preview.mcp_skipped,
        vec![
            (
                "keyed".to_string(),
                "~/.codex/config.toml".to_string(),
                "takes a key from HOME, which the box sets itself".to_string()
            ),
            (
                "token".to_string(),
                "~/.codex/config.toml".to_string(),
                "needs BOX_TEST_UNSET, which is not set in your environment".to_string()
            ),
        ]
    );
}

#[test]
fn codex_keeps_its_default_approval_policy_by_default() {
    let host = FakeHost::new();
    let generated = codex(&host).generate().expect("a configuration");
    let command = agent_command(&generated);
    assert!(
        command
            .iter()
            .all(|arg| !arg.starts_with("approval_policy")),
        "{command:?}"
    );
}

#[test]
fn skip_permissions_sets_codexs_approval_policy_to_never() {
    let host = FakeHost::new();
    let generated = codex(&host)
        .option("agent.skip-permissions", "true")
        .generate()
        .expect("a configuration");
    let command = agent_command(&generated);
    for setting in [
        r#"approval_policy="never""#,
        r#"sandbox_mode="danger-full-access""#,
    ] {
        assert!(
            command.windows(2).any(|pair| pair == ["-c", setting]),
            "{setting} in {command:?}"
        );
    }
}

#[test]
fn codex_reads_only_the_present_managed_policy_files() {
    let host = FakeHost::new();
    let policy = host.home().join("managed");
    let requirements = policy.join("requirements.toml");
    let legacy = host.home().join("deployed-policy.toml");
    let legacy_link = policy.join("managed_config.toml");
    strands_box_cli_profile::fixtures::write(
        &requirements,
        "allowed_approval_policies = ['on-request']",
    );
    strands_box_cli_profile::fixtures::write(&legacy, "approval_policy = 'on-request'");
    strands_box_cli_profile::fixtures::link(legacy.to_str().expect("a UTF-8 path"), &legacy_link);
    let pack = std::fs::read_to_string(resources().join("packs/codex/pack.toml"))
        .expect("the shipped pack")
        .replace("name = \"@box/codex\"", "name = \"codex\"")
        .replace("/etc/codex", "${{ home }}/managed")
        .replace(
            "read_file = [",
            "read_file = [\n    { path = \"${{ home }}/deployed-policy.toml\", optional = true },",
        );
    strands_box_cli_profile::fixtures::write(
        &host.home().join(".strands/box/packs/codex/pack.toml"),
        &pack,
    );

    for state in ["present", "broken", "absent"] {
        for os in ["macos", "linux"] {
            let generated = codex(&host).os(os).generate().expect("a configuration");
            let config: toml::Value =
                toml::from_str(generated.box_toml()).expect("box.toml parses");
            let filesystem = &config["agent"]["filesystem"];
            let policy_paths = |key: &str| -> Vec<&str> {
                filesystem
                    .get(key)
                    .and_then(toml::Value::as_array)
                    .into_iter()
                    .flatten()
                    .filter_map(toml::Value::as_str)
                    .filter(|path| {
                        Path::new(path).starts_with(&policy)
                            || policy.starts_with(path)
                            || legacy.starts_with(path)
                    })
                    .collect()
            };
            let expected = if state == "present" {
                vec![
                    requirements.to_str().unwrap(),
                    legacy_link.to_str().unwrap(),
                ]
            } else {
                vec![]
            };
            assert_eq!(policy_paths("read_file"), expected, "{os}");
            let metadata = if os == "macos" && state != "absent" {
                vec![policy.to_str().unwrap()]
            } else {
                vec![]
            };
            assert_eq!(policy_paths("metadata"), metadata, "{os}: {state}");
            for key in ["read", "write", "write_file", "list", "exec"] {
                assert!(policy_paths(key).is_empty(), "{os}: {key}");
            }
        }
        if state == "present" {
            std::fs::remove_file(&requirements).expect("remove the requirements");
            std::fs::remove_file(&legacy).expect("leave a broken optional link");
        } else if state == "broken" {
            std::fs::remove_file(&legacy_link).expect("remove the broken link");
            std::fs::remove_dir(&policy).expect("remove the policy directory");
        }
    }
}

#[test]
fn a_codex_box_tells_codex_it_runs_in_a_box_and_where_its_profile_is() {
    let host = FakeHost::new();
    let generated = codex(&host)
        .agent_args(&["--verbose"])
        .generate()
        .expect("a configuration");
    let command = agent_command(&generated);
    let at = command
        .iter()
        .position(|arg| arg.starts_with("developer_instructions="))
        .expect("developer_instructions in the command");
    assert_eq!(command[at - 1], "-c");
    assert_eq!(command.last().map(String::as_str), Some("--verbose"));
    let value = command[at].trim_start_matches("developer_instructions=");
    let parsed: toml::Table = toml::from_str(&format!("x = {value}")).expect("a TOML value");
    let guidance = parsed["x"].as_str().expect("a string");
    let profile = profiles_root(&host.home().join(".strands/box")).join("codex");
    let profile = profile.display();
    assert!(guidance.starts_with("# You run in a box\n"), "{guidance}");
    assert!(guidance.contains(SHELL_NOTE), "{guidance}");
    assert!(guidance.contains(OUTSIDE_FILES_NOTE), "{guidance}");
    assert!(guidance.contains(RESTART_NOTE), "{guidance}");
    assert!(guidance.contains(DNS_NOTE), "{guidance}");
    assert!(
        guidance.contains("`AWS_BEARER_TOKEN_BEDROCK`"),
        "{guidance}"
    );
    assert!(
        guidance.ends_with(&format!(
            "This run's box profile is the folder {profile}, and its file is {profile}/profile.toml."
        )),
        "{guidance}"
    );
}

fn codex(host: &FakeHost) -> Trial {
    host.trial().with("codex").with("bedrock-mantle")
}

/// The report and the next steps of a Codex profile on `host`.
fn codex_report(host: &FakeHost) -> (String, String) {
    let created = host
        .profile()
        .with("codex")
        .with("bedrock-mantle")
        .tools(["cargo", "git", "node", "npm"])
        .create()
        .expect("a profile");
    (created.summary(false), created.next_steps(false))
}

#[test]
fn codex_comes_from_the_path() {
    let host = FakeHost::new();
    let generated = codex(&host).generate().expect("a configuration");
    assert_eq!(generated.agent(), host.codex_install());
    let file: toml::Value = toml::from_str(generated.box_toml()).expect("TOML");
    assert_eq!(
        file["agent"]["command"][0].as_str(),
        host.codex_install().to_str()
    );
    let (summary, _) = codex_report(&host);
    assert!(
        summary
            .lines()
            .any(|line| line.split_whitespace().eq(["✓", "Codex", "@box/codex"])),
        "{summary}"
    );
}

#[test]
fn a_node_launcher_for_codex_on_the_path_is_passed_over_for_the_native_codex() {
    let host = FakeHost::new();
    let bin = host.home().join("npm-bin");
    write(&bin.join("codex"), "#!/usr/bin/env node\n");
    executable(&bin.join("codex"));
    let generated = codex(&host)
        .search_path(format!("{}:{}", bin.display(), host.search_path()))
        .generate()
        .expect("a configuration");
    assert_eq!(generated.agent(), host.codex_install());
}

#[test]
fn the_first_codex_on_the_path_runs() {
    let host = FakeHost::new();
    let bin = host.home().join("codex-bin");
    script(&bin.join("codex"), "true");
    let generated = codex(&host)
        .search_path(format!("{}:{}", bin.display(), host.search_path()))
        .generate()
        .expect("a configuration");
    assert_eq!(generated.agent(), bin.join("codex"));
}

#[test]
fn a_missing_codex_names_the_option_that_sets_it() {
    let host = FakeHost::new();
    host.uninstall_codex();
    let error = codex(&host).generate().expect_err("no agent");
    no_agent(&error, "codex");
    assert!(
        error
            .to_string()
            .contains("set `codex.path` in your profile's `[options]`"),
        "{error}"
    );
}

#[test]
fn a_codex_box_execs_the_binary_alone_with_its_home_in_storage() {
    let host = FakeHost::new();
    let generated = codex(&host).generate().expect("a configuration");
    let binary = host.codex_install().display().to_string();
    let file: toml::Value = toml::from_str(generated.box_toml()).expect("TOML");
    let agent = &file["agent"];
    let strings = |value: &toml::Value| -> Vec<String> {
        value
            .as_array()
            .expect("a list")
            .iter()
            .filter_map(|item| item.as_str().map(str::to_string))
            .collect()
    };
    let command = strings(&agent["command"]);
    assert_eq!(command.first(), Some(&binary));
    assert_eq!(strings(&agent["filesystem"]["exec"]), [binary]);
    let home = generated.storage().join("agent/home").display().to_string();
    assert_eq!(agent["env"]["CODEX_HOME"].as_str(), Some(home.as_str()));
    assert!(!generated.storage().starts_with(generated.project()));
    let env = agent["env"].as_table().expect("env");
    assert!(
        env.keys().all(|name| !name.starts_with("CLAUDE")),
        "{env:?}"
    );
    assert_eq!(
        strings(&file["egress"]["bedrock"]["destinations"]),
        ["bedrock-mantle.us-west-2.api.aws"]
    );
    assert!(
        generated
            .policy()
            .contains(r#"context.input.host == "bedrock-mantle.us-west-2.api.aws""#)
    );
    assert!(!generated.policy().contains("bedrock-runtime"));
}

#[test]
fn a_codex_box_runs_the_code_mode_host_installed_beside_codex() {
    let host = FakeHost::new();
    let helper = host
        .codex_install()
        .parent()
        .expect("a folder")
        .join("codex-code-mode-host");
    write(&helper, "");
    executable(&helper);
    let generated = codex(&host).generate().expect("a configuration");
    let file: toml::Value = toml::from_str(generated.box_toml()).expect("TOML");
    let filesystem = &file["agent"]["filesystem"];
    let paths = |key: &str| -> Vec<String> {
        filesystem[key]
            .as_array()
            .expect("a list")
            .iter()
            .filter_map(|item| item.as_str().map(str::to_string))
            .collect()
    };
    let binary = host.codex_install().display().to_string();
    let helper = helper.display().to_string();
    assert_eq!(paths("exec"), [binary.clone(), helper.clone()]);
    assert!(paths("read").contains(&binary), "{:?}", paths("read"));
    assert!(paths("read").contains(&helper), "{:?}", paths("read"));
}

#[test]
fn a_codex_box_carries_the_span_exporter_the_box_expands_at_launch() {
    let host = FakeHost::new();
    let generated = codex(&host).generate().expect("a configuration");
    let file: toml::Value = toml::from_str(generated.box_toml()).expect("TOML");
    let command: Vec<&str> = file["agent"]["command"]
        .as_array()
        .expect("a list")
        .iter()
        .filter_map(toml::Value::as_str)
        .collect();
    // Codex reads no `OTEL_EXPORTER_OTLP_*` variable and each exporter needs a literal endpoint,
    // so the box's token in argv is the only route to a kernel-assigned port.
    assert_eq!(
        command[command.len() - 8..],
        [
            "-c",
            "otel.trace_exporter={otlp-http={endpoint=\"${OTEL_EXPORTER_OTLP_TRACES_ENDPOINT}\",\
             protocol=\"json\"}}",
            "-c",
            "otel.exporter=\"none\"",
            "-c",
            "otel.metrics_exporter=\"none\"",
            "-c",
            "otel.log_user_prompt=false",
        ]
    );
    let env = file["agent"]["env"].as_table().expect("env");
    assert!(env.keys().all(|name| !name.starts_with("OTEL_")), "{env:?}");
}

#[test]
fn codex_settings_turn_off_its_own_sandbox() {
    let host = FakeHost::new();
    let generated = codex(&host).generate().expect("a configuration");
    let file: toml::Value = toml::from_str(generated.box_toml()).expect("TOML");
    let settings = codex_settings(&file["agent"]["command"]);
    for setting in [
        "sandbox_mode=\"danger-full-access\"",
        "check_for_update_on_startup=false",
    ] {
        assert!(settings.contains(&setting), "{setting} in {settings:?}");
    }
    assert!(
        settings
            .iter()
            .all(|setting| !setting.starts_with("model=")),
        "{settings:?}"
    );
    assert_eq!(
        generated.directories(),
        [
            generated.storage().join("agent/home"),
            generated.storage().join("agent/tmp")
        ]
    );
}

#[test]
fn a_manual_codex_profile_selects_its_bedrock_provider() {
    for (pack, option, provider, endpoint) in [
        (
            "bedrock-mantle",
            None,
            "amazon-bedrock",
            "bedrock-mantle.us-west-2.api.aws",
        ),
        (
            "bedrock",
            Some("amazon-bedrock-runtime"),
            "amazon-bedrock-runtime",
            "bedrock-runtime.us-west-2.amazonaws.com",
        ),
    ] {
        let host = FakeHost::new();
        let mut trial = host.trial().with("codex").with(pack);
        if let Some(value) = option {
            trial = trial.option("codex.host", value);
        }
        let generated = trial.generate().expect("a configuration");
        let file: toml::Table = toml::from_str(generated.box_toml()).unwrap();
        let settings = codex_settings(&file["agent"]["command"]);
        assert!(settings.contains(&format!(r#"model_provider="{provider}""#).as_str()));
        assert!(
            settings.contains(
                &format!(r#"model_providers.{provider}.aws.region="us-west-2""#).as_str()
            )
        );
        assert_eq!(
            file["egress"]["bedrock"]["destinations"]
                .as_array()
                .unwrap(),
            &[toml::Value::from(endpoint)]
        );
    }
}

#[test]
fn a_manual_codex_profile_selects_the_openai_api_with_the_key_as_a_stand_in() {
    let host = FakeHost::new();
    let generated = host
        .trial()
        .with("codex")
        .with("openai")
        .option("codex.host", "openai")
        .generate()
        .expect("a configuration");
    let file: toml::Table = toml::from_str(generated.box_toml()).unwrap();
    let settings = codex_settings(&file["agent"]["command"]);
    assert!(
        settings.contains(&r#"model_provider="openai-api""#),
        "{settings:?}"
    );
    assert!(
        settings.contains(
            &r#"model_providers.openai-api={name="OpenAI",base_url="https://api.openai.com/v1",env_key="OPENAI_API_KEY",wire_api="responses"}"#
        ),
        "{settings:?}"
    );
    assert!(
        settings
            .iter()
            .all(|setting| !setting.contains("aws.region")),
        "{settings:?}"
    );
    let route = &file["egress"]["openai"];
    assert_eq!(
        route["destinations"].as_array().unwrap(),
        &[toml::Value::from("api.openai.com")]
    );
    assert_eq!(
        route["secret"]["ref"].as_str(),
        Some("env://OPENAI_API_KEY")
    );
    assert!(file["egress"].get("bedrock").is_none());
    assert!(
        generated
            .policy()
            .contains(r#"context.input.host == "api.openai.com""#)
    );
}

#[test]
fn codex_refuses_an_unsupported_provider() {
    let host = FakeHost::new();
    let error = codex(&host)
        .option("codex.host", "anthropic")
        .generate()
        .expect_err("Codex has no Anthropic provider");
    assert!(
        error
            .to_string()
            .contains("is not one of amazon-bedrock, amazon-bedrock-runtime, openai"),
        "{error}"
    );
    let error = host
        .trial()
        .with("codex")
        .with("anthropic")
        .generate()
        .expect_err("Codex has no Anthropic provider");
    assert!(
        error.to_string().contains("inputs.bedrock.region"),
        "{error}"
    );
}

#[test]
fn the_report_names_codex_and_where_its_arguments_go() {
    let host = FakeHost::new();
    let steps = host
        .profile()
        .with("codex")
        .with("bedrock-mantle")
        .create()
        .expect("a profile")
        .next_steps(false);
    assert!(steps.contains("Wrote profile codex."), "{steps}");
    assert!(steps.contains("Start Codex in the box"), "{steps}");
    assert!(
        steps.contains("     Arguments after -- go to Codex: box run codex -- <args>\n"),
        "{steps}"
    );
    assert!(!steps.contains("resume --last"), "{steps}");
    assert!(
        steps.contains("The bedrock route signs with your default AWS identity."),
        "{steps}"
    );
}

/// The `@box/codex` pack imports the hooks of `hooks.json` with its row alone: each hook becomes
/// one command string that reads its script, and the run permits that read.
#[test]
fn a_codex_run_with_imported_hooks_writes_one_command_string_and_permits_its_script() {
    let host = FakeHost::new();
    strands_box_cli_profile::fixtures::write(
        &host.home().join(".codex/hooks/check.sh"),
        "exit 0\n",
    );
    strands_box_cli_profile::fixtures::write(
        &host.home().join(".codex/hooks.json"),
        r#"{"hooks":{"PreToolUse":[{"matcher":"Bash","hooks":[
            {"type":"command","command":"~/.codex/hooks/check.sh","timeout":5,
             "statusMessage":"checking","commandWindows":"check.cmd"},
            {"type":"mcp_tool","server":"s","tool":"t"},
            {"type":"command","command":"python3 ~/.codex/hooks/check.py"},
            {"type":"command","command":"bash ~/.codex/hooks/check.sh","command_windows":"check.cmd"}]}]}}"#,
    );
    let profile = |hooks: &str| {
        host.profile()
            .with("codex")
            .with("bedrock-mantle")
            .option("codex.import-hooks", hooks)
            .create()
            .expect("a profile")
            .write(true)
            .expect("a write");
    };
    let copy =
        strands_box_cli_profile::lang::storage_root(&host.home().join(".strands/box"), "codex")
            .join("agent/home/hooks.json");
    let script = host
        .home()
        .join(".codex/hooks/check.sh")
        .canonicalize()
        .expect("canonical");

    profile("true");
    let launch = host
        .launcher()
        .prepare("codex", &host.project(), None)
        .expect("Box Core accepts the generated permit");

    let lines = launch.hooks().join("\n");
    assert!(
        lines.contains("/.codex/hooks/check.sh, and the policy permits its read"),
        "{lines}"
    );
    assert!(
        lines.contains("did not import the hook PreToolUse (Bash) #2: a `mcp_tool` hook"),
        "{lines}"
    );
    assert!(
        lines.contains(
            "did not import the hook PreToolUse (Bash) #3: the command starts a program other \
             than sh, bash, or zsh"
        ),
        "{lines}"
    );
    assert!(
        !lines.contains("#4"),
        "a `command_windows` hook comes in: {lines}"
    );
    let policy =
        std::fs::read_to_string(launch.config().with_file_name("policy.dw")).expect("the policy");
    assert_eq!(policy.matches("@id(\"hook_script_0_read\")").count(), 1);
    assert_eq!(policy.matches("hook_script_").count(), 1, "{policy}");
    let config = std::fs::read_to_string(launch.config()).expect("box.toml");
    assert!(!config.contains("check.sh"), "no grant: {config}");
    let written: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&copy).expect("the copy")).expect("JSON");
    assert_eq!(
        written,
        serde_json::json!({"hooks": {"PreToolUse": [{"matcher": "Bash", "hooks": [
            {
                "type": "command",
                "timeout": 5,
                "statusMessage": "checking",
                "command": format!(". {}", script.display()),
            },
            {"type": "command", "command": format!(". {}", script.display())},
        ]}]}})
    );

    profile("false");
    let launch = host
        .launcher()
        .prepare("codex", &host.project(), None)
        .expect("a launch");
    assert!(
        launch
            .hooks()
            .iter()
            .any(|line| line.starts_with("removed the hooks")),
        "{:?}",
        launch.hooks()
    );
    let written: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&copy).expect("the copy")).expect("JSON");
    assert_eq!(written, serde_json::json!({}));
    let policy =
        std::fs::read_to_string(launch.config().with_file_name("policy.dw")).expect("the policy");
    assert!(!policy.contains("hook_script_"), "{policy}");
}

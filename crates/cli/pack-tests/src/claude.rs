use crate::support::*;

#[test]
fn the_claude_starter_takes_each_spelling_that_turns_bedrock_on() {
    for spelling in ["1", "true", "True", "TRUE", "yes", "on"] {
        let host = FakeHost::new();
        strands_box_cli_profile::fixtures::write(
            &host.home().join(".claude/settings.json"),
            &format!(r#"{{"env": {{"CLAUDE_CODE_USE_BEDROCK": "{spelling}"}}}}"#),
        );
        let created = host
            .profile()
            .name("claude")
            .policy("open")
            .answer(None)
            .unwrap_or_else(|error| panic!("{spelling}: {error}"))
            .create()
            .expect("a profile");
        assert!(
            created.text().contains("@box/bedrock"),
            "{spelling}: {}",
            created.text()
        );
    }
}

#[test]
fn the_claude_starter_follows_the_host_settings_and_the_report_names_each_place() {
    let host = FakeHost::new();
    strands_box_cli_profile::fixtures::write(
        &host.home().join(".claude/settings.json"),
        r#"{"env": {"CLAUDE_CODE_USE_BEDROCK": "1", "AWS_REGION": "us-east-2"},
            "permissions": {"defaultMode": "bypassPermissions"}}"#,
    );
    let created = host
        .profile()
        .name("claude")
        .policy("open")
        .answer(None)
        .expect("answered from the host")
        .create()
        .expect("a profile");
    let file: toml::Table = toml::from_str(created.text()).expect("TOML");
    let packs = strings(&file["packs"]);
    assert_eq!(
        packs[..2],
        ["@box/claude", "@box/bedrock"],
        "{}",
        created.text()
    );
    let options = file["options"].as_table().expect("options");
    assert_eq!(options["bedrock"]["region"].as_str(), Some("us-east-2"));
    assert!(!options.contains_key("agent"), "{}", created.text());
    let summary = created.summary(false);
    for expected in [
        "Detected",
        "Amazon Bedrock",
        "env.CLAUDE_CODE_USE_BEDROCK in ~/.claude/settings.json",
        "us-east-2",
    ] {
        assert!(summary.contains(expected), "{expected}: {summary}");
    }
    assert!(!summary.contains("permissions.defaultMode"), "{summary}");
    assert!(!summary.contains("bypassPermissions"), "{summary}");
}

#[test]
fn a_claude_run_copies_the_operators_instructions_and_skills_and_follows_host_edits() {
    let host = FakeHost::new();
    host.profile()
        .with("claude")
        .with("bedrock")
        .create()
        .expect("a profile")
        .write(false)
        .expect("a write");
    let claude = host.home().join(".claude");
    std::fs::create_dir_all(claude.join("skills/review")).expect("a skills folder");
    std::fs::write(claude.join("CLAUDE.md"), "host instructions").expect("a file");
    std::fs::write(claude.join("skills/review/SKILL.md"), "review").expect("a skill");
    std::fs::write(claude.join("settings.json"), "{\"env\":{}}").expect("settings");
    let elsewhere = host.home().join("tools/skills/installed");
    std::fs::create_dir_all(&elsewhere).expect("a folder");
    std::fs::write(elsewhere.join("SKILL.md"), "installed").expect("a skill");
    std::os::unix::fs::symlink(&elsewhere, claude.join("skills/installed")).expect("a link");
    std::os::unix::fs::symlink(host.project(), claude.join("skills/planted")).expect("a link");
    let preview = host
        .launcher()
        .preview("claude", &host.project())
        .expect("a preview");
    let copy = |source: &str, target: &str, what: &str| {
        (
            format!("~/.claude/{source}"),
            format!("agent/config/{target}"),
            what.to_string(),
        )
    };
    assert_eq!(
        preview.copies,
        vec![
            copy("CLAUDE.md", "CLAUDE.md", "will copy"),
            copy("rules", "rules", "absent on this host"),
            copy("skills", "skills", "will copy"),
            copy("commands", "commands", "absent on this host"),
            copy("agents", "agents", "absent on this host"),
            copy("output-styles", "output-styles", "absent on this host"),
            copy("themes", "themes", "absent on this host"),
            copy(
                "keybindings.json",
                "keybindings.json",
                "absent on this host"
            ),
            copy("settings.json", "settings.json", "will copy"),
            (
                "~/.claude.json".to_string(),
                "agent/config/.claude.json".to_string(),
                "absent on this host".to_string()
            ),
            copy(
                &format!("projects/{}/memory", dashed(&host.project())),
                &format!("projects/{}/memory", dashed(&host.project())),
                "absent on this host"
            ),
        ]
    );
    assert_eq!(
        preview.links,
        vec![
            (
                "~/.claude/skills/installed".to_string(),
                "follows the link to ~/tools/skills/installed".to_string()
            ),
            (
                "~/.claude/skills/planted".to_string(),
                "not copied: ~/project is the workspace; box copies no file from there".to_string()
            ),
        ]
    );
    let storage = storage_root(&host.home().join(".strands/box"), "claude");
    assert!(
        !storage.join("agent/config/CLAUDE.md").exists(),
        "a preview copies nothing"
    );
    let launch = host
        .launcher()
        .prepare("claude", &host.project(), None)
        .expect("a launch");
    let config = storage.join("agent/config");
    assert_eq!(
        std::fs::read_to_string(config.join("CLAUDE.md")).expect("read"),
        "host instructions"
    );
    assert!(config.join("skills/review/SKILL.md").is_file());
    assert!(config.join("skills/installed/SKILL.md").is_file());
    assert!(!config.join("skills/planted").exists());
    assert_eq!(
        std::fs::read_to_string(config.join("settings.json")).expect("read"),
        "{\n  \"skipWebFetchPreflight\": true\n}\n",
        "a settings file with no display preference copies no key"
    );
    assert_eq!(
        launch.not_copied(),
        [(
            "~/.claude/skills/planted".to_string(),
            "~/project is the workspace; box copies no file from there".to_string()
        )]
    );
    std::fs::write(config.join("CLAUDE.md"), "edited in the box").expect("an edit");
    host.launcher()
        .prepare("claude", &host.project(), None)
        .expect("a second launch");
    assert_eq!(
        std::fs::read_to_string(config.join("CLAUDE.md")).expect("read"),
        "edited in the box",
        "a run keeps the box's edit while the host's file is unchanged"
    );
    std::fs::write(claude.join("CLAUDE.md"), "host, changed").expect("an edit");
    host.launcher()
        .prepare("claude", &host.project(), None)
        .expect("a third launch");
    assert_eq!(
        std::fs::read_to_string(config.join("CLAUDE.md")).expect("read"),
        "host, changed",
        "a host edit replaces the box's edit"
    );
    let preview = host
        .launcher()
        .preview("claude", &host.project())
        .expect("a preview");
    let states: Vec<_> = preview
        .copies
        .iter()
        .filter(|(_, _, what)| what != "absent on this host")
        .map(|(_, target, what)| (target.as_str(), what.as_str()))
        .collect();
    assert_eq!(
        states,
        vec![
            ("agent/config/CLAUDE.md", "in sync with the host"),
            ("agent/config/skills", "in sync with the host"),
            ("agent/config/settings.json", "already in storage"),
        ]
    );
}

#[test]
fn a_claude_run_brings_in_the_display_preferences_the_model_the_permission_settings_the_listed_variables_and_no_other_setting()
 {
    let host = FakeHost::new();
    host.profile()
        .with("claude")
        .with("bedrock")
        .create()
        .expect("a profile")
        .write(false)
        .expect("a write");
    let preferences = serde_json::json!({
        "theme": "light",
        "tui": "fullscreen",
        "outputStyle": "Concise",
        "editorMode": "vim",
        "verbose": true,
        "language": "french",
        "spinnerTipsEnabled": false,
        "spinnerVerbs": {"mode": "append", "verbs": ["Pondering"]},
        "preferredNotifChannel": "terminal_bell",
        "prefersReducedMotion": true,
        "showTurnDuration": false,
        "terminalProgressBarEnabled": false,
        "env": {
            "MAX_THINKING_TOKENS": "2048",
            "ANTHROPIC_MODEL": "global.anthropic.claude-opus-5-5",
            "ANTHROPIC_DEFAULT_OPUS_MODEL": "global.anthropic.claude-opus-5-5",
            "ANTHROPIC_DEFAULT_SONNET_MODEL": "global.anthropic.claude-sonnet-5-5",
            "ANTHROPIC_DEFAULT_HAIKU_MODEL": "global.anthropic.claude-haiku-5-5",
        },
        "model": "opus",
        "skipDangerousModePermissionPrompt": true,
        "permissions": {
            "defaultMode": "dontAsk",
            "allow": ["Bash(npm test:*)", "Edit"],
            "deny": ["Read(./.env)"],
            "ask": ["Bash(git push:*)"],
        },
    });
    let mut settings = preferences.clone();
    settings.as_object_mut().expect("an object").extend(
        serde_json::json!({
            "env": {
                "ANTHROPIC_API_KEY": "sk-host",
                "ANTHROPIC_BASE_URL": "https://elsewhere.example.com",
                "ANTHROPIC_SMALL_FAST_MODEL": "elsewhere-model",
                "MAX_THINKING_TOKENS": "2048",
                "ANTHROPIC_MODEL": "global.anthropic.claude-opus-5-5",
                "ANTHROPIC_DEFAULT_OPUS_MODEL": "global.anthropic.claude-opus-5-5",
                "ANTHROPIC_DEFAULT_SONNET_MODEL": "global.anthropic.claude-sonnet-5-5",
                "ANTHROPIC_DEFAULT_HAIKU_MODEL": "global.anthropic.claude-haiku-5-5",
            },
            "apiKeyHelper": "/bin/key",
            "awsAuthRefresh": "/bin/refresh",
            "otelHeadersHelper": "/bin/headers",
            "hooks": {"Stop": []},
            "statusLine": {"type": "command", "command": "/bin/status"},
            "fileSuggestion": {"type": "command", "command": "/bin/files"},
            "permissions": {
                "defaultMode": "dontAsk",
                "allow": ["Bash(npm test:*)", "Edit"],
                "deny": ["Read(./.env)"],
                "ask": ["Bash(git push:*)"],
                "disableBypassPermissionsMode": "disable",
                "additionalDirectories": ["/"],
            },
            "enabledPlugins": {"plugin": true},
        })
        .as_object()
        .expect("an object")
        .clone(),
    );
    let claude = host.home().join(".claude");
    std::fs::create_dir_all(&claude).expect("a folder");
    std::fs::write(claude.join("settings.json"), settings.to_string()).expect("settings");
    host.launcher()
        .prepare("claude", &host.project(), None)
        .expect("a launch");
    let copy = storage_root(&host.home().join(".strands/box"), "claude")
        .join("agent/config/settings.json");
    let copied: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(copy).expect("read")).expect("JSON");
    let mut expected = preferences;
    expected["skipWebFetchPreflight"] = true.into();
    assert_eq!(copied, expected);
}

#[test]
fn a_claude_run_fills_onboarding_this_projects_trust_and_the_toggles_and_replaces_nothing() {
    let host = FakeHost::new();
    host.profile()
        .with("claude")
        .option("claude.import-mcp", "true")
        .with("bedrock")
        .create()
        .expect("a profile")
        .write(false)
        .expect("a write");
    let workspace = resolved(&host.project()).display().to_string();
    let toggles = serde_json::json!({
        "copyFullResponse": true,
        "copyOnSelect": false,
        "externalEditorContext": true,
        "leftArrowOpensAgents": false,
        "prStatusFooterEnabled": false,
        "defaultToAgentsView": true,
    });
    let mut app = serde_json::json!({
        "hasCompletedOnboarding": true,
        "lastOnboardingVersion": "2.1.300",
        "oauthAccount": {"emailAddress": "host@example.com"},
        "userID": "host-user",
        "autoConnectIde": true,
        "projects": {
            workspace.clone(): {"hasTrustDialogAccepted": true, "allowedTools": ["Bash"]},
            "/elsewhere": {"hasTrustDialogAccepted": true},
        },
        "mcpServers": {"docs": {"url": "https://docs.example.com"}},
    });
    app.as_object_mut()
        .expect("an object")
        .extend(toggles.as_object().expect("an object").clone());
    std::fs::write(host.home().join(".claude.json"), app.to_string()).expect("app state");
    host.launcher()
        .prepare("claude", &host.project(), None)
        .expect("a launch");
    let copy =
        storage_root(&host.home().join(".strands/box"), "claude").join("agent/config/.claude.json");
    let read = || -> serde_json::Value {
        serde_json::from_str(&std::fs::read_to_string(&copy).expect("read")).expect("JSON")
    };
    let mut expected = serde_json::json!({
        "hasCompletedOnboarding": true,
        "lastOnboardingVersion": "2.1.300",
        "projects": {workspace.clone(): {"hasTrustDialogAccepted": true}},
        "mcpServers": {"docs": {"url": "https://docs.example.com"}},
    });
    expected
        .as_object_mut()
        .expect("an object")
        .extend(toggles.as_object().expect("an object").clone());
    assert_eq!(read(), expected);

    let saved = serde_json::json!({
        "hasCompletedOnboarding": false,
        "numStartups": 3,
        "copyOnSelect": true,
        "projects": {workspace.clone(): {"hasTrustDialogAccepted": false}},
    });
    std::fs::write(&copy, saved.to_string()).expect("the box's own state");
    let preview = host
        .launcher()
        .preview("claude", &host.project())
        .expect("a preview");
    let parts: Vec<_> = preview
        .parts
        .iter()
        .filter(|(_, target, _)| target == "agent/config/.claude.json")
        .collect();
    assert_eq!(parts.len(), 1, "{parts:?}");
    assert_eq!(parts[0].0, "fills");
    assert!(parts[0].2.starts_with(&[
        vec!["hasCompletedOnboarding".to_string()],
        vec!["lastOnboardingVersion".to_string()]
    ]));
    assert!(
        !parts[0]
            .2
            .iter()
            .any(|path| path.iter().any(|key| key == "oauthAccount"))
    );
    host.launcher()
        .prepare("claude", &host.project(), None)
        .expect("a second launch");
    let mut expected = saved.clone();
    let filled = expected.as_object_mut().expect("an object");
    filled.insert("lastOnboardingVersion".into(), "2.1.300".into());
    for (key, value) in toggles.as_object().expect("an object") {
        filled.entry(key.clone()).or_insert_with(|| value.clone());
    }
    filled.insert(
        "mcpServers".into(),
        serde_json::json!({"docs": {"url": "https://docs.example.com"}}),
    );
    assert_eq!(read(), expected);
}

#[test]
fn each_project_of_a_claude_profile_gets_its_own_auto_memory_in_one_shared_storage() {
    let host = FakeHost::new();
    host.profile()
        .with("claude")
        .with("bedrock")
        .create()
        .expect("a profile")
        .write(false)
        .expect("a write");
    let other = host.home().join("work/other");
    std::fs::create_dir_all(&other).expect("a second project");
    let projects = host.home().join(".claude/projects");
    for (workspace, word) in [(host.project(), "teal"), (other.clone(), "amber")] {
        let mine = projects.join(dashed(&workspace));
        std::fs::create_dir_all(mine.join("memory")).expect("a folder");
        std::fs::write(mine.join("memory/MEMORY.md"), word).expect("a memory");
        std::fs::write(mine.join("session.jsonl"), "{}").expect("a transcript");
    }
    std::fs::create_dir_all(projects.join("-elsewhere/memory")).expect("a folder");
    std::fs::write(projects.join("-elsewhere/memory/MEMORY.md"), "x").expect("a memory");
    let mut configs = Vec::new();
    for workspace in [host.project(), other.clone()] {
        let launch = host
            .launcher()
            .prepare("claude", &workspace, None)
            .expect("a launch");
        let file: toml::Table =
            toml::from_str(&std::fs::read_to_string(launch.config()).expect("read")).expect("TOML");
        assert!(
            file["agent"]["env"]
                .get("CLAUDE_CODE_PROJECT_DIR_NAME")
                .is_none()
        );
        configs.push(file["agent"]["env"]["CLAUDE_CONFIG_DIR"].clone());
    }
    assert_eq!(configs[0], configs[1], "one config folder for the profile");
    let config = storage_root(&host.home().join(".strands/box"), "claude").join("agent/config");
    for (workspace, word) in [(host.project(), "teal"), (other, "amber")] {
        let folder = config.join("projects").join(dashed(&workspace));
        assert_eq!(
            std::fs::read_to_string(folder.join("memory/MEMORY.md")).expect("read"),
            word
        );
        assert!(!folder.join("session.jsonl").exists());
    }
    assert_eq!(
        std::fs::read_dir(config.join("projects"))
            .expect("a folder")
            .count(),
        2
    );
}

#[test]
fn a_claude_profile_takes_host_edits_on_each_run_and_keeps_the_boxs_memory() {
    let host = FakeHost::new();
    host.profile()
        .with("claude")
        .with("bedrock")
        .create()
        .expect("a profile")
        .write(false)
        .expect("a write");
    let claude = host.home().join(".claude");
    let memory = claude
        .join("projects")
        .join(dashed(&host.project()))
        .join("memory");
    std::fs::create_dir_all(&memory).expect("a folder");
    std::fs::write(memory.join("MEMORY.md"), "host notes").expect("a memory");
    std::fs::write(claude.join("CLAUDE.md"), "first").expect("instructions");
    std::fs::create_dir_all(claude.join("skills/review")).expect("a skill");
    std::fs::write(claude.join("skills/review/SKILL.md"), "review 1").expect("a skill");
    let other = host.home().join("work/other");
    std::fs::create_dir_all(&other).expect("a second project");
    let config = storage_root(&host.home().join(".strands/box"), "claude").join("agent/config");
    host.launcher()
        .prepare("claude", &host.project(), None)
        .expect("a launch");
    let box_memory = config
        .join("projects")
        .join(dashed(&host.project()))
        .join("memory/MEMORY.md");
    std::fs::write(&box_memory, "box notes").expect("the box's notes");

    std::fs::write(claude.join("CLAUDE.md"), "second").expect("a host edit");
    std::fs::write(claude.join("skills/review/SKILL.md"), "review 2").expect("a host edit");
    std::fs::write(memory.join("MEMORY.md"), "host notes, changed").expect("a host edit");
    let launch = host
        .launcher()
        .prepare("claude", &other, None)
        .expect("a launch in another project");
    assert_eq!(
        launch.synced(),
        [
            "updated agent/config/CLAUDE.md from ~/.claude/CLAUDE.md",
            "updated agent/config/skills/review/SKILL.md from ~/.claude/skills",
        ]
    );
    assert_eq!(
        std::fs::read_to_string(config.join("CLAUDE.md")).expect("read"),
        "second"
    );
    assert_eq!(
        std::fs::read_to_string(config.join("skills/review/SKILL.md")).expect("read"),
        "review 2"
    );
    host.launcher()
        .prepare("claude", &host.project(), None)
        .expect("a launch");
    assert_eq!(
        std::fs::read_to_string(&box_memory).expect("read"),
        "box notes",
        "memory is not synced"
    );
}

#[test]
fn a_second_project_of_a_claude_profile_gets_its_own_trust_and_project_servers() {
    let host = FakeHost::new();
    host.profile()
        .with("claude")
        .option("claude.import-mcp", "true")
        .with("bedrock")
        .create()
        .expect("a profile")
        .write(false)
        .expect("a write");
    let other = host.home().join("work/other");
    std::fs::create_dir_all(&other).expect("a second project");
    let first = resolved(&host.project()).display().to_string();
    let second = resolved(&other).display().to_string();
    let app = serde_json::json!({
        "hasCompletedOnboarding": true,
        "mcpServers": {"user": {"url": "https://user.example.com"}},
        "projects": {
            first.clone(): {"hasTrustDialogAccepted": true,
                "mcpServers": {"one": {"url": "https://one.example.com"}}},
            second.clone(): {"hasTrustDialogAccepted": true,
                "mcpServers": {"two": {"url": "https://two.example.com"}}},
        },
    });
    std::fs::write(host.home().join(".claude.json"), app.to_string()).expect("app state");
    for workspace in [host.project(), other] {
        host.launcher()
            .prepare("claude", &workspace, None)
            .expect("a launch");
    }
    let copy =
        storage_root(&host.home().join(".strands/box"), "claude").join("agent/config/.claude.json");
    let copied: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(copy).expect("read")).expect("JSON");
    assert_eq!(
        copied,
        serde_json::json!({
            "hasCompletedOnboarding": true,
            "mcpServers": {"user": {"url": "https://user.example.com"}},
            "projects": {
                first: {"hasTrustDialogAccepted": true,
                    "mcpServers": {"one": {"url": "https://one.example.com"}}},
                second: {"hasTrustDialogAccepted": true,
                    "mcpServers": {"two": {"url": "https://two.example.com"}}},
            },
        })
    );
}

#[test]
fn a_claude_box_reads_the_managed_policy_that_this_host_has() {
    let host = FakeHost::new();
    host.profile()
        .with("claude")
        .with("bedrock")
        .create()
        .expect("a profile")
        .write(false)
        .expect("a write");
    let preview = host
        .launcher()
        .preview("claude", &host.project())
        .expect("a preview");
    let file: toml::Table = toml::from_str(&preview.box_toml).expect("TOML");
    let list = |key: &str| -> Vec<String> {
        file["agent"]["filesystem"]
            .get(key)
            .and_then(toml::Value::as_array)
            .map(|entries| {
                entries
                    .iter()
                    .filter_map(|entry| entry.as_str().map(str::to_string))
                    .collect()
            })
            .unwrap_or_default()
    };
    let folder = if cfg!(target_os = "macos") {
        "/Library/Application Support/ClaudeCode"
    } else {
        "/etc/claude-code"
    };
    let present = |paths: Vec<String>| -> Vec<String> {
        paths
            .into_iter()
            .filter(|path| Path::new(path).exists())
            .map(|path| resolved(Path::new(&path)).display().to_string())
            .collect()
    };
    let policy = |key: &str| -> Vec<String> {
        list(key)
            .into_iter()
            .filter(|entry| {
                ["/etc/claude-code", "/Library/", "/usr/bin/plutil"]
                    .iter()
                    .any(|root| entry.starts_with(root))
                    || present(vec![folder.to_string()])
                        .iter()
                        .any(|real| entry.starts_with(real.as_str()))
            })
            .collect()
    };
    let mut files: Vec<String> = ["managed-settings.json", "managed-mcp.json", "CLAUDE.md"]
        .iter()
        .map(|name| format!("{folder}/{name}"))
        .collect();
    let mut exec = Vec::new();
    if cfg!(target_os = "macos") {
        files.insert(
            0,
            "/Library/Managed Preferences/com.anthropic.claudecode.plist".to_string(),
        );
        exec.push("/usr/bin/plutil".to_string());
    }
    assert_eq!(policy("read"), present(vec![folder.to_string()]));
    assert_eq!(policy("read_file"), present(files));
    assert_eq!(policy("exec"), present(exec));
}

#[test]
fn a_claude_run_declares_the_operators_and_the_projects_mcp_servers() {
    let host = FakeHost::new();
    let keg = brew_program(&host, "mcp-fetch");
    brew_program(&host, "mcp-issues");
    brew_program(&host, "mcp-tracker");
    std::fs::write(
        host.home().join(".claude.json"),
        format!(
            r#"{{"mcpServers": {{"fetch": {{"type": "stdio", "command": "mcp-fetch", "args": [], "env": {{}}}},
                 "issues": {{"command": "mcp-issues", "args": ["--token", "${{BOX_TEST_TOKEN}}"],
                             "env": {{"ISSUES_TOKEN": "${{BOX_TEST_TOKEN}}", "LOG_LEVEL": "info", "HTTPS_PROXY": "http://proxy.example.com"}}}},
                 "github": {{"type": "http", "url": "https://api.githubcopilot.com/mcp/", "headers": {{"Authorization": "Bearer x"}}}},
                 "keyed": {{"url": "https://keyed.example.com/mcp", "headers": {{"Authorization": "Bearer ${{BOX_TEST_UNSET}}"}}}}}},
                "projects": {{"{}": {{"mcpServers": {{"docs": {{"type": "http", "url": "https://docs.example.com/mcp"}},
                    "tracker": {{"command": "mcp-tracker", "env": {{"TRACKER_TOKEN": "${{BOX_TEST_TOKEN}}"}}}}}}}}}}}}"#,
            host.project().display()
        ),
    )
    .expect("a host file");
    host.profile()
        .with("claude")
        .option("claude.import-mcp", "true")
        .with("bedrock")
        .policy("open")
        .create()
        .expect("a profile")
        .write(false)
        .expect("a write");
    let environment = [("BOX_TEST_TOKEN", "ghp_real")];
    let preview = host
        .launcher()
        .environment(&environment)
        .preview("claude", &host.project())
        .expect("a preview");
    assert_eq!(
        preview.mcp_servers,
        vec![
            (
                "docs".to_string(),
                "~/.claude.json".to_string(),
                String::new()
            ),
            (
                "fetch".to_string(),
                "~/.claude.json".to_string(),
                String::new()
            ),
            (
                "github".to_string(),
                "~/.claude.json".to_string(),
                String::new()
            ),
            (
                "issues".to_string(),
                "~/.claude.json".to_string(),
                ", with ISSUES_TOKEN, LOG_LEVEL".to_string()
            ),
            (
                "tracker".to_string(),
                "~/.claude.json".to_string(),
                ", with TRACKER_TOKEN".to_string()
            ),
        ]
    );
    assert_eq!(
        preview.mcp_dropped,
        vec![(
            "HTTPS_PROXY".to_string(),
            "issues".to_string(),
            "~/.claude.json".to_string(),
            "the box sets it itself".to_string()
        )]
    );
    assert_eq!(
        preview.mcp_skipped,
        vec![(
            "keyed".to_string(),
            "~/.claude.json".to_string(),
            "needs BOX_TEST_UNSET, which is not set in your environment".to_string()
        )]
    );
    let file: toml::Table = toml::from_str(&preview.box_toml).expect("TOML");
    assert_eq!(
        file["mcp"]["fetch"]["filesystem"]["read"][1].as_str(),
        Some(keg.display().to_string().as_str()),
        "the selected Homebrew keg: {}",
        keg.display()
    );
    assert_eq!(
        file["mcp"]["docs"]["destinations"][0].as_str(),
        Some("docs.example.com")
    );
    assert_eq!(
        file["mcp"]["tracker"]["env"]["TRACKER_TOKEN"].as_str(),
        Some("ghp_real"),
        "the project row of the shipped pack expands env too"
    );
    let issues = &file["mcp"]["issues"];
    assert_eq!(
        issues["command"],
        toml::Value::Array(
            ["mcp-issues", "--token", "*"]
                .map(toml::Value::from)
                .to_vec()
        )
    );
    assert_eq!(
        issues["env"],
        toml::from_str::<toml::Value>("ISSUES_TOKEN = \"ghp_real\"\nLOG_LEVEL = \"info\"")
            .expect("TOML"),
        "the server's env holds the real value"
    );
    assert!(
        issues.get("network").is_none(),
        "a detected server keeps its contained egress"
    );
    assert!(
        file["agent"]
            .get("env")
            .and_then(|env| env.get("ISSUES_TOKEN"))
            .is_none(),
        "the agent does not get the server's key"
    );
    let launch = host
        .launcher()
        .environment(&environment)
        .prepare("claude", &host.project(), None)
        .expect("a launch");
    assert_eq!(launch.mcp_servers(), preview.mcp_servers.as_slice());
    assert_eq!(launch.mcp_dropped(), preview.mcp_dropped.as_slice());
    assert_eq!(launch.mcp_skipped(), preview.mcp_skipped.as_slice());
    host.profile()
        .with("claude")
        .with("bedrock")
        .option("claude.import-mcp", "false")
        .create()
        .expect("a profile")
        .write(true)
        .expect("a write");
    let preview = host
        .launcher()
        .preview("claude", &host.project())
        .expect("a preview");
    assert!(preview.mcp_servers.is_empty() && preview.mcp_skipped.is_empty());
    assert!(!preview.box_toml.contains("[mcp."), "{}", preview.box_toml);
}

#[test]
fn claude_code_comes_from_its_install_not_the_link_to_it() {
    let host = FakeHost::new();
    let generated = host
        .trial()
        .with("claude")
        .with("bedrock")
        .generate()
        .expect("a configuration");
    assert_eq!(generated.agent(), host.claude_install());
}

#[test]
fn a_claude_on_the_path_comes_before_the_standalone_install() {
    let host = FakeHost::new();
    let bin = host.home().join("path-bin");
    script(&bin.join("claude"), "true");
    let trial = || {
        host.trial()
            .with("claude")
            .with("bedrock")
            .search_path(format!("{}:{}", bin.display(), host.search_path()))
            .generate()
            .expect("a configuration")
    };
    assert_eq!(trial().agent(), bin.join("claude"));
    std::fs::remove_dir_all(&bin).expect("remove");
    assert_eq!(trial().agent(), host.claude_install());
}

#[test]
fn a_standalone_install_runs_the_version_the_installer_linked() {
    let host = FakeHost::new();
    host.uninstall_claude();
    let versions = host.home().join(".local/share/claude/versions");
    for version in ["2.1.9", "2.1.280"] {
        script(&versions.join(version), "true");
    }
    strands_box_cli_profile::fixtures::link(
        &versions.join("2.1.9").display().to_string(),
        &host.home().join(".local/bin/claude"),
    );
    let generated = host
        .trial()
        .with("claude")
        .with("bedrock")
        .generate()
        .expect("a configuration");
    assert_eq!(generated.agent(), versions.join("2.1.9"));
}

#[test]
fn no_claude_code_is_a_host_absence() {
    let host = FakeHost::new();
    host.uninstall_claude();
    let error = host
        .trial()
        .with("claude")
        .with("bedrock")
        .generate()
        .expect_err("no agent");
    no_agent(&error, "claude");
}

#[test]
fn a_claude_box_gets_only_the_listed_host_variables_that_the_shell_sets() {
    const LISTED: [&str; 14] = [
        "BASH_DEFAULT_TIMEOUT_MS",
        "BASH_MAX_TIMEOUT_MS",
        "BASH_MAX_OUTPUT_LENGTH",
        "CLAUDE_CODE_MAX_OUTPUT_TOKENS",
        "MAX_THINKING_TOKENS",
        "CLAUDE_CODE_EFFORT_LEVEL",
        "MAX_MCP_OUTPUT_TOKENS",
        "MCP_TIMEOUT",
        "MCP_TOOL_TIMEOUT",
        "CLAUDE_CODE_DISABLE_TERMINAL_TITLE",
        "ANTHROPIC_MODEL",
        "ANTHROPIC_DEFAULT_OPUS_MODEL",
        "ANTHROPIC_DEFAULT_SONNET_MODEL",
        "ANTHROPIC_DEFAULT_HAIKU_MODEL",
    ];
    let value = |name: &str| {
        if name == "CLAUDE_CODE_EFFORT_LEVEL" {
            "${{ home }}".to_string()
        } else {
            format!("{name}-value")
        }
    };
    let host = FakeHost::new();
    let env = |set: bool, option: Option<&str>| {
        let mut trial = host.trial().with("claude").with("bedrock");
        if let Some(value) = option {
            trial = trial.option("claude.import-env", value);
        }
        if set {
            for name in LISTED {
                trial = trial.variable(name, value(name));
            }
            trial = trial
                .variable("ANTHROPIC_BASE_URL", "https://elsewhere.example.com")
                .variable("CLAUDE_CODE_USE_VERTEX", "1");
        }
        let generated = trial.generate().expect("a configuration");
        let file: toml::Value = toml::from_str(generated.box_toml()).expect("TOML");
        (
            file["agent"]["env"]
                .as_table()
                .expect("an env table")
                .clone(),
            generated.inputs().to_vec(),
        )
    };
    let (baseline, _) = env(false, None);
    let (passed, inputs) = env(true, None);
    let mut expected = baseline.clone();
    for name in LISTED {
        expected.insert(name.to_string(), toml::Value::String(value(name)));
    }
    assert_eq!(passed, expected);
    assert!(
        inputs.iter().any(|(name, value, source)| {
            name == "agent.env.MAX_THINKING_TOKENS"
                && value == "MAX_THINKING_TOKENS-value"
                && source == "env:MAX_THINKING_TOKENS"
        }),
        "{inputs:?}"
    );
    let (off, _) = env(true, Some("false"));
    assert_eq!(off, baseline);
}

#[test]
fn a_claude_inside_the_project_is_never_run() {
    let host = FakeHost::new();
    host.uninstall_claude();
    let planted = host.project().join("bin");
    let marker = host.home().join("planted-ran");
    script(
        &planted.join("claude"),
        &format!("touch '{}'; echo '9 (Claude Code)'", marker.display()),
    );
    let error = host
        .trial()
        .with("claude")
        .with("bedrock")
        .search_path(format!("{}:/usr/bin:/bin", planted.display()))
        .generate()
        .expect_err("no agent");
    no_agent(&error, "claude");
    assert!(
        error
            .to_string()
            .contains("(in the workspace, which a box can write)"),
        "{error}"
    );
    assert!(!marker.exists());
}

#[test]
fn claude_code_keeps_its_permission_prompts_by_default() {
    let host = FakeHost::new();
    let generated = host
        .trial()
        .with("claude")
        .with("bedrock")
        .generate()
        .expect("a configuration");
    let mut expected = vec![generated.agent().to_str().expect("UTF-8").to_string()];
    expected.extend(box_guidance(&host));
    assert_eq!(agent_command(&generated), expected);
}

#[test]
fn a_claude_box_tells_claude_code_it_runs_in_a_box_and_lets_it_read_the_guidance() {
    let host = FakeHost::new();
    let generated = host
        .trial()
        .with("claude")
        .with("bedrock")
        .generate()
        .expect("a configuration");
    let guidance = resources().join("packs/claude/box.md");
    let text = std::fs::read_to_string(&guidance).expect("the claude pack ships box.md");
    assert!(text.starts_with("# You run in a box"));
    assert!(text.contains(SHELL_NOTE), "{text}");
    assert!(text.contains(OUTSIDE_FILES_NOTE), "{text}");
    assert!(text.contains(RESTART_NOTE), "{text}");
    assert!(text.contains(DNS_NOTE), "{text}");
    let config: toml::Value = toml::from_str(generated.box_toml()).expect("box.toml parses");
    let read_file = config["agent"]["filesystem"]["read_file"]
        .as_array()
        .expect("read_file");
    assert!(
        read_file
            .iter()
            .any(|entry| entry.as_str() == guidance.to_str()),
        "{read_file:?}"
    );
}

#[test]
fn skip_permissions_turns_off_claude_codes_prompts() {
    let host = FakeHost::new();
    let generated = host
        .trial()
        .with("claude")
        .with("bedrock")
        .option("agent.skip-permissions", "true")
        .agent_args(&["--verbose"])
        .generate()
        .expect("a configuration");
    let mut expected: Vec<String> = [
        generated.agent().to_str().expect("UTF-8"),
        "--dangerously-skip-permissions",
        "--settings",
        r#"{"skipDangerousModePermissionPrompt":true}"#,
    ]
    .map(String::from)
    .to_vec();
    expected.extend(box_guidance(&host));
    expected.push("--verbose".to_string());
    assert_eq!(agent_command(&generated), expected);
}

#[test]
fn a_claude_code_box_turns_on_claude_codes_own_exporter_for_all_three_signals() {
    let host = FakeHost::new();
    let generated = host
        .trial()
        .with("claude")
        .with("bedrock")
        .generate()
        .expect("a configuration");
    let file: toml::Value = toml::from_str(generated.box_toml()).expect("TOML");
    let env = file["agent"]["env"].as_table().expect("env");
    for (name, value) in [
        ("CLAUDE_CODE_ENABLE_TELEMETRY", "1"),
        ("CLAUDE_CODE_ENHANCED_TELEMETRY_BETA", "1"),
        ("CLAUDE_CODE_PROPAGATE_TRACEPARENT", "1"),
        ("OTEL_TRACES_EXPORTER", "otlp"),
        ("OTEL_LOGS_EXPORTER", "otlp"),
        ("OTEL_METRICS_EXPORTER", "otlp"),
    ] {
        assert_eq!(env.get(name).and_then(toml::Value::as_str), Some(value));
    }
    // Every default is tens of seconds, so a short run ends before a batch leaves.
    for name in [
        "OTEL_TRACES_EXPORT_INTERVAL",
        "OTEL_BSP_SCHEDULE_DELAY",
        "OTEL_LOGS_EXPORT_INTERVAL",
        "OTEL_BLRP_SCHEDULE_DELAY",
        "OTEL_METRICS_EXPORT_INTERVAL",
        "OTEL_METRIC_EXPORT_INTERVAL",
    ] {
        let value = env
            .get(name)
            .and_then(toml::Value::as_str)
            .unwrap_or_else(|| panic!("{name} in {env:?}"));
        assert!(
            value.parse::<u32>().is_ok_and(|delay| delay <= 5_000),
            "{name} is {value}"
        );
    }
}

#[test]
fn a_claude_box_keeps_its_configuration_and_scratch_in_storage() {
    let host = FakeHost::new();
    let generated = host
        .trial()
        .with("claude")
        .with("bedrock")
        .generate()
        .expect("a configuration");
    assert!(
        generated
            .storage()
            .starts_with(host.home().join(".strands/box/storage/claude")),
        "{}",
        generated.storage().display()
    );
    assert_eq!(
        generated.directories(),
        [
            generated.storage().join("agent/config"),
            generated.storage().join("agent/tmp")
        ]
    );
    let file: toml::Value = toml::from_str(generated.box_toml()).expect("TOML");
    let config = generated
        .storage()
        .join("agent/config")
        .display()
        .to_string();
    assert_eq!(
        file["agent"]["env"]["CLAUDE_CONFIG_DIR"].as_str(),
        Some(config.as_str())
    );
    assert!(
        generated
            .box_toml()
            .contains("bedrock-runtime.us-west-2.amazonaws.com")
    );
}

#[test]
fn an_npm_installed_claude_code_is_not_taken() {
    let host = FakeHost::new();
    host.uninstall_claude();
    let bin = host.home().join("npm-bin");
    std::fs::create_dir_all(&bin).expect("a directory");
    std::fs::write(
        bin.join("claude"),
        "#!/usr/bin/env node\nconsole.log('2.1.280 (Claude Code)')\n",
    )
    .expect("a launcher");
    std::fs::set_permissions(
        bin.join("claude"),
        std::os::unix::fs::PermissionsExt::from_mode(0o755),
    )
    .expect("mode 0755");
    let error = host
        .trial()
        .with("claude")
        .with("bedrock")
        .search_path(format!("{}:{}", bin.display(), host.search_path()))
        .generate()
        .expect_err("no agent");
    no_agent(&error, "claude");
    assert!(
        error
            .to_string()
            .contains("(a node script, which the box cannot start)"),
        "{error}"
    );
}

#[test]
fn a_claude_box_imports_no_hook_by_default_and_permits_the_read_of_each_imported_script() {
    let host = FakeHost::new();
    let hooks = host.home().join(".claude/hooks");
    std::fs::create_dir_all(&hooks).expect("a folder");
    std::fs::write(hooks.join("fmt.sh"), "exit 0\n").expect("a script");
    std::fs::write(
        host.home().join(".claude/settings.json"),
        r#"{"hooks":{"PostToolUse":[{"matcher":"Edit","hooks":[
            {"type":"command","command":"~/.claude/hooks/fmt.sh","timeout":5},
            {"type":"command","command":"bash ~/.claude/hooks/fmt.sh"}]}]}}"#,
    )
    .expect("host settings");
    let script = hooks
        .join("fmt.sh")
        .canonicalize()
        .expect("canonical")
        .display()
        .to_string();
    let permit = format!(
        "@id(\"hook_script_0_read\") permit (principal, action == Box::Action::\"fs:read\", \
         resource) when {{ context.input.path == {:?} }};",
        strands_box_cli_profile::host::tilde(
            &host.home().canonicalize().expect("canonical"),
            Path::new(&script)
        )
    );

    let off = host
        .trial()
        .with("claude")
        .with("bedrock")
        .generate()
        .expect("a configuration");
    assert_eq!(off.hooks().len(), 1);
    assert!(!off.hooks()[0].import, "hooks are off by default");
    assert!(!off.box_toml().contains(&script), "{}", off.box_toml());
    assert!(!off.policy().contains("hook_script_"), "{}", off.policy());

    let on = host
        .trial()
        .with("claude")
        .with("bedrock")
        .option("claude.import-hooks", "true")
        .generate()
        .expect("a configuration");
    assert!(on.hooks()[0].import);
    assert!(
        !on.box_toml().contains("fmt.sh") && !on.box_toml().contains(".claude/hooks"),
        "the script gets no grant: {}",
        on.box_toml()
    );
    assert!(on.policy().contains(&permit), "{}", on.policy());
    assert_eq!(
        on.policy().matches("hook_script_").count(),
        1,
        "one permit for one script: {}",
        on.policy()
    );
    assert!(
        on.generated_ids()
            .contains(&"hook_script_0_read".to_string()),
        "{:?}",
        on.generated_ids()
    );
}

/// Box Core accepts the permit that a run generates for an imported script, and the copy in
/// storage holds the hook in the form that the pack states.
#[test]
fn a_claude_run_with_imported_hooks_passes_box_cores_policy_check_and_writes_the_copy() {
    let host = FakeHost::new();
    strands_box_cli_profile::fixtures::write(&host.home().join(".claude/hooks/fmt.sh"), "exit 0\n");
    strands_box_cli_profile::fixtures::write(
        &host.home().join(".claude/settings.json"),
        r#"{"disableAllHooks":false,"hooks":{"PostToolUse":[{"matcher":"Edit","hooks":[
            {"type":"command","command":"~/.claude/hooks/fmt.sh","timeout":5,"shell":"bash"},
            {"type":"command","command":"~/.claude/hooks/fmt.sh","shell":"powershell"}]}]}}"#,
    );
    host.profile()
        .with("claude")
        .with("bedrock")
        .option("claude.import-hooks", "true")
        .create()
        .expect("a profile")
        .write(false)
        .expect("a write");

    let launch = host
        .launcher()
        .prepare("claude", &host.project(), None)
        .expect("Box Core accepts the generated permit");

    let script = host
        .home()
        .join(".claude/hooks/fmt.sh")
        .canonicalize()
        .expect("canonical");
    assert!(
        launch
            .hooks()
            .iter()
            .any(|line| line.starts_with("imported hooks run ")
                && line.ends_with("/.claude/hooks/fmt.sh, and the policy permits its read")),
        "{:?}",
        launch.hooks()
    );
    assert!(
        launch.hooks().iter().any(|line| line
            == "did not import the hook PostToolUse (Edit) #2: the hook's `shell` is \
                `powershell`; box imports the hook only when it is `bash`"),
        "{:?}",
        launch.hooks()
    );
    let copy =
        strands_box_cli_profile::lang::storage_root(&host.home().join(".strands/box"), "claude")
            .join("agent/config/settings.json");
    let copy: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(copy).expect("the copy")).expect("JSON");
    assert_eq!(
        copy["hooks"],
        serde_json::json!({"PostToolUse": [{"matcher": "Edit", "hooks": [{
            "type": "command",
            "timeout": 5,
            "command": "bash",
            "args": ["-c", format!(". {}", script.display())],
        }]}]})
    );
}

#[test]
fn a_claude_box_on_bedrock_turns_off_webfetchs_domain_lookup_on_every_run() {
    let host = FakeHost::new();
    host.profile()
        .with("claude")
        .with("bedrock")
        .create()
        .expect("a profile")
        .write(false)
        .expect("a write");
    let skip = vec![vec!["skipWebFetchPreflight".to_string()]];
    let preview = host
        .launcher()
        .preview("claude", &host.project())
        .expect("a preview");
    assert!(
        preview
            .parts
            .iter()
            .any(|(what, target, names)| what == "sets"
                && target == "agent/config/settings.json"
                && names == &skip),
        "{:?}",
        preview.parts
    );
    let copy = storage_root(&host.home().join(".strands/box"), "claude")
        .join("agent/config/settings.json");
    let read = || -> serde_json::Value {
        serde_json::from_str(&std::fs::read_to_string(&copy).expect("read")).expect("JSON")
    };
    host.launcher()
        .prepare("claude", &host.project(), None)
        .expect("a launch");
    assert_eq!(
        read(),
        serde_json::json!({"skipWebFetchPreflight": true}),
        "a host with no settings file gets a copy that holds only the setting"
    );
    std::fs::write(
        &copy,
        r#"{"skipWebFetchPreflight": false, "theme": "dark"}"#,
    )
    .expect("the box's own edit");
    host.launcher()
        .prepare("claude", &host.project(), None)
        .expect("a second launch");
    assert_eq!(
        read(),
        serde_json::json!({"skipWebFetchPreflight": true, "theme": "dark"}),
        "each run sets it again and keeps the rest of the copy"
    );
}

#[test]
fn a_claude_box_on_the_anthropic_api_keeps_webfetchs_domain_lookup_and_routes_its_host() {
    let host = FakeHost::new();
    host.profile()
        .with("claude")
        .with("anthropic")
        .option("claude.host", "anthropic")
        .create()
        .expect("a profile")
        .write(false)
        .expect("a write");
    write(
        &host.home().join(".claude/settings.json"),
        r#"{"theme": "dark"}"#,
    );
    let preview = host
        .launcher()
        .preview("claude", &host.project())
        .expect("a preview");
    assert!(
        !preview
            .parts
            .iter()
            .any(|(what, target, _)| what == "sets" && target == "agent/config/settings.json"),
        "{:?}",
        preview.parts
    );
    host.launcher()
        .prepare("claude", &host.project(), None)
        .expect("a launch");
    let copy = storage_root(&host.home().join(".strands/box"), "claude")
        .join("agent/config/settings.json");
    let copied: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(copy).expect("read")).expect("JSON");
    assert_eq!(copied, serde_json::json!({"theme": "dark"}));
    let generated = host
        .trial()
        .with("claude")
        .with("anthropic")
        .option("claude.host", "anthropic")
        .generate()
        .expect("a configuration");
    let file: toml::Value = toml::from_str(generated.box_toml()).expect("TOML");
    assert_eq!(
        strings(&file["egress"]["anthropic"]["destinations"]),
        ["api.anthropic.com"],
        "Claude Code asks api.anthropic.com/api/web/domain_info before each WebFetch"
    );
}

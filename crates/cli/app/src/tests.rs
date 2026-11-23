#![cfg(any(target_os = "macos", target_os = "linux"))]

use std::path::{Path, PathBuf};

use crate::report::NAME_COLUMN;
use crate::test_support::{Trial, codex_settings, no_agent, resolution, script};
use crate::{Error, FakeHost};

fn codex(host: &FakeHost) -> Trial {
    host.trial().with("codex").with("bedrock-mantle")
}

#[test]
fn line_menus_distinguish_escape_from_closed_input_and_interrupts() {
    for keys in [b"".as_slice(), b"\x03\n", b"\x04\n", b"\x1b\n"] {
        let mut input = keys;
        let mut output = Vec::new();
        let mut terminal = crate::starter::Terminal::new(&mut input, &mut output);
        let result = terminal.menu("Profiles", "box profile --help", &["Create"]);
        if keys == b"\x1b\n" {
            assert!(matches!(result, Err(Error::StarterAborted { .. })));
        } else {
            assert!(matches!(result, Err(Error::Interrupted)), "{keys:?}");
        }
    }
}

#[test]
fn every_tool_gets_its_own_scratch_folder_and_no_one_else_reaches_it() {
    let host = FakeHost::new();
    let generated = host
        .trial()
        .with("claude")
        .with("bedrock")
        .generate()
        .expect("a configuration");
    let file: toml::Value = toml::from_str(generated.box_toml()).expect("TOML");
    let run = Path::new(file["box_dir"].as_str().expect("a box folder"))
        .parent()
        .expect("the run's directory")
        .to_path_buf();
    let text = |path: &Path| path.display().to_string();
    let list = |table: &toml::Value, key: &str| -> Vec<String> {
        table["filesystem"]
            .get(key)
            .and_then(toml::Value::as_array)
            .map(|entries| {
                entries
                    .iter()
                    .filter_map(toml::Value::as_str)
                    .map(str::to_string)
                    .collect()
            })
            .unwrap_or_default()
    };
    let lists = ["read", "write", "read_file", "write_file"];
    for (name, table) in every_tool(&file) {
        let own = text(&run.join("tool-tmp").join(name));
        assert_eq!(
            table["env"]["TMPDIR"].as_str(),
            Some(own.as_str()),
            "{name}"
        );
        for key in ["read", "write"] {
            assert!(list(table, key).contains(&own), "{name} {key}");
        }
        for key in lists {
            let entries = list(table, key);
            assert!(
                entries
                    .iter()
                    .filter(|entry| Path::new(entry.as_str()).starts_with(&run))
                    .all(|entry| *entry == own),
                "{name} reaches nothing else in the run's directory (box.toml, policy.dw, \
                 the journal, box/, another tool's folder): {key} {entries:?}"
            );
        }
    }
    for key in lists {
        let entries = list(&file["agent"], key);
        assert!(
            entries
                .iter()
                .all(|entry| !Path::new(entry.as_str()).starts_with(run.join("tool-tmp"))),
            "the agent reaches no tool's folder: {key} {entries:?}"
        );
    }
}

#[test]
fn a_tool_that_cannot_be_given_a_table_is_skipped_with_its_reason() {
    let host = FakeHost::new();
    std::fs::remove_file(host.brew().join("bin/node")).expect("remove node");
    let generated = host
        .trial()
        .with("claude")
        .with("bedrock")
        .search_path(host.own_search_path())
        .tools(["git", "npm"])
        .generate()
        .expect("a configuration");
    assert_eq!(generated.resolutions().len(), 1);
    assert_eq!(
        generated.skipped(),
        [
            (
                "node (@box/node)".to_string(),
                "node is not on PATH".to_string()
            ),
            (
                "npm (@box/npm)".to_string(),
                "it runs node, and node was skipped".to_string()
            ),
        ]
    );
    assert!(!generated.policy().contains("spawn_npm"));
}

#[test]
fn an_unknown_tool_is_refused() {
    let host = FakeHost::new();
    let error = host
        .trial()
        .with("claude")
        .with("bedrock")
        .tools(["ruby"])
        .generate()
        .expect_err("unknown");
    assert!(matches!(error, Error::UnknownTool { .. }), "{error}");
}

#[test]
fn a_project_holding_the_configuration_or_the_box_is_refused() {
    let host = FakeHost::with_project(".strands/box");
    let error = host
        .trial()
        .with("claude")
        .with("bedrock")
        .generate()
        .expect_err("a refusal");
    assert!(matches!(error, Error::ProjectHoldsBox { .. }), "{error}");
}

#[test]
fn a_tool_table_declares_no_workspace_and_the_agent_declares_the_project() {
    let host = FakeHost::new();
    let generated = host
        .trial()
        .with("claude")
        .with("bedrock")
        .generate()
        .expect("a configuration");
    let file: toml::Value = toml::from_str(generated.box_toml()).expect("TOML");
    assert_eq!(
        file["agent"]["workspace"].as_str(),
        generated.project().to_str()
    );
    for (name, table) in every_tool(&file) {
        assert!(table.get("workspace").is_none(), "{name}");
    }
}

#[test]
fn a_tool_table_carries_only_the_lists_a_tool_may_hold() {
    let host = FakeHost::new();
    let generated = host
        .trial()
        .with("claude")
        .with("bedrock")
        .generate()
        .expect("a configuration");
    let file: toml::Value = toml::from_str(generated.box_toml()).expect("TOML");
    for (name, table) in every_tool(&file) {
        let lists = table["filesystem"].as_table().expect("filesystem");
        assert!(
            !lists.contains_key("exec") && !lists.contains_key("metadata"),
            "{name}"
        );
    }
}

#[test]
fn the_agent_runs_only_its_own_binary_the_policy_reader_and_no_host_shell() {
    let host = FakeHost::new();
    let generated = host
        .trial()
        .with("claude")
        .with("bedrock")
        .generate()
        .expect("a configuration");
    let file: toml::Value = toml::from_str(generated.box_toml()).expect("TOML");
    let exec: Vec<&str> = file["agent"]["filesystem"]["exec"]
        .as_array()
        .expect("an exec list")
        .iter()
        .filter_map(toml::Value::as_str)
        .collect();
    let agent = generated.agent().to_str().expect("UTF-8");
    let plutil = std::path::Path::new("/usr/bin/plutil");
    if cfg!(target_os = "macos") && plutil.exists() {
        assert_eq!(exec, [agent, "/usr/bin/plutil"]);
    } else {
        assert_eq!(exec, [agent]);
    }
}

/// Every `[tool.*]` table: the fake host's toolchains.
fn every_tool(file: &toml::Value) -> &toml::map::Map<String, toml::Value> {
    let tools = file["tool"].as_table().expect("tools");
    assert_eq!(
        tools.keys().map(String::as_str).collect::<Vec<_>>(),
        ["cargo", "git", "node", "npm"]
    );
    tools
}

#[test]
fn a_tool_inside_the_project_is_skipped() {
    let host = FakeHost::new();
    let planted = host.project().join("bin");
    script(&planted.join("node"), "echo planted");
    let generated = host
        .trial()
        .with("claude")
        .with("bedrock")
        .search_path(format!("{}:{}", planted.display(), host.search_path()))
        .generate()
        .expect("a configuration");
    let (_, why) = generated
        .skipped()
        .iter()
        .find(|(name, _)| name == "node (@box/node)")
        .expect("node is skipped");
    assert!(why.contains("lies in the workspace"), "{why}");
}

#[test]
fn a_star_in_the_project_path_permits_no_sibling() {
    let host = FakeHost::with_project("a*b");
    let generated = host
        .trial()
        .with("claude")
        .with("bedrock")
        .generate()
        .expect("a configuration");
    assert!(generated.policy().contains(r#"like "~/a\*b/*""#));
}

#[test]
fn a_project_that_holds_the_home_is_refused() {
    let host = FakeHost::new();
    let error = Trial::for_project(host.home())
        .search_path(host.search_path())
        .home(host.home())
        .generate()
        .expect_err("the home is no project");
    assert!(matches!(error, Error::ProjectHoldsHome { .. }), "{error}");
}

#[test]
fn a_region_that_is_not_a_region_name_is_refused() {
    let host = FakeHost::new();
    let error = host
        .trial()
        .with("claude")
        .with("bedrock")
        .option("bedrock.region", "us-west-2.example.com/")
        .generate()
        .expect_err("a bad region");
    assert!(
        matches!(&error, Error::Profile { reason, .. } if reason.contains("does not match its pattern")),
        "{error}"
    );
}

#[test]
fn the_other_common_installs_get_no_nested_reads() {
    let host = FakeHost::alternate();
    let generated = host
        .trial()
        .with("claude")
        .with("bedrock")
        .generate()
        .expect("a configuration");
    assert_eq!(
        resolution(&generated, "cargo").identity,
        host.brew().join("Cellar/rust/1.90.0/bin/cargo")
    );
    for tool in generated.resolutions() {
        for (index, entry) in tool.read.iter().enumerate() {
            let nested = tool
                .read
                .iter()
                .enumerate()
                .any(|(other, root)| other != index && entry.starts_with(root));
            assert!(
                !nested,
                "{}: {} lies inside another read",
                tool.name,
                entry.display()
            );
        }
    }
}

#[test]
fn a_relative_search_path_entry_is_never_run() {
    let host = FakeHost::new();
    host.uninstall_claude();
    let planted = host.home().join("relative-bin");
    let marker = host.home().join("relative-ran");
    script(
        &planted.join("claude"),
        &format!("touch '{}'; echo '9 (Claude Code)'", marker.display()),
    );
    let cwd = std::env::current_dir().expect("a working directory");
    let climb = "../".repeat(cwd.components().count() - 1);
    let relative = format!(
        "{climb}{}",
        planted.display().to_string().trim_start_matches('/')
    );
    assert!(Path::new(&relative).join("claude").is_file(), "{relative}");
    let error = host
        .trial()
        .with("claude")
        .with("bedrock")
        .search_path(format!("{relative}:/usr/bin:/bin"))
        .generate()
        .expect_err("no agent");
    no_agent(&error, "claude");
    assert!(!marker.exists());
}

#[test]
fn a_missing_home_is_refused() {
    let host = FakeHost::new();
    let error = host.trial().home("").generate().expect_err("no home");
    assert!(matches!(error, Error::NoHome), "{error}");
}

#[test]
fn the_profile_report_names_what_was_found_and_each_file() {
    let host = FakeHost::new();
    let created = host
        .profile()
        .with("claude")
        .with("bedrock")
        .tools(["cargo", "git", "node", "npm"])
        .create()
        .expect("a profile");
    let summary = created.summary(false);
    for expected in [
        "Claude Code  @box/claude",
        "@box/cargo",
        "@box/node",
        "~/.strands/box/profiles/claude/profile.toml",
    ] {
        assert!(summary.contains(expected), "{expected:?} in\n{summary}");
    }
    assert!(!summary.contains("policy.dw"), "{summary}");
}

#[test]
fn your_pack_with_a_shipped_packs_name_is_used_and_the_report_says_so() {
    let host = FakeHost::new();
    let folder = host.home().join(".strands/box/packs/claude");
    std::fs::create_dir_all(&folder).expect("a pack folder");
    std::fs::write(
        folder.join(crate::lang::PACK_FILE),
        "\n[pack]\nname = \"claude\"\nversion = 1\nkind = \"agent\"\nextend = [\"@box/claude\"]",
    )
    .expect("a pack");
    for (name, with) in [
        ("work", &["claude", "bedrock"][..]),
        ("claude", &["bedrock"]),
    ] {
        let mut profile = host.profile().name(name);
        for pack in with {
            profile = profile.with(*pack);
        }
        let created = profile.create().expect("a profile");
        assert_eq!(created.profile().packs()[..2], ["claude", "@box/bedrock"]);
        let summary = created.summary(false);
        assert!(
            summary.contains("~/.strands/box/packs/claude/pack.toml, used instead of @box/claude"),
            "{summary}"
        );
        assert!(!summary.contains("@box/bedrock, used"), "{summary}");
    }
    let team = host.home().join(".strands/box/packs/team");
    std::fs::create_dir_all(&team).expect("a pack folder");
    std::fs::write(
        team.join(crate::lang::PACK_FILE),
        "\n[pack]\nname = \"team\"\nversion = 1\nkind = \"agent\"\nextend = [\"claude\"]",
    )
    .expect("a pack");
    let summary = host
        .profile()
        .name("team")
        .with("team")
        .with("bedrock")
        .create()
        .expect("a profile")
        .summary(false);
    assert!(
        summary.contains("~/.strands/box/packs/claude/pack.toml, used instead of @box/claude"),
        "{summary}"
    );
    let git = host.home().join(".strands/box/packs/git");
    std::fs::create_dir_all(&git).expect("a pack folder");
    std::fs::write(
        git.join(crate::lang::PACK_FILE),
        "\n[pack]\nname = \"git\"\nversion = 1\nkind = \"support\"\ninclude = [\"@box/git\"]",
    )
    .expect("a pack");
    let created = host
        .profile()
        .name("tools")
        .with("@box/claude")
        .with("bedrock")
        .with("git")
        .tools(["cargo", "git", "node", "npm"])
        .create()
        .expect("a profile");
    assert_eq!(
        created.profile().packs(),
        [
            "@box/claude",
            "@box/bedrock",
            "git",
            "@box/cargo",
            "@box/node",
            "@box/npm"
        ]
    );
    assert!(
        created
            .summary(false)
            .contains("~/.strands/box/packs/git/pack.toml, used instead of @box/git")
    );
    let tools = host.home().join(".strands/box/packs/tools");
    std::fs::create_dir_all(&tools).expect("a pack folder");
    std::fs::write(
        tools.join(crate::lang::PACK_FILE),
        "\n[pack]\nname = \"tools\"\nversion = 1\nkind = \"support\"\nextend = [\"git\"]",
    )
    .expect("a pack");
    let created = host
        .profile()
        .name("through")
        .with("@box/claude")
        .with("bedrock")
        .with("tools")
        .tools(["cargo", "git", "node", "npm"])
        .create()
        .expect("a profile");
    assert_eq!(
        created.profile().packs(),
        [
            "@box/claude",
            "@box/bedrock",
            "tools",
            "@box/cargo",
            "@box/node",
            "@box/npm"
        ]
    );
    let created = host
        .profile()
        .name("shipped")
        .with("@box/claude")
        .with("bedrock")
        .create()
        .expect("a profile");
    assert_eq!(created.profile().packs()[0], "@box/claude");
    assert!(!created.summary(false).contains("used instead of"));
}

#[test]
fn the_profile_report_names_tools_and_points_to_full_grants() {
    let host = FakeHost::new();
    let created = host
        .profile()
        .with("claude")
        .with("bedrock")
        .create()
        .expect("a profile");
    let summary = created
        .summary(false)
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ");
    assert!(summary.contains("@box/cargo"), "{summary}");
    assert!(!summary.contains("reads "), "{summary}");
    assert!(!summary.contains("~/.rustup"), "{summary}");
    assert!(
        created
            .next_steps(false)
            .contains("box profile show claude --full"),
        "{}",
        created.next_steps(false)
    );
}

#[test]
fn wrapped_lines_keep_every_word_and_fit_the_width() {
    let text = "one two three four five six seven eight nine ten eleven twelve";
    let lines = crate::report::wrap(text, 14);
    assert!(lines.iter().all(|line| line.len() <= 14), "{lines:?}");
    assert_eq!(lines.join(" "), text);
}

#[test]
fn skip_permissions_takes_only_true_or_false() {
    let host = FakeHost::new();
    for trial in [host.trial().with("claude").with("bedrock"), codex(&host)] {
        let error = trial
            .option("agent.skip-permissions", "yes")
            .generate()
            .expect_err("a refusal")
            .to_string();
        assert!(
            error.contains(r#"`inputs.agent.skip-permissions` = "yes" is not true or false"#),
            "{error}"
        );
    }
}

/// Assert that the agent pack `trial` builds puts `agent-args` after every element of its command.
fn assert_agent_args_go_last(trial: impl Fn() -> Trial) {
    let command = |trial: Trial| -> Vec<String> {
        let generated = trial.generate().expect("a configuration");
        let file: toml::Value = toml::from_str(generated.box_toml()).expect("TOML");
        file["agent"]["command"]
            .as_array()
            .expect("a command")
            .iter()
            .filter_map(toml::Value::as_str)
            .map(str::to_string)
            .collect()
    };
    let mut expected = command(trial());
    expected.extend(["--x".to_string(), "y".to_string()]);
    assert_eq!(command(trial().agent_args(&["--x", "y"])), expected);
}

#[test]
fn the_shipped_agent_packs_put_agent_args_at_the_end_of_the_command() {
    let host = FakeHost::new();
    assert_agent_args_go_last(|| host.trial().with("claude").with("bedrock"));
    assert_agent_args_go_last(|| codex(&host));
}

#[test]
fn a_skipped_tool_is_reported_with_its_reason() {
    let host = FakeHost::new();
    std::fs::remove_file(host.brew().join("bin/node")).expect("remove node");
    let summary = host
        .profile()
        .with("claude")
        .with("bedrock")
        .search_path(host.own_search_path())
        .tools(["git", "npm"])
        .create()
        .expect("a profile")
        .summary(false);
    assert!(
        summary.contains("skipped: it runs node, and node was skipped"),
        "{summary}"
    );
}

#[test]
fn color_is_written_only_when_asked_for() {
    let host = FakeHost::new();
    let created = host
        .profile()
        .with("claude")
        .with("bedrock")
        .create()
        .expect("a profile");
    for text in [created.summary(false), created.next_steps(false)] {
        assert!(!text.contains('\x1b'), "{text}");
    }
    for text in [created.summary(true), created.next_steps(true)] {
        assert!(text.contains("\x1b["), "{text}");
    }
}

#[test]
fn the_next_steps_name_the_key_of_each_route_and_run_the_profile() {
    let host = FakeHost::new();
    let steps = host
        .profile()
        .with("claude")
        .with("bedrock")
        .option("bedrock.region", "eu-west-1")
        .option("bedrock.sign-in", "api-key")
        .create()
        .expect("a profile")
        .next_steps(false);
    assert!(
        steps.contains(
            "  1. Put the key for bedrock-runtime.eu-west-1.amazonaws.com in \
             AWS_BEARER_TOKEN_BEDROCK.\n  2. Start Claude Code in the box"
        ),
        "{steps}"
    );
    assert!(steps.contains("box run claude\n"), "{steps}");
    assert!(
        steps.contains(
            "     box run claude\n     \
             Arguments after -- go to Claude Code: box run claude -- <args>\n"
        ),
        "{steps}"
    );
    assert!(!steps.contains("--continue"), "{steps}");
    assert!(!steps.contains("uv run"), "{steps}");
    let steps = host
        .profile()
        .with("claude")
        .with("anthropic")
        .create()
        .expect("a profile")
        .next_steps(false);
    assert!(
        steps.contains("  1. Put the key for api.anthropic.com in ANTHROPIC_API_KEY.\n"),
        "{steps}"
    );
}

/// The profile `mine` on `host`, edited to read the Anthropic key with `@box/1password` and a key
/// for `search.example.com` with its own `[secret-source.vault]`, as `box profile create` reports it.
fn edited_with_a_vault(host: &FakeHost) -> crate::CreatedProfile {
    host.profile()
        .name("mine")
        .with("claude")
        .with("anthropic")
        .tools(Vec::<String>::new())
        .policy("scoped")
        .create()
        .expect("a profile")
        .write(false)
        .expect("written");
    let vault = host.brew().join("bin/vault");
    crate::test_support::binary(&vault);
    let path = host.home().join(".strands/box/profiles/mine/profile.toml");
    let saved = std::fs::read_to_string(&path).expect("the profile");
    std::fs::write(
        &path,
        format!(
            "plugins = [\"@box/1password\"]\n{saved}\n\
             [egress.anthropic.secret]\nref = \"op://Private/Anthropic/credential\"\n\
             env = \"ANTHROPIC_API_KEY\"\n\n\
             [egress.search]\ndestinations = [\"search.example.com\"]\n\
             secret.ref = \"vault://search/key\"\nsecret.env = \"SEARCH_KEY\"\n\n\
             [secret-source.vault]\nprotocol = \"box.secret-source.v1\"\n\
             command = [{:?}, \"kv\", \"get\", \"{{ref}}\"]\n",
            vault.display().to_string()
        ),
    )
    .expect("the edited profile");
    host.profile()
        .edit("mine")
        .expect("an edit")
        .answer(None)
        .expect("the answers")
        .create()
        .expect("a profile")
}

/// `text` with each run of white space as one space, so that a check does not depend on where a
/// line wraps.
fn flat(text: &str) -> String {
    text.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// The notes under "Before running" in the saved-profile summary of `created`, as `flat` text.
fn before_running(created: &crate::CreatedProfile) -> String {
    flat(
        created
            .guided_summary(false)
            .split_once("BEFORE RUNNING\n")
            .expect("the steps before running")
            .1
            .split_once("\n\n")
            .expect("the end of the notes")
            .0,
    )
}

#[test]
fn the_steps_say_that_a_declared_source_reads_a_key_and_ask_for_no_variable() {
    let host = FakeHost::new();
    crate::test_support::binary(&host.brew().join("bin/op"));
    let edited = edited_with_a_vault(&host);
    let steps = flat(&edited.next_steps(false));
    assert!(
        steps.contains(
            "1. When the box starts, it reads the key for api.anthropic.com with the program of \
             @box/1password, so you set no variable for it. \
             2. When the box starts, it reads the key for search.example.com with the program of \
             your `[secret-source.vault]`, so you set no variable for it. 3. "
        ),
        "a step for each route that reads from a declared source, before the other steps: {steps}"
    );
    assert!(
        !steps.contains("Put the key for"),
        "no step asks for a variable: {steps}"
    );
    assert_eq!(
        before_running(&edited),
        "• When the box starts, it reads the key for api.anthropic.com with the program of \
         @box/1password, so you set no variable for it. \
         • When the box starts, it reads the key for search.example.com with the program of your \
         `[secret-source.vault]`, so you set no variable for it."
    );
}

#[test]
fn the_report_names_a_missing_plugin_program_and_not_the_agent() {
    let host = FakeHost::new();
    let edited = edited_with_a_vault(&host);
    let summary = flat(&edited.summary(false));
    assert!(
        summary.contains(
            "op (@box/1password) is not on this host now: `run.command.0` of the plugin \
             @box/1password: no `op` that the box can run"
        ) && summary.contains("`box run` looks again each time."),
        "the report names the program, its plugin, and the key of the plugin's file: {summary}"
    );
    assert!(
        !summary.contains("Claude Code is not on this host"),
        "the report does not name the agent: {summary}"
    );
    assert_eq!(
        before_running(&edited),
        "• op (@box/1password) is not on this host. Install it before running. \
         • When the box starts, it reads the key for api.anthropic.com with the program of \
         @box/1password, so you set no variable for it. \
         • When the box starts, it reads the key for search.example.com with the program of your \
         `[secret-source.vault]`, so you set no variable for it."
    );
}

#[test]
fn the_next_steps_name_one_variable_once_for_all_the_routes_that_read_it() {
    let host = FakeHost::new();
    operator_pack(
        &host,
        "keys",
        "[egress.control]\ndestinations = [\"control.example.com\"]\nsecret.ref = \"env://TEAM_KEY\"\n\n\
         [egress.lookup]\ndestinations = [\"search.example.com\"]\nsecret.ref = \"env://SEARCH_KEY\"\n\n\
         [egress.model]\ndestinations = [\"model.example.com\"]\nsecret.ref = \"env://TEAM_KEY\"\n",
    );
    let steps = host
        .profile()
        .with("claude")
        .with("keys")
        .create()
        .expect("a profile")
        .next_steps(false);
    assert!(
        steps.contains(
            "  1. Put the key for control.example.com and model.example.com in TEAM_KEY.\n  \
             2. Put the key for search.example.com in SEARCH_KEY.\n  3. Start Claude Code in the box"
        ),
        "{steps}"
    );
}

#[test]
fn no_declared_variable_claims_a_name_the_box_owns() {
    let host = FakeHost::new();
    for trial in [host.trial().with("claude").with("bedrock"), codex(&host)] {
        let generated = trial.generate().expect("a configuration");
        let file: toml::Value = toml::from_str(generated.box_toml()).expect("TOML");
        for table in [&file["agent"], &file["tool"]["git"]] {
            for name in table["env"].as_table().expect("env").keys() {
                assert!(
                    !name.starts_with("OTEL_EXPORTER_OTLP_"),
                    "{name} is the box's own"
                );
            }
        }
    }
}

#[test]
fn one_target_takes_the_boxs_own_records_and_the_agents_spans() {
    let host = FakeHost::new();
    for init in [host.trial().with("claude").with("bedrock"), codex(&host)] {
        let groups = ["deny", "permit", "trace", "logs"];
        let generated = init.generate().expect("a configuration");
        let file: toml::Value = toml::from_str(generated.box_toml()).expect("TOML");
        let target = &file["telemetry"]["records"];
        assert_eq!(target["kind"].as_str(), Some("file"));
        assert_eq!(
            target["destination"].as_str(),
            generated.journal().to_str(),
            "{}",
            generated.project().display()
        );
        let include: Vec<&str> = target["include"]
            .as_array()
            .expect("a list")
            .iter()
            .filter_map(toml::Value::as_str)
            .collect();
        assert_eq!(include, groups, "{}", generated.project().display());
    }
}

#[test]
fn the_codex_starter_selects_one_bedrock_endpoint_and_its_region() {
    let runtime = "amazon-bedrock-runtime";
    let mantle = "amazon-bedrock";
    for custom_home in [false, true] {
        for (detected, flag, region_option, provider, region) in [
            (None, None, None, mantle, "us-west-2"),
            (Some(runtime), None, None, runtime, "us-east-2"),
            (Some(mantle), Some("bedrock"), None, runtime, "us-east-2"),
            (
                Some(runtime),
                Some("bedrock-mantle"),
                None,
                mantle,
                "eu-west-1",
            ),
            (Some(mantle), None, Some("ap-south-1"), mantle, "ap-south-1"),
        ] {
            let host = FakeHost::new();
            let config_home = host.home().join(if custom_home {
                "custom-codex"
            } else {
                ".codex"
            });
            let environment = if custom_home {
                vec![("CODEX_HOME", config_home.to_str().unwrap())]
            } else {
                Vec::new()
            };
            if let Some(detected) = detected {
                let runtime_region = if region_option.is_some() {
                    "[]"
                } else {
                    "'us-east-2'"
                };
                crate::test_support::write(
                    &config_home.join("config.toml"),
                    &format!(
                        "model_provider = '{detected}'\n\
                         model_providers.amazon-bedrock.aws.region = 'eu-west-1'\n\
                         model_providers.amazon-bedrock-runtime.aws.region = {runtime_region}\n"
                    ),
                );
            }
            let mut request = host
                .profile()
                .environment(&environment)
                .with("codex")
                .policy("scoped")
                .tools(Vec::<String>::new());
            if let Some(flag) = flag {
                request = request.with(flag);
            }
            if let Some(value) = region_option {
                request = request.option("bedrock.region", value);
            }
            let created = request.answer(None).unwrap().create().unwrap();
            assert!(
                created.detected.iter().all(|line| line.answer.is_some()),
                "{:?}",
                created.detected
            );
            let (pack, endpoint) = if provider == runtime {
                (
                    "@box/bedrock",
                    format!("bedrock-runtime.{region}.amazonaws.com"),
                )
            } else {
                (
                    "@box/bedrock-mantle",
                    format!("bedrock-mantle.{region}.api.aws"),
                )
            };
            assert_eq!(
                created.profile().packs(),
                ["@box/codex", "@box/rg", pack],
                "{detected:?}, {flag:?}"
            );
            let saved: toml::Table = toml::from_str(created.text()).unwrap();
            assert_eq!(
                saved["options"]["codex"]
                    .get("host")
                    .and_then(toml::Value::as_str),
                Some(provider)
            );
            created.write(false).unwrap();
            let preview = host
                .launcher()
                .environment(&environment)
                .preview("codex", &host.project())
                .unwrap();
            let file: toml::Table = toml::from_str(&preview.box_toml).unwrap();
            let mut settings: Vec<_> = codex_settings(&file["agent"]["command"])
                .into_iter()
                .filter(|arg| arg.starts_with("model_provider"))
                .collect();
            settings.sort_unstable();
            assert_eq!(
                settings,
                [
                    format!(r#"model_provider="{provider}""#),
                    format!(r#"model_providers.{provider}.aws.region="{region}""#),
                ]
            );
            assert_eq!(
                file["egress"]["bedrock"]["destinations"]
                    .as_array()
                    .unwrap(),
                &[toml::Value::from(endpoint)]
            );
        }
    }
}

#[test]
fn the_codex_starter_selects_the_openai_api_from_a_flag_or_the_host_provider() {
    for (detected, flag) in [(None, Some("openai")), (Some("openai"), None)] {
        let host = FakeHost::new();
        if let Some(detected) = detected {
            crate::test_support::write(
                &host.home().join(".codex/config.toml"),
                &format!("model_provider = '{detected}'\n"),
            );
        }
        let mut request = host
            .profile()
            .with("codex")
            .policy("scoped")
            .tools(Vec::<String>::new());
        if let Some(flag) = flag {
            request = request.with(flag);
        }
        let created = request.answer(None).unwrap().create().unwrap();
        assert_eq!(
            created.profile().packs(),
            ["@box/codex", "@box/rg", "@box/openai"],
            "{detected:?}, {flag:?}"
        );
        let saved: toml::Table = toml::from_str(created.text()).unwrap();
        assert_eq!(
            saved["options"]["codex"]
                .get("host")
                .and_then(toml::Value::as_str),
            Some("openai")
        );
        assert!(
            created
                .next_steps(false)
                .contains("Put the key for api.openai.com in OPENAI_API_KEY."),
            "{}",
            created.next_steps(false)
        );
        created.write(false).unwrap();
        let preview = host.launcher().preview("codex", &host.project()).unwrap();
        let file: toml::Table = toml::from_str(&preview.box_toml).unwrap();
        let settings: Vec<_> = codex_settings(&file["agent"]["command"])
            .into_iter()
            .filter(|arg| arg.starts_with("model_provider"))
            .collect();
        assert_eq!(
            settings,
            [
                r#"model_provider="openai-api""#,
                r#"model_providers.openai-api={name="OpenAI",base_url="https://api.openai.com/v1",env_key="OPENAI_API_KEY",wire_api="responses"}"#,
            ]
        );
        assert_eq!(
            file["egress"]["openai"]["destinations"].as_array().unwrap(),
            &[toml::Value::from("api.openai.com")]
        );
        assert!(file["egress"].get("bedrock").is_none());
    }
}

/// Write the operator's pack `name` with the body `text`.
/// Your starter `name`: `text`, a `starter.toml` that opens with `[starter]`, gets its `name`.
fn operator_starter(host: &FakeHost, name: &str, text: &str) {
    let body = text
        .strip_prefix("[starter]\n")
        .expect("a starter text opens with [starter]");
    crate::test_support::write(
        &host
            .home()
            .join(".strands/box")
            .join(crate::starter::STARTERS)
            .join(name)
            .join(crate::starter::STARTER_FILE),
        &format!("[starter]\nname = {name:?}\n{body}"),
    );
}

fn operator_pack(host: &FakeHost, name: &str, text: &str) {
    let folder = host.home().join(".strands/box/packs").join(name);
    std::fs::create_dir_all(&folder).expect("a pack folder");
    std::fs::write(
        folder.join(crate::lang::PACK_FILE),
        format!(
            "[pack]\nname = \"{name}\"\nversion = 1\n{}{text}",
            crate::lang::test_kind_line(text)
        ),
    )
    .expect("a pack");
}

#[test]
fn a_team_starter_writes_its_packs_and_options_and_needs_no_pack_of_its_own() {
    let host = FakeHost::new();
    crate::test_support::write(
        &host.home().join(".strands/box/config.toml"),
        "[starters]\nadd = [\"acme\"]\n",
    );
    let starter = "[starter]\nlabel = \"Acme\"\npacks = [\"@box/claude\", \"@box/bedrock\"]\n\
                   options = { \"bedrock.region\" = \"us-east-1\" }\n";
    operator_starter(&host, "acme", starter);
    let created = host
        .profile()
        .name("acme")
        .policy("open")
        .answer(None)
        .and_then(|profile| profile.create())
        .expect("a profile from a starter with no pack");
    let text = created.text();
    assert!(
        text.contains("packs = [\"@box/claude\", \"@box/bedrock\", "),
        "{text}"
    );
    assert!(text.contains("us-east-1"), "{text}");
    let named = host
        .profile()
        .name("work")
        .with("acme")
        .policy("open")
        .answer(None)
        .and_then(|profile| profile.create())
        .expect("`--with` names a starter that has no pack of its name");
    assert!(
        named
            .text()
            .contains("packs = [\"@box/claude\", \"@box/bedrock\", "),
        "{}",
        named.text()
    );
    operator_starter(&host, "acme", &starter.replace("@box/bedrock", "@box/gone"));
    let error = host
        .profile()
        .name("acme")
        .policy("open")
        .answer(None)
        .expect_err("a starter that names a missing pack");
    assert!(
        error
            .to_string()
            .contains("the pack \"@box/gone\" does not exist"),
        "{error}"
    );
    operator_starter(
        &host,
        "acme",
        &starter.replace("@box/bedrock", "box/bedrock"),
    );
    let error = host
        .profile()
        .name("acme")
        .policy("open")
        .answer(None)
        .expect_err("a starter that names a pack in the old spelling")
        .to_string();
    assert!(
        error.contains("starters/acme/starter.toml")
            && error.contains(
                "\"box/bedrock\" is not a pack name; the pack that box ships is @box/bedrock"
            ),
        "{error}"
    );
}

#[test]
fn a_pack_that_extends_an_agent_pack_takes_its_name_from_that_pack() {
    let host = FakeHost::new();
    operator_pack(&host, "work", "extend = [\"@box/claude\"]\n");
    let created = host
        .profile()
        .with("work")
        .with("bedrock")
        .create()
        .expect("a profile");
    let steps = created.next_steps(false);
    assert!(steps.contains("Start Claude Code in the box"), "{steps}");
    assert!(
        steps.contains("Arguments after -- go to Claude Code: box run work -- <args>\n"),
        "{steps}"
    );
    let summary = created.summary(false);
    assert!(summary.contains("✓ Claude Code"), "{summary}");
}

#[test]
fn a_long_agent_name_does_not_widen_the_found_table() {
    let host = FakeHost::new();
    let long = "Claude Code on Amazon Bedrock, with the cargo and node toolchains and the \
                payments team's MCP servers";
    operator_pack(&host, "team", "extend = [\"@box/claude\"]\n");
    operator_starter(
        &host,
        "team",
        &format!("[starter]\nlabel = {long:?}\npacks = [\"team\"]\n"),
    );
    crate::test_support::write(
        &host.home().join(".strands/box/config.toml"),
        "[starters]\nadd = [\"team\"]\n",
    );
    let summary = host
        .profile()
        .with("team")
        .with("bedrock")
        .create()
        .expect("a profile")
        .summary(false);
    assert!(summary.contains(&format!("✓ {long}")), "{summary}");
    let detail = summary
        .lines()
        .skip_while(|line| !line.contains('✓'))
        .nth(1)
        .expect("the agent's path");
    let indent = detail.len() - detail.trim_start().len();
    assert!(indent <= 4 + NAME_COLUMN + 2, "{summary}");
}

#[test]
fn an_agent_pack_takes_its_name_from_the_starter_that_names_it() {
    let host = FakeHost::new();
    operator_pack(&host, "work", "extend = [\"@box/claude\"]\n");
    operator_starter(
        &host,
        "work",
        "[starter]\nlabel = \"Claude Code for work\"\npacks = [\"work\"]\n",
    );
    crate::test_support::write(
        &host.home().join(".strands/box/config.toml"),
        "[starters]\nadd = [\"work\"]\n",
    );
    let steps = host
        .profile()
        .with("work")
        .with("bedrock")
        .create()
        .expect("a profile")
        .next_steps(false);
    assert!(
        steps.contains("Start Claude Code for work in the box"),
        "{steps}"
    );
}

/// The team starter `acme-claude` from the user guide, which names `@box/claude` and asks nothing.
fn acme_starter(host: &FakeHost, starters: &str) {
    operator_starter(
        host,
        "acme-claude",
        "[starter]\nlabel = \"Claude Code on Acme's Bedrock\"\n\
         packs = [\"@box/claude\", \"@box/bedrock\"]\n\
         options = { \"claude.host\" = \"bedrock\", \"bedrock.region\" = \"us-east-1\" }\n",
    );
    crate::test_support::write(&host.home().join(".strands/box/config.toml"), starters);
}

#[test]
fn the_agent_is_named_by_its_own_starter_whatever_the_menu_holds() {
    for starters in [
        "[starters]\nonly = [\"acme-claude\", \"@box/codex\"]\n",
        "[starters]\nremove = [\"@box/claude\"]\n",
    ] {
        let host = FakeHost::new();
        acme_starter(&host, starters);
        let steps = host
            .profile()
            .with("claude")
            .with("anthropic")
            .create()
            .expect("a profile")
            .next_steps(false);
        assert!(
            steps.contains("Start Claude Code in the box"),
            "{starters}: {steps}"
        );
    }
}

#[test]
fn guided_edit_never_takes_a_team_starter_for_the_agents_own() {
    let host = FakeHost::new();
    host.profile()
        .name("mine")
        .with("claude")
        .with("anthropic")
        .tools(Vec::<String>::new())
        .policy("scoped")
        .create()
        .expect("a profile")
        .write(false)
        .expect("written");
    acme_starter(
        &host,
        "[starters]\nonly = [\"acme-claude\", \"@box/codex\"]\n",
    );
    let error = host
        .profile()
        .edit("mine")
        .expect_err("no starter of the agent's own");
    assert!(
        error
            .to_string()
            .contains("guided setup is not available for this profile"),
        "{error}"
    );
}

#[test]
fn guided_edit_takes_your_starter_that_replaces_the_shipped_one() {
    let host = FakeHost::new();
    operator_starter(
        &host,
        "claude",
        "[starter]\nlabel = \"Claude Code\"\npacks = [\"@box/claude\", \"@box/bedrock\"]\n\
         options = { \"claude.host\" = \"bedrock\" }\n",
    );
    crate::test_support::write(
        &host.home().join(".strands/box/config.toml"),
        "[starters]\nadd = [\"claude\"]\nremove = [\"@box/claude\"]\n",
    );
    host.profile()
        .name("claude")
        .tools(Vec::<String>::new())
        .policy("scoped")
        .answer(None)
        .and_then(|profile| profile.create())
        .expect("a profile from your starter")
        .write(false)
        .expect("written");
    host.profile()
        .edit("claude")
        .expect("your starter answers the edit of the profile it made");
}

#[test]
fn an_agent_pack_that_no_starter_names_is_named_by_its_short_name() {
    let host = FakeHost::new();
    operator_pack(
        &host,
        "helper",
        "extend = [\"@box/base\"]\n\n[run]\ncommand = [\"/bin/sh\"]",
    );
    let steps = host
        .profile()
        .with("helper")
        .create()
        .expect("a profile")
        .next_steps(false);
    assert!(steps.contains("Start helper in the box"), "{steps}");
    assert!(
        steps.contains("Arguments after -- go to helper: box run helper -- <args>\n"),
        "{steps}"
    );
}

#[test]
fn profile_create_asks_for_the_policy_after_the_starter_and_without_a_terminal_needs_policy() {
    let host = FakeHost::new();
    let error = host
        .profile()
        .with("claude")
        .with("bedrock")
        .answer(None)
        .expect_err("no policy");
    assert_eq!(
        error.to_string(),
        "box profile create claude needs an answer to \"Which policy should the agent start \
         with?\"\n  --policy open     Open\n  --policy scoped   Scoped\n  --policy locked   Locked"
    );
    let mut input = "\n\n\n\n\n".as_bytes();
    let mut output = Vec::new();
    let answered = host
        .profile()
        .with("claude")
        .with("bedrock")
        .answer(Some(crate::Terminal::new(&mut input, &mut output)))
        .expect("answered at a terminal");
    let output = String::from_utf8(output).expect("text");
    let region = output
        .find("(bedrock.region)")
        .expect("the region question");
    let policy = output
        .find("Which policy should the agent start with?\n  1. Open: ")
        .expect("the policy question");
    assert!(region < policy, "{output}");
    assert!(output.ends_with("> [1] "), "{output}");
    let created = answered.create().expect("created");
    assert!(
        created
            .text()
            .contains("claude.import-mcp = \"false\"\nclaude.import-hooks = \"false\"\n"),
        "{}",
        created.text()
    );
    assert!(
        created
            .policy_text
            .as_deref()
            .is_some_and(|copy| copy.starts_with("// Copied from @box/open ")),
        "{}",
        created.text()
    );
    assert!(
        created.summary(false).contains(
            "Policy\n  Open (@box/open), copied to ~/.strands/box/profiles/claude/policy.dw\n"
        ),
        "{}",
        created.summary(false)
    );
    assert!(
        created.summary(false).contains(
            "Files\n  profile    ~/.strands/box/profiles/claude/profile.toml\n  policy     \
             ~/.strands/box/profiles/claude/policy.dw\n"
        ),
        "{}",
        created.summary(false)
    );
    let created = host
        .profile()
        .name("closed")
        .with("claude")
        .with("bedrock")
        .policy("scoped")
        .answer(None)
        .and_then(|profile| profile.create())
        .expect("created with --policy");
    assert!(
        created
            .policy_text
            .as_deref()
            .is_some_and(|copy| copy.starts_with("// Copied from @box/scoped ")),
        "{}",
        created.text()
    );
}

#[test]
fn a_profile_with_no_starter_still_gets_the_policy_question() {
    let host = FakeHost::new();
    let shared = host.home().join(".strands/box/packs/helper");
    std::fs::create_dir_all(&shared).expect("a pack folder");
    std::fs::write(
        shared.join("pack.toml"),
        "[pack]\nname = \"helper\"\nversion = 1\nkind = \"agent\"\n[run]\n\
         command = [\"/usr/bin/true\"]",
    )
    .expect("a pack");
    let error = host
        .profile()
        .with("helper")
        .answer(None)
        .expect_err("no policy");
    assert!(
        error
            .to_string()
            .starts_with("box profile create helper needs an answer to \"Which policy"),
        "{error}"
    );
    let created = host
        .profile()
        .with("helper")
        .policy("@box/scoped")
        .answer(None)
        .and_then(|profile| profile.create())
        .expect("created");
    assert!(
        created
            .policy_text
            .as_deref()
            .is_some_and(|copy| copy.starts_with("// Copied from @box/scoped "))
    );
    operator_starter(
        &host,
        "helper",
        "[starter]\nlabel = \"Helper\"\npacks = [\"helper\"]\npolicy = \"@box/scoped\"\n",
    );
    std::fs::write(
        host.home().join(".strands/box/config.toml"),
        "[starters]\nadd = [\"helper\"]\n",
    )
    .expect("config");
    let created = host
        .profile()
        .name("helper")
        .answer(None)
        .and_then(|profile| profile.create())
        .expect("the starter answers the policy question");
    assert!(
        created
            .policy_text
            .as_deref()
            .is_some_and(|copy| copy.starts_with("// Copied from @box/scoped ")),
        "{}",
        created.text()
    );
    assert!(
        created
            .summary(false)
            .contains("Policy\n  Scoped (@box/scoped), from the helper starter, copied to ~/.strands/box/profiles/helper/policy.dw\n"),
        "{}",
        created.summary(false)
    );
    let created = host
        .profile()
        .name("helper2")
        .with("helper")
        .policy("open")
        .answer(None)
        .and_then(|profile| profile.create())
        .expect("--policy wins over the starter");
    assert!(
        created
            .policy_text
            .as_deref()
            .is_some_and(|copy| copy.starts_with("// Copied from @box/open ")),
        "{}",
        created.text()
    );
    assert!(
        !created.summary(false).contains("from the"),
        "{}",
        created.summary(false)
    );
    std::fs::write(
        host.home().join(".strands/box/config.toml"),
        "[starters]\nadd = [\"helper\"]\n\n[policy-starters]\nonly = [\"@box/scoped\"]\n",
    )
    .expect("config");
    std::fs::write(
        shared.join("pack.toml"),
        "[pack]\nname = \"helper\"\nversion = 1\nkind = \"agent\"\n[run]\n\
         command = [\"/usr/bin/true\"]\n[inputs.helper.region]\ndescription = \"The region\"\n\
         default = \"east\"\n",
    )
    .expect("a pack with an input");
    operator_starter(
        &host,
        "helper",
        "[starter]\nlabel = \"Helper\"\npacks = [\"helper\"]\npolicy = \"@box/open\"\n\
         ask = [\"helper.region\"]\n",
    );
    let mut input = "west\n".as_bytes();
    let mut output = Vec::new();
    let error = host
        .profile()
        .name("helper3")
        .with("helper")
        .answer(Some(crate::Terminal::new(&mut input, &mut output)))
        .expect_err("a starter policy outside the operator's list");
    assert_eq!(
        error.to_string(),
        format!(
            "{}: the starter helper sets `[starter] policy` to @box/open, which is not in your \
             `[policy-starters]` list; the policy starters are @box/scoped. Name one with \
             `--policy`, such as `--policy scoped`",
            host.home()
                .join(".strands/box/profiles/helper3/profile.toml")
                .display()
        )
    );
    assert!(output.is_empty(), "refused before the first prompt");
    std::fs::remove_file(host.home().join(".strands/box/config.toml")).expect("config removed");
    let mut input = "1\n".as_bytes();
    let mut output = Vec::new();
    let error = host
        .profile()
        .name("mine")
        .answer(Some(crate::Terminal::new(&mut input, &mut output)))
        .expect_err("no agent pack");
    assert!(
        error.to_string().contains("no pack runs an agent"),
        "{error}"
    );
    assert!(
        output.is_empty(),
        "a profile box cannot build asks no policy question"
    );
}

#[test]
fn an_own_policy_starter_is_copied_when_the_list_offers_it() {
    let host = FakeHost::new();
    let pack = host.home().join(".strands/box/packs/helper");
    std::fs::create_dir_all(&pack).expect("a pack folder");
    std::fs::write(
        pack.join("pack.toml"),
        "[pack]\nname = \"helper\"\nversion = 1\nkind = \"agent\"\n[run]\n\
         command = [\"/usr/bin/true\"]\n",
    )
    .expect("an agent pack");
    operator_starter(
        &host,
        "helper",
        "[starter]\nlabel = \"Helper\"\npacks = [\"helper\"]\npolicy = \"team\"\n",
    );
    let team = host.home().join(".strands/box/policies/team");
    std::fs::create_dir_all(&team).expect("a policy folder");
    std::fs::write(
        team.join("policy.toml"),
        "[policy]\nname = \"team\"\nlabel = \"Team hosts\"\ndescription = \"Team.\"\n",
    )
    .expect("policy.toml");
    std::fs::write(team.join("policy.dw"), "// team rules\n").expect("policy.dw");
    std::fs::write(
        host.home().join(".strands/box/config.toml"),
        "[starters]\nadd = [\"helper\"]\n",
    )
    .expect("config");
    let error = host
        .profile()
        .name("helper")
        .answer(None)
        .expect_err("an own policy outside the list");
    assert!(
        error.to_string().contains(
            "the starter helper sets `[starter] policy` to team, which is not in your \
             `[policy-starters]` list"
        ),
        "{error}"
    );
    let error = host
        .profile()
        .with("helper")
        .policy("team")
        .answer(None)
        .expect_err("--policy outside the list");
    assert!(
        error
            .to_string()
            .contains("`--policy` names \"team\", which is not a policy starter"),
        "{error}"
    );
    std::fs::write(
        host.home().join(".strands/box/config.toml"),
        "[starters]\nadd = [\"helper\"]\n\n[policy-starters]\nadd = [\"team\"]\n",
    )
    .expect("config");
    for (name, profile) in [
        ("helper", host.profile().name("helper")),
        (
            "helper2",
            host.profile().name("helper2").with("helper").policy("team"),
        ),
    ] {
        let created = profile
            .answer(None)
            .and_then(|profile| profile.create())
            .expect(name);
        assert_eq!(
            created.policy_text.as_deref(),
            Some(
                "// Copied from team (Team hosts) by `box profile create`. This file is yours: \
                 only\n// `box profile create --force` replaces it. Edit the rules here, and the \
                 next run\n// uses them.\n\n// team rules\n"
            ),
            "{name}"
        );
    }
}

#[test]
fn guided_edit_requires_an_available_starter_and_preserves_unsupported_profiles() {
    let host = FakeHost::new();
    operator_pack(
        &host,
        "custom",
        "[run]\ncommand = [\"/usr/bin/true\"]\n[inputs.custom.mode]\ndefault = \"default\"\n",
    );
    operator_pack(&host, "extra", "");
    operator_starter(
        &host,
        "extra",
        "[starter]\nlabel = \"Extra tools\"\npacks = [\"extra\", \"@box/git\"]\n",
    );
    crate::test_support::write(
        &host.home().join(".strands/box/config.toml"),
        "[starters]\nadd = [\"extra\"]\n",
    );
    for (name, packs) in [
        ("claude", ""),
        ("work", "packs = [\"@box/git\"]\n"),
        (
            "custom",
            "packs = [\"custom\"]\n[options]\ncustom.mode = \"saved\"\n",
        ),
        ("extra", "packs = [\"extra\"]\n"),
    ] {
        let path = host
            .home()
            .join(".strands/box/profiles")
            .join(name)
            .join("profile.toml");
        let text = format!("{packs}[agent]\ncommand = [\"/usr/bin/true\"]\n");
        crate::test_support::write(&path, &text);
        let error = host.profile().edit(name).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("guided setup is not available for this profile")
        );
        assert_eq!(std::fs::read_to_string(&path).unwrap(), text);
    }
}

#[test]
fn guided_edit_keeps_saved_settings_instead_of_reapplying_starter_defaults() {
    let host = FakeHost::new();
    operator_pack(
        &host,
        "agent",
        r#"
[run]
command = ["/usr/bin/true"]
[inputs.agent.mode]
default = "default"
[inputs.agent.extra]
default = "runtime"
[inputs.agent.choice]
default = "runtime"
[inputs.agent.removed]
default = "runtime"
"#,
    );
    operator_starter(
        &host,
        "agent",
        r#"[starter]
label = "Helper"
policy = "@box/open"
packs = ["agent", "@box/node"]
options = { "agent.extra" = "starter" }
ask = ["agent.mode"]
[[question]]
id = "tools"
prompt = "Tools"
[[question.choice]]
id = "dev"
label = "Development"
packs = ["@box/git", "@box/cargo"]
options = { "agent.choice" = "starter" }
[[question.choice]]
id = "none"
label = "None"
packs = []
[[question]]
id = "extra"
prompt = "Extra tools"
when = { variable = "answers.tools", equals = "dev" }
[[question.choice]]
id = "uv"
label = "UV"
packs = ["@box/uv"]
options = { "agent.removed" = "uv" }
[[question]]
id = "last"
prompt = "Last tool"
[[question.choice]]
id = "npm"
label = "NPM"
packs = ["@box/npm"]
options = { "agent.choice" = "last" }
"#,
    );
    operator_pack(
        &host,
        "work-agent",
        "extend = [\"agent\"]\ninclude = [\"@box/uv\"]\n",
    );
    operator_starter(
        &host,
        "extra",
        "[starter]\nlabel = \"Extra tools\"\npacks = [\"agent\", \"@box/git\"]\n",
    );
    crate::test_support::write(
        &host.home().join(".strands/box/config.toml"),
        "[starters]\nadd = [\"agent\", \"extra\"]\n[policy-starters]\nonly = [\"@box/scoped\"]\n",
    );
    let original = host
        .profile()
        .name("extra")
        .with("work-agent")
        .with("git")
        .with("npm")
        .option("agent.mode", "saved")
        .option("agent.removed", "uv")
        .tools(Vec::<String>::new())
        .policy("scoped")
        .create()
        .unwrap();
    original.write(false).unwrap();
    let edit = |answers: &str| {
        let mut input = answers.as_bytes();
        let mut output = Vec::new();
        host.profile()
            .edit("extra")
            .unwrap()
            .guided(&mut crate::Terminal::new(&mut input, &mut output))
    };
    let edited = edit("\n\n\n\n\n").unwrap();
    assert_eq!(edited.text(), original.text());
    let unchanged = host
        .profile()
        .edit("extra")
        .unwrap()
        .answer(None)
        .unwrap()
        .create()
        .unwrap();
    assert_eq!(unchanged.text(), original.text());
    assert_eq!(
        edited.profile().packs(),
        ["work-agent", "@box/git", "@box/npm"]
    );
    let error = edit("1\n\n\n\n").unwrap_err();
    assert!(
        error.to_string().contains("comes from a custom pack"),
        "{error}"
    );
    let direct = original
        .text()
        .replace("\"work-agent\"", "\"agent\", \"@box/uv\"");
    crate::test_support::write(&original.path(), &direct);
    let edited = edit("1\n\n\n\n").unwrap();
    assert_eq!(edited.profile().packs(), ["agent", "@box/npm"]);
    assert!(
        edited.text().contains("agent.choice = \"last\""),
        "{}",
        edited.text()
    );
    assert!(
        !edited.text().contains("agent.removed"),
        "{}",
        edited.text()
    );
}

#[test]
fn guided_edits_keep_custom_profile_content_and_refuse_stale_saves() {
    let host = FakeHost::new();
    let original = host
        .profile()
        .name("work")
        .with("codex")
        .with("bedrock-mantle")
        .option("bedrock.region", "us-west-2")
        .option("bedrock.sign-in", "aws")
        .option("codex.import-mcp", "true")
        .option("codex.import-hooks", "false")
        .tools(["git"])
        .policy("open")
        .create()
        .unwrap();
    original.write(false).unwrap();
    let text = original
        .text()
        .replace("import-mcp = \"true\"", "import-mcp = true")
        .replace(
            "policies = [\"policy.dw\"]",
            "policies = [\"policy.dw\", \"custom.dw\"] # keep both",
        )
        + "\n# Keep my environment\n[agent.env]\nEDITOR = \"vim\"\n";
    crate::test_support::write(&original.path(), &text);
    crate::test_support::write(&original.folder().join("custom.dw"), "// custom rules\n");
    crate::test_support::write(
        &original.folder().join("editing-box-profile.md"),
        "my notes",
    );
    let policy = std::fs::read(original.folder().join("policy.dw")).unwrap();
    let edit = |request: crate::NewProfile, answers: &str| {
        let mut input = answers.as_bytes();
        let mut output = Vec::new();
        let edited = request
            .guided(&mut crate::Terminal::new(&mut input, &mut output))
            .unwrap();
        (edited, String::from_utf8(output).unwrap())
    };
    let (unchanged, _) = edit(host.profile(), "2\nwork\n\n\n\n\n\n\n");
    assert_eq!(
        unchanged.text(),
        text,
        "accepting saved answers preserves the file"
    );
    let (edited, output) = edit(host.profile().edit("work").unwrap(), "\n\n\n2\n\n\n");
    assert!(output.contains("> [us-west-2]"), "{output}");
    assert!(output.contains("> [Yes]"), "{output}");
    assert_eq!(
        std::fs::read_to_string(original.path()).unwrap(),
        text,
        "review writes nothing"
    );
    edited.write(false).unwrap();
    assert_eq!(edited.profile().packs(), original.profile().packs());
    assert_eq!(edited.profile().policies(), ["policy.dw", "custom.dw"]);
    assert!(edited.text().contains("# keep both"));
    assert!(
        edited
            .text()
            .contains("# Keep my environment\n[agent.env]\nEDITOR = \"vim\"")
    );
    assert!(
        edited.text().contains("import-mcp = \"false\""),
        "{}",
        edited.text()
    );
    assert_eq!(
        std::fs::read(original.folder().join("policy.dw")).unwrap(),
        policy
    );
    assert_eq!(
        std::fs::read_to_string(original.folder().join("custom.dw")).unwrap(),
        "// custom rules\n"
    );
    assert_eq!(
        std::fs::read_to_string(original.folder().join("editing-box-profile.md")).unwrap(),
        "my notes"
    );
    let (stale, _) = edit(host.profile().edit("work").unwrap(), "\n\n\n2\n\n\n");
    let concurrent = edited.text().to_string() + "\n# another edit\n";
    crate::test_support::write(&original.path(), &concurrent);
    assert!(
        stale
            .write(false)
            .unwrap_err()
            .to_string()
            .contains("changed during setup")
    );
    assert_eq!(
        std::fs::read_to_string(original.path()).unwrap(),
        concurrent
    );
}

#[test]
fn editing_a_provider_replaces_its_packs_and_options_without_overwriting_policy_files() {
    let host = FakeHost::new();
    let edit = |request: crate::NewProfile, answers: &str| {
        let mut input = answers.as_bytes();
        let mut output = Vec::new();
        let result = request.guided(&mut crate::Terminal::new(&mut input, &mut output));
        (result, output)
    };
    let original = host
        .profile()
        .name("work")
        .with("claude")
        .with("bedrock")
        .option("claude.host", "bedrock")
        .option("bedrock.region", "us-west-2")
        .option("bedrock.sign-in", "aws")
        .option("claude.import-mcp", "false")
        .option("claude.import-hooks", "false")
        .tools(Vec::<String>::new())
        .policy("open")
        .create()
        .unwrap();
    original.write(false).unwrap();
    let policy = std::fs::read(original.folder().join("policy.dw")).unwrap();
    crate::test_support::write(
        &host.home().join(".claude/settings.json"),
        r#"{"env":{"CLAUDE_CODE_USE_BEDROCK":"1","AWS_REGION":"us-east-1"}}"#,
    );
    let default_region = original
        .text()
        .replace("bedrock.region = \"us-west-2\"\n", "");
    assert_ne!(default_region, original.text());
    crate::test_support::write(&original.path(), &default_region);
    let (unchanged, _) = edit(host.profile().edit("work").unwrap(), "\n\n\n\n\n\n");
    assert_eq!(
        unchanged.unwrap().text(),
        default_region,
        "saved omissions keep pack defaults"
    );
    let credential = default_region
        + "\n[egress.private]\ndestinations = [\"private.example.com\"]\nsecret.ref = \"env://AWS_REGION\"\n";
    crate::test_support::write(&original.path(), &credential);
    let (result, output) = edit(host.profile().edit("work").unwrap(), "\n\n\n\n\n\n");
    let error = result.unwrap_err();
    assert!(error.to_string().contains("reads AWS_REGION"), "{error}");
    assert!(
        output.is_empty(),
        "a custom credential is refused before detection or prompts"
    );
    crate::test_support::write(&original.path(), original.text());
    let (edited, _) = edit(host.profile(), "1\nwork\n2\n\n\n2\n");
    let edited = edited.unwrap();
    assert_eq!(edited.profile().packs(), ["@box/claude", "@box/anthropic"]);
    assert!(!edited.text().contains("bedrock"));
    assert!(edited.text().contains("host = \"anthropic\""));
    edited.write(false).unwrap();
    assert_eq!(
        std::fs::read(original.folder().join("policy.dw")).unwrap(),
        policy
    );
    assert_eq!(edited.profile().policies(), ["policy-1.dw"]);
    assert!(original.folder().join("policy-1.dw").exists());
    let wrapped = original.text().replace(
        "packs = [\"@box/claude\", \"@box/bedrock\"]",
        "packs = [\"work-agent\"]",
    );
    operator_pack(
        &host,
        "bedrock",
        "[inputs.bedrock.region]\ndefault = \"us-west-2\"\n\
         [inputs.bedrock.sign-in]\nvalues = [\"aws\", \"api-key\"]\ndefault = \"aws\"\n",
    );
    for provider in ["@box/bedrock", "bedrock"] {
        operator_pack(
            &host,
            "work-agent",
            &format!("extend = [\"@box/claude\", \"{provider}\"]\n"),
        );
        for text in [
            wrapped.clone(),
            wrapped.replace(
                "packs = [\"work-agent\"]",
                &format!("packs = [\"work-agent\", \"{provider}\"]"),
            ),
        ] {
            crate::test_support::write(&original.path(), &text);
            let (edited, _) = edit(host.profile(), "1\nwork\n\n\n\n\n\n\n");
            assert_eq!(
                edited.unwrap().text(),
                text,
                "custom packs keep their inherited choices"
            );
            let (result, _) = edit(host.profile(), "1\nwork\n2\n\n\n2\n");
            let error = result.unwrap_err();
            assert!(
                error.to_string().contains("comes from a custom pack"),
                "{provider}: {error}"
            );
            assert_eq!(std::fs::read_to_string(original.path()).unwrap(), text);
        }
    }
}

#[test]
fn a_picked_starter_keeps_a_custom_name_and_a_taken_name_asks_for_another() {
    let host = FakeHost::new();
    let create = |profile: crate::NewProfile, input: &str| {
        let mut input = input.as_bytes();
        let mut output = Vec::new();
        profile
            .policy("open")
            .tools(Vec::<String>::new())
            .pick_starter(&mut crate::Terminal::new(&mut input, &mut output))
            .and_then(|profile| profile.answer(None))
            .and_then(crate::NewProfile::create)
            .expect("created")
    };
    let created = create(host.profile().name("foobar"), "2\n");
    assert_eq!(created.name(), "foobar");
    assert_eq!(created.profile().packs()[0], "@box/codex");
    crate::test_support::write(
        &host.home().join(".strands/box/profiles/codex/profile.toml"),
        "",
    );
    let created = create(host.profile(), "2\nmine\n");
    assert_eq!(created.name(), "mine");
    assert_eq!(created.profile().packs()[0], "@box/codex");

    crate::test_support::write(
        &host
            .home()
            .join(".strands/box/profiles/other-agent/profile.toml"),
        "packs = [\"@box/claude\"]\n",
    );
    let created = create(host.profile(), "2\nother-agent\nnew-codex\n");
    assert_eq!(created.name(), "new-codex");
    assert!(
        !host.home().join(".strands/box/profiles/new-codex").exists(),
        "choosing a name does not write a profile"
    );
    created.write(false).unwrap();
    let mut input = b"2\nnew-codex\n".as_slice();
    let mut output = Vec::new();
    let edited = host
        .profile()
        .policy("scoped")
        .tools(["git"])
        .pick_starter(&mut crate::Terminal::new(&mut input, &mut output))
        .unwrap()
        .answer(None)
        .unwrap()
        .create()
        .unwrap();
    assert_eq!(
        (
            edited.policy.as_ref().map(|policy| policy.name.as_str()),
            edited.profile().packs().contains(&"@box/git".to_string()),
        ),
        (Some("@box/scoped"), true),
        "selecting an existing profile keeps explicit policy and tool flags"
    );
}

#[test]
fn a_profile_with_no_name_and_no_packs_is_refused() {
    let host = FakeHost::new();
    for error in [
        host.profile().create().expect_err("no name"),
        host.profile().answer(None).expect_err("no name"),
    ] {
        assert!(matches!(error, Error::ProfileUnnamed), "{error}");
        assert_eq!(
            error.to_string(),
            "provide a profile name or --with <PACK>\n\n  \
             tip: list starters with 'box profile list'"
        );
    }
    assert!(!host.home().join(".strands/box/profiles/claude").exists());
}

#[test]
fn a_profile_with_no_agent_pack_names_no_agent_in_its_error() {
    let host = FakeHost::new();
    let error = host
        .profile()
        .name("work")
        .with("bedrock")
        .create()
        .expect_err("no agent");
    let text = error.to_string();
    assert!(text.contains("no pack runs an agent"), "{text}");
    assert!(
        !text.contains("claude") && !text.contains("codex"),
        "{text}"
    );
}

/// Copy the folder `from` to `to`, with every file and folder in it.
fn copy_tree(from: &Path, to: &Path) {
    std::fs::create_dir_all(to).expect("a folder");
    for entry in std::fs::read_dir(from).expect("a listing") {
        let entry = entry.expect("an entry");
        let target = to.join(entry.file_name());
        if entry.file_type().expect("a type").is_dir() {
            copy_tree(&entry.path(), &target);
        } else {
            std::fs::copy(entry.path(), &target).expect("a copy");
        }
    }
}

/// A copy of the shipped resources whose `[tools] defaults` is `defaults`.
fn resources_with_default_tools(defaults: &[&str]) -> tempfile::TempDir {
    let directory = tempfile::tempdir().expect("a folder");
    copy_tree(&crate::resources::source_tree(), directory.path());
    let names: Vec<String> = defaults.iter().map(|name| format!("{name:?}")).collect();
    std::fs::write(
        directory.path().join("config.toml"),
        format!(
            "[starters]\nonly = [\"@box/claude\", \"@box/codex\"]\n\n[tools]\ndefaults = [{}]\n",
            names.join(", ")
        ),
    )
    .expect("a config");
    directory
}

#[test]
fn a_new_profile_copies_a_file_of_a_shipped_pack_that_box_installed_in_its_home() {
    let host = FakeHost::new();
    let resources = host.home().join(".strands/box/packages/1/resources");
    copy_tree(&crate::resources::source_tree(), &resources);
    let pack = resources.join("packs/claude/pack.toml");
    let mut text = std::fs::read_to_string(&pack).expect("the claude pack");
    text.push_str(
        "\n[[storage.files]]\nsource = \"${{ pack }}/box.md\"\ntarget = \"config/box-copy.md\"\n",
    );
    std::fs::write(&pack, text).expect("the claude pack");
    host.profile()
        .with("claude")
        .with("bedrock")
        .resources(&resources)
        .create()
        .expect("a copy from box's own packs in ~/.strands/box");
}

#[test]
fn a_new_profile_gets_the_default_tools_in_their_order_and_names_a_missing_one() {
    let host = FakeHost::new();
    let resources = resources_with_default_tools(&["npm", "git", "pnpm"]);
    let created = host
        .profile()
        .with("claude")
        .with("bedrock")
        .resources(resources.path())
        .create()
        .expect("a profile");
    assert_eq!(
        created.profile().packs(),
        [
            "@box/claude",
            "@box/bedrock",
            "@box/npm",
            "@box/git",
            "@box/pnpm"
        ]
    );
    let summary = created.summary(false);
    assert!(
        summary.lines().any(|line| {
            line.trim_start().starts_with("! pnpm (@box/pnpm) ")
                && line.ends_with("skipped: pnpm is not on PATH")
        }),
        "{summary}"
    );
}

#[test]
fn tools_on_the_command_line_take_the_place_of_the_default_tools() {
    let host = FakeHost::new();
    let resources = resources_with_default_tools(&["npm", "git", "pnpm"]);
    let created = host
        .profile()
        .with("claude")
        .with("bedrock")
        .resources(resources.path())
        .tools(["cargo"])
        .create()
        .expect("a profile");
    assert_eq!(
        created.profile().packs(),
        ["@box/claude", "@box/bedrock", "@box/cargo"]
    );
}

#[test]
fn a_default_tool_with_no_shipped_pack_refuses_the_profile() {
    let host = FakeHost::new();
    let resources = resources_with_default_tools(&["git", "gti"]);
    let error = host
        .profile()
        .with("claude")
        .with("bedrock")
        .resources(resources.path())
        .create()
        .expect_err("a refusal")
        .to_string();
    assert!(
        error.contains("`[tools] defaults` names `gti`, which is not a tool pack `box` ships"),
        "{error}"
    );
}

#[test]
fn an_existing_profile_keeps_its_packs_when_the_default_tools_change() {
    let host = FakeHost::new();
    let before = resources_with_default_tools(&["git"]);
    host.profile()
        .with("claude")
        .with("anthropic")
        .resources(before.path())
        .create()
        .expect("a profile")
        .write(false)
        .expect("a write");
    let preview = host
        .launcher()
        .preview("claude", &host.project())
        .expect("a preview");
    assert_eq!(
        preview.pack_list(),
        "@box/claude 1, @box/base 1, @box/anthropic 1, @box/git 1"
    );
}

/// The `TERM` that a run of the claude profile gives the agent, at a terminal, with `flag`, the
/// profile's `[banner]` table `profile`, and the operator's `[banner]` table `user`.
fn banner_term(flag: Option<bool>, profile: &str, user: &str) -> Option<String> {
    let host = FakeHost::new();
    host.profile()
        .with("claude")
        .with("bedrock")
        .create()
        .expect("a profile")
        .write(false)
        .expect("a write");
    let path = host
        .home()
        .join(".strands/box/profiles/claude/profile.toml");
    let text = std::fs::read_to_string(&path).expect("the profile");
    crate::test_support::write(
        &path,
        &format!("{text}\n[agent.env]\nTERM = \"profile-term\"\n\n{profile}"),
    );
    crate::test_support::write(&host.home().join(".strands/box/config.toml"), user);
    let launch = host
        .launcher()
        .banner(flag)
        .at_terminal()
        .prepare("claude", &host.project(), None)
        .expect("a run");
    let config: toml::Table =
        toml::from_str(&std::fs::read_to_string(launch.config()).expect("box.toml")).expect("TOML");
    config
        .get("agent")
        .and_then(|agent| agent.get("env"))
        .and_then(|env| env.get("TERM"))
        .and_then(toml::Value::as_str)
        .map(str::to_string)
}

#[test]
fn the_banner_follows_the_flag_then_the_profile_then_the_operators_config() {
    let banner = Some("xterm-256color".to_string());
    let direct = Some("profile-term".to_string());
    let on = "[banner]\nenabled = true\n";
    let off = "[banner]\nenabled = false\n";
    assert_eq!(banner_term(None, "", ""), banner);
    assert_eq!(banner_term(None, "", off), direct);
    assert_eq!(banner_term(None, on, off), banner);
    assert_eq!(banner_term(None, off, on), direct);
    assert_eq!(banner_term(Some(true), off, off), banner);
    assert_eq!(banner_term(Some(false), on, on), direct);
}

#[test]
fn the_operators_config_refuses_a_banner_table_it_cannot_read() {
    for (user, reason) in [
        (
            "[banner]\nenabled = \"off\"\n",
            "`banner.enabled` is `true` or `false`",
        ),
        (
            "[banner]\nenabled = false\nexpanded = true\n",
            "`[banner]` holds the unknown key `expanded`",
        ),
        (
            "banner = false\n",
            "`[banner]` is a table with `enabled`, `true` or `false`",
        ),
        (
            "[starters]\nonly = [\"@box/claude\"]\nadd = [\"x\"]\n",
            "`[starters]` holds `only` with `add` or `remove`",
        ),
        (
            "[starters]\nbogus = 1\n",
            "`[starters]` holds the unknown key `bogus`",
        ),
        (
            "[starters]\nonly = [\"box/claude\"]\n",
            "`[starters]` names \"box/claude\", which is not a starter name; a starter that box \
             ships is @box/<name>",
        ),
        (
            "[policy-starters]\nkeep = [\"@box/open\"]\n",
            "`[policy-starters]` holds the unknown key `keep`",
        ),
        (
            "[policy-starters]\nremove = [\"@box/opne\"]\n",
            "`[policy-starters] remove` names @box/opne, which is not in the policy menu",
        ),
        (
            "[policy-starters]\nonly = []\n",
            "`[policy-starters]` lists no policy starter",
        ),
        (
            "[policy-starters]\nonly = [\"@box/open\", \"@box/open\"]\n",
            "`[policy-starters] only` names @box/open twice",
        ),
        (
            "[policy-starters]\ndefault = \"@box/nope\"\n",
            "`[policy-starters] default` is @box/nope, which is not in the list",
        ),
        (
            "[run]\nbanner = false\n",
            "`config.toml` holds the unknown key `run`; it holds `[starters]` and \
             `[policy-starters]` and `[banner]`",
        ),
    ] {
        let host = FakeHost::new();
        host.profile()
            .with("claude")
            .with("bedrock")
            .create()
            .expect("a profile")
            .write(false)
            .expect("a write");
        crate::test_support::write(&host.home().join(".strands/box/config.toml"), user);
        for flag in [None, Some(true), Some(false)] {
            match host.launcher().banner(flag).at_terminal().prepare(
                "claude",
                &host.project(),
                None,
            ) {
                Err(Error::Config {
                    path,
                    reason: found,
                }) => {
                    assert_eq!(path, host.home().join(".strands/box/config.toml"), "{user}");
                    assert!(found.contains(reason), "{user} {flag:?}: {found}");
                }
                other => panic!("{user} {flag:?}: a refusal, not {:?}", other.map(|_| ())),
            }
        }
    }
}

#[test]
fn a_run_needs_no_policy_folder_that_config_toml_lists() {
    let host = FakeHost::new();
    host.profile()
        .with("claude")
        .with("bedrock")
        .create()
        .expect("a profile")
        .write(false)
        .expect("a write");
    crate::test_support::write(
        &host.home().join(".strands/box/config.toml"),
        "[policy-starters]\nadd = [\"team\"]\n",
    );
    host.launcher()
        .prepare("claude", &host.project(), None)
        .expect("a run of an existing profile reads no policy folder");
}

/// A profile file named `name` in its own folder beside the fake project.
fn profile_file(host: &FakeHost, folder: &str, name: Option<&str>) -> PathBuf {
    let directory = host.home().join(folder);
    std::fs::create_dir_all(&directory).expect("a profile folder");
    let header = name.map_or(String::new(), |name| {
        format!("\n[profile]\nname = {name:?}\n")
    });
    let path = directory.join("profile.toml");
    std::fs::write(
        &path,
        format!("packs = [\"@box/base\"]\n{header}\n[agent]\ncommand = [\"/usr/bin/true\"]\n"),
    )
    .expect("a profile file");
    path
}

fn argument(path: &Path) -> String {
    path.display().to_string()
}

#[test]
fn a_profile_file_outside_the_project_resolves_under_its_declared_name() {
    let host = FakeHost::new();
    let file = profile_file(&host, "repo/box", Some("weather"));
    let preview = host
        .launcher()
        .preview(&argument(&file), &host.project())
        .expect("a preview");
    assert!(
        preview
            .storage
            .ends_with(".strands/box/storage/weather/default"),
        "{}",
        preview.storage.display()
    );
}

#[test]
fn a_profile_file_without_a_name_is_refused() {
    let host = FakeHost::new();
    let file = profile_file(&host, "repo/box", None);
    let error = host
        .launcher()
        .preview(&argument(&file), &host.project())
        .expect_err("a path profile needs a name");
    assert!(matches!(error, Error::ProfileFileUnnamed { .. }), "{error}");
}

#[test]
fn a_profile_file_in_the_project_is_refused_unless_it_is_in_the_projects_box_folder() {
    let host = FakeHost::new();
    let project = host.project();
    let inside = project
        .strip_prefix(host.home())
        .expect("the project is in the home");
    let file = profile_file(&host, &inside.display().to_string(), Some("weather"));
    let error = host
        .launcher()
        .preview(&argument(&file), &project)
        .expect_err("the agent can write the project");
    assert!(matches!(error, Error::ProfileInWorkspace { .. }), "{error}");

    let file = profile_file(
        &host,
        &inside.join(".box").display().to_string(),
        Some("weather"),
    );
    host.launcher()
        .preview(&argument(&file), &project)
        .expect("the agent cannot reach the project's .box folder");
}

/// **A write grant may not reach a profile file or its policy files**, wherever the file lives,
/// because a later run trusts them.
#[test]
fn a_write_grant_over_a_profile_file_or_its_policy_is_refused() {
    let host = FakeHost::new();
    let folder = host.home().join("repo/box");
    std::fs::create_dir_all(&folder).expect("a profile folder");
    std::fs::create_dir_all(host.home().join("scratch")).expect("a scratch folder");
    std::fs::create_dir_all(folder.join("policies")).expect("a policy folder");
    std::fs::write(folder.join("policies/policy.dw"), "").expect("a policy file");
    let file = folder.join("profile.toml");
    let write = |grant: &str, policies: &str| {
        std::fs::write(
            &file,
            format!(
                "packs = [\"@box/base\"]\n{policies}\n[profile]\nname = \"weather\"\n\
                 [agent]\ncommand = [\"/usr/bin/true\"]\n\
                 [agent.filesystem]\nread = [\"{grant}\"]\nwrite = [\"{grant}\"]\n"
            ),
        )
        .expect("a profile file");
    };
    for (grant, policies) in [
        ("~/repo", ""),
        ("~/repo/box/policies", "policies = [\"policies/policy.dw\"]"),
    ] {
        write(grant, policies);
        let error = host
            .launcher()
            .preview(&argument(&file), &host.project())
            .expect_err("the grant reaches the profile file");
        assert!(
            matches!(error, Error::WriteOverProtected { .. }),
            "{grant}: {error}"
        );
    }
    write("~/scratch", "policies = [\"policies/policy.dw\"]");
    host.launcher()
        .preview(&argument(&file), &host.project())
        .expect("a grant beside the profile file is allowed");
}

/// **The Shell and Monty cannot change a profile file or its policy files** outside the workspace:
/// the compiled policy forbids writing, deleting, and moving each one, and moving or deleting each
/// folder above it. A profile in the workspace's `.box` gets no such rule, because `.box` already
/// has its own.
#[test]
fn a_profile_file_outside_the_workspace_is_forbidden_to_the_shell_and_monty() {
    let host = FakeHost::new();
    let folder = host.home().join("my-agent/box");
    std::fs::create_dir_all(folder.join("policies")).expect("a profile folder");
    std::fs::write(folder.join("policies/team.dw"), "").expect("a policy file");
    let file = folder.join("profile.toml");
    std::fs::write(
        &file,
        "packs = [\"@box/base\"]\npolicies = [\"policies/team.dw\"]\n\
         [profile]\nname = \"weather\"\n[agent]\ncommand = [\"/usr/bin/true\"]\n",
    )
    .expect("a profile file");
    let preview = host
        .launcher()
        .preview(&argument(&file), &host.project())
        .expect("the profile file loads");
    let reported = |path: &str| format!("context.input.path == {:?}", format!("~/{path}"));
    let files = format!(
        "{} || {}",
        reported("my-agent/box/profile.toml"),
        reported("my-agent/box/policies/team.dw")
    );
    for (action, id) in [
        ("fs:write", "profile_file_write"),
        ("fs:delete", "profile_file_delete"),
        ("fs:move", "profile_file_move"),
    ] {
        let rule = format!(
            "@id({id:?}) forbid (principal, action == Box::Action::{action:?}, resource) when {{ {files} }};"
        );
        assert!(preview.policy.contains(&rule), "{rule}\n{}", preview.policy);
    }
    let folders = format!(
        "{} || {} || {}",
        reported("my-agent/box"),
        reported("my-agent"),
        reported("my-agent/box/policies"),
    );
    for (action, id) in [
        ("fs:move", "profile_folder_move"),
        ("fs:delete", "profile_folder_delete"),
    ] {
        let rule = format!(
            "@id({id:?}) forbid (principal, action == Box::Action::{action:?}, resource) when {{ {folders} }};"
        );
        assert!(preview.policy.contains(&rule), "{rule}\n{}", preview.policy);
    }

    let project = host.project();
    let inside = project
        .strip_prefix(host.home())
        .expect("the project is in the home");
    let in_box = profile_file(
        &host,
        &inside.join(".box").display().to_string(),
        Some("inbox"),
    );
    let preview = host
        .launcher()
        .preview(&argument(&in_box), &project)
        .expect("a profile in .box loads");
    assert!(
        !preview.policy.contains("profile_file_"),
        ".box already has its own rules: {}",
        preview.policy
    );
}

/// **A run of a profile file records its owner, and no box may later run in a folder that holds
/// it**, outside that folder's own `.box`, because its agent could change the file before the
/// profile's next run.
#[test]
fn a_run_records_its_profile_file_and_a_project_holding_it_is_refused() {
    let host = FakeHost::new();
    let file = profile_file(&host, "repo/box", Some("weather"));
    host.launcher()
        .prepare(&argument(&file), &host.project(), None)
        .expect("a run of the profile file");
    let record = host
        .home()
        .join(".strands/box/storage/weather/.profile-source");
    assert_eq!(
        std::fs::read_to_string(&record).expect("the run records the owner"),
        format!(
            "{}\n",
            std::fs::canonicalize(&file).expect("a real path").display()
        )
    );

    profile_file(&host, ".strands/box/profiles/claude", None);
    let repo = host.home().join("repo");
    let error = host
        .launcher()
        .prepare("claude", &repo, None)
        .expect_err("the project holds the profile file");
    assert!(
        matches!(error, Error::WorkspaceHoldsProfile { .. }),
        "{error}"
    );
    let error = host
        .launcher()
        .preview("claude", &repo)
        .expect_err("show refuses it too");
    assert!(
        matches!(error, Error::WorkspaceHoldsProfile { .. }),
        "{error}"
    );
    host.launcher()
        .prepare("claude", &host.home().join("repo/box/.."), None)
        .expect_err("a spelling of the same folder is refused too");

    let boxed = profile_file(&host, "other/.box", Some("other"));
    host.launcher()
        .prepare(&argument(&boxed), &host.home().join("other"), None)
        .expect("a profile in the workspace's .box runs");
    host.launcher()
        .prepare("claude", &host.home().join("other"), None)
        .expect("a profile in this workspace's own .box is protected by it");
}

/// **`${{ profile.file }}` names the profile's own file**: the file a path named, whatever its
/// name, or `profile.toml` in a named profile's folder.
#[test]
fn profile_file_names_the_file_that_was_run() {
    let host = FakeHost::new();
    let body = "packs = [\"@box/base\"]\n[agent]\ncommand = [\"/usr/bin/true\"]\n\
                [agent.env]\nPROFILE_FILE = \"${{ profile.file }}\"\n";
    let folder = host.home().join("my-agent/box");
    std::fs::create_dir_all(&folder).expect("a profile folder");
    let file = folder.join("ci.toml");
    std::fs::write(&file, format!("{body}[profile]\nname = \"ci\"\n")).expect("a profile file");
    let env = |preview: &crate::Preview| -> String {
        let config: toml::Table = toml::from_str(&preview.box_toml).expect("box.toml");
        config["agent"]["env"]["PROFILE_FILE"]
            .as_str()
            .expect("the variable")
            .to_string()
    };
    let preview = host
        .launcher()
        .preview(&argument(&file), &host.project())
        .expect("the profile file loads");
    assert_eq!(
        env(&preview),
        std::fs::canonicalize(&file)
            .expect("a real path")
            .display()
            .to_string()
    );

    let named = host.home().join(".strands/box/profiles/radar");
    std::fs::create_dir_all(&named).expect("a profile folder");
    std::fs::write(named.join("profile.toml"), body).expect("a named profile");
    let preview = host
        .launcher()
        .preview("radar", &host.project())
        .expect("the named profile loads");
    assert!(
        env(&preview).ends_with(".strands/box/profiles/radar/profile.toml"),
        "{}",
        env(&preview)
    );
}

/// **A profile or policy file must be one that only the operator can change**: no second hard
/// link, no other owner, no group or other write; a policy file in the project is refused like the
/// profile file; and a profile name cannot end in `.toml`.
#[test]
fn a_profile_or_policy_file_another_name_or_user_can_change_is_refused() {
    use std::os::unix::fs::PermissionsExt as _;
    let host = FakeHost::new();
    let file = profile_file(&host, "repo/box", Some("weather"));
    let preview = |file: &Path| host.launcher().preview(&argument(file), &host.project());

    std::fs::hard_link(&file, host.home().join("repo/link.toml")).expect("a second name");
    let error = preview(&file).expect_err("a hard-linked profile file");
    assert!(matches!(error, Error::ProfileFileShared { .. }), "{error}");
    std::fs::remove_file(host.home().join("repo/link.toml")).expect("remove the link");

    std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o666)).expect("other write");
    let error = preview(&file).expect_err("an other-writable profile file");
    assert!(matches!(error, Error::ProfileFileShared { .. }), "{error}");
    assert!(error.to_string().contains("chmod go-w"), "{error}");
    std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o664)).expect("group write");
    let private = {
        use std::os::unix::fs::MetadataExt as _;
        let gid = std::fs::metadata(&file).expect("metadata").gid();
        let account = nix::unistd::User::from_uid(nix::unistd::getuid())
            .expect("a user")
            .expect("an account");
        nix::unistd::Group::from_gid(nix::unistd::Gid::from_raw(gid))
            .expect("a group")
            .is_some_and(|group| {
                group.gid == account.gid
                    && group.name == account.name
                    && group.mem.iter().all(|member| *member == account.name)
            })
    };
    match preview(&file) {
        Ok(_) => assert!(private, "group write in a shared group must be refused"),
        Err(error) => {
            assert!(
                !private,
                "group write in the operator's private group loads: {error}"
            );
            assert!(matches!(error, Error::ProfileFileShared { .. }), "{error}");
        }
    }
    std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o644)).expect("owner write");
    preview(&file).expect("a profile only the operator can change");

    let project = host.project();
    let inside = project
        .strip_prefix(host.home())
        .expect("the project is in the home");
    let folder = host.home().join(inside).join("box");
    std::fs::create_dir_all(&folder).expect("a folder in the project");
    std::fs::write(folder.join("policy.dw"), "").expect("a policy file in the project");
    std::fs::write(
        &file,
        format!(
            "packs = [\"@box/base\"]\npolicies = [{:?}]\n[profile]\nname = \"weather\"\n\
             [agent]\ncommand = [\"/usr/bin/true\"]\n",
            "policy.dw"
        ),
    )
    .expect("a profile with a policy");
    std::fs::write(host.home().join("repo/box/policy.dw"), "").expect("a policy beside it");
    preview(&file).expect("a policy beside the profile file");

    let moved = folder.join("profile.toml");
    std::fs::copy(&file, &moved).expect("a profile in the project");
    let error = preview(&moved).expect_err("the profile and its policy are in the project");
    assert!(matches!(error, Error::ProfileInWorkspace { .. }), "{error}");

    let work = host.home().join("repo/box/work");
    std::fs::create_dir_all(&work).expect("a workspace below the profile's folder");
    std::fs::write(work.join("policy.dw"), "").expect("a policy file in that workspace");
    std::fs::write(
        &file,
        "packs = [\"@box/base\"]\npolicies = [\"work/policy.dw\"]\n[profile]\nname = \"weather\"\n\
         [agent]\ncommand = [\"/usr/bin/true\"]\n",
    )
    .expect("a profile whose policy is in the workspace");
    let error = host
        .launcher()
        .preview(&argument(&file), &work)
        .expect_err("the policy file is in the workspace");
    assert!(
        matches!(error, Error::ProfileInWorkspace { ref path, .. } if path.ends_with("work/policy.dw")),
        "{error}"
    );

    let error = crate::profile::validate_name("team.toml").expect_err("a .toml name");
    assert!(error.to_string().contains("`.toml`"), "{error}");
}

#[test]
fn a_profile_file_cannot_take_the_name_of_a_named_profile() {
    let host = FakeHost::new();
    profile_file(&host, ".strands/box/profiles/weather", None);
    let file = profile_file(&host, "repo/box", Some("weather"));
    let error = host
        .launcher()
        .preview(&argument(&file), &host.project())
        .expect_err("the name belongs to ~/.strands/box/profiles/weather");
    assert!(matches!(error, Error::ProfileNameTaken { .. }), "{error}");
}

#[test]
fn a_second_profile_file_cannot_take_a_name_another_file_owns() {
    let host = FakeHost::new();
    let first = profile_file(&host, "repo/box", Some("weather"));
    let record = host
        .home()
        .join(".strands/box/storage/weather/.profile-source");
    std::fs::create_dir_all(record.parent().expect("a folder")).expect("a storage folder");
    std::fs::write(
        &record,
        format!(
            "{}\n",
            std::fs::canonicalize(&first)
                .expect("a real path")
                .display()
        ),
    )
    .expect("a record");
    host.launcher()
        .preview(&argument(&first), &host.project())
        .expect("the owner keeps its name");
    let second = profile_file(&host, "other/box", Some("weather"));
    let error = host
        .launcher()
        .preview(&argument(&second), &host.project())
        .expect_err("another file owns the name");
    assert!(matches!(error, Error::ProfileNameTaken { .. }), "{error}");
}

/// **A name that a profile file owns is refused to every other profile**: a profile in
/// `~/.strands/box/profiles/` of that name does not run, and `box profile create` and a starter do not
/// make one, because the storage of the name holds that file's state.
#[test]
fn a_name_a_profile_file_owns_is_refused_to_a_named_and_a_new_profile() {
    let host = FakeHost::new();
    let file = profile_file(&host, "repo/box", Some("weather"));
    host.launcher()
        .prepare(&argument(&file), &host.project(), None)
        .expect("a run of the profile file records its owner");

    let create = |profile: crate::NewProfile| {
        profile
            .policy("open")
            .tools(Vec::<String>::new())
            .answer(None)
            .and_then(crate::NewProfile::create)
    };
    let error = create(host.profile().name("weather").with("@box/codex"))
        .expect_err("box profile create of the owned name");
    assert!(matches!(error, Error::ProfileNameOwned { .. }), "{error}");
    assert!(
        error.to_string().contains("run that file by its path"),
        "{error}"
    );
    assert!(
        !host.home().join(".strands/box/profiles/weather").exists(),
        "the refused profile is not saved"
    );

    profile_file(&host, ".strands/box/profiles/weather", None);
    let error = host
        .launcher()
        .prepare("weather", &host.project(), None)
        .expect_err("a named profile of the owned name");
    assert!(matches!(error, Error::ProfileNameOwned { .. }), "{error}");
}

/// **A name whose owner file is gone points at its record**: a moved profile file is told to
/// remove the record, and then takes the name and its storage.
#[test]
fn a_name_whose_owner_file_is_gone_points_at_its_record() {
    let host = FakeHost::new();
    let first = profile_file(&host, "repo/box", Some("weather"));
    host.launcher()
        .prepare(&argument(&first), &host.project(), None)
        .expect("a run of the profile file records its owner");
    std::fs::remove_dir_all(host.home().join("repo")).expect("the repository moves");
    let moved = profile_file(&host, "moved/box", Some("weather"));
    let record = host
        .home()
        .join(".strands/box/storage/weather/.profile-source");

    let error = host
        .launcher()
        .preview(&argument(&moved), &host.project())
        .expect_err("the record still names the old path");
    assert!(
        matches!(error, Error::ProfileNameOwnerGone { record: ref path, .. } if *path == record),
        "{error}"
    );
    assert!(error.to_string().contains("remove"), "{error}");
    let error = host
        .launcher()
        .preview("weather", &host.project())
        .expect_err("a named run is told the same");
    assert!(
        matches!(error, Error::ProfileNameOwnerGone { .. }),
        "{error}"
    );

    std::fs::remove_file(&record).expect("remove the record");
    host.launcher()
        .preview(&argument(&moved), &host.project())
        .expect("the moved file takes the name");
}

/// **A profile file that renames itself leaves its old name free once its record is removed**: the
/// refusal for the old name says the file no longer declares it, and names the record.
#[test]
fn a_renamed_profile_files_old_name_points_at_its_record() {
    let host = FakeHost::new();
    let file = profile_file(&host, "repo/box", Some("weather"));
    host.launcher()
        .prepare(&argument(&file), &host.project(), None)
        .expect("a run of the profile file records its owner");
    profile_file(&host, "repo/box", Some("forecast"));
    host.launcher()
        .prepare(&argument(&file), &host.project(), None)
        .expect("the renamed file runs under its new name");
    let record = host
        .home()
        .join(".strands/box/storage/weather/.profile-source");

    let error = host
        .launcher()
        .preview("weather", &host.project())
        .expect_err("the old record still holds the name");
    assert!(
        matches!(error, Error::ProfileNameOwnerGone { record: ref path, .. } if *path == record),
        "{error}"
    );
    assert!(
        error.to_string().contains("no longer declares it"),
        "{error}"
    );
    let other = profile_file(&host, "other/box", Some("weather"));
    let error = host
        .launcher()
        .preview(&argument(&other), &host.project())
        .expect_err("another file is told the same");
    assert!(
        matches!(error, Error::ProfileNameOwnerGone { .. }),
        "{error}"
    );

    std::fs::remove_file(&record).expect("remove the record");
    host.launcher()
        .preview(&argument(&other), &host.project())
        .expect("the other file takes the name");
}

#[test]
fn a_named_profile_whose_declared_name_differs_from_its_folder_is_refused() {
    let host = FakeHost::new();
    profile_file(&host, ".strands/box/profiles/radar", Some("storm"));
    let error = host
        .launcher()
        .preview("radar", &host.project())
        .expect_err("the folder names the profile");
    assert!(
        error.to_string().contains("`[profile] name` is \"storm\""),
        "{error}"
    );
}

#[test]
fn a_profile_argument_is_a_path_when_it_holds_a_slash_or_ends_in_toml() {
    for path in [
        "./profile.toml",
        "../box/profile.toml",
        "/abs/p.toml",
        "agent.toml",
        "@box/p",
    ] {
        assert!(crate::is_profile_path(path), "{path}");
    }
    for name in ["claude", "my-agent", "a.b"] {
        assert!(!crate::is_profile_path(name), "{name}");
    }
}

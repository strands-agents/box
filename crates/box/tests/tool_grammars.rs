//! A `[tool.<name>.grammar]` table, through a real `run`: the switch, the record version, the
//! policy that names a grammar action, and the Shell that decides a bound spawn as that action.

mod support {
    pub mod fixture;
}

use std::path::Path;
use std::process::Output;

use support::fixture::{Configured, Request, namespace_launcher_is_usable};

const FORBID_PUSH: &str = r#"
permit (principal, action == Box::Action::"shell:exec", resource);
forbid (principal, action == Tool::git::Action::"push", resource);
"#;

const ORDINARY: &str = r#"permit (principal, action == Box::Action::"shell:exec", resource);"#;

const GRAMMAR: &str = r#"
[tool.git.grammar]
format = 1
version = 1
name = "git"
program = "git"

[tool.git.grammar.effects]
force_push = "Replaces commits on a remote branch"

[tool.git.grammar.shell.push]
usage = "git push [options] [<remote>]"
options.force = { flag = ["-f", "--force"], adds = ["force_push"] }

[tool.git.grammar.shell.status]
usage = "git status"
"#;

/// Every git command the grammar reads, except a push.
const GIT_WITHOUT_PUSH: &str = r#"
permit (principal, action == Box::Action::"shell:exec", resource);
permit (principal, action == Box::Action::"fs:read", resource);
permit (principal, action in Tool::git::Action::"*", resource);
@id("no_push")
@description("Pushes are not allowed.")
forbid (principal, action == Tool::git::Action::"push", resource);
"#;

const SWITCH_ON: &str = "\n[experimental-features]\ntool-grammars = true\n";

/// A `[tool.git]` whose program is a copy of `true(1)`, named `git`, that the test owns.
fn git_tool(home: &Path) -> String {
    let program = git_program(home);
    format!(
        "[tool.git]\ncommand = [{:?}]\n[tool.git.filesystem]\nread = [{:?}]\n",
        program.display().to_string(),
        tools_directory(home).display().to_string()
    )
}

fn tools_directory(home: &Path) -> std::path::PathBuf {
    home.join("tools")
}

/// The test's own `git`, a copy of `true(1)`, at its canonical path.
fn git_program(home: &Path) -> std::path::PathBuf {
    let directory = tools_directory(home);
    std::fs::create_dir_all(&directory).expect("the tools directory");
    let program = directory.join("git");
    if !program.exists() {
        std::fs::copy(support::fixture::no_op_program(), &program).expect("a git stand-in");
    }
    program.canonicalize().expect("the git stand-in resolves")
}

fn stdout(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

/// A created box whose `git` tool has the grammar, under `policy`, and whose trusted process finds
/// that `git` first on its search path.
fn grammar_box(home: &Path, policy: &str) -> Configured {
    Request::with_config(
        "grammar-enforce",
        policy,
        &format!("{}{GRAMMAR}{SWITCH_ON}", git_tool(home)),
    )
    .env(
        "PATH",
        &format!("{}:/usr/bin:/bin", tools_directory(home).display()),
    )
    .expect()
}

/// Run `command` in the hosted Shell, and print its status after it.
fn in_the_shell(box_: &Configured, command: &str) -> Output {
    box_.bash(&format!(r#"zsh -c '{command}; printf "|status=%s" "$?"'"#))
}

/// The `(category, action, verdict)` of each policy decision the box journaled.
fn decisions(box_: &Configured) -> Vec<(String, String, String)> {
    let text = std::fs::read_to_string(box_.root().join("private/telemetry/records.jsonl"))
        .unwrap_or_default();
    let mut found = Vec::new();
    for line in text.lines() {
        let Ok(batch) = serde_json::from_str::<serde_json::Value>(line) else {
            continue;
        };
        for resource in batch["resourceLogs"].as_array().into_iter().flatten() {
            for scope in resource["scopeLogs"].as_array().into_iter().flatten() {
                for entry in scope["logRecords"].as_array().into_iter().flatten() {
                    let text = |key: &str| {
                        entry["attributes"]
                            .as_array()
                            .into_iter()
                            .flatten()
                            .find(|attribute| attribute["key"] == key)
                            .and_then(|attribute| attribute["value"]["stringValue"].as_str())
                            .unwrap_or_default()
                            .to_string()
                    };
                    found.push((
                        text("strands.box.policy.category"),
                        text("strands.box.policy.action"),
                        text("strands.box.policy.verdict"),
                    ));
                }
            }
        }
    }
    found
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

fn record_version(root: &Path) -> Option<i64> {
    let text = std::fs::read_to_string(root.join("private/box.toml")).ok()?;
    let record: toml::Table = toml::from_str(&text).ok()?;
    record.get("version")?.as_integer()
}

fn attempt(policy: &str, body: impl FnOnce(&Path) -> String) -> (Output, Option<i64>) {
    let home = support::fixture::short_temporary_home();
    let request = Request::with_config("grammar", policy, &body(home.path()));
    let (configured, output) = request.attempt();
    (output, record_version(&configured.root()))
}

#[test]
fn a_policy_naming_a_grammar_action_starts_with_its_grammar_and_the_switch() {
    if !namespace_launcher_is_usable() {
        eprintln!("skipping: the namespace launcher is not usable on this host");
        return;
    }

    let (output, version) = attempt(FORBID_PUSH, |home| {
        format!("{}{GRAMMAR}{SWITCH_ON}", git_tool(home))
    });

    assert!(output.status.success(), "{}", stderr(&output));
    assert_eq!(
        version,
        Some(21),
        "a grammar box keeps the ordinary record version"
    );
    assert!(
        !stderr(&output).contains("does not fire yet"),
        "a rule on a grammar action fires, so startup warns of nothing: {}",
        stderr(&output)
    );
}

#[test]
fn a_forbid_on_a_grammar_action_denies_the_command_that_raises_it() {
    if !namespace_launcher_is_usable() {
        eprintln!("skipping: the namespace launcher is not usable on this host");
        return;
    }
    let home = support::fixture::short_temporary_home();
    let box_ = grammar_box(home.path(), GIT_WITHOUT_PUSH);
    let git = git_program(home.path()).display().to_string();

    let output = in_the_shell(&box_, &format!("{git} push origin"));

    assert!(stdout(&output).contains("|status=126"), "{output:?}");
    assert!(
        stderr(&output).contains(&format!(
            "policy denied Tool::git::Action::\"push\" on '{git}' [policy: no_push]: Pushes are \
             not allowed."
        )),
        "the denial names the grammar action: {output:?}"
    );
    let journaled = decisions(&box_);
    assert!(
        journaled.contains(&(
            "Tool::git".to_string(),
            "push".to_string(),
            "deny".to_string()
        )),
        "telemetry names the grammar action: {journaled:?}"
    );
}

#[test]
fn a_permit_on_a_grammar_action_runs_the_command_that_raises_it() {
    if !namespace_launcher_is_usable() {
        eprintln!("skipping: the namespace launcher is not usable on this host");
        return;
    }
    let home = support::fixture::short_temporary_home();
    let box_ = grammar_box(home.path(), GIT_WITHOUT_PUSH);
    let git = git_program(home.path()).display().to_string();

    let output = in_the_shell(&box_, &format!("{git} status"));

    assert!(stdout(&output).contains("|status=0"), "{output:?}");
}

#[test]
fn a_command_the_grammar_cannot_read_is_denied_without_a_permit_that_names_unmodeled() {
    if !namespace_launcher_is_usable() {
        eprintln!("skipping: the namespace launcher is not usable on this host");
        return;
    }
    let home = support::fixture::short_temporary_home();
    let box_ = grammar_box(home.path(), GIT_WITHOUT_PUSH);
    let git = git_program(home.path()).display().to_string();

    let output = in_the_shell(&box_, &format!("{git} frobnicate"));

    assert!(stdout(&output).contains("|status=126"), "{output:?}");
    assert!(
        stderr(&output).contains("policy denied Tool::git::Action::\"unmodeled\""),
        "{output:?}"
    );
}

#[test]
fn a_command_through_sh_is_decided_as_the_grammar_action_a_direct_command_raises() {
    if !namespace_launcher_is_usable() {
        eprintln!("skipping: the namespace launcher is not usable on this host");
        return;
    }
    let home = support::fixture::short_temporary_home();
    let box_ = grammar_box(home.path(), GIT_WITHOUT_PUSH);

    let output = box_.bash(r#"sh -c 'git push origin; printf "|status=%s" "$?"'"#);

    assert!(stdout(&output).contains("|status=126"), "{output:?}");
    assert!(
        stderr(&output).contains("policy denied Tool::git::Action::\"push\"")
            && stderr(&output).contains("[policy: no_push]"),
        "the same forbid denies the push through `sh -c`: {output:?}"
    );
}

#[test]
fn with_the_switch_off_a_tool_is_decided_as_shell_spawn() {
    if !namespace_launcher_is_usable() {
        eprintln!("skipping: the namespace launcher is not usable on this host");
        return;
    }
    let home = support::fixture::short_temporary_home();
    let box_ = Request::with_config(
        "grammar-off",
        r#"permit (principal, action == Box::Action::"shell:exec", resource);
           permit (principal, action == Box::Action::"fs:read", resource);
           @id("no_git")
           forbid (principal, action == Box::Action::"shell:spawn", resource);"#,
        &git_tool(home.path()),
    )
    .expect();
    let git = git_program(home.path()).display().to_string();

    let output = in_the_shell(&box_, &format!("{git} push origin"));

    assert!(stdout(&output).contains("|status=126"), "{output:?}");
    assert!(
        stderr(&output).contains("policy denied this operation")
            && stderr(&output).contains("[policy: no_git]"),
        "`shell:spawn` decides the spawn: {output:?}"
    );
    assert!(!stderr(&output).contains("Tool::"), "{output:?}");
}

#[test]
fn the_same_policy_without_the_grammar_is_refused_at_startup() {
    if !namespace_launcher_is_usable() {
        eprintln!("skipping: the namespace launcher is not usable on this host");
        return;
    }

    let (output, _) = attempt(FORBID_PUSH, |home| format!("{}{SWITCH_ON}", git_tool(home)));

    assert!(!output.status.success(), "{}", stderr(&output));
    assert!(
        stderr(&output).contains("Tool::git::Action::\"push\""),
        "the refusal names the action no grammar declares: {}",
        stderr(&output)
    );
}

#[test]
fn a_grammar_with_the_switch_off_is_refused_at_startup() {
    if !namespace_launcher_is_usable() {
        eprintln!("skipping: the namespace launcher is not usable on this host");
        return;
    }

    let (output, version) = attempt(FORBID_PUSH, |home| format!("{}{GRAMMAR}", git_tool(home)));

    assert!(!output.status.success(), "{}", stderr(&output));
    assert!(
        stderr(&output).contains("`grammar` is experimental"),
        "{}",
        stderr(&output)
    );
    assert_eq!(version, None, "a refused configuration stores no record");
}

#[test]
fn two_grammars_for_one_program_are_refused_at_startup() {
    if !namespace_launcher_is_usable() {
        eprintln!("skipping: the namespace launcher is not usable on this host");
        return;
    }
    let second = GRAMMAR
        .replace("[tool.git.", "[tool.brew_git.")
        .replace("name = \"git\"", "name = \"brew_git\"");

    let (output, version) = attempt(FORBID_PUSH, |home| {
        format!(
            "{}{GRAMMAR}[tool.brew_git]\ncommand = [\"/opt/homebrew/bin/git\"]\n{second}{SWITCH_ON}",
            git_tool(home)
        )
    });

    assert!(!output.status.success(), "{}", stderr(&output));
    assert!(
        stderr(&output).contains(
            "tool grammar refused: `tool.brew_git.grammar` and `tool.git.grammar` both have \
             `program = \"git\"`; keep one grammar for each program"
        ),
        "{}",
        stderr(&output)
    );
    assert_eq!(version, None, "a refused configuration stores no record");
}

#[test]
fn a_box_with_the_switch_off_and_no_grammar_is_unchanged() {
    if !namespace_launcher_is_usable() {
        eprintln!("skipping: the namespace launcher is not usable on this host");
        return;
    }

    let (output, version) = attempt(ORDINARY, git_tool);

    assert!(output.status.success(), "{}", stderr(&output));
    assert_eq!(
        version,
        Some(21),
        "the ordinary record version is unchanged"
    );
}

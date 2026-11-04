//! A `[tool.<name>.grammar]` table, through a real `run`: the switch, the record version, and the
//! policy that names a grammar action.

mod support {
    pub mod fixture;
}

use std::path::Path;
use std::process::Output;

use support::fixture::{Request, namespace_launcher_is_usable};

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
"#;

const SWITCH_ON: &str = "\n[experimental-features]\ntool-grammars = true\n";

/// A `[tool.git]` whose program is a copy of `true(1)`, named `git`, that the test owns.
fn git_tool(home: &Path) -> String {
    let directory = home.join("tools");
    std::fs::create_dir_all(&directory).expect("the tools directory");
    let program = directory.join("git");
    std::fs::copy(support::fixture::no_op_program(), &program).expect("a git stand-in");
    format!(
        "[tool.git]\ncommand = [{:?}]\n",
        program.display().to_string()
    )
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
        Some(25),
        "a grammar box carries its own record version"
    );
    assert!(
        stderr(&output).contains("[tool.git] grammar: the Shell still decides a spawn of `git`"),
        "a rule on a grammar action does not fire yet, and startup says so: {}",
        stderr(&output)
    );
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

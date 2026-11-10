//! A `[tool.<name>.grammar]` table, through a real `run`: the switch, the record version, the
//! policy that names a grammar action, and the Shell that decides a bound spawn as that action.

mod support {
    pub mod fixture;
}

use std::path::Path;
use std::process::Output;

use support::fixture::{Configured, PROJECT, Request, namespace_launcher_is_usable};

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

const CARGO_GRAMMAR: &str = r#"
[tool.cargo.grammar]
format = 1
version = 1
name = "cargo"
program = "cargo"

[tool.cargo.grammar.shell.test]
usage = "cargo test"
"#;

/// A push only after a `cargo test` that exited 0.
const PUSH_AFTER_A_PASSING_TEST: &str = r#"
permit (principal, action == Box::Action::"shell:exec", resource);
permit (principal, action == Box::Action::"fs:read", resource);
permit (principal, action in Tool::git::Action::"*", resource);
permit (principal, action in Tool::cargo::Action::"*", resource);
@id("push_after_a_passing_test")
@description("Run the tests before you push.")
forbid (principal, action == Tool::git::Action::"push", resource)
unless temporal {
    formerly within 1h Tool::cargo::Action::"test"::response{ output.status: 0 }
};
"#;

const SWITCH_ON: &str = "\n[experimental-features]\ntool-grammars = true\n";

/// A `[tool.git]` whose program is the test's own `git`.
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

/// The test's own `git`, which always exits 0, at its canonical path.
fn git_program(home: &Path) -> std::path::PathBuf {
    let directory = tools_directory(home);
    std::fs::create_dir_all(&directory).expect("the tools directory");
    let program = directory.join("git");
    if !program.exists() {
        compile_tool(&program, 0);
    }
    program.canonicalize().expect("the git stand-in resolves")
}

/// A `[tool.cargo]` whose program is the test's own `cargo`.
fn cargo_tool(home: &Path) -> String {
    format!(
        "[tool.cargo]\ncommand = [{:?}]\n[tool.cargo.filesystem]\nread = [{:?}]\n",
        cargo_path(home).display().to_string(),
        tools_directory(home).display().to_string()
    )
}

fn cargo_path(home: &Path) -> std::path::PathBuf {
    tools_directory(home).join("cargo")
}

/// The test's `cargo`, rebuilt with `exit_status`, at its canonical path.
fn install_cargo(home: &Path, exit_status: i32) -> String {
    std::fs::create_dir_all(tools_directory(home)).expect("the tools directory");
    let path = cargo_path(home);
    let staged = path.with_extension("new");
    compile_tool(&staged, exit_status);
    std::fs::rename(&staged, &path).expect("install the cargo stand-in");
    path.canonicalize()
        .expect("the cargo stand-in resolves")
        .display()
        .to_string()
}

fn compile_tool(path: &Path, exit_status: i32) {
    use std::io::Write as _;
    use std::process::{Command, Stdio};

    let mut compiler = Command::new(std::env::var_os("RUSTC").unwrap_or_else(|| "rustc".into()))
        .args(["--edition=2024", "--crate-name", "tool_grammar_probe", "-"])
        .arg("-o")
        .arg(path)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("start the tool probe compiler");
    compiler
        .stdin
        .take()
        .expect("compiler input")
        .write_all(format!("fn main() {{ std::process::exit({exit_status}); }}").as_bytes())
        .expect("write the tool probe source");
    let output = compiler.wait_with_output().expect("compile the tool probe");
    assert!(
        output.status.success(),
        "tool probe compilation: {output:?}"
    );
}

fn stdout(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

/// A created box whose `git` tool has the grammar, under `policy`, and whose trusted process finds
/// that `git` first on its search path.
fn grammar_box(home: &Path, policy: &str) -> Configured {
    grammar_box_with(home, policy, "")
}

/// A `grammar_box` whose configuration also holds `more`.
fn grammar_box_with(home: &Path, policy: &str, more: &str) -> Configured {
    Request::with_config(
        "grammar-enforce",
        policy,
        &format!("{}{GRAMMAR}{more}{SWITCH_ON}", git_tool(home)),
    )
    .env("PATH", &tools_first(home))
    .expect()
}

/// Run `command` in the hosted Shell, and print its status after it.
fn in_the_shell(box_: &Configured, command: &str) -> Output {
    box_.bash(&format!(r#"zsh -c '{command}; printf "|status=%s" "$?"'"#))
}

/// The box journaled a denial of the git grammar action `action`.
fn assert_grammar_decision(box_: &Configured, action: &str) {
    let journaled = decisions(box_);
    assert!(
        journaled.contains(&(
            "Tool::git".to_string(),
            action.to_string(),
            "deny".to_string()
        )),
        "telemetry names the grammar action: {journaled:?}"
    );
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

/// The search path of a trusted process that finds the test's tools first.
fn tools_first(home: &Path) -> String {
    format!("{}:/usr/bin:/bin", tools_directory(home).display())
}

fn attempt(policy: &str, body: impl FnOnce(&Path) -> String) -> (Output, Option<i64>) {
    let home = support::fixture::short_temporary_home();
    let request = Request::with_config("grammar", policy, &body(home.path()));
    let (configured, output) = request.attempt();
    (output, record_version(&configured.root()))
}

/// An `attempt` whose trusted process finds the test's tools first on its search path.
fn attempt_with_tools_first(policy: &str, body: impl FnOnce(&Path) -> String) -> Output {
    let home = support::fixture::short_temporary_home();
    Request::with_config("grammar", policy, &body(home.path()))
        .env("PATH", &tools_first(home.path()))
        .attempt()
        .1
}

const NPM_GRAMMAR: &str = r#"
[tool.npm.grammar]
format = 1
version = 1
name = "npm"
program = "npm"

[tool.npm.grammar.shell.install]
usage = "npm install"
"#;

/// An install is not allowed.
const NO_INSTALL: &str = r#"
permit (principal, action == Box::Action::"shell:exec", resource);
permit (principal, action == Box::Action::"fs:read", resource);
@id("no_install")
@description("Installs are not allowed.")
forbid (principal, action == Tool::npm::Action::"install", resource);
"#;

/// The test's `npm-cli.js`, a copy of `true(1)` at its canonical path, with a link `npm` to it
/// in the tools directory.
fn linked_npm(home: &Path) -> std::path::PathBuf {
    let library = tools_directory(home).join("lib");
    std::fs::create_dir_all(&library).expect("the library directory");
    let file = library.join("npm-cli.js");
    std::fs::copy(support::fixture::no_op_program(), &file).expect("an npm stand-in");
    std::os::unix::fs::symlink("lib/npm-cli.js", tools_directory(home).join("npm"))
        .expect("the npm link");
    file.canonicalize().expect("the npm stand-in resolves")
}

/// A `[tool.<label>]` whose command is `program`, with read access to the tools directory.
fn tool_at(home: &Path, label: &str, program: &Path) -> String {
    format!(
        "[tool.{label}]\ncommand = [{:?}]\n[tool.{label}.filesystem]\nread = [{:?}]\n",
        program.display().to_string(),
        tools_directory(home).display().to_string()
    )
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
    assert!(
        stderr(&output).contains(
            "strands-box: [tool.git]: a spawn of `git` is decided by its tool grammar, and no \
             `shell:spawn` rule applies to it"
        ),
        "startup names the tool that its grammar decides: {}",
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
            "policy denied this operation on '{git}' [policy: no_push]: Pushes are not allowed."
        )),
        "{output:?}"
    );
    assert_grammar_decision(&box_, "push");
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
        stderr(&output).contains(&format!(
            "policy denied this operation on '{git}' [default-deny]: No permit policy matched \
             this request."
        )),
        "{output:?}"
    );
    assert_grammar_decision(&box_, "unmodeled");
}

#[test]
fn a_command_through_sh_is_decided_as_the_grammar_action_a_direct_command_raises() {
    if !namespace_launcher_is_usable() {
        eprintln!("skipping: the namespace launcher is not usable on this host");
        return;
    }
    let home = support::fixture::short_temporary_home();
    let box_ = grammar_box(home.path(), GIT_WITHOUT_PUSH);
    let git = git_program(home.path()).display().to_string();

    let output = box_.bash(r#"sh -c 'git push origin; printf "|status=%s" "$?"'"#);

    assert!(stdout(&output).contains("|status=126"), "{output:?}");
    assert!(
        stderr(&output).contains(&format!("policy denied this operation on '{git}'"))
            && stderr(&output).contains("[policy: no_push]: Pushes are not allowed."),
        "the same forbid denies the push through `sh -c`: {output:?}"
    );
    assert_grammar_decision(&box_, "push");
}

#[test]
fn a_push_is_denied_until_a_test_exits_0_and_stays_allowed_after_a_restart() {
    if !namespace_launcher_is_usable() {
        eprintln!("skipping: the namespace launcher is not usable on this host");
        return;
    }
    let home = support::fixture::short_temporary_home();
    let cargo = install_cargo(home.path(), 1);
    let box_ = grammar_box_with(
        home.path(),
        PUSH_AFTER_A_PASSING_TEST,
        &format!("{}{CARGO_GRAMMAR}", cargo_tool(home.path())),
    );
    let git = git_program(home.path()).display().to_string();

    let failed = box_.bash(&format!(
        r#"zsh -c '{git} push origin; printf "|untested=%s" "$?"; {cargo} test; printf "|test=%s" "$?"; {git} push origin; printf "|after_a_failure=%s" "$?"'"#
    ));

    assert!(
        stdout(&failed).contains("|untested=126|test=1|after_a_failure=126"),
        "a push before any test, and after a test that exited 1, is denied: {failed:?}"
    );
    assert_eq!(
        stderr(&failed)
            .matches("[policy: push_after_a_passing_test]")
            .count(),
        2,
        "the rule denies both pushes: {failed:?}"
    );

    let cargo = install_cargo(home.path(), 0);
    let passed = box_.bash(&format!(
        r#"zsh -c '{cargo} test; printf "|test=%s" "$?"; {git} push origin; printf "|push=%s" "$?"'"#
    ));

    assert!(
        stdout(&passed).contains("|test=0|push=0"),
        "a test that exited 0 allows the push: {passed:?}"
    );

    let restarted = box_.bash(&format!(
        r#"zsh -c '{git} push origin; printf "|push=%s" "$?"'"#
    ));

    assert!(
        stdout(&restarted).contains("|push=0"),
        "a new run on the same box directory reads the test from history: {restarted:?}"
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

#[test]
fn a_grammar_decides_the_name_the_agent_types_when_the_command_names_the_linked_file() {
    if !namespace_launcher_is_usable() {
        eprintln!("skipping: the namespace launcher is not usable on this host");
        return;
    }
    let home = support::fixture::short_temporary_home();
    let npm = linked_npm(home.path());
    let (box_, started) = Request::with_config(
        "grammar-linked",
        NO_INSTALL,
        &format!(
            "{}{NPM_GRAMMAR}{SWITCH_ON}",
            tool_at(home.path(), "npm", &npm)
        ),
    )
    .env("PATH", &tools_first(home.path()))
    .attempt();
    assert!(started.status.success(), "{}", stderr(&started));
    assert!(
        stderr(&started).contains(
            "strands-box: [tool.npm]: a spawn of `npm` is decided by its tool grammar, and no \
             `shell:spawn` rule applies to it"
        ),
        "startup names the program the grammar binds: {}",
        stderr(&started)
    );

    let output = in_the_shell(&box_, "npm install");

    assert!(stdout(&output).contains("|status=126"), "{output:?}");
    assert!(
        stderr(&output).contains("[policy: no_install]: Installs are not allowed."),
        "{output:?}"
    );
    assert!(
        decisions(&box_).contains(&(
            "Tool::npm".to_string(),
            "install".to_string(),
            "deny".to_string()
        )),
        "telemetry names the grammar action: {:?}",
        decisions(&box_)
    );
}

#[test]
fn a_grammar_whose_program_finds_another_file_on_path_is_refused_at_startup() {
    if !namespace_launcher_is_usable() {
        eprintln!("skipping: the namespace launcher is not usable on this host");
        return;
    }
    let grammar = GRAMMAR.replace("[tool.git.", "[tool.gh.");

    let output = attempt_with_tools_first(FORBID_PUSH, |home| {
        git_program(home);
        let gh = tools_directory(home).join("gh");
        std::fs::copy(support::fixture::no_op_program(), &gh).expect("a gh stand-in");
        let gh = gh.canonicalize().expect("the gh stand-in resolves");
        format!("{}{grammar}{SWITCH_ON}", tool_at(home, "gh", &gh))
    });

    assert!(!output.status.success(), "{}", stderr(&output));
    assert!(
        stderr(&output).contains(
            "invalid `[tool.gh]` table: `tool.gh.grammar.program` is \"git\", and `PATH` finds "
        ) && stderr(&output).contains("/tools/git, but `command` runs ")
            && stderr(&output)
                .contains("/tools/gh; a grammar reads only the program its own tool runs"),
        "{}",
        stderr(&output)
    );
}

#[test]
fn a_grammar_whose_program_finds_nothing_on_path_is_refused_at_startup() {
    if !namespace_launcher_is_usable() {
        eprintln!("skipping: the namespace launcher is not usable on this host");
        return;
    }
    let grammar = GRAMMAR
        .replace("[tool.git.", "[tool.absent.")
        .replace("program = \"git\"", "program = \"strands_box_absent\"")
        .replace("usage = \"git ", "usage = \"strands_box_absent ");

    let output = attempt_with_tools_first(ORDINARY, |home| {
        format!(
            "{}{grammar}{SWITCH_ON}",
            tool_at(home, "absent", &git_program(home))
        )
    });

    assert!(!output.status.success(), "{}", stderr(&output));
    assert!(
        stderr(&output).contains(
            "invalid `[tool.absent]` table: `tool.absent.grammar.program` is \
             \"strands_box_absent\", and `PATH` finds no program by that name, but `command` runs "
        ),
        "{}",
        stderr(&output)
    );
}

/// A search path whose first `git` is a decoy that exits 3, ahead of the test's own tools.
fn decoy_first(home: &Path) -> String {
    let decoy = home.join("decoy");
    std::fs::create_dir_all(&decoy).expect("the decoy directory");
    compile_tool(&decoy.join("git"), 3);
    format!(
        "{}:{}:/usr/bin:/bin",
        decoy.display(),
        tools_directory(home).display()
    )
}

#[test]
fn a_bare_name_runs_the_tool_that_declares_it_when_another_file_is_first_on_path() {
    if !namespace_launcher_is_usable() {
        eprintln!("skipping: the namespace launcher is not usable on this host");
        return;
    }
    let home = support::fixture::short_temporary_home();
    let git = git_program(home.path()).display().to_string();
    let (box_, started) = Request::with_config(
        "bare-name-grammar",
        GIT_WITHOUT_PUSH,
        &format!("{}{GRAMMAR}{SWITCH_ON}", git_tool(home.path())),
    )
    .env("PATH", &decoy_first(home.path()))
    .attempt();
    assert!(started.status.success(), "{}", stderr(&started));
    assert!(
        stderr(&started).contains(&format!(
            "strands-box: [tool.git]: a bare `git` in the Shell runs {git}\n"
        )),
        "startup names the file a bare `git` runs: {}",
        stderr(&started)
    );

    let status = in_the_shell(&box_, "git status");
    let push = in_the_shell(&box_, "git push origin");

    assert!(stdout(&status).contains("|status=0"), "{status:?}");
    assert!(stdout(&push).contains("|status=126"), "{push:?}");
    assert!(
        stderr(&push).contains(&format!("policy denied this operation on '{git}'"))
            && stderr(&push).contains("[policy: no_push]: Pushes are not allowed."),
        "the grammar decides the tool's file, not the decoy: {push:?}"
    );
    assert_grammar_decision(&box_, "push");
}

#[test]
fn without_a_grammar_a_bare_name_runs_its_tool_under_shell_spawn() {
    if !namespace_launcher_is_usable() {
        eprintln!("skipping: the namespace launcher is not usable on this host");
        return;
    }
    let home = support::fixture::short_temporary_home();
    let git = git_program(home.path()).display().to_string();
    let box_ = Request::with_config(
        "bare-name-spawn",
        &format!(
            r#"permit (principal, action == Box::Action::"shell:exec", resource);
               permit (principal, action == Box::Action::"fs:read", resource);
               permit (principal, action == Box::Action::"shell:spawn", resource)
               when {{ context.input.program == "git" && context.input.program_path == "{git}" }};"#
        ),
        &git_tool(home.path()),
    )
    .env("PATH", &decoy_first(home.path()))
    .expect();

    let output = in_the_shell(&box_, "git status");

    assert!(
        stdout(&output).contains("|status=0"),
        "a permit pinned on the typed name and the tool's file admits it: {output:?}"
    );
}

#[test]
fn a_tool_with_fixed_arguments_claims_its_bare_name_and_refuses_other_arguments() {
    if !namespace_launcher_is_usable() {
        eprintln!("skipping: the namespace launcher is not usable on this host");
        return;
    }
    let home = support::fixture::short_temporary_home();
    let cargo = install_cargo(home.path(), 0);
    let decoy = home.path().join("decoy");
    std::fs::create_dir_all(&decoy).expect("the decoy directory");
    compile_tool(&decoy.join("cargo"), 0);
    let box_ = Request::with_config(
        "bare-name-fixed",
        r#"permit (principal, action == Box::Action::"shell:exec", resource);
           permit (principal, action == Box::Action::"fs:read", resource);
           permit (principal, action == Box::Action::"shell:spawn", resource);"#,
        &format!(
            "[tool.cargo_fmt]\ncommand = [{cargo:?}, \"fmt\"]\n[tool.cargo_fmt.filesystem]\nread = [{:?}]\n",
            tools_directory(home.path()).display().to_string()
        ),
    )
    .env("PATH", &format!("{}:/usr/bin:/bin", decoy.display()))
    .expect();

    let fmt = in_the_shell(&box_, "cargo fmt");
    let build = in_the_shell(&box_, "cargo build");

    assert!(stdout(&fmt).contains("|status=0"), "{fmt:?}");
    assert!(stdout(&build).contains("|status=126"), "{build:?}");
    assert!(
        stderr(&build).contains("no `[tool.<name>] command` matches this program"),
        "the tool's file is selected, and its fixed arguments do not match: {build:?}"
    );
}

/// Compile a program at `path` that prints `args=` and its arguments, prints `cwd=` and its working
/// directory on stderr, then exits 0.
fn compile_arguments_printer(path: &Path) {
    use std::io::Write as _;
    use std::process::{Command, Stdio};

    let mut compiler = Command::new(std::env::var_os("RUSTC").unwrap_or_else(|| "rustc".into()))
        .args([
            "--edition=2024",
            "--crate-name",
            "replaced_command_probe",
            "-",
        ])
        .arg("-o")
        .arg(path)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("start the probe compiler");
    compiler
        .stdin
        .take()
        .expect("compiler input")
        .write_all(
            b"fn main() { let args: Vec<String> = std::env::args().skip(1).collect(); \
              println!(\"args={}\", args.join(\" \")); \
              eprintln!(\"cwd={}\", std::env::current_dir().unwrap().display()); }",
        )
        .expect("write the probe source");
    let output = compiler.wait_with_output().expect("compile the probe");
    assert!(output.status.success(), "probe compilation: {output:?}");
}

/// A `[tool.python]` whose program is a probe named `python3`, with `more` after its `command`.
fn python_box(home: &Path, name: &str, more: &str) -> (Configured, Output, String) {
    let directory = tools_directory(home);
    std::fs::create_dir_all(&directory).expect("the tools directory");
    let python = directory.join("python3");
    compile_arguments_printer(&python);
    let python = python
        .canonicalize()
        .expect("the python probe resolves")
        .display()
        .to_string();
    let (box_, started) = Request::with_config(
        name,
        r#"permit (principal, action == Box::Action::"shell:exec", resource);
           permit (principal, action == Box::Action::"fs:read", resource);
           permit (principal, action == Box::Action::"shell:spawn", resource);"#,
        &format!(
            "[tool.python]\ncommand = [{python:?}]\n{more}[tool.python.filesystem]\nread = [{:?}]\n",
            directory.display().to_string()
        ),
    )
    .attempt();
    assert!(started.status.success(), "{}", stderr(&started));
    (box_, started, python)
}

#[test]
fn a_tool_that_replaces_python3_runs_for_the_bare_name_with_every_argument() {
    if !namespace_launcher_is_usable() {
        eprintln!("skipping: the namespace launcher is not usable on this host");
        return;
    }
    let home = support::fixture::short_temporary_home();
    let (box_, started, python) = python_box(
        home.path(),
        "replaced-python",
        "replaces = [\"python3\", \"python\"]\n",
    );
    for name in ["python", "python3"] {
        assert!(
            stderr(&started).contains(&format!(
                "strands-box: [tool.python]: a bare `{name}` in the Shell runs {python}, in place \
                 of Box's Python (Monty)\n"
            )),
            "startup names the file a bare `{name}` runs: {}",
            stderr(&started)
        );
    }

    let module = in_the_shell(&box_, "python3 -m venv .venv");
    let isolated = in_the_shell(&box_, "python -I -c pass");
    let found = in_the_shell(&box_, "command -v python3");

    assert!(
        stdout(&module).contains("args=-m venv .venv\n|status=0"),
        "`python3 -m` reaches the tool with every argument: {module:?}"
    );
    assert!(
        stdout(&isolated).contains("args=-I -c pass\n|status=0"),
        "`python -I` reaches the same tool: {isolated:?}"
    );
    assert!(
        stdout(&found).contains(&format!("{python}\n|status=0")),
        "`command -v` names the tool's file: {found:?}"
    );
}

#[test]
fn the_direct_python_alias_runs_the_tool_that_replaces_its_name() {
    if !namespace_launcher_is_usable() {
        eprintln!("skipping: the namespace launcher is not usable on this host");
        return;
    }
    let home = support::fixture::short_temporary_home();
    let (box_, _, _) = python_box(
        home.path(),
        "replaced-alias",
        "replaces = [\"python3\", \"python\"]\n",
    );

    // The host's own bash runs these, so `python3` is the box's alias in `bin/`, not the Shell.
    let module = box_.bash(r#"python3 -m venv .venv; printf "|status=%s" "$?""#);
    let quoted = box_.bash(r#"python -c "it's a b" ''; printf "|status=%s" "$?""#);

    assert!(
        stdout(&module).contains("args=-m venv .venv\n|status=0"),
        "the alias sends `-m` to the replacing tool: {module:?}"
    );
    assert!(
        stdout(&quoted).contains("args=-c it's a b \n|status=0"),
        "each argument reaches the tool as one word, quotes and empty ones included: {quoted:?}"
    );
}

#[test]
fn the_direct_python_alias_runs_the_tool_in_the_callers_directory() {
    if !namespace_launcher_is_usable() {
        eprintln!("skipping: the namespace launcher is not usable on this host");
        return;
    }
    let home = support::fixture::short_temporary_home();
    let directory = tools_directory(home.path());
    std::fs::create_dir_all(&directory).expect("the tools directory");
    let python = directory.join("python3");
    compile_arguments_printer(&python);
    let python = python.canonicalize().expect("the python probe resolves");
    let (box_, started) = Request::with_config(
        "replaced-cwd",
        r#"permit (principal, action == Box::Action::"shell:exec", resource);
           permit (principal, action == Box::Action::"fs:read", resource);
           permit (principal, action == Box::Action::"shell:spawn", resource);"#,
        &format!(
            "[tool.python]\ncommand = [{:?}]\nreplaces = [\"python3\"]\n\
             [tool.python.filesystem]\nread = [{:?}, {PROJECT:?}]\n",
            python.display().to_string(),
            directory.display().to_string()
        ),
    )
    .agent_list("read", &[PROJECT])
    .attempt();
    assert!(started.status.success(), "{}", stderr(&started));
    let sub = box_.workspace().join("sub");
    std::fs::create_dir_all(&sub).expect("a folder in the workspace");
    let sub = sub.canonicalize().expect("the folder resolves");

    let ran = box_.bash(r#"cd sub && python3 setup.py; printf "|status=%s" "$?""#);

    assert!(stdout(&ran).contains("args=setup.py\n|status=0"), "{ran:?}");
    assert!(
        stderr(&ran).contains(&format!("cwd={}\n", sub.display())),
        "the tool runs in the caller's directory, not the workspace: {ran:?}"
    );
}

#[test]
fn a_python_tool_without_replaces_leaves_python3_to_monty() {
    if !namespace_launcher_is_usable() {
        eprintln!("skipping: the namespace launcher is not usable on this host");
        return;
    }
    let home = support::fixture::short_temporary_home();
    let (box_, started, _) = python_box(home.path(), "monty-python", "");
    assert!(
        !stderr(&started).contains("a bare `python3` in the Shell runs"),
        "{}",
        stderr(&started)
    );

    let version = in_the_shell(&box_, "python3 --version");
    let direct = box_.bash(r#"python3 -c "print(6*7)"; printf "|status=%s" "$?""#);

    assert!(
        stdout(&version).contains("Monty (Strands-Box Python subset)\n|status=0"),
        "{version:?}"
    );
    assert!(
        stdout(&direct).contains("42\n|status=0"),
        "the direct alias still runs Monty: {direct:?}"
    );
    assert!(
        !box_.root().join("bin/.replaced-python").exists(),
        "a box with no replaced name has no list"
    );
}

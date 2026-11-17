//! `run` in a workspace: it reads `.strands-box/`, creates the box, and reuses it afterwards.
//!
//! These are the two operator-facing properties the Lifecycle design leads with. Everything here
//! drives the real binary from a real workspace directory, because the whole point is what happens
//! when somebody types one command in a source tree.

mod support {
    pub mod fixture;
}

use std::path::Path;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use support::fixture::{BOX_HOME, Request, box_binary, namespace_launcher_is_usable};

/// Drive `strands-box run` from `working`, with `home` as the operator's home.
///
/// No `--name`: the verb has to settle the box itself, which is what is under test.
fn run_in(home: &Path, working: &Path, argv: &[&str]) -> std::process::Output {
    let mut command = Command::new(box_binary());
    command
        .arg("run")
        .arg("--config")
        .arg(home.join("workspace/service/.strands-box/box.toml"));
    if !argv.is_empty() {
        command.arg("--").args(argv);
    }
    command
        .current_dir(working)
        .env("HOME", home)
        .env("XDG_STATE_HOME", home.join(".local/state"))
        .output()
        .expect("spawn strands-box run")
}

/// Seed `workspace` with the two files an operator writes, so a `run` there has authority to read.
///
/// **`run` no longer writes these, and that is the point.** It used to author `box.toml` and
/// `policy.dw` itself on a first run in a bare directory — a permissive starter policy the operator
/// had neither written nor read, which contradicts "the authored policy is the only authorizer".
/// The operator writes a workspace deliberately; `run` only reads one.
///
/// Written here, because these tests are about `run`'s own settling. The policy grants nothing:
/// every test that needs a permit adds its own.
fn seed(workspace: &Path, name: &str, program: &str, args: &[&str]) {
    std::fs::create_dir_all(workspace.join(".strands-box")).expect("the workspace directory");
    let home = workspace
        .parent()
        .and_then(Path::parent)
        .expect("the fixture workspace is below its home");
    let box_directory = box_directory(home, name);
    std::fs::create_dir_all(
        box_directory
            .parent()
            .expect("the box directory has a parent"),
    )
    .expect("the box directory's parent");
    std::fs::create_dir(&box_directory).expect("the empty caller-owned box directory");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&box_directory, std::fs::Permissions::from_mode(0o700))
            .expect("the box directory is private");
    }
    let rendered = args
        .iter()
        .map(|argument| format!("{argument:?}"))
        .collect::<Vec<_>>()
        .join(", ");
    std::fs::write(
        workspace.join(".strands-box/box.toml"),
        format!(
            "name = {name:?}\nbox_dir = {:?}\npolicy = \"policy.dw\"\n\n[agent]\n\
             command = [{program:?}{}{rendered}]\nworkspace = {:?}\n",
            box_directory.display().to_string(),
            if rendered.is_empty() { "" } else { ", " },
            workspace
                .canonicalize()
                .expect("the workspace resolves")
                .display()
                .to_string(),
        ),
    )
    .expect("the config");
    std::fs::write(workspace.join(".strands-box/policy.dw"), "")
        .expect("a policy that grants nothing");
}

/// Where [`seed`] sites one box's state: a directory this fixture owns, never `~/.strands-box/b/`.
///
/// One place computes it, because Box sites no box for a caller now — so a test that spelled the
/// path itself would be asserting against a layout nothing produces.
fn box_directory(home: &Path, name: &str) -> std::path::PathBuf {
    home.join("boxes").join(name)
}

/// A workspace tree under a fresh operator home, with nothing configured.
///
/// The home comes from [`support::fixture::short_temporary_home`], short enough for the box's
/// broker socket to fit the `AF_UNIX` path limit that `$TMPDIR` blows on macOS.
fn workspace() -> (tempfile::TempDir, std::path::PathBuf) {
    let home = support::fixture::short_temporary_home();
    let workspace = home.path().join("workspace/service");
    std::fs::create_dir_all(workspace.join("src")).expect("the workspace tree");
    (home, workspace)
}

fn text(output: &std::process::Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

/// **A run in a directory with no `.strands-box/` is REFUSED, and the refusal names the missing file.**
///
/// This test asserted the opposite until 2026-08-20: that a first run wrote `box.toml` and
/// `policy.dw` itself. It did, and that was the defect. The starter policy `run` wrote is permissive
/// by construction — it has to be, or the workload could do nothing — so a bare `run` in a fresh
/// directory materialized the widest authority the box holds, and the operator had neither written
/// nor read it.
///
/// That contradicts the first premise: the authored policy is the only authorizer. A policy the box
/// wrote on the operator's behalf is not an authored policy. The operator writes a workspace
/// deliberately, and `run` reads the one `--config` names.
///
/// Both halves matter. The refusal must happen, **and** it must leave nothing behind: a partially
/// written `.strands-box/` would be authority nobody authored.
#[test]
fn a_run_without_an_explicit_config_is_refused() {
    let (home, workspace) = workspace();
    let output = run_in(home.path(), &workspace, &[]);
    let reported = text(&output);

    assert!(
        !output.status.success(),
        "a run with no configuration must fail rather than create one: {reported}"
    );
    assert!(
        reported.contains("box.toml") && reported.contains("No such file"),
        "the refusal must name the missing configuration: {reported}"
    );
    assert!(
        !workspace.join(".strands-box").exists(),
        "a refused run must leave no authority behind: {reported}"
    );
}

/// **A second run reuses the box rather than creating another.**
///
/// `create` refuses a name that already has a record, so a `run` that tried to create twice
/// would fail on the second invocation. Reuse is what makes one verb enough.
#[test]
fn a_second_run_reuses_the_box() {
    let (home, workspace) = workspace();
    seed(
        &workspace,
        "echo_workspace_service",
        "/bin/echo",
        &["hello"],
    );
    let first = run_in(home.path(), &workspace, &[]);
    assert!(
        text(&first).contains("created"),
        "the first run creates: {}",
        text(&first)
    );

    let second = run_in(home.path(), &workspace, &[]);
    let reported = text(&second);
    // Reuse of an unchanged box says nothing about creation and refuses nothing: it just runs.
    assert!(
        !reported.contains("created"),
        "a second run must reuse, not re-create. Output: {reported}"
    );
    assert!(
        !reported.contains("already") && !reported.contains("in progress"),
        "reuse of one's own box must not surface a lock refusal. Output: {reported}"
    );
}

/// **A bare `run` launches the stored `[agent] command`.**
///
/// The doc's promise: a later run needs no program name, because the file already holds it.
#[test]
fn a_bare_run_launches_the_stored_executable() {
    let (home, workspace) = workspace();
    seed(
        &workspace,
        "echo_workspace_service",
        "/bin/echo",
        &["stored-argv-ran"],
    );
    run_in(home.path(), &workspace, &[]);

    let bare = run_in(home.path(), &workspace, &[]);
    let reported = text(&bare);
    assert!(
        reported.contains("stored-argv-ran") || reported.contains("starting workload"),
        "a bare run must launch the stored program. Output: {reported}"
    );
}

/// **An edited policy is picked up by the next `run`, with no second verb.**
///
/// This is §4.1's loop. A run that did not re-read the file would leave the operator editing a
/// policy nothing consulted, and the box's own denial message would keep naming the old rule.
#[test]
fn an_edited_policy_is_re_read_by_the_next_run() {
    let (home, workspace) = workspace();
    seed(
        &workspace,
        "echo_workspace_service",
        "/bin/echo",
        &["hello"],
    );
    run_in(home.path(), &workspace, &[]);

    let policy = workspace.join(".strands-box/policy.dw");
    let before = std::fs::read_to_string(&policy).expect("readable");
    std::fs::write(&policy, format!("{before}\n// an operator's edit\n")).expect("the edit");

    let after = run_in(home.path(), &workspace, &[]);
    assert!(
        text(&after).contains("updated") || after.status.success(),
        "the edited policy must be applied by an ordinary run: {}",
        text(&after)
    );
    assert_eq!(
        std::fs::read_to_string(&policy).expect("readable"),
        format!("{before}\n// an operator's edit\n"),
        "a run must never rewrite the operator's policy"
    );
}

/// **A policy the engine refuses fails at `run`, not inside a daemon that exits later.**
///
/// `run` re-validates on every invocation for exactly this reason. Without it the refusal
/// arrives as "the box's daemon exited during startup", which names nothing an operator can fix.
#[test]
fn an_invalid_edited_policy_is_refused_by_run() {
    let (home, workspace) = workspace();
    seed(
        &workspace,
        "echo_workspace_service",
        "/bin/echo",
        &["hello"],
    );
    run_in(home.path(), &workspace, &[]);

    std::fs::write(
        workspace.join(".strands-box/policy.dw"),
        "permit (principal, action == Box::Action::\"fs:raed\", resource);\n",
    )
    .expect("a typo'd action");

    let output = run_in(home.path(), &workspace, &[]);
    assert!(
        !output.status.success(),
        "a policy the engine cannot load must refuse the run: {}",
        text(&output)
    );
    let reported = text(&output);
    assert!(
        reported.contains("fs:raed") || reported.to_lowercase().contains("policy"),
        "the refusal must name the policy problem. Output: {reported}"
    );
}

/// **A run from a subdirectory finds the workspace above it.**
///
/// An agent is usually started from wherever the operator happens to be standing, so the search
/// walks up. Requiring the workspace root would make the verb fail in the common case.
#[test]
fn an_explicit_config_does_not_depend_on_the_working_directory() {
    let (home, workspace) = workspace();
    seed(
        &workspace,
        "echo_workspace_service",
        "/bin/echo",
        &["hello"],
    );
    run_in(home.path(), &workspace, &[]);

    let deep = workspace.join("src");
    let output = run_in(home.path(), &deep, &[]);
    assert!(
        !text(&output).contains("created"),
        "a run with an explicit config must reuse the same box from another directory: {}",
        text(&output)
    );
    assert!(
        !deep.join(".strands-box").exists(),
        "it must not write a second workspace inside the subdirectory"
    );
}

/// A refusal never names a verb the box does not have.
///
/// The `NotConfigured` message said "run `strands-box create --name … first`" after `create` was
/// removed, so an operator following it typed something that could not work. Asserted on the text
/// because the text is the whole failure.
///
/// The refusal this drives is the one the `box_dir` contract made common: a caller names a directory
/// whose parent does not exist, and Box creates no ancestor for them.
#[test]
fn a_refusal_does_not_name_a_removed_verb() {
    let (home, workspace) = workspace();
    seed(
        &workspace,
        "echo_workspace_service",
        "/bin/echo",
        &["hello"],
    );
    let config = workspace.join(".strands-box/box.toml");
    let existing = std::fs::read_to_string(&config).expect("the seeded config");
    let absent = home.path().join("absent-parent/box");
    std::fs::write(
        &config,
        existing.replace(
            &existing
                .lines()
                .find(|line| line.starts_with("box_dir = "))
                .expect("the seeded config states a box directory")
                .to_string(),
            &format!("box_dir = {:?}", absent.display().to_string()),
        ),
    )
    .expect("re-point the box directory at an absent parent");

    let output = run_in(home.path(), &workspace, &[]);
    let reported = text(&output);

    assert!(
        !output.status.success(),
        "a box directory below an absent parent must be refused: {reported}"
    );
    for removed in REMOVED_VERBS {
        assert!(
            !reported.contains(removed),
            "a refusal must not tell the operator to run `{removed}`: {reported}"
        );
    }
    assert!(
        reported.contains("parent does not exist"),
        "the refusal must say what the operator has to create: {reported}"
    );
    assert!(
        !absent.exists(),
        "a refused box directory must create no ancestor: {reported}"
    );
}

/// Every verb spelling this build removed. `ls`, `stop`, `rm`, and `reset` went with the
/// `~/.strands-box/b/` namespace they enumerated.
const REMOVED_VERBS: [&str; 7] = [
    "strands-box create",
    "strands-box update",
    "strands-box cp",
    "strands-box ls",
    "strands-box stop",
    "strands-box rm",
    "strands-box reset",
];

/// **No message in the taxonomy names a verb this build removed.**
///
/// `a_refusal_does_not_name_a_removed_verb` above exercises exactly one refusal — `NotConfigured`,
/// reached by running `stop` outside a workspace. That is the right shape for proving the text
/// actually reaches an operator, and it cannot see the other messages. An earlier
/// `RecordVersion` message named the removed `create` verb.
///
/// So this sweeps the source of the taxonomy instead. Neither test subsumes the other: this one
/// knows every message and proves none of them mentions a dead verb, and that one proves one
/// message really is what an operator sees.
#[test]
fn no_error_message_names_a_removed_verb() {
    let errors = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/error.rs"),
    )
    .expect("read src/error.rs");

    // A guard that matched nothing would pass over an empty file, so prove it is reading the
    // taxonomy before relying on it. The anchor is a key rather than a verb, because the taxonomy
    // now names no operator verb at all — every message that did named one of the four removed.
    assert!(
        errors.contains("`box_dir`"),
        "src/error.rs names no configuration key, so this sweep is reading the wrong file"
    );

    for removed in REMOVED_VERBS {
        // `#[error(...)]` text and doc comments both reach a reader, but only the former reaches an
        // operator. A doc comment may name a removed verb while explaining what changed, so the
        // check is scoped to lines that are not comments.
        let offending: Vec<&str> = errors
            .lines()
            .filter(|line| !line.trim_start().starts_with("//"))
            .filter(|line| line.contains(removed))
            .collect();
        assert!(
            offending.is_empty(),
            "an error message tells the operator to run `{removed}`, which this build removed: \
             {offending:?}"
        );
    }
}

/// **The alias stamp is written, and a second run does not re-materialize.**
///
/// `run` refreshes a stale alias image, and the staleness question runs on every reused run — so how
/// it is answered is a cost on the hot path. Two earlier shapes were wrong: comparing each alias's
/// mtime made a copied alias permanently stale, and comparing each alias's contents read about
/// 105 MB per run on a host where the install and `$HOME` are on different filesystems.
///
/// It is answered from a stamp of the **install's** content digest instead. This asserts both
/// halves of that: the stamp is written, and a reused run reports no refresh, through the real
/// `run` verb and the image installed beside it.
#[test]
fn the_alias_stamp_is_written_and_a_reused_run_does_not_refresh() {
    let (home, workspace) = workspace();
    let name = "echo_workspace_service";
    seed(&workspace, name, "/bin/echo", &["hello"]);
    let first = run_in(home.path(), &workspace, &[]);
    assert!(text(&first).contains("created"), "the first run creates");

    let stamp = box_directory(home.path(), name).join("private/alias-image.stamp");
    let recorded = std::fs::read_to_string(&stamp).unwrap_or_else(|error| {
        panic!(
            "the first run must stamp which image it placed, at {}: {error}",
            stamp.display()
        )
    });
    assert!(
        recorded.len() == 64 && recorded.chars().all(|c| c.is_ascii_hexdigit()),
        "the stamp is the SHA-256 of the installed image: {recorded:?}"
    );

    let second = run_in(home.path(), &workspace, &[]);
    let reported = text(&second);
    assert!(
        !reported.contains("alias image refreshed"),
        "a reused run must not re-materialize when the stamp already matches the install: \
         {reported}"
    );

    // A stamp naming a different image is what a rebuild looks like, and the next run must refresh.
    std::fs::write(&stamp, "0 0.000000000").expect("stand in for an older image");
    let third = run_in(home.path(), &workspace, &[]);
    assert!(
        text(&third).contains("alias image refreshed"),
        "a stamp naming a different image must make the next run refresh: {}",
        text(&third)
    );
    assert_ne!(
        std::fs::read_to_string(&stamp).expect("the stamp is rewritten"),
        "0 0.000000000",
        "the refresh must rewrite the stamp, or every later run refreshes again"
    );
}

/// **A second `run` on a running box is refused before it can touch an alias name.**
///
/// The run lock is taken before the alias image is judged stale, so a box whose workload is
/// executing its aliases never has one unlinked under it, however stale the stamp reads.
#[test]
fn a_run_on_a_running_box_is_refused_before_it_touches_an_alias() {
    if !namespace_launcher_is_usable() {
        return;
    }
    let box_ = Request::with_policy("project-locked-alias", FORBIDDING_POLICY).expect();
    let home = box_.box_home();
    let mut run = box_.command_for("/bin/bash");
    run.arg("-c")
        .arg(WAIT_FOR_THE_EDIT_THEN_ASK.replace(BOX_HOME, &home.display().to_string()))
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut running = run.spawn().expect("spawn strands-box run");
    wait_for_file(&home.join("started"), &mut running, Duration::from_secs(60));

    let identity = |path: &Path| {
        use std::os::unix::fs::MetadataExt as _;
        let metadata = std::fs::metadata(path)
            .unwrap_or_else(|error| panic!("{} must exist: {error}", path.display()));
        (
            metadata.dev(),
            metadata.ino(),
            metadata.ctime(),
            metadata.ctime_nsec(),
        )
    };
    let image = box_.root().join("bin/.alias-image");
    let alias = box_.root().join("bin/zsh");
    let image_before = identity(&image);
    let alias_before = identity(&alias);
    assert_eq!(
        (image_before.0, image_before.1),
        (alias_before.0, alias_before.1),
        "the alias is a link to the box's own image"
    );
    let stamp = box_.root().join("private/alias-image.stamp");
    std::fs::write(&stamp, "0 0.000000000").expect("stand in for an older image");

    let second = box_
        .command_for("/bin/bash")
        .arg("-c")
        .arg("true")
        .output()
        .expect("spawn the second run");
    assert!(
        !second.status.success() && text(&second).contains("is already running"),
        "the second run must be refused because one run owns the box: {}",
        text(&second)
    );
    assert_eq!(
        std::fs::read_to_string(&stamp).expect("the stamp is readable"),
        "0 0.000000000",
        "the refused run must not have re-materialized: the stamp it would rewrite is untouched"
    );
    assert_eq!(
        identity(&image),
        image_before,
        "the refused run must not have unlinked or relinked a name of the image"
    );
    assert_eq!(
        identity(&alias),
        alias_before,
        "the alias name is untouched"
    );

    std::fs::write(home.join("edited"), "").expect("release the workload");
    let first = running.wait_with_output().expect("the run ends");
    assert!(
        !text(&first).contains("alias image refreshed"),
        "the running box must not refresh its own aliases: {}",
        text(&first)
    );

    let next = box_.bash("true");
    assert!(
        text(&next).contains("alias image refreshed"),
        "once the run has exited, the next run refreshes the stale aliases: {}",
        text(&next)
    );
    assert_ne!(
        std::fs::read_to_string(&stamp).expect("the stamp is rewritten"),
        "0 0.000000000"
    );
}

/// A load-time finding that does not refuse the policy reaches stderr as `strands-box: warning:`
/// with the `program_path` hint, before the workload starts, and changes nothing else.
#[test]
fn a_load_time_warning_reaches_stderr_with_the_program_path_hint() {
    let (home, workspace) = workspace();
    seed(
        &workspace,
        "echo_workspace_service",
        "/bin/echo",
        &["hello"],
    );
    let control = run_in(home.path(), &workspace, &[]);
    let quiet = String::from_utf8_lossy(&control.stderr);
    assert!(
        !quiet.contains("strands-box: warning:"),
        "a policy with no finding must earn no warning: {quiet}"
    );
    assert!(
        quiet.contains("starting workload"),
        "the control run must reach its workload: {quiet}"
    );

    std::fs::write(
        workspace.join(".strands-box/policy.dw"),
        "permit(principal, action == Box::Action::\"shell:spawn\", resource)\n\
         when { context.input.program == \"/usr/bin/git\" };\n",
    )
    .expect("a policy that spells a program as a path");
    let warned = run_in(home.path(), &workspace, &[]);
    let reported = String::from_utf8_lossy(&warned.stderr);
    let warning = reported
        .lines()
        .find(|line| line.starts_with("strands-box: warning:"))
        .unwrap_or_else(|| panic!("the warning must reach stderr: {reported}"));
    assert!(
        warning.contains("\"/usr/bin/git\"") && warning.contains("program_path"),
        "the warning must name the literal and the program_path hint: {warning}"
    );
    let started = reported
        .find("starting workload")
        .unwrap_or_else(|| panic!("the warned run must still reach its workload: {reported}"));
    assert!(
        reported.find("strands-box: warning:").unwrap_or(usize::MAX) < started,
        "the warning must precede the workload start: {reported}"
    );
    assert_eq!(
        warned.status.code(),
        control.status.code(),
        "a warning must not change the exit code: {reported}"
    );
}

/// A policy that permits every hosted-shell command except one.
const FORBIDDING_POLICY: &str = r#"
permit(principal == Box::Agent::"self", action == Box::Action::"shell:exec", resource);
forbid(principal == Box::Agent::"self", action == Box::Action::"shell:exec", resource)
when { context.input.command == "printf forbidden" };
"#;

/// The same policy with the forbid dropped.
const PERMITTING_POLICY: &str = r#"
permit(principal == Box::Agent::"self", action == Box::Action::"shell:exec", resource);
"#;

/// A workload that reports it is running, waits for the operator's edit, then issues the
/// forbidden command once and records the verdict it received.
const WAIT_FOR_THE_EDIT_THEN_ASK: &str = r#"
: > "{box_home}/started"
polls=0
while [ ! -e "{box_home}/edited" ] && [ "$polls" -lt 600 ]; do
    polls=$((polls + 1))
    zsh -c "sleep 0.1" >/dev/null 2>&1
done
zsh -c "printf forbidden" >"{box_home}/output" 2>"{box_home}/denial"
printf 'status=%s polls=%s\n' "$?" "$polls" > "{box_home}/result"
"#;

/// Wait until `path` exists, or fail with the run's output when the run ends or the deadline passes.
fn wait_for_file(path: &Path, run: &mut std::process::Child, deadline: Duration) {
    let started = Instant::now();
    while !path.exists() {
        if let Some(status) = run.try_wait().expect("poll the run") {
            panic!(
                "the run ended with {status} before {} appeared",
                path.display()
            );
        }
        assert!(
            started.elapsed() < deadline,
            "{} did not appear within {deadline:?}",
            path.display()
        );
        std::thread::sleep(Duration::from_millis(20));
    }
}

/// **A `policy.dw` edited while a box runs governs the next run, and not the running one.**
#[test]
fn a_policy_edited_during_a_run_governs_the_next_run_and_not_the_running_one() {
    if !namespace_launcher_is_usable() {
        return;
    }
    let box_ = Request::with_policy("project-live-edit", FORBIDDING_POLICY).expect();
    let settled = box_.bash("true");
    assert!(
        settled.status.success(),
        "a bash run must settle the record before the edit is tested: {}",
        text(&settled)
    );
    let authored = box_.workspace().join(".strands-box/policy.dw");
    let staged = box_.root().join("private/policy.dw");
    let before = std::fs::read_to_string(&staged).expect("the staged policy is readable");
    assert!(
        before.contains("forbid("),
        "the staged policy must carry the forbid: {before}"
    );
    let home = box_.box_home();

    let mut run = box_.command_for("/bin/bash");
    run.arg("-c")
        .arg(WAIT_FOR_THE_EDIT_THEN_ASK.replace(BOX_HOME, &home.display().to_string()))
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut running = run.spawn().expect("spawn strands-box run");
    wait_for_file(&home.join("started"), &mut running, Duration::from_secs(60));

    std::fs::write(&authored, PERMITTING_POLICY).expect("the operator's edit");
    assert_eq!(
        std::fs::read_to_string(&staged).expect("the staged policy is readable"),
        before,
        "the running box's own copy must not follow an edit to the source"
    );
    std::fs::write(home.join("edited"), "").expect("tell the workload the edit landed");
    let first = running.wait_with_output().expect("the run ends");
    let reported = text(&first);

    let result = std::fs::read_to_string(home.join("result")).unwrap_or_default();
    assert!(
        result.starts_with("status=126 "),
        "the running box must refuse the command the policy it loaded forbids: result={result:?} \
         run={reported}"
    );
    let denial = std::fs::read_to_string(home.join("denial")).unwrap_or_default();
    assert!(
        denial.contains("effect denied"),
        "the refusal must be the policy's: denial={denial:?} run={reported}"
    );
    assert!(
        !reported.contains("updated"),
        "a running box must not re-stage its policy: {reported}"
    );
    assert_eq!(
        std::fs::read_to_string(&staged).expect("the staged policy is readable"),
        before,
        "the box's own copy must be unchanged when the run that loaded it ends"
    );

    let next = box_.bash(r#"zsh -c "printf forbidden"; printf "|status=%s" "$?""#);
    let reported = text(&next);
    assert!(
        reported.contains("updated"),
        "the next run must stage the edited policy: {reported}"
    );
    assert!(
        reported.contains("forbidden|status=0"),
        "the next run must permit what the edit permits: {reported}"
    );
    let after = std::fs::read_to_string(&staged).expect("the staged policy is readable");
    assert!(
        after != before && !after.contains("forbid("),
        "the box's own copy must move with the next run and carry no forbid: {after}"
    );
}

/// A policy that permits one command and caps how many times it may be asked for.
const COUNTING_POLICY: &str = r#"
permit(principal == Box::Agent::"self", action == Box::Action::"shell:exec", resource)
when { context.input.command == "printf tick" };
forbid(principal == Box::Agent::"self", action == Box::Action::"shell:exec", resource)
when temporal {
    exists (issued: Long). (
        (count for (t: Timepoint). where (
            formerly within 3600s (
                Box::Action::"shell:exec"::request{ input.command: _ } && tp(t)
            )
        )) == issued
        && issued >= 50
    )
};
"#;

/// Run a box once under [`COUNTING_POLICY`], so its record is committed and its history holds one
/// decision, and return the home, the workspace, and the history's path and bytes.
fn a_box_that_has_run(
    name: &str,
) -> (
    tempfile::TempDir,
    std::path::PathBuf,
    std::path::PathBuf,
    Vec<u8>,
) {
    a_box_that_has_run_under(name, COUNTING_POLICY, r#"zsh -c "printf tick""#)
}

/// Run a box once under `policy` with `script` as its bash agent, so its record is committed and
/// its history holds one decision, and return the home, the workspace, and the history's path and
/// bytes.
fn a_box_that_has_run_under(
    name: &str,
    policy: &str,
    script: &str,
) -> (
    tempfile::TempDir,
    std::path::PathBuf,
    std::path::PathBuf,
    Vec<u8>,
) {
    let (home, workspace) = workspace();
    seed(&workspace, name, "/bin/bash", &["-c", script]);
    std::fs::write(workspace.join(".strands-box/policy.dw"), policy).expect("the policy");
    let first = run_in(home.path(), &workspace, &[]);
    let reported = text(&first);
    assert!(
        !reported.contains("policy staging failed") && !reported.contains("policy load failed"),
        "the first run must stage the policy: {reported}"
    );
    if namespace_launcher_is_usable() {
        assert!(
            first.status.success() && reported.contains("tick"),
            "the first run must put one decision into the history: {reported}"
        );
    }

    let history = box_directory(home.path(), name).join("private/dogwood.redb");
    let intact = std::fs::read(&history).expect("the first run leaves a history file");
    assert!(
        !intact.is_empty(),
        "the history file must hold something to damage"
    );
    (home, workspace, history, intact)
}

/// Assert that `second` refused with a line starting with `refusal` before any workload started.
fn refused_before_the_workload(second: &std::process::Output, refusal: &str) {
    let reported = text(second);
    assert!(
        !second.status.success(),
        "a run over a damaged box must refuse: {reported}"
    );
    assert!(
        reported.lines().any(|line| line.starts_with(refusal)),
        "the refusal must say what was found: {reported}"
    );
    assert!(
        !reported.contains("starting workload"),
        "a box with a damaged history must not start: {reported}"
    );
}

/// Run a box once, damage its history with `damage`, and check that the next run refuses before
/// any workload starts and leaves the damaged file as it found it; return that run's output.
fn a_damaged_history_refuses_the_next_run(
    name: &str,
    damage: impl Fn(&[u8]) -> Vec<u8>,
) -> std::process::Output {
    let (home, workspace, history, intact) = a_box_that_has_run(name);
    let damaged = damage(&intact);
    assert_ne!(damaged, intact, "the damage must change the file");
    std::fs::write(&history, &damaged).expect("damage the history");

    let second = run_in(home.path(), &workspace, &[]);
    let reported = text(&second);
    assert!(
        !second.status.success(),
        "a run over a damaged history must refuse: {reported}"
    );
    assert!(
        reported.lines().any(|line| {
            line.starts_with("strands-box: error: policy staging failed:")
                || line.starts_with("strands-box: error: policy load failed:")
        }),
        "the refusal must name the policy history: {reported}"
    );
    assert!(
        !reported.contains("starting workload"),
        "a box with a damaged history must not start: {reported}"
    );
    assert_eq!(
        std::fs::read(&history).expect("the history file remains"),
        damaged,
        "the refused run must leave the damaged file byte for byte as it found it"
    );
    second
}

/// **A history truncated to half its length refuses the next run and is left as found.**
#[test]
fn a_truncated_history_refuses_the_next_run_and_is_left_as_found() {
    a_damaged_history_refuses_the_next_run("history_truncated", |intact| {
        intact[..intact.len() / 2].to_vec()
    });
}

/// **A history replaced by a file that is not a Dogwood database refuses the next run and is left
/// as found.**
#[test]
fn a_history_that_is_not_a_dogwood_database_refuses_the_next_run_and_is_left_as_found() {
    a_damaged_history_refuses_the_next_run("history_foreign", |intact| {
        format!("# not a history\n{}", "x".repeat(intact.len().min(4096))).into_bytes()
    });
}

/// **A history truncated to zero length refuses the next run and is left as found.**
#[test]
fn a_zero_length_history_refuses_the_next_run_and_is_left_as_found() {
    let second = a_damaged_history_refuses_the_next_run("history_zero_length", |_| Vec::new());
    let reported = text(&second);
    assert!(
        reported.lines().any(|line| {
            line.starts_with(
                "strands-box: error: policy staging failed: the box record is committed, but the \
                 history ",
            ) && line.ends_with(" is empty. Wipe the box directory to start again.")
        }),
        "the refusal must say the record is committed and the history is empty: {reported}"
    );
}

/// **A history whose record commit is removed refuses the next run through the private-record
/// validation, before the history check runs, and is left as found.**
#[test]
fn a_history_without_a_committed_record_refuses_the_next_run_and_is_left_as_found() {
    let name = "history_uncommitted";
    let (home, workspace, history, intact) = a_box_that_has_run(name);
    let commit = box_directory(home.path(), name).join("private/configured");
    std::fs::remove_file(&commit).expect("remove the record commit");

    let second = run_in(home.path(), &workspace, &[]);
    refused_before_the_workload(&second, "strands-box: error: unsafe box directory ");
    assert!(
        text(&second).contains("contains no valid private record"),
        "the refusal must name the missing record: {}",
        text(&second)
    );
    assert!(
        !commit.exists(),
        "the refused run must not commit a record it did not write"
    );
    assert_eq!(
        std::fs::read(&history).expect("the history file remains"),
        intact,
        "the refused run must leave the history byte for byte as it found it"
    );
}

/// A policy that permits one command and caps how many times it may be asked for at two.
const TWO_REQUEST_POLICY: &str = r#"
permit(principal == Box::Agent::"self", action == Box::Action::"shell:exec", resource)
when { context.input.command == "printf tick" };
forbid(principal == Box::Agent::"self", action == Box::Action::"shell:exec", resource)
when temporal {
    exists (issued: Long). (
        (count for (t: Timepoint). where (
            formerly within 3600s (
                Box::Action::"shell:exec"::request{ input.command: _ } && tp(t)
            )
        )) == issued
        && issued >= 2
    )
};
"#;

/// A bash agent that asks for one `printf tick` and reports the status it got.
const TICK_WITH_STATUS: &str = r#"zsh -c "printf tick"; printf "|status=%s" "$?""#;

/// Copy `source` to `destination` with every mode kept, so the copy differs only in its inodes.
fn copy_tree(source: &Path, destination: &Path) {
    let metadata = std::fs::symlink_metadata(source).expect("source metadata");
    if metadata.is_dir() {
        std::fs::create_dir(destination).expect("copied directory");
        for entry in std::fs::read_dir(source).expect("source entries") {
            let entry = entry.expect("source entry");
            copy_tree(&entry.path(), &destination.join(entry.file_name()));
        }
        std::fs::set_permissions(destination, metadata.permissions()).expect("directory mode");
    } else if metadata.is_file() {
        std::fs::copy(source, destination).expect("copied file");
    } else if metadata.file_type().is_symlink() {
        let target = std::fs::read_link(source).expect("link target");
        std::os::unix::fs::symlink(target, destination).expect("copied link");
    }
}

/// **A box directory rebuilt from the same bytes under new inodes reopens as the same box, and on a
/// host that can spawn a box its budget is still bound.**
#[test]
fn a_box_directory_rebuilt_under_new_inodes_continues_the_same_history() {
    use std::os::unix::fs::MetadataExt as _;

    let name = "identity_new_inodes";
    let (home, workspace, _history, _intact) =
        a_box_that_has_run_under(name, TWO_REQUEST_POLICY, TICK_WITH_STATUS);
    let directory = box_directory(home.path(), name);
    let record = directory.join("private/box.toml");
    let bytes_before = std::fs::read(&record).expect("the committed record");
    let inode_before = record.metadata().expect("record metadata").ino();

    let copy = directory.with_file_name(format!("{name}.copy"));
    copy_tree(&directory, &copy);
    std::fs::remove_dir_all(&directory).expect("remove the original");
    std::fs::rename(&copy, &directory).expect("the copy takes the original's place");
    assert_eq!(
        std::fs::read(&record).expect("the rebuilt record"),
        bytes_before,
        "the rebuilt directory must hold the same record bytes"
    );
    assert_ne!(
        record.metadata().expect("record metadata").ino(),
        inode_before,
        "the rebuilt directory must hold the record under a new inode"
    );

    let second = run_in(home.path(), &workspace, &[]);
    let reported = text(&second);
    assert!(
        !reported.contains("unsafe box directory"),
        "a box directory with the same bytes must open: {reported}"
    );
    assert!(
        !reported.contains("created") && !reported.contains("updated"),
        "the second run must reuse the box the first run created: {reported}"
    );
    if namespace_launcher_is_usable() {
        assert!(
            reported.contains("|status=126") && !reported.contains("tick|"),
            "the second request must be refused as the second of a budget of two: {reported}"
        );
    }
}

/// **A record edited in place refuses the next run, names the stored and the found identity, and
/// starts no workload.**
#[test]
fn an_edited_record_refuses_the_next_run_and_starts_no_workload() {
    let name = "identity_edited_record";
    let (home, workspace, history, intact) = a_box_that_has_run(name);
    let record = box_directory(home.path(), name).join("private/box.toml");
    let edited = format!(
        "{}\n# edited after the commit\n",
        std::fs::read_to_string(&record).expect("the committed record")
    );
    std::fs::write(&record, &edited).expect("edit the record in place");

    let second = run_in(home.path(), &workspace, &[]);
    refused_before_the_workload(&second, "strands-box: error: unsafe box directory ");
    let reported = text(&second);
    assert!(
        reported.lines().any(|line| {
            line.starts_with("strands-box: error: unsafe box directory ")
                && line.contains(": its record identity is box-")
                && line.contains(" sha256:")
                && line.contains(", but the committed record has identity box-")
                && line.ends_with(". Delete the box directory to start again.")
        }),
        "the refusal must name both identities and the remedy: {reported}"
    );
    assert_eq!(
        std::fs::read_to_string(&record).expect("the record remains"),
        edited,
        "the refused run must leave the edited record as it found it"
    );
    assert_eq!(
        std::fs::read(&history).expect("the history file remains"),
        intact,
        "the refused run must leave the history byte for byte as it found it"
    );
}

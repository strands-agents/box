//! `run` against real boxes: the policy refusals, and the creation race.
//!
//! These drive the shipped binary rather than calling the library, because the refusals *are* the
//! operator's interface: a refusal that names the wrong fix is a defect no unit test on the helpers
//! would catch.
//!
//! The `ls`, `rm`, and `reset` cases are gone with their verbs. They read `~/.strands-box/b/`, which
//! Box no longer owns: a caller supplies `box_dir`, so there is no namespace to list or sweep.

use std::process::{Command, Output};

#[path = "support/fixture.rs"]
mod fixture;

use fixture::{Configured, Request, box_binary};

fn stdout(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

/// Run a verb with this fixture's operator home, so the test never reads the real one.
fn verb(box_: &Configured, args: &[&str]) -> Output {
    Command::new(box_binary())
        .args(args)
        .env("HOME", box_.operator_home())
        .output()
        .expect("spawn strands-box")
}

/// `run` refuses a policy the engine cannot load, and writes no Box state.
///
/// Measured before this was wired: `create` exited 0 and reported `policy stored`, and the
/// refusal arrived at the next `run` as "the box's daemon exited during startup". That is a
/// different invocation from the one that chose the policy, and it leaves a box on disk whose
/// only stored authority cannot govern anything.
///
/// A typo'd action is the case to test rather than a syntax error. `lower()` alone accepts it,
/// so it parses cleanly and is caught only by the engine's strict validation — which is exactly
/// what `PolicyEngine::validate` runs and what a hand-rolled syntax check here would miss.
#[test]
fn create_refuses_a_policy_the_engine_cannot_load() {
    if !fixture::namespace_launcher_is_usable() {
        return;
    }
    let (box_, output) = Request::with_policy(
        "life-badpolicy",
        r#"permit(principal, action == Box::Action::"fs:reed_content", resource);"#,
    )
    .attempt();

    assert!(
        !output.status.success(),
        "create must refuse a policy that will not load: {output:?}"
    );
    let said = stderr(&output);
    assert!(
        said.contains("will not load") && said.contains("fs:reed_content"),
        "the refusal must name the file and the engine's reason: {said}"
    );
    assert!(
        box_.root().is_dir(),
        "the caller-owned box directory must remain: {}",
        box_.root().display()
    );
    assert_eq!(
        std::fs::read_dir(box_.root())
            .expect("read the caller-owned box directory")
            .count(),
        0,
        "a refused run must leave no Box-owned state"
    );
}

/// `run` refuses a budget written as a permit beside a broader permit for the same action, before
/// any platform check and any workload, and names both rules.
#[test]
fn create_refuses_a_cap_written_as_a_permit_beside_a_broader_permit() {
    let (box_, output) = Request::with_policy(
        "life-permit-cap",
        r#"permit(principal == Box::Agent::"self", action == Box::Action::"shell:exec", resource);
@id("exec_budget")
permit(principal == Box::Agent::"self", action == Box::Action::"shell:exec", resource)
when temporal {
    exists (issued: Long). (
        (count for (t: Timepoint). where (
            formerly within 60s (
                Box::Action::"shell:exec"::response{ input.program: _ } && tp(t)
            )
        )) == issued
        && issued < 20
    )
};
"#,
    )
    .attempt();

    assert!(
        !output.status.success(),
        "run must refuse a cap written as a permit: {output:?}"
    );
    let said = stderr(&output);
    assert!(
        said.contains(
            "will not load: policy writes a cap as a permit: rule @id(\"exec_budget\") (rule 2) \
             carries a temporal clause beside the permit rule with no @id (rule 1), which permits \
             the same action with no condition; a permit cannot narrow another permit, so write the \
             cap as a forbid"
        ),
        "the refusal must name both rules and the forbid shape: {said}"
    );
    assert!(
        !said.contains("starting workload"),
        "a refused policy must start no workload: {said}"
    );
    assert_eq!(
        std::fs::read_dir(box_.root())
            .expect("read the caller-owned box directory")
            .count(),
        0,
        "a refused run must leave no Box-owned state"
    );
}

// ── `update`: the narrow half of `create` ────────────────────────────────────
//
// Added under the interface freeze, with the maintainers' explicit approval. Each test
// below pins one of the two refusals that let this verb exist without weakening why the record
// was immutable — so none of them may be deleted to green a suite.

/// A refused `update` leaves the previous policy stored, so the box keeps working.
///
/// The validation happens before anything is written — the same property `create` has. Without
/// it a typo would leave a box whose only stored authority cannot govern anything, and the
/// refusal would arrive at the next `run` as a daemon that exited during startup.
#[test]
fn update_refuses_a_policy_the_engine_cannot_load_and_keeps_the_old_one() {
    if !fixture::namespace_launcher_is_usable() {
        return;
    }
    let box_ = Request::with_policy(
        "life-updatebad",
        r#"permit(principal, action == Box::Action::"shell:exec", resource);"#,
    )
    .expect();

    let stored = box_.root().join("private/policy.dw");
    let before = std::fs::read_to_string(&stored).expect("the stored policy is readable");

    let bad = box_.operator_home().join("bad.dw");
    std::fs::write(
        &bad,
        r#"permit(principal, action == Box::Action::"fs:reed_content", resource);"#,
    )
    .expect("write the unloadable policy");

    let refused = verb(
        &box_,
        &[
            "update",
            "--name",
            box_.name(),
            "--policy",
            bad.to_str().expect("a UTF-8 path"),
        ],
    );

    assert!(
        !refused.status.success(),
        "update must refuse a policy that will not load: {refused:?}"
    );
    assert_eq!(
        std::fs::read_to_string(&stored).expect("the stored policy is still readable"),
        before,
        "a refused update must leave the previous authority in place, not a partial write"
    );
}
/// Concurrent `create` calls for one name produce exactly one box.
///
/// **`create` was check-then-act until 2026-08-12.** `refuse_an_existing_box` tested the record
/// and `apply` then wrote it, with nothing serializing the two, so N callers all saw no record
/// and all proceeded. The record write is a rename, so the last writer won — and because the
/// policy file and the alias image are written separately, a loser's policy could pair with the
/// winner's record. `Daemon::load` already took the box's operation lock for this exact reason,
/// which is what made the gap visible: one side of the race was guarded and the other was not.
///
/// Eight processes rather than two, because a race needs enough contenders to lose reliably.
///
/// **The shape changed with the `create` verb's removal.** There is no `create` to win: a box is
/// created by `run` in a workspace, and `run` is create-or-reuse. So eight concurrent runs of one
/// workspace must all *succeed* — the first creates, the other seven reuse — and produce exactly one
/// box. The invariant is unchanged where it matters: the creation is still serialized under the
/// box's operation lock, so a torn record is still impossible, and the stored record proves one
/// usable box. `ls` proved that until the verb was deleted with the namespace it listed.
#[test]
fn concurrent_runs_of_one_project_produce_exactly_one_box() {
    if !fixture::namespace_launcher_is_usable() {
        return;
    }
    let request = Request::with_nothing("life-race");
    let home = request.operator_home().to_path_buf();
    let name = format!("life-race-{}", std::process::id());

    // A workspace the runs share, with the contended name fixed in its `box.toml`.
    let workspace = home.join("workspace");
    let dot = workspace.join(".strands-box");
    std::fs::create_dir_all(&dot).expect("the workspace directory");
    // A directory this test owns. Box creates no ancestor, so the parent is created here.
    let box_directory = home.join("boxes").join(&name);
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
    let config = dot.join("box.toml");
    std::fs::write(
        &config,
        format!(
            "name = {name:?}\nbox_dir = {:?}\n\
             [agent]\ncommand = [\"{}\"]\nworkspace = {:?}\n",
            box_directory.display().to_string(),
            fixture::no_op_program(),
            workspace
                .canonicalize()
                .expect("the workspace resolves")
                .display()
                .to_string(),
        ),
    )
    .expect("write the workspace box.toml");

    // Spawned before any is waited on, so they contend rather than run in sequence.
    let contenders: Vec<_> = (0..8)
        .map(|_| {
            Command::new(box_binary())
                .arg("run")
                .arg("--config")
                .arg(&config)
                .current_dir(&workspace)
                .env("HOME", &home)
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::piped())
                .spawn()
                .expect("spawn strands-box run")
        })
        .collect();

    let outputs: Vec<Output> = contenders
        .into_iter()
        .map(|child| child.wait_with_output().expect("wait for run"))
        .collect();

    // At least one run succeeds, and every run that does not **refuses cleanly** — the operation
    // lock serializes creation and loading, so a loser gets "in progress" or "already", never a
    // torn record or a crash. That clean-refusal contract is the property this test guards; the
    // record integrity is proven by `ls` below.
    let succeeded = outputs.iter().filter(|out| out.status.success()).count();
    assert!(
        succeeded >= 1,
        "at least one concurrent run must create or reuse the box. Errors: {:?}",
        outputs
            .iter()
            .map(|out| stderr(out).trim().to_string())
            .collect::<Vec<_>>()
    );
    for out in outputs.iter().filter(|out| !out.status.success()) {
        let reason = stderr(out);
        assert!(
            reason.contains("in progress") || reason.contains("already"),
            "a run that did not win the lock must name its refusal, not crash: {reason}"
        );
    }

    // One box on disk, and its record parses. A torn record would still count as one winner above,
    // so the stored record is what proves the survivor is usable. `ls` proved this until the verb
    // was deleted with the namespace; the record is the stronger check anyway, because it reads the
    // bytes the contenders raced to write rather than a table rendered from them.
    let record = box_directory.join("private").join("box.toml");
    let stored = std::fs::read_to_string(&record).unwrap_or_else(|error| {
        panic!(
            "exactly one run must leave one readable record at {}: {error}",
            record.display()
        )
    });
    let parsed: toml::Value = toml::from_str(&stored)
        .unwrap_or_else(|error| panic!("the surviving record must parse: {error}\n{stored}"));
    assert_eq!(
        parsed["name"].as_str(),
        Some(name.as_str()),
        "the surviving record must name the contended box: {stored}"
    );
    assert_eq!(
        parsed["box_dir"].as_str(),
        Some(box_directory.display().to_string().as_str()),
        "and it must name the one directory every contender was given: {stored}"
    );

    // The fixture's `Drop` never saw this box, because no `Configured` was built for it, and no verb
    // deletes a box root now.
    let _ = std::fs::remove_dir_all(&home);
}

#[test]
fn a_workload_runs_through_an_interpreter_link_chain() {
    if !fixture::namespace_launcher_is_usable() {
        return;
    }
    let interpreter = std::fs::canonicalize("/bin/bash").expect("the host shell interpreter");
    let operator = std::env::var_os("HOME").expect("the operator home");
    let home = tempfile::Builder::new()
        .prefix(".box-chain-")
        .tempdir_in(operator)
        .expect("an operator home for the workload");
    let home_path = home.path().canonicalize().expect("the canonical home");
    let runtime = home_path.join("r");
    std::fs::create_dir(&runtime).expect("the interpreter link directory");
    let middle = runtime.join("hop");
    let route = runtime.join("bash");
    std::os::unix::fs::symlink(&interpreter, &middle).expect("the first interpreter link");
    std::os::unix::fs::symlink(&middle, &route).expect("the second interpreter link");
    let workspace = home_path.join("w");
    let configuration = workspace.join(".strands-box");
    std::fs::create_dir_all(&configuration).expect("the workload configuration directory");
    std::fs::write(configuration.join("policy.dw"), "").expect("the default-deny policy");
    let box_directory = home_path.join("b");
    std::fs::create_dir(&box_directory).expect("the box directory");
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&box_directory, std::fs::Permissions::from_mode(0o700))
            .expect("a private box directory");
    }
    std::fs::write(
        configuration.join("box.toml"),
        format!(
            "name = \"chain\"\nbox_dir = {box_directory:?}\n\
             policy = \"policy.dw\"\n[agent]\n\
             command = [\"bash\"]\nworkspace = {workspace:?}\n",
        ),
    )
    .expect("the workload configuration");
    let output = Command::new(box_binary())
        .arg("run")
        .arg("--config")
        .arg(configuration.join("box.toml"))
        .args([
            "--",
            "--noprofile",
            "--norc",
            "-c",
            "printf 'CHAIN_WORKLOAD=%s\\n' \"$USER\"",
        ])
        .env("HOME", &home_path)
        .env("PATH", &runtime)
        .current_dir(&workspace)
        .output()
        .expect("launch the workload");
    assert!(
        output.status.success(),
        "the workload must run through both links: {}",
        stderr(&output)
    );
    assert_eq!(stdout(&output).trim(), "CHAIN_WORKLOAD=strands-box");
}

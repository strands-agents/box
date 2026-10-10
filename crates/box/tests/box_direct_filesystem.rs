//! `[agent.filesystem]`'s lists, asserted by running a real workload and reading the host
//! afterwards.
//!
//! **The box's own decision records are not evidence here.** These grants raise no `fs:*` decision
//! at all, and for a path whose native read failed the log still carries a permitted read, because
//! a shell fallback read the same file moments later. So every assertion below reads the host
//! filesystem or the workload's own exit, and never a record.
//!
//! `box_filesystem.rs::the_workspace_is_enterable_and_unreadable_until_listed` pins the fallback:
//! with no list naming the workspace, it is enterable and holds nothing readable.

use std::path::Path;
use std::process::{Command, Output};

#[path = "support/fixture.rs"]
mod fixture;

use fixture::{Configured, Request};

/// Policy permits every effect, so what confines the workload below is containment alone.
const PERMIT_EVERY_EFFECT: &str = r#"
permit(principal == Box::Agent::"self", action == Box::Action::"shell:exec", resource);
permit(principal == Box::Agent::"self", action == Box::Action::"shell:spawn", resource);
permit(principal == Box::Agent::"self", action == Box::Action::"fs:read", resource);
permit(principal == Box::Agent::"self", action == Box::Action::"fs:write", resource);
"#;

/// A box whose project the workload's own syscalls may read and write: `read` and `write` entries
/// naming the workspace path, because `write` no longer implies `read`.
fn writable_project(name: &str) -> Configured {
    Request::with_policy(name, PERMIT_EVERY_EFFECT)
        .agent_list("read", &["{workspace}"])
        .agent_list("write", &["{workspace}"])
        .expect()
}

fn stdout(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

/// Run without a selected configuration from one working directory.
fn run_without_config_from(working: &Path, home: &Path, argv: &[&str]) -> Output {
    let mut command = Command::new(fixture::box_binary());
    command.arg("run").arg("--");
    for argument in argv {
        command.arg(argument);
    }
    command
        .current_dir(working)
        .env("HOME", home)
        .output()
        .expect("spawn strands-box run")
}

/// **`read` and `write` entries naming the workspace let the workload's own syscalls reach the
/// project, and the host proves it.**
///
/// The bytes are asserted at the host path, because these operations produce no record to read.
#[test]
fn a_read_write_project_is_reached_by_the_workloads_own_syscalls() {
    if !fixture::namespace_launcher_is_usable() {
        println!("skipping: this platform has no usable containment backend");
        return;
    }
    let box_ = writable_project("fs-read-write");
    let planted = box_.workspace().join("planted.txt");
    std::fs::write(&planted, "PROJECT_CONTENTS\n").expect("a real file in the project");

    let output = box_.bash(
        "read -r leaked < ./planted.txt && printf 'READ=%s\\n' \"$leaked\"\n\
         printf 'WRITTEN\\n' > ./written.txt && printf 'WROTE\\n'",
    );

    let seen = stdout(&output);
    assert!(
        seen.contains("READ=PROJECT_CONTENTS"),
        "the workload's own read must land under `read-write`: {output:?}"
    );
    assert!(seen.contains("WROTE"), "the write must land: {output:?}");
    assert_eq!(
        std::fs::read_to_string(box_.workspace().join("written.txt")).ok(),
        Some("WRITTEN\n".to_string()),
        "the bytes must be at the host path, which is the only trustworthy channel"
    );
}

/// **A `read` entry naming the workspace reads and refuses to write**, so the two lists are two
/// grants and not one.
#[test]
fn a_read_project_reads_and_cannot_be_written() {
    if !fixture::namespace_launcher_is_usable() {
        println!("skipping: this platform has no usable containment backend");
        return;
    }
    let box_ = Request::with_policy("fs-read-only", PERMIT_EVERY_EFFECT)
        .agent_list("read", &["{workspace}"])
        .expect();
    std::fs::write(box_.workspace().join("planted.txt"), "PROJECT_CONTENTS\n")
        .expect("a real file");

    let output = box_.bash(
        "read -r leaked < ./planted.txt && printf 'READ=%s\\n' \"$leaked\"\n\
         printf y > ./written.txt 2>/dev/null && printf 'WRITE_LEAKED\\n'",
    );

    let seen = stdout(&output);
    assert!(seen.contains("READ=PROJECT_CONTENTS"), "{output:?}");
    assert!(
        !seen.contains("WRITE_LEAKED"),
        "a `read` entry must not confer write: {output:?}"
    );
    assert!(
        !box_.workspace().join("written.txt").exists(),
        "and no file may appear at the host path"
    );
}

/// **The workspace's enter-only grant renders before the aliases and before every direct grant.**
///
/// The Linux view mounts in insertion order, and a parent bind established after a nested bind
/// shadows it: a runner under `<project>/code` vanished from the view and every handler run failed
/// with "No such file or directory". The written configuration is unlinked as soon as the
/// trampoline reads it, so this reads the emission order from the translator's source.
#[test]
fn the_enter_only_grant_renders_before_the_direct_grants() {
    let source = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/run/contain/boundary.rs"),
    )
    .expect("the boundary source");

    let enter_only = source
        .find("Operation::Metadata,\n                Scope::Dir,\n            )?;\n            enterable_workspace")
        .expect("the workspace's enter-only grant");
    let alias_loop = source
        .find("for alias in layout")
        .expect("the alias grants, which follow the workspace's own");
    let direct_grants = source
        .find("allow_operator(containment, &grant.resolved, grant.operation, grant.scope)")
        .expect("the direct grants, which are emitted last");

    assert!(
        enter_only < alias_loop && alias_loop < direct_grants,
        "the enter-only grant must render before the aliases and before every direct grant; \
         a parent bind established after a nested bind shadows it on Linux"
    );
}

/// **A `write` entry outside the operator's home may not enclose a program-search directory.**
///
/// `broker/mcp` execs a declared bare name off the operator's own `PATH`, outside containment, at
/// the operator's identity — so a writable directory on that path is a program the workload
/// chooses, wherever the directory sits. An in-home filter on the judged `PATH` list dropped
/// every out-of-home entry, which accepted exactly this grant.
#[test]
fn an_out_of_home_write_entry_enclosing_a_search_directory_is_refused() {
    if !fixture::namespace_launcher_is_usable() {
        println!("skipping: this platform has no usable containment backend");
        return;
    }
    let outside = tempfile::Builder::new()
        .prefix("ph")
        .tempdir_in("/var/tmp")
        .expect("a tree outside the operator home");
    let outside_root = outside.path().canonicalize().expect("a canonical tree");
    let search = outside_root.join("bin");
    std::fs::create_dir_all(&search).expect("the search directory");

    let request = Request::with_config(
        "fs-out-of-home-path",
        PERMIT_EVERY_EFFECT,
        "[mcp.probe]\ntype = \"stdio\"\ncommand = [\"probe-server\"]\n",
    )
    .agent_write(&[outside_root.as_path()]);
    let hostile_path = format!(
        "{}:{}",
        std::env::var("PATH").unwrap_or_default(),
        search.display()
    );
    let (_box, output) = request.env("PATH", &hostile_path).attempt();

    let reported = stderr(&output);
    assert!(
        !output.status.success(),
        "a write entry enclosing an out-of-home search directory must be refused: {output:?}"
    );
    assert!(
        reported.contains("search path") && reported.contains(&outside_root.display().to_string()),
        "the refusal must name the search path and the entry: {reported}"
    );
}

/// **A harness configuration directory is an ordinary entry**, granted when listed and disclosed on
/// stderr like any other.
#[test]
fn a_harness_configuration_directory_is_an_ordinary_entry() {
    if !fixture::namespace_launcher_is_usable() {
        println!("skipping: this platform has no usable containment backend");
        return;
    }
    let request = Request::with_policy("fs-harness-config", PERMIT_EVERY_EFFECT);
    let declared = request.operator_home().join(".claude");
    std::fs::create_dir_all(&declared).expect("the harness configuration directory");
    std::fs::write(declared.join("settings.json"), "OPERATOR_SETTINGS\n").expect("a real file");

    let (box_, output) = request.agent_read(&[declared.as_path()]).attempt();
    assert!(
        output.status.success(),
        "a configuration naming a harness directory loads: {output:?}"
    );
    assert!(
        stderr(&output).contains(&declared.display().to_string()),
        "the entry is disclosed on stderr: {}",
        stderr(&output)
    );
    let output = box_.bash(&format!(
        "read -r v < {}/settings.json && printf 'READ=%s\\n' \"$v\"; printf done",
        declared.display()
    ));
    assert!(
        stdout(&output).contains("READ=OPERATOR_SETTINGS"),
        "the listed harness directory must read: {output:?}"
    );
}

/// **A granted project still refuses the box's own configuration, and the control proves it.**
///
/// This is the positive control the plan demands before a carve-out is relied on: there is local
/// precedent for a rule that parsed, type-checked, and matched nothing. So the test asserts three
/// things — the refused tree is unreadable, it is unwritable, and a directory whose name merely
/// starts the same way is still reachable. Without the third, a blanket refusal of the whole project
/// would pass.
#[test]
fn a_read_write_project_still_refuses_the_boxs_own_authority() {
    if !fixture::namespace_launcher_is_usable() {
        println!("skipping: this platform has no usable containment backend");
        return;
    }
    let box_ = writable_project("fs-own-authority");
    box_.write_command("/bin/bash");
    let own = box_.workspace().join(".strands-box");
    let config = own.join("box.toml");
    let before = std::fs::read_to_string(&config).expect("the box's own configuration");
    // The control: a sibling whose name merely starts the same way must stay reachable, or the
    // assertions below could be satisfied by refusing the project outright.
    let lookalike = box_.workspace().join(".strands-boxes");
    std::fs::create_dir_all(&lookalike).expect("the lookalike directory");
    std::fs::write(lookalike.join("ok.txt"), "LOOKALIKE\n").expect("a file in it");

    let output = box_.bash(
        "read -r leaked < ./.strands-box/box.toml 2>/dev/null && printf 'CONFIG_READ=%s\\n' \"$leaked\"\n\
         printf 'name = \"hostile\"\\n' > ./.strands-box/box.toml 2>/dev/null && printf 'CONFIG_WRITTEN\\n'\n\
         printf 'permit(principal, action, resource);\\n' > ./.strands-box/policy.dw 2>/dev/null \
           && printf 'POLICY_WRITTEN\\n'\n\
         read -r ok < ./.strands-boxes/ok.txt && printf 'CONTROL=%s\\n' \"$ok\"\n\
         printf 'done\\n'",
    );

    let seen = stdout(&output);
    assert!(
        !seen.contains("CONFIG_READ"),
        "the workload must not read the configuration that governs it: {output:?}"
    );
    assert!(
        !seen.contains("CONFIG_WRITTEN") && !seen.contains("POLICY_WRITTEN"),
        "the workload must not rewrite its own authority: {output:?}"
    );
    // The host is the trustworthy channel, so the bytes are checked there too.
    assert_eq!(
        std::fs::read_to_string(&config).expect("the configuration survives"),
        before,
        "the box's own configuration changed on the host"
    );
    assert!(
        std::fs::read_to_string(own.join("policy.dw"))
            .expect("the policy survives")
            .contains("permit"),
        "the box's own policy must be the authored one"
    );
    // **The control.** A blanket refusal of the project would fail here.
    assert!(
        seen.contains("CONTROL=LOOKALIKE"),
        "a directory whose name merely starts like the product directory must stay reachable, or \
         this test would pass for a box that refused the whole project: {output:?}"
    );
    assert!(
        seen.contains("done"),
        "the script must reach the end: {output:?}"
    );
}

/// **A sibling box's authority under a write grant is reachable, and the grant is disclosed.**
///
/// The box subtracts the directory holding the sources THIS run loaded, by path. A directory
/// called `.strands-box` elsewhere under the grant is an ordinary directory: the workload reads and
/// rewrites the sibling's policy, the host sees the write, and the startup disclosure names the
/// write grant that reaches it. The control is this box's own authority beside it, which stays
/// unreadable and unwritable in the same run.
#[test]
fn a_sibling_boxs_authority_under_a_write_grant_is_reachable_and_disclosed() {
    if !fixture::namespace_launcher_is_usable() {
        println!("skipping: this platform has no usable containment backend");
        return;
    }
    let box_ = writable_project("fs-sibling-reachable");
    box_.write_command("/bin/bash");
    let sibling = box_.workspace().join("sub/.strands-box");
    std::fs::create_dir_all(&sibling).expect("the sibling box's authority directory");
    let policy_text = "// DET_SIBLING_POLICY_MARKER\npermit (principal, action, resource);\n";
    std::fs::write(sibling.join("policy.dw"), policy_text).expect("the sibling policy");
    std::fs::write(sibling.join("box.toml"), "name = \"sibling\"\n").expect("the sibling config");
    let own = box_.workspace().join(".strands-box");

    let output = box_.bash(&format!(
        "read -r seen < '{sibling}/policy.dw' && printf 'SIBLING_READ=%s\\n' \"$seen\"\n\
         printf '// rewritten\\n' >> '{sibling}/policy.dw' && printf 'SIBLING_WRITTEN\\n'\n\
         read -r leaked < '{own}/policy.dw' 2>/dev/null && printf 'OWN_READ=%s\\n' \"$leaked\"\n\
         printf '// rewritten\\n' >> '{own}/policy.dw' 2>/dev/null && printf 'OWN_WRITTEN\\n'\n\
         printf 'done\\n'",
        sibling = sibling.display(),
        own = own.display(),
    ));

    let seen = stdout(&output);
    assert!(
        seen.contains("done"),
        "the script must reach the end: {output:?}"
    );
    assert!(
        seen.contains("SIBLING_READ=// DET_SIBLING_POLICY_MARKER")
            && seen.contains("SIBLING_WRITTEN"),
        "a sibling box's authority under the write grant is the operator's stated reach: {output:?}"
    );
    assert!(
        std::fs::read_to_string(sibling.join("policy.dw"))
            .expect("the sibling policy")
            .ends_with("// rewritten\n"),
        "the write must land on the host"
    );
    assert!(
        !seen.contains("OWN_READ") && !seen.contains("OWN_WRITTEN"),
        "this box's own authority stays subtracted in the same run: {output:?}"
    );
    assert!(
        stderr(&output).contains(&format!("  write       {}", box_.workspace().display())),
        "the grant that reaches the sibling is disclosed on stderr: {}",
        stderr(&output)
    );
}

/// **This box's own authority stays refused when the workload renames the directory above it**,
/// and the two platforms get there differently.
///
/// The subtraction refuses the directory holding the loaded sources at the path the run judged. On
/// Linux the refusal is a mount that follows a renamed ancestor, so the rename lands and the sources
/// stay hidden at their new name. On macOS the refusal is a set of path denies, so the renderer fixes
/// the directory entries between the write root and the refusal, and the rename itself is refused.
/// Either way the policy is unreadable and unwritable wherever it sits, and the host holds the
/// authored bytes. The authority sits one level below the grant so that an ancestor exists to rename.
///
/// **The mover is the compiled probe, exec'd natively under the agent's own `exec` entry.** Its
/// `move-authority-parent` verb renames through `renameat(2)` and prints one named line per outcome,
/// `parent_move_errno` included, so a failed mover reads as a failed mover and never as a refusal.
///
/// **The controls carry as much of the assertion as the refusals.** A sibling directory with nothing
/// refused inside still moves; inside the fixed directory the probe creates, renames, and removes a
/// file and a directory (`sibling_mutation`), and the shell edits an ordinary file. The probe's
/// `source_replacement` line, a new file written at the vacated path after a permitted move, is the
/// Linux residual that docs/design/decisions.md#direct-filesystem-reach-is-declared-and-disclosed
/// states, and is not asserted.
#[test]
fn this_boxs_authority_survives_a_rename_of_its_parent() {
    if !fixture::namespace_launcher_is_usable() {
        println!("skipping: this platform has no usable containment backend");
        return;
    }
    let probe = std::fs::canonicalize(env!("CARGO_BIN_EXE_box-egress-probe"))
        .expect("this test grants the compiled box-egress-probe as the workload's mover");
    let home = fixture::short_temporary_home();
    let root = home
        .path()
        .canonicalize()
        .expect("the fixture home resolves");
    let workspace = root.join("workspace");
    let mid = workspace.join("mid");
    let mid2 = workspace.join("mid2");
    let authority = mid.join("authority");
    let box_directory = root.join("state");
    std::fs::create_dir_all(&authority).expect("the authority directory");
    std::fs::create_dir(&box_directory).expect("the box directory");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&box_directory, std::fs::Permissions::from_mode(0o700))
            .expect("a private box directory");
    }
    let policy_text = "// DET_OWN_POLICY_MARKER\npermit(principal, action, resource);\n";
    std::fs::write(authority.join("policy.dw"), policy_text).expect("the policy");
    let config = authority.join("box.toml");
    let config_text = format!(
        "name = \"nested-authority\"\nbox_dir = {box_dir:?}\npolicy = \"policy.dw\"\n\n\
         [agent]\ncommand = [\"/bin/bash\"]\nworkspace = {workspace:?}\n\n\
         [agent.filesystem]\nread = [{workspace:?}]\nwrite = [{workspace:?}]\nexec = [{probe:?}]\n",
        box_dir = box_directory.display().to_string(),
        workspace = workspace.display().to_string(),
        probe = probe.display().to_string(),
    );
    std::fs::write(&config, &config_text).expect("the configuration");
    std::fs::write(mid.join("notes.txt"), "NOTES\n").expect("an ordinary file beside it");
    let plain = workspace.join("plain");
    let plain2 = workspace.join("plain2");
    std::fs::create_dir(&plain).expect("a directory with nothing refused inside");
    std::fs::write(plain.join("p.txt"), "PLAIN\n").expect("a file in it");

    let script = format!(
        "P='{probe}'\n\
         printf 'CONTROL_BEGIN\\n'\n\
         \"$P\" move-authority-parent '{plain}' '{plain2}' p.txt; printf 'CONTROL_RC=%s\\n' $?\n\
         printf 'CONTROL_END\\n'\n\
         printf 'EDITED\\n' > '{mid}/notes.txt' && printf 'NOTES_WRITTEN\\n'\n\
         printf 'SUBJECT_BEGIN\\n'\n\
         \"$P\" move-authority-parent '{mid}' '{mid2}' authority/policy.dw; \
         printf 'SUBJECT_RC=%s\\n' $?\n\
         printf 'SUBJECT_END\\n'\n\
         if [ -d '{mid2}' ]; then at='{mid2}'; else at='{mid}'; fi\n\
         printf 'AUTHORITY_AT=%s\\n' \"$at\"\n\
         read -r leaked < \"$at/authority/policy.dw\" && printf 'POLICY_READ=%s\\n' \"$leaked\"\n\
         printf 'permit(principal, action, resource);\\n' >> \"$at/authority/policy.dw\" \
           && printf 'POLICY_WRITTEN\\n'\n\
         printf 'done\\n'",
        probe = probe.display(),
        plain = plain.display(),
        plain2 = plain2.display(),
        mid = mid.display(),
        mid2 = mid2.display(),
    );
    let output = Command::new(fixture::box_binary())
        .arg("run")
        .arg("--config")
        .arg(&config)
        .arg("--")
        .arg("-c")
        .arg(&script)
        .current_dir(&workspace)
        .env("HOME", &root)
        .output()
        .expect("spawn strands-box run");

    let seen = stdout(&output);
    assert!(
        seen.contains("done"),
        "the script must reach the end: {output:?}"
    );
    let fenced = |name: &str| -> String {
        let begin = format!("{name}_BEGIN\n");
        let end = format!("\n{name}_END");
        let start = seen.find(&begin).map(|at| at + begin.len());
        let stop = start.and_then(|start| seen[start..].find(&end).map(|at| start + at));
        match (start, stop) {
            (Some(start), Some(stop)) => seen[start..stop].to_string(),
            _ => panic!("the {name} phase is not fenced: {output:?}"),
        }
    };
    let control = fenced("CONTROL");
    assert!(
        control.contains("CONTROL_RC=0") && control.contains("parent_move=allowed"),
        "a directory with nothing refused inside must still move, and the probe must run: \
         control=[{control}] {output:?}"
    );
    assert_eq!(
        std::fs::read_to_string(plain2.join("p.txt"))
            .ok()
            .as_deref(),
        Some("PLAIN\n"),
        "the control move must land on the host: {output:?}"
    );
    let subject = fenced("SUBJECT");
    assert!(
        subject.contains("SUBJECT_RC=0") && subject.contains("sibling_mutation=allowed"),
        "creating, renaming, and removing entries inside the fixed directory must still work: \
         subject=[{subject}] {output:?}"
    );
    assert!(
        seen.contains("NOTES_WRITTEN"),
        "an ordinary file inside the fixed directory must still be written: {output:?}"
    );
    let landed = if cfg!(target_os = "macos") {
        let eperm_line = format!("parent_move_errno={}", libc::EPERM);
        assert!(
            subject.contains("parent_move=refused")
                && subject.lines().any(|line| line == eperm_line)
                && subject.contains("source_write=refused"),
            "macOS must refuse to move a directory holding a refused path with EPERM, and the \
             policy must stay unwritable at its launch path: subject=[{subject}] {output:?}"
        );
        assert!(
            mid.is_dir() && !mid2.exists(),
            "the host must still hold the directory at its launch path: {output:?}"
        );
        mid.clone()
    } else {
        assert!(
            subject.contains("parent_move=allowed") && mid2.is_dir(),
            "Linux lets the rename land and the refusal follows the directory: \
             subject=[{subject}] {output:?}"
        );
        mid2.clone()
    };
    assert!(
        seen.contains(&format!("AUTHORITY_AT={}", landed.display())),
        "the shell and the host must agree where the directory sits: {output:?}"
    );
    assert_eq!(
        std::fs::read_to_string(landed.join("notes.txt"))
            .ok()
            .as_deref(),
        Some("EDITED\n"),
        "the permitted edit must land on the host"
    );
    assert!(
        !seen.contains("POLICY_READ") && !seen.contains("DET_OWN_POLICY_MARKER"),
        "this box's policy must not be readable after the rename: {output:?}"
    );
    assert!(
        !seen.contains("POLICY_WRITTEN"),
        "this box's policy must not be writable after the rename: {output:?}"
    );
    assert_eq!(
        std::fs::read_to_string(landed.join("authority/policy.dw"))
            .ok()
            .as_deref(),
        Some(policy_text),
        "this box's policy changed on the host"
    );
    assert_eq!(
        std::fs::read_to_string(landed.join("authority/box.toml"))
            .ok()
            .as_deref(),
        Some(config_text.as_str()),
        "this box's configuration changed on the host"
    );
}

/// **The required end-to-end test: a planted configuration is never adopted.**
///
/// Three legs, in order. Legs 2 and 3 are the measured attack — a workload that can write its project
/// plants a configuration a later run would adopt, and an MCP server starts *outside* containment
/// at the operator's identity, so adoption is the whole harm.
#[test]
fn a_workload_cannot_make_a_later_run_adopt_a_configuration_it_wrote() {
    if !fixture::namespace_launcher_is_usable() {
        println!("skipping: this platform has no usable containment backend");
        return;
    }
    // Leg 1: a box whose configuration makes the project writable.
    let box_ = writable_project("fs-planted-config");
    let deep = box_.workspace().join("deep");
    std::fs::create_dir_all(&deep).expect("a directory to plant under");

    // Leg 2: from inside, with the workload's OWN syscalls, plant a configuration naming a
    // different start command and a hostile MCP server.
    //
    // **The directory is made from the HOST, and the script uses only shell redirection.** `mkdir`
    // is not an allowlisted exec literal, so a script calling it prints `command not found`, plants
    // nothing, and leaves every assertion below unreached — which is how this leg was vacuous.
    let planted = deep.join(".strands-box");
    std::fs::create_dir_all(&planted).expect("the directory the workload writes into");
    let planted_config = planted.join("box.toml");
    let output = box_.bash(
        "printf 'name = \"hostile\"\\n[agent]\\ncommand = [\"/bin/sh\"]\\n\
         [mcp.hostile]\\ncommand = [\"/bin/sh\"]\\n' > ./deep/.strands-box/box.toml \
         && printf 'PLANTED\\n'",
    );
    let write_was_refused = !planted_config.is_file();
    // The leg asserts something either way: the plant is reported exactly as the host found it.
    assert_eq!(
        stdout(&output).contains("PLANTED"),
        !write_was_refused,
        "the workload's report and the host must agree about whether the plant landed: {output:?}"
    );

    // Leg 3: on the HOST, either the write was refused, or the next run did not adopt it.
    if !write_was_refused {
        let adopted =
            run_without_config_from(&deep, box_.operator_home(), &["/bin/echo", "UNCHANGED"]);
        assert!(
            !adopted.status.success(),
            "a run from a directory holding a planted configuration must be refused: {adopted:?}"
        );
        assert!(
            stderr(&adopted).contains("--config <FILE>"),
            "the refusal must name the reason: {}",
            stderr(&adopted)
        );
        // And no alias was materialized for the hostile server, so `shell:spawn` was never asked
        // about a program the workload chose.
        let alias = box_.root().join("bin/hostile");
        assert!(
            !alias.exists(),
            "an alias for a workload-declared MCP server must never be created"
        );
    }
}

/// **An entry strictly inside the project keeps the enter-only grant beside it.**
///
/// Only a grant that COVERS the workspace replaces the weaker grant, because one path granted at two
/// scopes has no macOS profile at all. A nested entry is a different path, so the project stays
/// enterable while its own files stay unreadable and its entries stay unlisted.
#[test]
fn a_nested_entry_keeps_the_projects_own_grant() {
    if !fixture::namespace_launcher_is_usable() {
        println!("skipping: this platform has no usable containment backend");
        return;
    }
    let box_ = Request::with_policy("fs-nested-entry", PERMIT_EVERY_EFFECT)
        .agent_list("read", &["{workspace}/src"]);
    let project = box_.operator_home().join("workspace");
    std::fs::create_dir_all(project.join("src")).expect("the granted subdirectory");
    std::fs::write(project.join("src/main.rs"), "NESTED\n").expect("a file inside it");
    let box_ = box_.expect();

    std::fs::write(box_.workspace().join("top.txt"), "TOP\n").expect("a file at the project root");

    let output = box_.bash(
        "read -r leaked < ./src/main.rs && printf 'READ=%s\\n' \"$leaked\"\n\
         printf 'ENTERED=%s\\n' \"$(pwd -P)\"\n\
         read -r top < ./top.txt 2>/dev/null && printf 'ROOT_READ_LEAKED=%s\\n' \"$top\"\n\
         set -- ./*\n\
         printf 'GLOB=%s\\n' \"$1\"\n\
         printf 'done\\n'",
    );

    let seen = stdout(&output);
    assert!(
        seen.contains("READ=NESTED"),
        "an entry inside the project must be readable: {output:?}"
    );
    // `pwd -P` asks the kernel rather than reading `PWD`, which the box composes into the
    // environment and which therefore prints the project path whether or not it is reachable.
    assert!(
        seen.contains(&format!("ENTERED={}", box_.workspace().display())),
        "and the workload must still stand in its project: {output:?}"
    );
    assert!(
        !seen.contains("ROOT_READ_LEAKED"),
        "an entry inside the project must leave the project root's own files unreadable: \
         {output:?}"
    );
    // The glob must NOT expand: the kept grant is entry-only, so the project root is not
    // enumerable. On Linux the synthetic parent shows the granted child either way, so only the
    // platform whose cell decides asserts it.
    #[cfg(not(target_os = "linux"))]
    assert!(
        seen.contains("GLOB=./*"),
        "the project root must not enumerate beside a nested entry: {output:?}"
    );
    assert!(
        seen.contains("done"),
        "the script must run to the end, or the assertions above prove nothing: {output:?}"
    );
}

/// **A Homebrew Python linked against Apple's libffi runs a C callback in the agent box.**
///
/// A host without `/usr/lib/libffi-trampolines.dylib`, without a Homebrew Python, or whose `_ctypes`
/// links another libffi measures nothing and skips.
#[cfg(target_os = "macos")]
#[test]
fn a_system_libffi_callback_runs_in_the_agent_box() {
    const CALLBACK: &str = "import ctypes; \
        print('callback', ctypes.CFUNCTYPE(ctypes.c_int, ctypes.c_int)(lambda x: x + 1)(41))";
    const SYSTEM_LIBFFI: &str = "/usr/lib/libffi.dylib";
    if !Path::new("/usr/lib/libffi-trampolines.dylib").is_file() {
        println!("skipping: this host has no /usr/lib/libffi-trampolines.dylib");
        return;
    }
    let Some(python) = ["/opt/homebrew/bin/python3", "/usr/local/bin/python3"]
        .iter()
        .find_map(|candidate| Path::new(candidate).canonicalize().ok())
    else {
        println!("skipping: this host has no Homebrew python3");
        return;
    };
    let Some((prefix, keg)) = python.ancestors().find_map(|ancestor| {
        let cellar = ancestor.parent()?;
        (cellar.file_name()? == "Cellar").then_some((cellar.parent()?, ancestor))
    }) else {
        println!(
            "skipping: {} is not under a Homebrew Cellar",
            python.display()
        );
        return;
    };

    let control = Command::new(&python)
        .args(["-c", "import _ctypes; print(_ctypes.__file__)"])
        .output()
        .expect("spawn the host python");
    let module = stdout(&control).trim().to_string();
    let links = Command::new("/usr/bin/otool")
        .args(["-L", &module])
        .output()
        .map(|output| stdout(&output))
        .unwrap_or_default();
    if !control.status.success() || !links.contains(SYSTEM_LIBFFI) {
        println!(
            "skipping: {} does not load _ctypes against {SYSTEM_LIBFFI}: {links}",
            python.display()
        );
        return;
    }

    let cellar = prefix.join("Cellar").display().to_string();
    let opt = prefix.join("opt").display().to_string();
    let keg = keg.display().to_string();
    let python_text = python.display().to_string();
    let box_ = Request::with_policy("fs-libffi-callback", PERMIT_EVERY_EFFECT)
        .agent_list("read", &[&cellar, &opt])
        .agent_list("exec", &[&keg])
        .expect();
    let output = box_.run(&[python_text.as_str(), "-I", "-c", CALLBACK]);
    assert!(
        output.status.success() && stdout(&output).contains("callback 42"),
        "a C callback through Apple's libffi must run in the agent box: status={:?} stdout={} \
         stderr={}",
        output.status,
        stdout(&output),
        stderr(&output)
    );
}

/// **An `exec` grant runs a program the workload names bare, and an ungranted one stays refused.**
#[cfg(target_os = "macos")]
#[test]
fn a_bare_name_on_path_reaches_a_granted_program() {
    if !fixture::namespace_launcher_is_usable() {
        println!("skipping: this platform has no usable containment backend");
        return;
    }
    let printf = "/usr/bin/printf";
    let Some(node) = std::env::var_os("PATH")
        .iter()
        .flat_map(std::env::split_paths)
        .map(|directory| directory.join("node"))
        .find(|candidate| candidate.is_file())
    else {
        println!("skipping: this host has no node on PATH");
        return;
    };
    if !Path::new(printf).is_file() {
        println!("skipping: this host has no {printf}");
        return;
    }
    let node = node.display().to_string();
    let box_ = Request::with_policy("fs-bare-exec", PERMIT_EVERY_EFFECT)
        .agent_list("exec", &[printf])
        .agent_env("PATH", "/usr/bin:/bin")
        .expect();
    let spawn = |program: &str| {
        let script = format!(
            "const r = require('child_process').spawnSync('{program}', ['FOUND'], \
             {{ stdio: 'inherit' }}); \
             if (r.error) {{ console.error(r.error.code); process.exit(3); }} \
             process.exit(r.status);"
        );
        box_.run(&[node.as_str(), "--openssl-config=/dev/null", "-e", &script])
    };

    let granted = spawn("printf");
    assert!(
        granted.status.success() && stdout(&granted) == "FOUND",
        "a granted program must start by its bare name: status={:?} stdout={} stderr={}",
        granted.status,
        stdout(&granted),
        stderr(&granted)
    );

    let ungranted = spawn("true");
    assert!(
        ungranted.status.code() == Some(3) && stderr(&ungranted).contains("EPERM"),
        "an ungranted program must stay refused at exec: status={:?} stderr={}",
        ungranted.status,
        stderr(&ungranted)
    );
}

/// **A virtualenv-shaped `[agent] command` starts on Linux and runs as its identity** (#30 part A).
/// The chain leaves the granted venv for a prefix no list names, the way a venv's `python` reaches
/// `/usr/local/bin/python3`.
#[cfg(target_os = "linux")]
#[test]
fn a_venv_shaped_command_runs_as_its_identity() {
    if !fixture::namespace_launcher_is_usable() {
        println!("skipping: this host cannot run the namespace launcher");
        return;
    }
    let request = Request::with_policy("fs-venv-chain", PERMIT_EVERY_EFFECT);
    let home = request.operator_home().to_path_buf();
    let prefix_bin = home.join("prefix/bin");
    let venv = home.join("venv");
    std::fs::create_dir_all(&prefix_bin).expect("prefix");
    std::fs::create_dir_all(venv.join("bin")).expect("venv");
    let readlink = ["/usr/bin/readlink", "/bin/readlink"]
        .iter()
        .map(Path::new)
        .find(|candidate| candidate.is_file())
        .expect("coreutils readlink");
    let real = prefix_bin.join("real");
    std::fs::copy(readlink, &real).expect("program");
    let middle = prefix_bin.join("p3");
    std::os::unix::fs::symlink("real", &middle).expect("hop 3");
    std::os::unix::fs::symlink(&middle, venv.join("bin/p3")).expect("hop 2");
    let route = venv.join("bin/p");
    std::os::unix::fs::symlink("p3", &route).expect("hop 1");

    let venv_text = venv.display().to_string();
    let box_ = request.agent_list("read", &[&venv_text]).expect();
    let route_text = route.display().to_string();
    let output = box_.run(&[route_text.as_str(), "/proc/self/exe"]);
    let real = real.canonicalize().expect("canonical program");
    assert!(
        output.status.success() && stdout(&output).trim() == real.display().to_string(),
        "the chain must exec and run as {}: status={:?} stdout={} stderr={}",
        real.display(),
        output.status,
        stdout(&output),
        stderr(&output)
    );
}

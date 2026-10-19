//! Kernel-level tests for the existence deny across the operator's home.
#![cfg(target_os = "macos")]

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use containment::{ContainmentConfig, Network, Operation, Scope};
use sha2::{Digest as _, Sha256};

#[path = "support/target_env.rs"]
mod target_env;

const TRUST_BUNDLE_PEM: &str =
    "-----BEGIN CERTIFICATE-----\nMIIBfixture\n-----END CERTIFICATE-----\n";

/// A fixture inside the operator's own home, so the home deny covers it.
fn fixture_in_operator_home() -> (tempfile::TempDir, PathBuf) {
    let spellings = containment::test_support::operator_home_spellings().expect("operator home");
    let home = spellings.first().expect("at least one spelling");
    let directory = tempfile::Builder::new()
        .prefix(".strands-containment-test-")
        .tempdir_in(home)
        .expect("fixture inside the operator home");
    let root = directory
        .path()
        .canonicalize()
        .expect("canonical fixture root");
    (directory, root)
}

/// The grants a box carries, plus whatever the caller's program needs, written beside its home.
fn written_config(
    root: &Path,
    executable: &Path,
    extra: &[(PathBuf, Operation, Scope)],
) -> (PathBuf, PathBuf) {
    let home = root.join("home");
    std::fs::create_dir_all(&home).expect("box home");
    let trust_bundle = home.join("proxy-ca.pem");
    std::fs::write(&trust_bundle, TRUST_BUNDLE_PEM).expect("trust bundle");

    let mut config = ContainmentConfig::new()
        .allow(executable, Operation::Exec, Scope::File)
        .expect("interpreter")
        .allow(&trust_bundle, Operation::Read, Scope::File)
        .expect("trust bundle")
        .allow(&home, Operation::Read, Scope::Root)
        .expect("box home")
        .allow(&home, Operation::Write, Scope::Root)
        .expect("box home")
        .allow(Path::new("/"), Operation::Read, Scope::Dir)
        .expect("the root's own entry")
        .set_network(Network::localhost().connect(43123))
        .expect("proxy port");
    for (path, operation, scope) in extra {
        config = config
            .allow(path, *operation, *scope)
            .expect("caller-declared grant");
    }

    let config_json = config.to_json().expect("config JSON");
    let config_path = home.join("containment.json");
    std::fs::write(&config_path, &config_json).expect("write config");
    (config_path, home)
}

/// Drive `containment-test-probe`, which reads the config and contains itself.
fn probed(root: &Path, probes: &[String]) -> Output {
    probed_granting(root, &[], probes)
}

/// `probed`, with grants beyond the ones every box carries.
fn probed_granting(
    root: &Path,
    extra: &[(PathBuf, Operation, Scope)],
    probes: &[String],
) -> Output {
    let probe = PathBuf::from(env!("CARGO_BIN_EXE_containment-test-probe"));
    let (config_path, home) = written_config(root, &probe, extra);
    let mut command = Command::new(&probe);
    command.arg(&config_path);
    for spec in probes {
        command.arg(spec);
    }
    command
        .current_dir(&home)
        .output()
        .expect("spawn containment-test-probe")
}

/// Apply through the trampoline, then exec a real interpreter.
fn contained(
    root: &Path,
    executable: &Path,
    extra: &[(PathBuf, Operation, Scope)],
    arguments: &[String],
) -> Output {
    let (config_path, home) = written_config(root, executable, extra);
    let digest = Sha256::digest(std::fs::read(&config_path).expect("config bytes"))
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    let environment = BTreeMap::from([("HOME".to_string(), home.display().to_string())]);
    let mut command = Command::new(env!("CARGO_BIN_EXE_strands-box-contain-trampoline"));
    command
        .arg("--config")
        .arg(&config_path)
        .arg("--config-sha256")
        .arg(digest);
    let _environment = target_env::attach(&mut command, &environment);
    command.arg("--").arg(executable);
    for argument in arguments {
        command.arg(argument);
    }
    command
        .current_dir(&home)
        .output()
        .expect("spawn strands-box-contain-trampoline")
}

/// The first interpreter of this name that lives inside the operator's home, if any.
fn interpreter_in_operator_home(name: &str) -> Option<PathBuf> {
    let spellings = containment::test_support::operator_home_spellings().ok()?;
    let home = spellings.first()?.clone();
    let output = Command::new("/usr/bin/which").arg(name).output().ok()?;
    let path = PathBuf::from(String::from_utf8_lossy(&output.stdout).trim())
        .canonicalize()
        .ok()?;
    path.starts_with(home).then_some(path)
}

/// An entry of a granted `Dir` tree answers, and an ungranted sibling of that tree does not.
///
/// The workload stands in a directory it may list and may not read, so a probe for an optional
/// file there must read "absent" rather than "refused".
#[test]
fn an_entry_of_a_granted_directory_answers_and_an_ungranted_sibling_does_not() {
    let (_fixture, root) = fixture_in_operator_home();
    let project = root.join("project");
    std::fs::create_dir(&project).expect("the directory the workload stands in");
    let ungranted = root.join("sibling-that-exists");
    std::fs::create_dir(&ungranted).expect("a sibling the box is not granted");

    let output = probed_granting(
        &root,
        &[(project.clone(), Operation::Read, Scope::Dir)],
        &[
            // Inside the grant: the errno discloses absence, which is what a caller expects.
            format!(
                "expect-deny:exists-stat:{}",
                project.join("tools").display()
            ),
            format!(
                "expect-deny:exists-stat:{}",
                project.join("deep").join("nope").display()
            ),
            // Outside every grant, and still inside the home: refused, present or absent alike.
            format!("expect-ok:exists-stat:{}", ungranted.display()),
            format!("expect-deny:exists-access:{}", ungranted.display()),
            format!(
                "expect-ok:exists-stat:{}",
                root.join("sibling-that-does-not-exist").display()
            ),
        ],
    );

    assert_eq!(
        output.status.code(),
        Some(0),
        "a granted directory's entries answer and an ungranted sibling does not: stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
}

/// A name that is not there and a name that is are the same answer, inside the home.
#[test]
fn a_present_name_and_an_absent_name_are_the_same_answer() {
    let (_fixture, root) = fixture_in_operator_home();
    let present = root.join("sibling-that-exists");
    std::fs::create_dir(&present).expect("a sibling the box is not granted");
    let absent = root.join("sibling-that-does-not-exist");

    // Present and absent report the same refusal, over both operations that answer.
    let output = probed(
        &root,
        &[
            format!("expect-deny:exists-access:{}", present.display()),
            format!("expect-ok:exists-stat:{}", present.display()),
            format!("expect-ok:exists-stat:{}", absent.display()),
        ],
    );

    assert_eq!(
        output.status.code(),
        Some(0),
        "a name inside the operator home must answer nothing: stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
}

/// The home's second name answers nothing either.
#[test]
fn every_spelling_of_the_operator_home_answers_nothing() {
    let spellings =
        containment::test_support::operator_home_spellings().expect("operator home spellings");
    assert!(
        spellings.len() >= 2,
        "the home answers to at least two names on macOS: {spellings:?}"
    );
    let (_fixture, root) = fixture_in_operator_home();
    let present = root.join("sibling-that-exists");
    std::fs::create_dir(&present).expect("a sibling the box is not granted");

    // The data volume's mount point, named here and not read back from the code under test. A loop
    // over the same set the renderer denies could only probe spellings already denied, so a wrong
    // prefix would pass.
    let mut respellings = vec![present.clone()];
    respellings.push(
        Path::new("/System/Volumes/Data").join(
            present
                .strip_prefix("/")
                .expect("the fixture path is absolute"),
        ),
    );
    assert!(
        respellings[1].exists(),
        "{} must name the same directory, or this host is not firmlinked as expected",
        respellings[1].display()
    );

    let mut probes = Vec::new();
    for respelled in &respellings {
        probes.push(format!("expect-deny:exists-access:{}", respelled.display()));
        probes.push(format!("expect-ok:exists-stat:{}", respelled.display()));
        probes.push(format!(
            "expect-ok:exists-stat:{}",
            respelled
                .parent()
                .expect("a parent")
                .join("absent-at-this-spelling")
                .display()
        ));
    }
    let output = probed(&root, &probes);

    assert_eq!(
        output.status.code(),
        Some(0),
        "every spelling of the home must refuse alike: stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
}

/// No respelling reaches what the home deny refuses, including a link the workload plants itself.
#[test]
fn no_respelling_of_a_refused_path_answers() {
    let (_fixture, root) = fixture_in_operator_home();
    let home = root.join("home");
    std::fs::create_dir_all(&home).expect("box home");
    let present = root.join("sibling-that-exists");
    std::fs::create_dir(&present).expect("a sibling the box is not granted");
    let absent = root.join("sibling-that-does-not-exist");

    // The workload owns its home, so a link it plants there is the laundering attempt to refuse.
    let to_present = home.join("link-to-present");
    let to_absent = home.join("link-to-absent");
    std::os::unix::fs::symlink(&present, &to_present).expect("planted link");
    std::os::unix::fs::symlink(&absent, &to_absent).expect("planted dangling link");

    let text = present.display().to_string();
    let mut respellings = vec![
        // Lexical variants the kernel normalizes before Seatbelt matches.
        format!("/{text}"),
        text.replacen('/', "/./", 1),
        format!("{}/../sibling-that-exists", present.display()),
        // Both planted links, one to a present target and one dangling.
        to_present.display().to_string(),
        to_absent.display().to_string(),
    ];
    // A symlinked prefix, where the host has one. `/Volumes/Macintosh HD` is a link to `/`.
    let through_a_linked_prefix = Path::new("/Volumes/Macintosh HD").join(
        present
            .strip_prefix("/")
            .expect("the fixture path is absolute"),
    );
    if through_a_linked_prefix.exists() {
        respellings.push(through_a_linked_prefix.display().to_string());
    }

    let mut probes = Vec::new();
    for respelled in &respellings {
        probes.push(format!("expect-deny:exists-access:{respelled}"));
        probes.push(format!("expect-ok:exists-stat:{respelled}"));
    }
    let output = probed(&root, &probes);

    assert_eq!(
        output.status.code(),
        Some(0),
        "every respelling must refuse alike: stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
}

/// A granted path stays reachable, and the ancestor chain a tool walks upward stays statable.
#[test]
fn a_granted_path_and_its_ancestors_survive_the_home_deny() {
    let (_fixture, root) = fixture_in_operator_home();
    let home = root.join("home");
    std::fs::create_dir_all(&home).expect("box home");
    let inside = home.join("state.txt");
    std::fs::write(&inside, "state").expect("a file the box owns");

    let mut probes = vec![
        format!("expect-ok:read:{}", inside.display()),
        format!("expect-ok:write:{}", inside.display()),
        format!("expect-ok:exists-access:{}", home.display()),
    ];
    // Every ancestor from the box home up to the filesystem root.
    let mut ancestor = home.parent();
    while let Some(path) = ancestor {
        probes.push(format!("expect-ok:exists-access:{}", path.display()));
        ancestor = path.parent();
    }
    let output = probed(&root, &probes);

    assert_eq!(
        output.status.code(),
        Some(0),
        "a grant and its ancestor chain must survive the deny: stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
}

/// A real interpreter that lives under the operator's home still runs.
#[test]
fn an_interpreter_under_the_operator_home_still_runs() {
    let Some(node) = interpreter_in_operator_home("node") else {
        println!("skipping: no node inside the operator home");
        return;
    };
    let (_fixture, root) = fixture_in_operator_home();
    let output = contained(
        &root,
        &node,
        // What an `[agent] read` entry states for Node, because a caller states what its program reads.
        &[(
            PathBuf::from("/System/Library/OpenSSL"),
            Operation::Read,
            Scope::Root,
        )],
        &["--version".to_string()],
    );

    assert!(
        output.status.success(),
        "an interpreter under the operator home must still run: stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        String::from_utf8_lossy(&output.stdout).starts_with('v'),
        "the interpreter must report its version: {}",
        String::from_utf8_lossy(&output.stdout)
    );
}

/// A home-resident Python still imports its standard library.
#[test]
fn a_home_resident_python_still_imports_its_standard_library() {
    let Some(python) = interpreter_in_operator_home("python3") else {
        println!("skipping: no python3 inside the operator home");
        return;
    };
    // The interpreter tree, as an `[agent] read` entry grants it: the prefix two levels above `bin/python3`.
    let Some(prefix) = python.parent().and_then(Path::parent) else {
        println!("skipping: {} has no prefix to grant", python.display());
        return;
    };
    let (_fixture, root) = fixture_in_operator_home();
    let output = contained(
        &root,
        &python,
        &[(prefix.to_path_buf(), Operation::Read, Scope::Root)],
        &[
            "-c".to_string(),
            "import json, sqlite3, ssl, tempfile; print('imports ok')".to_string(),
        ],
    );

    assert!(
        output.status.success(),
        "a home-resident interpreter must still import its standard library: stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        String::from_utf8_lossy(&output.stdout).contains("imports ok"),
        "the standard library must load: {}",
        String::from_utf8_lossy(&output.stdout)
    );
}

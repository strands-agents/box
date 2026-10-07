//! Real apply-then-exec tests for the fixed macOS Agent profile.
#![cfg(target_os = "macos")]

use std::collections::BTreeMap;
use std::path::Path;
use std::process::{Command, Output};

use containment::{ContainmentConfig, Network, Operation, Scope};
use sha2::{Digest as _, Sha256};

fn run_contained(
    executable_grant: &Path,
    command: &Path,
    target_environment: &BTreeMap<String, String>,
) -> Output {
    let directory = tempfile::tempdir().expect("fixtures");
    let canonical_directory = directory.path().canonicalize().expect("canonical fixtures");
    let trust_bundle = canonical_directory.join("proxy-ca.pem");
    std::fs::write(
        &trust_bundle,
        "-----BEGIN CERTIFICATE-----\nMIIBfixture\n-----END CERTIFICATE-----\n",
    )
    .expect("trust bundle");
    // **A caller declares what its program reads before it runs a line.** The profile once carried
    // `/`, `/etc`, and `/dev/null` as static text, so every box got them whether or not it needed
    // them. They are grants now, which means a direct caller states them: without the root's own
    // entry a path lookup resolves nothing, and the target dies producing no output at all.
    let config = ContainmentConfig::new()
        .allow(executable_grant, Operation::Exec, Scope::File)
        .expect("exact executable")
        .allow(&trust_bundle, Operation::Read, Scope::File)
        .expect("exact trust bundle")
        .allow(&canonical_directory, Operation::Read, Scope::Root)
        .expect("exact home directory")
        .allow(&canonical_directory, Operation::Write, Scope::Root)
        .expect("exact home directory")
        .allow(Path::new("/"), Operation::Read, Scope::Dir)
        .expect("the root's own entry")
        .allow(Path::new("/etc"), Operation::Metadata, Scope::Dir)
        .expect("the /etc entry")
        .allow(Path::new("/dev/null"), Operation::Read, Scope::File)
        .expect("the null device")
        .allow(Path::new("/dev/null"), Operation::Write, Scope::File)
        .expect("the null device")
        .set_network(Network::localhost().connect(43123))
        .expect("exact proxy port");
    let config_json = config.to_json().expect("config JSON");
    let digest = Sha256::digest(config_json.as_bytes())
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    let config_path = canonical_directory.join("containment.json");
    std::fs::write(&config_path, config_json).expect("write config");

    Command::new(env!("CARGO_BIN_EXE_strands-box-contain-trampoline"))
        .arg("--config")
        .arg(&config_path)
        .arg("--config-sha256")
        .arg(digest)
        .arg("--target-env-json")
        .arg(serde_json::to_string(target_environment).expect("target environment"))
        .arg("--")
        .arg(command)
        .env("CONTAIN_AMBIENT_CANARY", "must-not-survive")
        .current_dir(canonical_directory)
        .output()
        .expect("spawn strands-box-contain-trampoline")
}

/// One box for a probe-driven test: a home granted read and write, and a trust bundle.
///
/// The `TempDir` is returned because dropping it removes the fixture.
fn probe_box() -> (tempfile::TempDir, std::path::PathBuf, std::path::PathBuf) {
    let fixtures = tempfile::tempdir().expect("fixtures");
    let root = fixtures.path().canonicalize().expect("canonical fixtures");
    let home = root.join("home");
    let trust_bundle = root.join("proxy-ca.pem");
    std::fs::create_dir(&home).expect("home fixture");
    std::fs::write(
        &trust_bundle,
        "-----BEGIN CERTIFICATE-----\nMIIBfixture\n-----END CERTIFICATE-----\n",
    )
    .expect("trust bundle");

    let probe = std::path::PathBuf::from(env!("CARGO_BIN_EXE_containment-test-probe"));
    let config = ContainmentConfig::new()
        .allow(&probe, Operation::Exec, Scope::File)
        .expect("exact executable")
        .allow(&trust_bundle, Operation::Read, Scope::File)
        .expect("exact trust bundle")
        .allow(&home, Operation::Read, Scope::Root)
        .expect("exact home directory")
        .allow(&home, Operation::Write, Scope::Root)
        .expect("exact home directory")
        .set_network(Network::localhost().connect(43123))
        .expect("exact proxy port");
    let config_path = root.join("containment.json");
    std::fs::write(&config_path, config.to_json().expect("config JSON")).expect("write config");

    (fixtures, home, config_path)
}

/// One box whose grants include a read-only root beside the read-write home.
///
/// The library-load rule needs both cells in one profile to be measured at all: the deny belongs to
/// the write cells, and a read-only root is what proves it is scoped rather than a refuse-all.
///
/// Returns the home, the read-only root, and the config path. The `TempDir` is returned because
/// dropping it removes the fixture.
fn probe_box_with_read_only_root() -> (
    tempfile::TempDir,
    std::path::PathBuf,
    std::path::PathBuf,
    std::path::PathBuf,
) {
    let fixtures = tempfile::tempdir().expect("fixtures");
    let root = fixtures.path().canonicalize().expect("canonical fixtures");
    let home = root.join("home");
    let read_only = root.join("runner");
    let trust_bundle = root.join("proxy-ca.pem");
    std::fs::create_dir(&home).expect("home fixture");
    std::fs::create_dir(&read_only).expect("read root fixture");
    std::fs::write(
        &trust_bundle,
        "-----BEGIN CERTIFICATE-----\nMIIBfixture\n-----END CERTIFICATE-----\n",
    )
    .expect("trust bundle");

    let probe = std::path::PathBuf::from(env!("CARGO_BIN_EXE_containment-test-probe"));
    let config = ContainmentConfig::new()
        .allow(&probe, Operation::Exec, Scope::File)
        .expect("exact executable")
        .allow(&trust_bundle, Operation::Read, Scope::File)
        .expect("exact trust bundle")
        .allow(&home, Operation::Read, Scope::Root)
        .expect("exact home directory")
        .allow(&home, Operation::Write, Scope::Root)
        .expect("exact home directory")
        .allow(&read_only, Operation::Read, Scope::Root)
        .expect("a read-only root")
        .set_network(Network::localhost().connect(43123))
        .expect("exact proxy port");
    let config_path = root.join("containment.json");
    std::fs::write(&config_path, config.to_json().expect("config JSON")).expect("write config");

    (fixtures, home, read_only, config_path)
}

/// Run the probe inside the box that `config_path` describes.
fn run_probe(config_path: &Path, probes: &[String]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_containment-test-probe"))
        .arg(config_path)
        .args(probes)
        .output()
        .expect("spawn containment-test-probe")
}

/// Run the same probes with no containment, which is the control half of a refusal.
fn run_uncontained(probes: &[String]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_containment-test-probe"))
        .arg("--uncontained")
        .args(probes)
        .output()
        .expect("spawn containment-test-probe")
}

/// The upper-case spelling of `directory` when that reaches the same object, and nothing otherwise.
///
/// Three ways this answers nothing, and each would put a useless row in the caller's list. A leaf
/// that is already upper-case, or has no case at all, gives back the same string. A case-sensitive
/// volume leaves the upper-case name absent, and an absent path measures no rule. A distinct object
/// under that name is not this directory. Identity is `dev` and `ino`, because existence alone does
/// not say the two names meet.
fn upper_case_spelling(directory: &Path) -> Option<std::path::PathBuf> {
    use std::os::unix::fs::MetadataExt as _;

    let name = directory.file_name()?.to_str()?;
    let upper = name.to_uppercase();
    if upper == name {
        return None;
    }
    let candidate = directory.parent()?.join(upper);
    let (here, there) = (
        directory.symlink_metadata().ok()?,
        candidate.symlink_metadata().ok()?,
    );
    (here.dev() == there.dev() && here.ino() == there.ino()).then_some(candidate)
}

#[test]
fn exact_executable_crosses_the_fixed_seatbelt_boundary() {
    let executable = Path::new("/usr/bin/true");
    let output = run_contained(executable, executable, &BTreeMap::new());

    assert!(
        output.status.success(),
        "exact target failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

fn private_executables_cross_the_boundary(read_installation: bool) {
    use std::os::unix::fs::PermissionsExt as _;

    let fixtures = tempfile::tempdir_in("/var/tmp").expect("private startup fixtures");
    let root = fixtures.path().canonicalize().expect("canonical fixtures");
    let installation = root.join(".local/share/codex");
    let box_directory = root.join("box");
    let bin = box_directory.join("bin");
    let home = box_directory.join("home");
    let private = box_directory.join("private");
    for directory in [&installation, &bin, &home, &private] {
        std::fs::create_dir_all(directory).expect("fixture directory");
    }
    std::fs::set_permissions(&box_directory, std::fs::Permissions::from_mode(0o700))
        .expect("private box directory");
    assert_eq!(
        std::fs::metadata(&box_directory)
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o700
    );

    let program = installation.join("codex");
    let alias = bin.join("zsh");
    let probe = Path::new(env!("CARGO_BIN_EXE_containment-test-probe"));
    for executable in [&program, &alias] {
        std::fs::copy(probe, executable).expect("native executable fixture");
        assert!(
            Command::new(executable)
                .arg("--exec-target")
                .status()
                .expect("uncontained executable control")
                .success()
        );
    }
    let authority = private.join("policy.dw");
    let sibling = private.join("secret");
    let protected = home.join("authority");
    for file in [&authority, &sibling, &protected] {
        std::fs::write(file, "private contents").expect("authority fixture");
    }
    let opened_authority = std::fs::File::open(&authority).expect("opened authority");
    let opened_protected = std::fs::File::open(&protected).expect("opened protected file");
    let mut config = ContainmentConfig::new()
        .anchored_at(&root)
        .allow(&program, Operation::Exec, Scope::File)
        .expect("workload executable")
        .allow(&alias, Operation::Exec, Scope::File)
        .expect("alias executable")
        .allow(&home, Operation::Read, Scope::Root)
        .expect("box home read")
        .allow(&home, Operation::Write, Scope::Root)
        .expect("box home write")
        .allow("/", Operation::Read, Scope::Dir)
        .expect("root entry")
        .refuse(&private, Scope::Root)
        .expect("private state refusal")
        .require_file_identity(&authority, &opened_authority)
        .expect("loaded authority identity")
        .protect_write(&protected, &opened_protected)
        .expect("loaded authority write protection")
        .set_network(Network::localhost().connect(43123))
        .expect("proxy endpoint");
    if read_installation {
        config = config
            .allow(&installation, Operation::Read, Scope::Root)
            .expect("installation read");
    }
    let json = config.to_json().expect("startup config");
    let digest = Sha256::digest(json.as_bytes())
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    let config_path = private.join("containment.json");
    for executable in [&program, &alias] {
        std::fs::write(&config_path, &json).expect("write startup config");
        let output = Command::new(env!("CARGO_BIN_EXE_strands-box-contain-trampoline"))
            .arg("--config")
            .arg(&config_path)
            .arg("--config-sha256")
            .arg(&digest)
            .arg("--target-env-json")
            .arg("{}")
            .arg("--")
            .arg(executable)
            .arg("--exec-target")
            .current_dir(&home)
            .output()
            .expect("start contained executable");
        assert!(
            output.status.success(),
            "{} failed: {}",
            executable.display(),
            String::from_utf8_lossy(&output.stderr)
        );
    }

    std::fs::write(&config_path, &json).expect("write probe config");
    let mut probes = vec![
        format!("expect-deny:read-errno:{}", alias.display()),
        format!("expect-deny:read-errno:{}", authority.display()),
        format!("expect-deny:read-errno:{}", sibling.display()),
        format!("expect-deny:write:{}", protected.display()),
    ];
    if read_installation {
        probes.push(format!("expect-ok:read-errno:{}", program.display()));
    } else {
        probes.push(format!("expect-deny:read-errno:{}", program.display()));
    }
    let output = run_probe(&config_path, &probes);
    assert!(
        output.status.success(),
        "private startup grants: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn an_execute_only_workload_starts_with_a_private_box_directory() {
    private_executables_cross_the_boundary(false);
}

#[test]
fn an_execute_only_alias_starts_when_the_installation_is_readable() {
    private_executables_cross_the_boundary(true);
}

#[test]
fn core_foundation_initializer_can_inspect_only_its_own_process() {
    let executable = Path::new("/usr/bin/plutil");
    let output = run_contained(executable, executable, &BTreeMap::new());

    assert!(
        output.status.code().is_some(),
        "CoreFoundation bootstrap terminated by signal: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

/// A program reached through a chain of two links still crosses the boundary.
#[test]
fn an_executable_reached_through_a_link_chain_crosses_the_boundary() {
    let directory = tempfile::tempdir().expect("chain fixtures");
    let root = directory
        .path()
        .canonicalize()
        .expect("canonical chain root");
    // Every link target is spelled canonically. A target reached through a link of its own adds an
    // unrendered node and moves what this test measures.
    let middle = root.join("hop-1");
    let route = root.join("hop-2");
    std::os::unix::fs::symlink(Path::new("/usr/bin/true"), &middle).expect("hop 1");
    std::os::unix::fs::symlink(&middle, &route).expect("hop 2");

    let output = run_contained(&route, &route, &BTreeMap::new());

    assert!(
        output.status.success(),
        "a two-link chain must exec: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn a_different_executable_is_denied_after_containment() {
    let output = run_contained(
        Path::new("/usr/bin/true"),
        Path::new("/usr/bin/false"),
        &BTreeMap::new(),
    );

    assert_eq!(
        output.status.code(),
        Some(4),
        "a denied exec must fail in strands-box-contain-trampoline, not run /usr/bin/false"
    );
    assert!(
        String::from_utf8_lossy(&output.stderr)
            .contains("exec \"/usr/bin/false\" failed: Operation not permitted"),
        "unexpected stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn target_receives_only_the_explicit_environment() {
    let executable = Path::new("/usr/bin/env");
    let target = BTreeMap::from([("CONTAIN_EXPLICIT".to_string(), "present".to_string())]);
    let output = run_contained(executable, executable, &target);
    let stdout = String::from_utf8_lossy(&output.stdout);

    assert!(output.status.success(), "env failed: {stdout}");
    assert_eq!(stdout.trim(), "CONTAIN_EXPLICIT=present");
    assert!(!stdout.contains("CONTAIN_AMBIENT_CANARY"));
}

/// The Agent owns its home's contents and cannot replace the home itself.
///
/// A `(subpath X)` grant covers `X` as well as its descendants, so before the profile's
/// `file-write-unlink`/`file-write-create` denies on the home literal, a contained
/// workload could remove its own granted home and leave a symbolic link at that path.
/// Measured, not theorized: `rmdir` and `symlink` both returned success.
///
/// **Why this one directory's identity is load-bearing.** A trusted sibling reads the
/// home by pathname and re-resolves that name on every access, so a link left here
/// redirects those reads to the link's target, served with the reader's authority rather
/// than the Agent's. The Agent cannot follow such a link itself — the profile grants
/// nothing outside the home — which is what makes planting one useful to it.
///
/// All three probes run in one contained process, and the write is first on purpose: a
/// deny that also blocked ordinary writes would be a broken home rather than a protected
/// one, so "write inside succeeds" is as much the assertion as the two refusals.
///
/// The two refusals measure **one profile rule each** — `rmdir` the unlink deny,
/// `create-over` the create deny — and each fails on its own if that rule is deleted.
/// A single "replace the home" probe could not do that: with unlink denied the directory
/// survives, so the create attempt returns `EEXIST` and passes whether or not creating
/// was permitted.
///
/// Driven through `containment-test-probe` rather than a shell, because the profile
/// grants one exec literal: `rmdir`/`ln` are unreachable as executables, and `/bin/sh`
/// cannot even boot (it re-execs `/bin/bash` through `/private/var/select/sh`, which is
/// denied).
#[test]
fn the_agent_cannot_replace_its_own_home_directory() {
    let (_fixtures, home, config_path) = probe_box();

    let inside = home.join("inner.txt");
    let output = run_probe(
        &config_path,
        &[
            format!("expect-ok:write:{}", inside.display()),
            format!("expect-deny:rmdir:{}", home.display()),
            format!("expect-deny:create-over:{}", home.display()),
        ],
    );

    assert_eq!(
        output.status.code(),
        Some(0),
        "every probe must behave as demanded: stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    // The filesystem agrees with the probe's own verdict: the home is still the
    // directory the profile granted, not a link to somewhere else.
    assert!(
        !home
            .symlink_metadata()
            .expect("the home must survive")
            .is_symlink(),
        "the home must not be replaceable by a symbolic link"
    );
    assert!(home.is_dir(), "the home must still be a directory");
}

/// A refusal strictly inside the writable home fixes every directory between the two, and
/// nothing else.
///
/// The refusal names the object at its launch path, and the kernel judges the object's current
/// canonical path, so a `rename(2)` of a parent the home grants would carry the refused object to a
/// name no deny matches. So each directory between the root and the refusal refuses to be moved,
/// removed, or replaced, exactly as the root itself does.
///
/// **The permitted probes carry as much of the assertion as the refused ones.** A fix that also
/// froze the directory's contents, or its siblings, would be a broken home rather than a protected
/// one: an ordinary file inside a fixed directory is still created, edited, and renamed, and a
/// sibling directory with nothing refused inside still moves.
#[test]
fn a_refusal_inside_the_home_fixes_its_ancestors_and_frees_their_contents() {
    let fixtures = tempfile::tempdir().expect("fixtures");
    let root = fixtures.path().canonicalize().expect("canonical fixtures");
    let home = root.join("home");
    let trust_bundle = root.join("proxy-ca.pem");
    std::fs::write(
        &trust_bundle,
        "-----BEGIN CERTIFICATE-----\nMIIBfixture\n-----END CERTIFICATE-----\n",
    )
    .expect("trust bundle");
    // A sibling box's authority two levels down, and a refused file two levels down beside it.
    let sibling_box = home.join("sub/deep/.strands-box");
    std::fs::create_dir_all(&sibling_box).expect("the sibling box's authority directory");
    let policy = sibling_box.join("policy.dw");
    std::fs::write(&policy, "permit (principal, action, resource);\n").expect("the policy");
    let secret = home.join("files/nested/secret.txt");
    std::fs::create_dir_all(secret.parent().expect("parent")).expect("the file's directory");
    std::fs::write(&secret, "secret").expect("the refused file");
    // An ordinary file inside a fixed directory, and a sibling directory with nothing refused.
    let notes = home.join("sub/notes.txt");
    std::fs::write(&notes, "notes").expect("an ordinary file in the fixed directory");
    let plain = home.join("plain");
    std::fs::create_dir(&plain).expect("a directory with nothing refused inside");
    std::fs::write(plain.join("p.txt"), "plain").expect("a file in it");
    let policy_before = std::fs::read(&policy).expect("the policy's bytes");

    let probe = std::path::PathBuf::from(env!("CARGO_BIN_EXE_containment-test-probe"));
    let config = ContainmentConfig::new()
        .allow(&probe, Operation::Exec, Scope::File)
        .expect("exact executable")
        .allow(&trust_bundle, Operation::Read, Scope::File)
        .expect("exact trust bundle")
        .allow(&home, Operation::Read, Scope::Root)
        .expect("exact home directory")
        .allow(&home, Operation::Write, Scope::Root)
        .expect("exact home directory")
        .refuse(&sibling_box, Scope::Root)
        .expect("the sibling box's authority")
        .refuse(&secret, Scope::File)
        .expect("the refused file")
        .set_network(Network::localhost().connect(43127))
        .expect("exact proxy port");
    let config_path = root.join("containment.json");
    std::fs::write(&config_path, config.to_json().expect("config JSON")).expect("write config");

    let output = run_probe(
        &config_path,
        &[
            // Normal work first, so a refusal below cannot be a broken home.
            format!("expect-ok:write:{}", home.join("sub/created.txt").display()),
            format!("expect-ok:write:{}", notes.display()),
            format!("expect-ok:rename-away:{}", notes.display()),
            format!(
                "expect-ok:write:{}",
                home.join("sub/deep/beside.txt").display()
            ),
            format!("expect-ok:rename-away:{}", plain.display()),
            format!(
                "expect-ok:write:{}",
                home.join("files/nested/other.txt").display()
            ),
            // The parent and the grandparent of each refusal stay where they are.
            format!("expect-deny:rename-away:{}", home.join("sub").display()),
            format!(
                "expect-deny:rename-away:{}",
                home.join("sub/deep").display()
            ),
            format!("expect-deny:create-over:{}", home.join("sub").display()),
            format!(
                "expect-deny:create-over:{}",
                home.join("sub/deep").display()
            ),
            format!("expect-deny:rename-away:{}", home.join("files").display()),
            format!(
                "expect-deny:rename-away:{}",
                home.join("files/nested").display()
            ),
            // The refused objects themselves stay refused.
            format!("expect-deny:read:{}", policy.display()),
            format!("expect-deny:write:{}", policy.display()),
            format!("expect-deny:read:{}", secret.display()),
            format!("expect-deny:write:{}", secret.display()),
        ],
    );

    assert_eq!(
        output.status.code(),
        Some(0),
        "every probe must behave as demanded: stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    // The host agrees: every fixed directory is still a directory at its launch path, the
    // permitted writes landed, and the refused bytes are unchanged.
    for fixed in ["sub", "sub/deep", "files", "files/nested"] {
        let path = home.join(fixed);
        assert!(
            path.symlink_metadata()
                .expect("the fixed directory must survive")
                .is_dir(),
            "{} must still be the directory the refusal sits under",
            path.display()
        );
    }
    assert!(home.join("sub/created.txt").is_file());
    assert!(home.join("sub/deep/beside.txt").is_file());
    assert!(home.join("files/nested/other.txt").is_file());
    assert!(
        plain.join("p.txt").is_file(),
        "the sibling moved and moved back"
    );
    assert_eq!(
        std::fs::read(&policy).expect("the policy survives"),
        policy_before,
        "the refused policy's bytes changed"
    );
    assert_eq!(
        std::fs::read(&secret).expect("the secret survives"),
        b"secret"
    );
}

/// The Agent cannot set a BSD file flag inside the home it can write.
///
/// **Why a flag is authority at all.** The kernel checks a file flag *above* the ownership
/// check, so `UF_IMMUTABLE` refuses the owner as well as everybody else. The Agent holds
/// `file-write*` over its home, that wildcard includes `file-write-flags`, and one flag made a
/// single `remove_dir_all` over the box directory fail. Flags survive reboot and nothing in
/// `strands-box` clears one, so recovery was out of band. Measured when `rm` and `reset` ran that
/// call; both verbs are deleted, and a caller deleting its own `box_dir` meets the same failure.
///
/// The write runs first on purpose, for the same reason it does above: a deny that also
/// blocked ordinary writes would be a broken home rather than a protected one, so "write
/// inside succeeds" is as much the assertion as the refusal.
///
/// **This measures the owner flag class only, and that is deliberate.** The super-user class
/// is refused at the privilege check *before* the profile is consulted, so as an ordinary
/// user `chflags-sf` would report a refusal whether or not the rule exists — it would pass
/// vacuously. Run as root the privilege check passes and the profile is what answers. That
/// leg needs root, so it is a measurement (`tests/support/measure-sf-flags-as-root.sh`) rather
/// than a test here: a
/// root-gated assertion is skipped on every ordinary run, and this repository has already
/// shipped one gate that never executed. `chflags-sf` exists in the probe for that run.
///
/// One rule covers both classes regardless, because `chflags(2)` is a single Seatbelt
/// operation whose flag argument no rule can read.
#[test]
fn the_agent_cannot_set_a_file_flag_in_its_own_home() {
    let (_fixtures, home, config_path) = probe_box();
    // Created out here, so the flag probe measures the deny and not a missing file.
    let inside = home.join("inner.txt");
    std::fs::write(&inside, "inner").expect("a file inside the home");

    let output = run_probe(
        &config_path,
        &[
            format!("expect-ok:write:{}", inside.display()),
            format!("expect-deny:chflags-uf:{}", inside.display()),
            format!("expect-deny:chflags-uf:{}", home.display()),
        ],
    );

    assert_eq!(
        output.status.code(),
        Some(0),
        "every probe must behave as demanded: stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    // The filesystem agrees with the probe's own verdict. Read directly rather than trusting
    // the exit code, because a flag that stuck is what breaks the operator's cleanup — and it
    // would also break this fixture's own teardown.
    use std::os::macos::fs::MetadataExt as _;
    for path in [&inside, &home] {
        let flags = std::fs::metadata(path)
            .expect("the path must survive")
            .st_flags();
        assert_eq!(
            flags,
            0,
            "{} carries file flags {flags:#x}, so the deny did not hold and this tree is now \
             undeletable",
            path.display()
        );
    }
}

/// A fixture whose only grants are the profile's two required cells, plus the probe's exec.
///
/// No credential path is granted, and none can be: the floor refuses every grant that overlaps
/// one, which is why a deny there can never shadow an allow.
fn existence_probe_fixture() -> (tempfile::TempDir, std::path::PathBuf, std::path::PathBuf) {
    let fixtures = tempfile::tempdir().expect("fixtures");
    let root = fixtures.path().canonicalize().expect("canonical fixtures");
    let home = root.join("home");
    let trust_bundle = root.join("proxy-ca.pem");
    std::fs::create_dir(&home).expect("home fixture");
    std::fs::write(
        &trust_bundle,
        "-----BEGIN CERTIFICATE-----\nMIIBfixture\n-----END CERTIFICATE-----\n",
    )
    .expect("trust bundle");

    let probe = std::path::PathBuf::from(env!("CARGO_BIN_EXE_containment-test-probe"));
    let config = ContainmentConfig::new()
        .allow(&probe, Operation::Exec, Scope::File)
        .expect("exact executable")
        .allow(&trust_bundle, Operation::Read, Scope::File)
        .expect("exact trust bundle")
        .allow(&home, Operation::Read, Scope::Root)
        .expect("exact home directory")
        .allow(&home, Operation::Write, Scope::Root)
        .expect("exact home directory")
        .set_network(Network::localhost().connect(43123))
        .expect("exact proxy port");
    let config_path = root.join("containment.json");
    std::fs::write(&config_path, config.to_json().expect("config JSON")).expect("write config");
    (fixtures, probe, config_path)
}

/// No credential store answers an existence test, at any spelling the floor names.
#[test]
fn no_credential_store_answers_an_existence_test() {
    let protected =
        containment::test_support::credential_store_paths().expect("the floor's credential stores");
    // At least one per row per home spelling. A row whose anchor is a symlink renders two paths, so
    // the exact name set is pinned against a fixture home in
    // `floors.rs::the_existence_deny_covers_exactly_these_credential_stores`.
    let homes = containment::test_support::operator_home_spellings().expect("home spellings");
    assert!(
        protected.len() >= 12 * homes.len(),
        "the floor named {} credential paths, and twelve rows across {} home spellings is at \
         least {}",
        protected.len(),
        homes.len(),
        12 * homes.len()
    );

    let (_fixtures, probe, config_path) = existence_probe_fixture();
    let mut command = Command::new(&probe);
    command.arg(&config_path);
    for anchor in &protected {
        // The anchor, and a child that certainly is not there. Both must report EPERM.
        for path in [
            anchor.clone(),
            anchor.join("absent-c2f0b7d4-existence-probe"),
        ] {
            command.arg(format!("expect-deny:exists-access:{}", path.display()));
            command.arg(format!("expect-ok:exists-stat:{}", path.display()));
        }
    }
    let output = command.output().expect("spawn containment-test-probe");

    assert_eq!(
        output.status.code(),
        Some(0),
        "every credential store must refuse both existence tests: stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
}

/// An ungranted path outside the operator's home still answers an existence test.
#[test]
fn an_ungranted_path_outside_the_operator_home_still_answers_existence() {
    let present = Path::new("/bin/bash");
    assert!(
        present.exists(),
        "this test needs an ungranted path that exists on the host"
    );
    let absent = "/bin/absent-c2f0b7d4-existence-probe";

    let (_fixtures, probe, config_path) = existence_probe_fixture();
    let output = Command::new(&probe)
        .arg(&config_path)
        // `access` answers outright on the path that is there. Then the two `stat` errnos differ,
        // and that difference is the oracle. The absent path gets no `access` leg, because its
        // ENOENT is what an absent path reports with no rule in play.
        .arg(format!("expect-ok:exists-access:{}", present.display()))
        .arg(format!("expect-ok:exists-stat:{}", present.display()))
        .arg(format!("expect-deny:exists-stat:{absent}"))
        .output()
        .expect("spawn containment-test-probe");

    assert_eq!(
        output.status.code(),
        Some(0),
        "the recorded residual changed, so it needs re-deciding: stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
}

/// The Agent cannot set a set-user-ID or set-group-ID bit inside the home it can write.
#[test]
fn the_agent_cannot_set_a_setuid_bit_in_its_own_home() {
    let fixtures = tempfile::tempdir().expect("fixtures");
    let root = fixtures.path().canonicalize().expect("canonical fixtures");
    let home = root.join("home");
    let trust_bundle = root.join("proxy-ca.pem");
    std::fs::create_dir(&home).expect("home fixture");
    std::fs::write(
        &trust_bundle,
        "-----BEGIN CERTIFICATE-----\nMIIBfixture\n-----END CERTIFICATE-----\n",
    )
    .expect("trust bundle");
    // Created out here, so the probe measures the deny and not a missing file.
    let inside = home.join("inner.txt");
    std::fs::write(&inside, "inner").expect("a file inside the home");

    let probe = std::path::PathBuf::from(env!("CARGO_BIN_EXE_containment-test-probe"));
    let config = ContainmentConfig::new()
        .allow(&probe, Operation::Exec, Scope::File)
        .expect("exact executable")
        .allow(&trust_bundle, Operation::Read, Scope::File)
        .expect("exact trust bundle")
        .allow(&home, Operation::Read, Scope::Root)
        .expect("exact home directory")
        .allow(&home, Operation::Write, Scope::Root)
        .expect("exact home directory")
        .set_network(Network::localhost().connect(43124))
        .expect("exact proxy port");
    let config_path = root.join("containment.json");
    std::fs::write(&config_path, config.to_json().expect("config JSON")).expect("write config");

    let output = Command::new(&probe)
        .arg(&config_path)
        .arg(format!("expect-ok:write:{}", inside.display()))
        .arg(format!("expect-deny:setuid-bit:{}", inside.display()))
        .arg(format!("expect-deny:setgid-bit:{}", inside.display()))
        .current_dir(&root)
        .output()
        .expect("spawn containment-test-probe");

    assert_eq!(
        output.status.code(),
        Some(0),
        "every probe must behave as demanded: stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    // The filesystem agrees with the probe's own verdict, because a bit that stuck is the whole
    // defect and the probe's exit code is not the artifact an attacker keeps.
    use std::os::unix::fs::MetadataExt as _;
    let mode = std::fs::metadata(&inside)
        .expect("the file must survive")
        .mode();
    assert_eq!(
        mode & (libc::S_ISUID | libc::S_ISGID) as u32,
        0,
        "{} carries mode {mode:#o}, so the set-user-ID or set-group-ID bit was stored",
        inside.display()
    );
}

/// The Agent cannot change ownership inside the home it can write.
#[test]
fn the_agent_cannot_change_ownership_inside_its_own_home() {
    use std::os::unix::fs::MetadataExt as _;

    let fixtures = tempfile::tempdir().expect("fixtures");
    let root = fixtures.path().canonicalize().expect("canonical fixtures");
    let home = root.join("home");
    let trust_bundle = root.join("proxy-ca.pem");
    std::fs::create_dir(&home).expect("home fixture");
    std::fs::write(
        &trust_bundle,
        "-----BEGIN CERTIFICATE-----\nMIIBfixture\n-----END CERTIFICATE-----\n",
    )
    .expect("trust bundle");
    let inside = home.join("inner.txt");
    std::fs::write(&inside, "inner").expect("a file inside the home");
    let group_before = std::fs::metadata(&inside)
        .expect("the file must exist")
        .gid();

    let probe = std::path::PathBuf::from(env!("CARGO_BIN_EXE_containment-test-probe"));
    let config = ContainmentConfig::new()
        .allow(&probe, Operation::Exec, Scope::File)
        .expect("exact executable")
        .allow(&trust_bundle, Operation::Read, Scope::File)
        .expect("exact trust bundle")
        .allow(&home, Operation::Read, Scope::Root)
        .expect("exact home directory")
        .allow(&home, Operation::Write, Scope::Root)
        .expect("exact home directory")
        .set_network(Network::localhost().connect(43125))
        .expect("exact proxy port");
    let config_path = root.join("containment.json");
    std::fs::write(&config_path, config.to_json().expect("config JSON")).expect("write config");

    let output = Command::new(&probe)
        .arg(&config_path)
        .arg(format!("expect-ok:write:{}", inside.display()))
        .arg(format!("expect-deny:chown-self:{}", inside.display()))
        .current_dir(&root)
        .output()
        .expect("spawn containment-test-probe");

    assert_eq!(
        output.status.code(),
        Some(0),
        "every probe must behave as demanded: stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    let group_after = std::fs::metadata(&inside)
        .expect("the file must survive")
        .gid();
    assert_eq!(
        group_after,
        group_before,
        "{} moved from group {group_before} to {group_after}, so the deny did not hold",
        inside.display()
    );
}

/// The Agent cannot put an access-control-list entry inside the home it can write.
///
/// The last assertion is the point: `remove_dir_all` is what deleting a box directory runs, so a
/// stored entry breaks that delete for the operator who owns the tree.
#[test]
fn the_agent_cannot_set_an_access_control_list_in_its_own_home() {
    let fixtures = tempfile::tempdir().expect("fixtures");
    let root = fixtures.path().canonicalize().expect("canonical fixtures");
    let home = root.join("home");
    let trust_bundle = root.join("proxy-ca.pem");
    std::fs::create_dir(&home).expect("home fixture");
    std::fs::write(
        &trust_bundle,
        "-----BEGIN CERTIFICATE-----\nMIIBfixture\n-----END CERTIFICATE-----\n",
    )
    .expect("trust bundle");
    let inside = home.join("inner.txt");
    std::fs::write(&inside, "inner").expect("a file inside the home");

    let probe = std::path::PathBuf::from(env!("CARGO_BIN_EXE_containment-test-probe"));
    let config = ContainmentConfig::new()
        .allow(&probe, Operation::Exec, Scope::File)
        .expect("exact executable")
        .allow(&trust_bundle, Operation::Read, Scope::File)
        .expect("exact trust bundle")
        .allow(&home, Operation::Read, Scope::Root)
        .expect("exact home directory")
        .allow(&home, Operation::Write, Scope::Root)
        .expect("exact home directory")
        .set_network(Network::localhost().connect(43127))
        .expect("exact proxy port");
    let config_path = root.join("containment.json");
    std::fs::write(&config_path, config.to_json().expect("config JSON")).expect("write config");

    let output = Command::new(&probe)
        .arg(&config_path)
        .arg(format!("expect-ok:write:{}", inside.display()))
        .arg(format!("expect-deny:acl:{}", inside.display()))
        .current_dir(&root)
        .output()
        .expect("spawn containment-test-probe");

    assert_eq!(
        output.status.code(),
        Some(0),
        "every probe must behave as demanded: stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    // The operator's own cleanup, run outside any sandbox as the tree's owner. This is the assertion
    // an exit code cannot make: a deny entry the workload stored would refuse it.
    std::fs::remove_dir_all(&home)
        .expect("the operator must still be able to remove the box home it owns");
}

/// A write grant on ONE file lets the Agent write that file, and nothing else about it.
///
/// `unlink` runs last, because it is the one probe that would remove the fixture the others need.
#[test]
fn a_write_grant_on_one_file_cannot_change_or_replace_it() {
    use std::os::unix::fs::MetadataExt as _;

    let fixtures = tempfile::tempdir().expect("fixtures");
    let root = fixtures.path().canonicalize().expect("canonical fixtures");
    let home = root.join("home");
    let trust_bundle = root.join("proxy-ca.pem");
    std::fs::create_dir(&home).expect("home fixture");
    std::fs::write(
        &trust_bundle,
        "-----BEGIN CERTIFICATE-----\nMIIBfixture\n-----END CERTIFICATE-----\n",
    )
    .expect("trust bundle");
    // Outside the home, which is what `/dev/null` is to a real box: a file the workload may write
    // and does not own the tree of.
    let granted_file = root.join("sink");
    std::fs::write(&granted_file, "sink").expect("the granted file");
    let mode_before = std::fs::metadata(&granted_file)
        .expect("the file must exist")
        .mode();
    let group_before = std::fs::metadata(&granted_file)
        .expect("the file must exist")
        .gid();

    let probe = std::path::PathBuf::from(env!("CARGO_BIN_EXE_containment-test-probe"));
    let config = ContainmentConfig::new()
        .allow(&probe, Operation::Exec, Scope::File)
        .expect("exact executable")
        .allow(&trust_bundle, Operation::Read, Scope::File)
        .expect("exact trust bundle")
        .allow(&home, Operation::Read, Scope::Root)
        .expect("exact home directory")
        .allow(&home, Operation::Write, Scope::Root)
        .expect("exact home directory")
        // Read beside write at file scope, which is how `base.toml` grants `/dev/null`. The write
        // cell renders no metadata rule of its own, so without the read the probe cannot stat its
        // own target and every verdict below would be about an unreadable path.
        .allow(&granted_file, Operation::Read, Scope::File)
        .expect("one readable file")
        .allow(&granted_file, Operation::Write, Scope::File)
        .expect("one writable file")
        .set_network(Network::localhost().connect(43126))
        .expect("exact proxy port");
    let config_path = root.join("containment.json");
    std::fs::write(&config_path, config.to_json().expect("config JSON")).expect("write config");

    let output = Command::new(&probe)
        .arg(&config_path)
        .arg(format!(
            "expect-ok:write-open-modes:{}",
            granted_file.display()
        ))
        .arg(format!("expect-deny:chmod-mode:{}", granted_file.display()))
        .arg(format!("expect-deny:chown-self:{}", granted_file.display()))
        .arg(format!("expect-deny:acl:{}", granted_file.display()))
        .arg(format!(
            "expect-deny:create-over:{}",
            granted_file.display()
        ))
        .arg(format!("expect-deny:unlink:{}", granted_file.display()))
        .current_dir(&root)
        .output()
        .expect("spawn containment-test-probe");

    assert_eq!(
        output.status.code(),
        Some(0),
        "every probe must behave as demanded: stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    // The filesystem agrees, and it answers the identity question the probe cannot: a path that is
    // still a regular file with the mode and group it started with was neither replaced nor
    // re-permissioned.
    let after = std::fs::symlink_metadata(&granted_file).expect("the file must survive");
    assert!(
        after.file_type().is_file(),
        "{} is no longer a regular file, so it was replaced",
        granted_file.display()
    );
    assert_eq!(
        after.mode(),
        mode_before,
        "{} changed mode, so the mode deny did not hold",
        granted_file.display()
    );
    assert_eq!(
        after.gid(),
        group_before,
        "{} changed group, so the owner deny did not hold",
        granted_file.display()
    );
}

/// A second name for the home reaches the same refusal as the first.
///
/// The write cells render one rule set on the home's resolved identity, and three denies subtract
/// from it. macOS gives one directory more than one absolute name, and none of the extra names is a
/// symbolic link that `canonicalize` collapses:
///
/// - The firmlink twin under `/System/Volumes/Data`, which reaches the Data volume directly.
/// - An upper-case spelling, which a case-insensitive volume resolves to the same object.
/// - A spelling that leaves the directory through `..` and comes back.
/// - A trailing separator.
///
/// **The permitted probe carries as much of the assertion as the refused ones.** A grant that
/// matched only the canonical spelling would also refuse the write, and the box would be broken
/// rather than protected. So each spelling writes first and is refused after.
///
/// Two spellings depend on the host and are skipped rather than failed. An absent path answers
/// `ENOENT`, and `rmdir_probe` reports an absent directory as removed — so a skipped row is the
/// difference between measuring nothing and passing for the wrong reason.
#[test]
fn a_second_name_for_the_home_reaches_the_same_refusal() {
    let (_fixtures, home, config_path) = probe_box();
    let display = home.display().to_string();

    let mut spellings: Vec<(&str, String)> = vec![
        ("the resolved identity", display.clone()),
        ("a trailing separator", format!("{display}/")),
        (
            "a return through the parent",
            format!(
                "{display}/../{}",
                home.file_name().unwrap().to_string_lossy()
            ),
        ),
    ];

    let firmlink = std::path::PathBuf::from(format!("/System/Volumes/Data{display}"));
    if firmlink.symlink_metadata().is_ok() {
        spellings.push(("the Data-volume firmlink", firmlink.display().to_string()));
    } else {
        eprintln!("skipping: this host has no {} firmlink", firmlink.display());
    }

    match upper_case_spelling(&home) {
        Some(upper) => spellings.push(("an upper-case spelling", upper.display().to_string())),
        None => {
            eprintln!("skipping: an upper-case name does not reach this home on this volume");
        }
    }

    for (what, spelling) in &spellings {
        let inside = format!("{spelling}/inner.txt");
        let output = run_probe(
            &config_path,
            &[
                format!("expect-ok:write:{inside}"),
                format!("expect-deny:chflags-uf:{inside}"),
                format!("expect-deny:rmdir:{spelling}"),
                format!("expect-deny:create-over:{spelling}"),
            ],
        );
        assert_eq!(
            output.status.code(),
            Some(0),
            "{what} ({spelling}) did not reach the home's own rules: stderr={}",
            String::from_utf8_lossy(&output.stderr)
        );
        // The filesystem agrees with the probe. A spelling that reached past the denies would
        // leave a link or a missing directory here.
        assert!(
            !home
                .symlink_metadata()
                .expect("the home must survive")
                .is_symlink(),
            "{what} replaced the home with a symbolic link"
        );
        assert!(home.is_dir(), "{what} removed the home");
    }
}

/// A second profile cannot widen the first.
///
/// `sandbox_init` is reachable from inside the box, so the box can ask for a profile of its own.
/// The probe asks for `(allow default)` and then reads a path no grant names.
///
/// **Both halves are needed.** A kernel that rejects the second profile and a kernel that accepts
/// one which widens nothing are both refusals of this route, and the read is what tells them apart
/// from a kernel that widened. The verb reports which one happened on stderr.
///
/// `/private/etc/hosts` is the ungranted target because every macOS host has it. The control run
/// reads it with no containment, so a missing or unreadable file fails loudly instead of passing.
#[test]
fn a_second_profile_cannot_widen_the_first() {
    let (_fixtures, _home, config_path) = probe_box();
    let ungranted = "/private/etc/hosts";

    let control = run_uncontained(&[format!("expect-ok:read-errno:{ungranted}")]);
    assert_eq!(
        control.status.code(),
        Some(0),
        "{ungranted} must be readable outside a box, or this measures nothing: stderr={}",
        String::from_utf8_lossy(&control.stderr)
    );

    let output = run_probe(
        &config_path,
        &[format!("expect-deny:sandbox-loosen:{ungranted}")],
    );
    assert_eq!(
        output.status.code(),
        Some(0),
        "a second profile widened the first: stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn privileged_mach_services_remain_denied() {
    let (_fixtures, _home, config_path) = probe_box();
    let services = [
        "com.apple.DiskArbitration.diskarbitrationd",
        "com.apple.system.opendirectoryd.api",
    ];

    let mut measured = 0;
    for service in services {
        let control = run_uncontained(&[format!("expect-ok:mach-lookup:{service}")]);
        if control.status.code() != Some(0) {
            eprintln!(
                "skipping: {service} answers nobody on this host, so it measures no rule: {}",
                String::from_utf8_lossy(&control.stderr)
            );
            continue;
        }
        let output = run_probe(
            &config_path,
            &[format!("expect-deny:mach-lookup:{service}")],
        );
        assert_eq!(
            output.status.code(),
            Some(0),
            "{service} answered inside the box, which is a route to a root daemon: stderr={}",
            String::from_utf8_lossy(&output.stderr)
        );
        measured += 1;
    }

    assert!(
        measured > 0,
        "no service answered its uncontained control, so this test measured nothing"
    );
}

#[test]
fn account_lookup_is_allowed_but_preferences_services_remain_denied() {
    let (_fixtures, _home, config_path) = probe_box();
    for (service, expected) in [
        ("com.apple.system.opendirectoryd.libinfo", "expect-ok"),
        ("com.apple.cfprefsd.agent", "expect-deny"),
        ("com.apple.cfprefsd.daemon", "expect-deny"),
    ] {
        let control = run_uncontained(&[format!("expect-ok:mach-lookup:{service}")]);
        assert_eq!(
            control.status.code(),
            Some(0),
            "{service} must answer outside containment: {}",
            String::from_utf8_lossy(&control.stderr)
        );
        let output = run_probe(&config_path, &[format!("{expected}:mach-lookup:{service}")]);
        assert_eq!(
            output.status.code(),
            Some(0),
            "{service} did not match {expected}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
}

/// A native image inside `home`, for the box to copy and then try to run.
///
/// **Planted from outside the box, and that is not a weakening of the measurement.** An exec grant
/// renders `file-read-metadata` and never `file-read*`, so the contained probe cannot read its own
/// image; and the workload holds `file-write*` over the whole home, so bytes it did not author are
/// bytes it could have authored. The probe still writes the file it executes, which is the half
/// write-xor-exec is about.
///
/// The probe binary rather than a script: a `#!` line names an interpreter the profile grants no
/// exec literal for, so a shell script would be refused for the wrong reason. Copying the bytes also
/// keeps the ad-hoc signature valid, so the uncontained control is not answered by code signing.
fn plant_seed(home: &Path) -> std::path::PathBuf {
    let seed = home.join("i1-seed.bin");
    std::fs::copy(env!("CARGO_BIN_EXE_containment-test-probe"), &seed).expect("seed image");
    seed
}

/// A file the box writes into its own home is not executable.
///
/// The profile renders one `process-exec` literal per grant, and the home is not one of them. So the
/// box writes a valid native image at a path it fully controls, and the kernel must refuse to run
/// it.
///
/// **The control is what makes the refusal mean the profile.** macOS refuses an image for its own
/// reasons — an unsigned or truncated file answers `EPERM` too — so the same route runs with no
/// containment first, and a control that cannot run skips rather than passing.
#[test]
fn a_file_written_in_the_home_cannot_be_executed() {
    let (_fixtures, home, config_path) = probe_box();
    let seed = plant_seed(&home);
    let (seed, outside, inside) = (
        seed.display(),
        home.join("i1-exec-control").display().to_string(),
        home.join("i1-exec-boxed").display().to_string(),
    );

    let control = run_uncontained(&[format!("expect-ok:exec-written:{seed}|{outside}")]);
    if control.status.code() != Some(0) {
        eprintln!(
            "skipping: a written copy does not run outside a box on this host, so a refusal inside \
             one measures no rule: {}",
            String::from_utf8_lossy(&control.stderr)
        );
        return;
    }

    let output = run_probe(
        &config_path,
        &[format!("expect-deny:exec-written:{seed}|{inside}")],
    );
    assert_eq!(
        output.status.code(),
        Some(0),
        "the box executed a file it wrote into its own home, so write-xor-exec does not hold for \
         the process-exec route: stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
}

/// A library the box writes into its own home cannot be loaded.
///
/// **This is the library-load leg of write-xor-exec, and it is the one that measures the profile.**
/// A plain `mmap(PROT_EXEC)` on a file is unavailable to an ordinary process here, so the sibling
/// test below measures the platform. `dlopen` runs through dyld, which does map executable — every
/// read-granted runtime root depends on that — so this asks whether the same load works from the
/// one tree the workload can write.
///
/// The seed is a system library the harness copies in, because `/usr/lib` is ungranted inside the
/// box. Most of that directory lives only in the dyld shared cache, so the candidates are tried in
/// turn and the first whose **uncontained** load succeeds is the one measured. None loading is a
/// skip, not a pass.
#[test]
fn a_library_written_in_the_home_cannot_be_loaded() {
    let (_fixtures, home, read_only, config_path) = probe_box_with_read_only_root();
    // Small, on-disk, and none is a dependency of this probe, so loading one changes nothing about
    // the process that measures it.
    let candidates = [
        "/usr/lib/libffi-trampolines.dylib",
        "/usr/lib/libobjc-trampolines.dylib",
        "/usr/lib/libRPAC.dylib",
    ];

    for candidate in candidates {
        if !Path::new(candidate).is_file() {
            continue;
        }
        let seed = home.join("i1-dylib-seed.dylib");
        std::fs::copy(candidate, &seed).expect("dylib seed");
        let library = read_only.join("library.dylib");
        std::fs::copy(candidate, &library).expect("read-only library");
        let seed = seed.display().to_string();
        let outside = home.join("i1-dlopen-control.dylib").display().to_string();
        let inside = home.join("i1-dlopen-boxed.dylib").display().to_string();

        let control = run_uncontained(&[format!("expect-ok:dlopen-written:{seed}|{outside}")]);
        if control.status.code() != Some(0) {
            eprintln!(
                "skipping {candidate}: a written copy does not load outside a box: {}",
                String::from_utf8_lossy(&control.stderr)
            );
            let _ = std::fs::remove_file(&seed);
            continue;
        }

        let output = run_probe(
            &config_path,
            &[format!("expect-deny:dlopen-written:{seed}|{inside}")],
        );
        assert_eq!(
            output.status.code(),
            Some(0),
            "the box loaded a library it wrote into its own home, so write-xor-exec does not hold \
             for the library-load route: stderr={}",
            String::from_utf8_lossy(&output.stderr)
        );

        // **The bound, in the same profile.** The identical library in a read-only root must still
        // load: that is every runtime's stdlib, and a rule refusing it would be a refuse-all wearing
        // this test as cover. So the difference between the two runs is the cell, not the library.
        let bound = run_probe(
            &config_path,
            &[format!("expect-ok:dlopen:{}", library.display())],
        );
        assert_eq!(
            bound.status.code(),
            Some(0),
            "a read-only root must keep loading libraries, or the write cells' deny is refusing \
             every load rather than the writable ones: stderr={}",
            String::from_utf8_lossy(&bound.stderr)
        );
        return;
    }

    eprintln!(
        "skipping: no candidate library loaded from a written copy outside a box, so the \
         library-load route is unmeasured on this host"
    );
}

/// **A forward tripwire, and it pins nothing today.** It goes green whether or not the profile
/// refuses anything, because its uncontained control cannot map either.
///
/// A direct `mmap(PROT_READ|PROT_EXEC)` on a file is unavailable to an unentitled process on this
/// platform, so the route is closed above the profile and there is no rule here to measure. The
/// library-load leg that *is* measurable goes through dyld, and
/// `a_library_written_in_the_home_cannot_be_loaded` is that test.
///
/// It stays for one reason: if a later macOS returns the mapping authority to ordinary callers, the
/// control starts passing and this begins measuring the profile on the day that matters. Read a pass
/// here as "not measured", never as "refused", on the precedent the `SF_` flag class set.
#[test]
fn a_direct_executable_mapping_is_closed_above_the_profile() {
    let (_fixtures, home, config_path) = probe_box();
    let seed = plant_seed(&home);
    let (seed, outside, inside) = (
        seed.display(),
        home.join("i1-map-control").display().to_string(),
        home.join("i1-map-boxed").display().to_string(),
    );

    let control = run_uncontained(&[format!("expect-ok:map-exec:{seed}|{outside}")]);
    if control.status.code() != Some(0) {
        eprintln!(
            "NOT MEASURED: no process can map a file executable on this host, so the profile is not \
             what closes this route and there is no rule here to measure: {}",
            String::from_utf8_lossy(&control.stderr)
        );
        return;
    }

    // The control passed, so this platform hands the mapping authority to an ordinary caller and the
    // profile is now the only thing between the workload and code it wrote. The recorded
    // measurement has expired: re-measure the leg and record the new platform behaviour.
    let output = run_probe(
        &config_path,
        &[format!("expect-deny:map-exec:{seed}|{inside}")],
    );
    assert_eq!(
        output.status.code(),
        Some(0),
        "this host now permits a direct executable mapping, and the box mapped a file it wrote into \
         its own home: stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
}

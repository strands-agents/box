//! Pre-flight for the three cells CR 1 added: does `sandbox_init` accept the rendered rules on a
//! real Mac, and does the kernel honour them?
//!
//! Two launch shapes, both the ones the existing macOS suites use:
//!
//! - **Self-contained probe.** `containment-test-probe <config> <probe>...` reads the config, calls
//!   `Containment::apply` on itself, then runs each probe. Exit 3 means `apply` failed, which is the
//!   outcome this file exists to detect early. This shape measures `List` at `Root` and `Deny` at
//!   `File`, and proves every cell compiles.
//! - **Trampoline to `--exec-target`.** The trampoline applies the config and execs the probe in a
//!   mode that exits 0 and touches nothing. A zero exit means the exec rule admitted the program.
//!   This shape measures `Exec` at `Root`, with an ungranted control beside it.

#![cfg(target_os = "macos")]

use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

use containment::{ContainmentConfig, Network, Operation, Scope};
use sha2::{Digest as _, Sha256};

/// The fixture every test lays out under one canonical temporary root.
struct Fixture {
    root: tempfile::TempDir,
    tools: PathBuf,
    tools_probe: PathBuf,
    work: PathBuf,
    listed: PathBuf,
    secret: PathBuf,
    future: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let root = tempfile::tempdir().expect("a temporary directory");
        let base = root.path().canonicalize().expect("a canonical root");

        // The exec tree, disjoint from the write root so no write-plus-exec warning is involved.
        let tools = base.join("tools");
        std::fs::create_dir(&tools).expect("the tools directory");
        let tools_probe = tools.join("probe");
        std::fs::copy(
            PathBuf::from(env!("CARGO_BIN_EXE_containment-test-probe")),
            &tools_probe,
        )
        .expect("copy the probe into the exec tree");

        // The read-write root, holding a readable control, a denied existing file, and the name of
        // a denied file that does not exist yet.
        let work = base.join("work");
        std::fs::create_dir(&work).expect("the work directory");
        std::fs::write(work.join("readable.txt"), "readable").expect("the control file");
        let secret = work.join("secret.txt");
        std::fs::write(&secret, "secret").expect("the denied file");
        let future = work.join("future.txt");

        // The listed tree: enumerable, its file contents unreadable.
        let listed = base.join("listed");
        std::fs::create_dir(&listed).expect("the listed directory");
        std::fs::write(listed.join("file.txt"), "hidden").expect("a file inside the listed tree");

        Self {
            root,
            tools,
            tools_probe,
            work,
            listed,
            secret,
            future,
        }
    }

    /// Everything a probe needs to start and print, before any cell under test.
    fn baseline(&self) -> ContainmentConfig {
        ContainmentConfig::new()
            .allow(&self.work, Operation::Read, Scope::Root)
            .expect("read the work directory")
            .allow(&self.work, Operation::Write, Scope::Root)
            .expect("write the work directory")
            .allow(Path::new("/"), Operation::Read, Scope::Dir)
            .expect("the root's own entry")
            .allow(Path::new("/etc"), Operation::Metadata, Scope::Dir)
            .expect("the /etc entry")
            .allow(Path::new("/dev/null"), Operation::Read, Scope::File)
            .expect("read the null device")
            .allow(Path::new("/dev/null"), Operation::Write, Scope::File)
            .expect("write the null device")
            .set_network(Network::localhost().connect(43123))
            .expect("one proxy port")
    }

    /// Write `config` beside the fixture and return its path and digest.
    fn write_config(&self, config: &ContainmentConfig, name: &str) -> (PathBuf, String) {
        let config_json = config.to_json().expect("config JSON");
        let digest = Sha256::digest(config_json.as_bytes())
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        let config_path = self.root.path().join(name);
        std::fs::write(&config_path, &config_json).expect("write the config");
        (config_path, digest)
    }

    /// The probe contains itself under `config`, then runs `probes`.
    fn self_contained(&self, config: &ContainmentConfig, probes: &[String]) -> Output {
        let (config_path, _) = self.write_config(config, "self-contained.json");
        Command::new(env!("CARGO_BIN_EXE_containment-test-probe"))
            .arg(&config_path)
            .args(probes)
            .current_dir(&self.work)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
            .expect("the probe starts")
    }

    /// The trampoline applies `config` and execs the copied probe in `--exec-target` mode.
    fn through_trampoline(&self, config: &ContainmentConfig) -> Output {
        let (config_path, digest) = self.write_config(config, "trampoline.json");
        Command::new(env!("CARGO_BIN_EXE_strands-box-contain-trampoline"))
            .arg("--config")
            .arg(&config_path)
            .arg("--config-sha256")
            .arg(digest)
            .arg("--target-env-json")
            .arg("{}")
            .arg("--")
            .arg(&self.tools_probe)
            .arg("--exec-target")
            .current_dir(&self.work)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
            .expect("the trampoline starts")
    }
}

fn s(path: &Path) -> String {
    path.display().to_string()
}

fn report(label: &str, output: &Output) -> String {
    format!(
        "{label}: status {:?}\n--- stdout ---\n{}\n--- stderr ---\n{}",
        output.status.code(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

/// Exec at Root: the probe is admitted only through its directory tree, and refused without it.
#[test]
fn exec_at_root_admits_a_program_granted_only_through_its_tree() {
    let f = Fixture::new();

    // The renderer requires one file-scoped exec grant in every profile, so the ORIGINAL probe is
    // granted at file scope in both arms below. Only the tree grant differs between them, so the
    // copied probe's admission is attributable to the tree alone.
    let granted = f
        .baseline()
        .allow(
            PathBuf::from(env!("CARGO_BIN_EXE_containment-test-probe")),
            Operation::Exec,
            Scope::File,
        )
        .expect("exec the original probe")
        .allow(&f.tools, Operation::Exec, Scope::Root)
        .expect("exec over the tools tree");
    let output = f.through_trampoline(&granted);
    let text = report("exec-at-root granted", &output);
    println!("{text}");
    assert_eq!(output.status.code(), Some(0), "{text}");

    // The control: the same profile with an unrelated exec grant instead, so the copied probe is
    // not admitted. A zero exit here would mean the tree grant was not what admitted it above.
    let control = f
        .baseline()
        .allow(
            PathBuf::from(env!("CARGO_BIN_EXE_containment-test-probe")),
            Operation::Exec,
            Scope::File,
        )
        .expect("exec the original probe, not the copy");
    let output = f.through_trampoline(&control);
    let text = report("exec-at-root control", &output);
    println!("{text}");
    assert_ne!(
        output.status.code(),
        Some(0),
        "the copied probe ran without an exec grant on its tree: {text}"
    );
}

/// List at Root and Deny at File, applied by the probe on itself.
#[test]
fn list_at_root_and_deny_at_file_apply_and_hold() {
    let f = Fixture::new();
    let config = f
        .baseline()
        .allow(
            PathBuf::from(env!("CARGO_BIN_EXE_containment-test-probe")),
            Operation::Exec,
            Scope::File,
        )
        .expect("exec the probe")
        .allow(&f.listed, Operation::List, Scope::Root)
        .expect("list the listed tree")
        .refuse(&f.secret, Scope::File)
        .expect("refuse the existing file")
        .refuse(&f.future, Scope::File)
        .expect("refuse the file that does not exist yet");
    let probes = vec![
        format!("expect-ok:write:{}", s(&f.work.join("out.txt"))),
        format!("expect-ok:read:{}", s(&f.work.join("readable.txt"))),
        format!("expect-ok:list:{}", s(&f.listed)),
        format!("expect-deny:read:{}", s(&f.listed.join("file.txt"))),
        format!("expect-deny:read:{}", s(&f.secret)),
        format!("expect-deny:write:{}", s(&f.secret)),
        format!("expect-deny:write:{}", s(&f.future)),
    ];
    let output = f.self_contained(&config, &probes);
    let text = report("list-and-deny-file", &output);
    println!("{text}");
    assert_eq!(output.status.code(), Some(0), "{text}");
}

/// All three cells in one profile, the shape CR 2 will produce for a tool: the command at file
/// scope, a toolchain tree at root scope, a listed tree, and two file denials.
#[test]
fn all_three_cells_compose_in_one_profile() {
    let f = Fixture::new();
    let config = f
        .baseline()
        .allow(
            PathBuf::from(env!("CARGO_BIN_EXE_containment-test-probe")),
            Operation::Exec,
            Scope::File,
        )
        .expect("exec the original probe")
        .allow(&f.tools, Operation::Exec, Scope::Root)
        .expect("exec over the tools tree")
        .allow(&f.listed, Operation::List, Scope::Root)
        .expect("list the listed tree")
        .refuse(&f.secret, Scope::File)
        .expect("refuse the existing file")
        .refuse(&f.future, Scope::File)
        .expect("refuse the file that does not exist yet");
    let probes = vec![
        format!("expect-ok:write:{}", s(&f.work.join("out.txt"))),
        format!("expect-ok:list:{}", s(&f.listed)),
        format!("expect-deny:read:{}", s(&f.listed.join("file.txt"))),
        format!("expect-deny:read:{}", s(&f.secret)),
        format!("expect-deny:write:{}", s(&f.future)),
    ];
    let output = f.self_contained(&config, &probes);
    let text = report("all-three", &output);
    println!("{text}");
    assert_eq!(output.status.code(), Some(0), "{text}");
}

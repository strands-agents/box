//! Linux behavior for `strands-box-contain-trampoline`: real containment, at the kernel.
//!
//! On Linux, `Containment::apply` selects the namespace launcher on ARM64, contains the process,
//! and execs the target. `facade.rs::an_arm64_kernel_selects_the_namespace_launcher` pins the
//! selection.
//!
//! What is proven here is the trampoline's end of the contract — that the target is
//! born contained and that a setup failure never becomes a workload run. The
//! boundary's own properties (an ungranted path is unreachable, capabilities do not
//! survive, host processes are invisible) are asserted at the kernel in
//! `backend::linux::namespace`'s own tests, which is where the namespace exists.
#![cfg(target_os = "linux")]

use std::path::Path;
use std::process::Command;

use containment::{ContainmentConfig, Operation, Scope};
use sha2::{Digest as _, Sha256};

const IDENTITY_MARKER: &[u8] =
    b"STRANDS_BOX_CONTAIN_EXECUTABLE_IDENTITY_8E313B0F21A04D3BA52C4E87D493E6C2";

fn sha256_hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>()
}

/// Run `strands-box-contain-trampoline` with valid launch metadata -> (exit, stdout, stderr).
fn run_contained(
    config: &ContainmentConfig,
    work_dir: &Path,
    cmd: &[&str],
) -> (i32, String, String) {
    let config_json = config.to_json().expect("config json");
    let config_sha256 = sha256_hex(config_json.as_bytes());
    let config_file = tempfile::NamedTempFile::new().expect("config file");
    std::fs::write(config_file.path(), config_json).expect("write config");

    let exe = env!("CARGO_BIN_EXE_strands-box-contain-trampoline");
    let out = Command::new(exe)
        .current_dir(work_dir)
        .arg("--config")
        .arg(config_file.path())
        .arg("--config-sha256")
        .arg(config_sha256)
        .arg("--target-env-json")
        .arg("{}")
        .arg("--")
        .args(cmd)
        .output()
        .expect("spawn strands-box-contain-trampoline");
    (
        out.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

#[test]
fn binary_contains_the_expected_identity_marker() {
    let bytes = std::fs::read(env!("CARGO_BIN_EXE_strands-box-contain-trampoline"))
        .expect("read strands-box-contain-trampoline");
    assert!(
        bytes
            .windows(IDENTITY_MARKER.len())
            .any(|window| window == IDENTITY_MARKER),
        "strands-box-contain-trampoline binary must carry the exact executable identity marker"
    );
}

#[test]
fn replaced_config_digest_mismatch_precedes_linux_refusal_and_target_exec() {
    let work_dir = tempfile::tempdir().expect("work directory");
    let config_file = work_dir.path().join("config.json");
    let authorized = ContainmentConfig::new()
        .to_json()
        .expect("authorized config");
    let authorized_digest = sha256_hex(authorized.as_bytes());
    std::fs::write(&config_file, authorized).expect("write authorized config");

    // Replacement must be detected before UTF-8/config parsing and before the
    // platform refusal path.
    std::fs::write(&config_file, b"{ replacement is not valid config JSON")
        .expect("replace config");
    let out = Command::new(env!("CARGO_BIN_EXE_strands-box-contain-trampoline"))
        .arg("--config")
        .arg(&config_file)
        .arg("--config-sha256")
        .arg(authorized_digest)
        .arg("--target-env-json")
        .arg("{}")
        .arg("--")
        .args(["/bin/sh", "-c", "echo TARGET_RAN"])
        .output()
        .expect("spawn strands-box-contain-trampoline");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);

    assert_eq!(out.status.code(), Some(2));
    assert!(
        stderr.contains("digest mismatch"),
        "replacement must fail digest verification first; stderr:\n{stderr}"
    );
    assert!(
        !stdout.contains("TARGET_RAN"),
        "target ran after config replacement; stdout:\n{stdout}"
    );
}

/// A granted, dynamically linked target runs contained, and its output proves it
/// reached `exec` rather than being refused.
///
/// This is the trampoline's whole contract in one assertion: apply succeeded, so the
/// target was exec'd, and it was exec'd *inside* the boundary — which is why the
/// grant has to name the interpreter's dependencies too. `/bin/sh` needs its ELF
/// interpreter and libc, and the mount view plans those from the executable grant
/// rather than from a library directory.
#[test]
fn a_granted_target_runs_contained() {
    if !the_host_can_build_a_view() {
        println!("skipping: this host cannot build a namespace mount view");
        return;
    }

    let work_dir = tempfile::tempdir().expect("work directory");

    // A read grant beside the exec grant: a shell reads scripts and its own startup files, and the
    // launcher plans a read-only bind for either cell.
    let config = ContainmentConfig::new()
        .allow("/bin/sh", Operation::Read, Scope::File)
        .expect("read the shell")
        .allow("/bin/sh", Operation::Exec, Scope::File)
        .expect("grant the shell")
        .allow(work_dir.path(), Operation::Read, Scope::Root)
        .expect("grant the working directory")
        .allow(work_dir.path(), Operation::Write, Scope::Root)
        .expect("grant the working directory");

    let (code, stdout, stderr) = run_contained(
        &config,
        work_dir.path(),
        &["/bin/sh", "-c", "echo TARGET_RAN"],
    );

    assert!(
        stdout.contains("TARGET_RAN"),
        "a granted target must run contained (exit {code}); stderr:\n{stderr}"
    );
    assert_eq!(code, 0, "the target's own exit status must propagate");
}

/// An UNGRANTED target is not reachable, and the failure is an exec failure rather
/// than a workload run.
///
/// The distinction matters: exit 4 is "containment succeeded, exec did not", which
/// is the trampoline reporting that the boundary held. A zero exit with output would
/// mean the target ran outside the view.
#[test]
fn an_ungranted_target_cannot_be_reached() {
    if !the_host_can_build_a_view() {
        println!("skipping: this host cannot build a namespace mount view");
        return;
    }

    let work_dir = tempfile::tempdir().expect("work directory");
    // No grant for `/bin/sh`, so it is absent from the mount view entirely.
    let config = ContainmentConfig::new()
        .allow(work_dir.path(), Operation::Read, Scope::Root)
        .expect("grant the working directory");

    let (code, stdout, stderr) = run_contained(
        &config,
        work_dir.path(),
        &["/bin/sh", "-c", "echo TARGET_RAN"],
    );

    assert!(
        !stdout.contains("TARGET_RAN"),
        "FAIL-OPEN: an ungranted target ran; stdout:\n{stdout}"
    );
    assert_eq!(
        code, 4,
        "an ungranted target must fail at exec *after* containment (exit 4), which \
         is the trampoline reporting the boundary held; stderr:\n{stderr}"
    );
}

/// Whether this host lets the launcher build a mount view at all.
///
/// This used to measure `unshare(CLONE_NEWUSER)` alone, mirroring the backend's own
/// probe. That question is too narrow: a host can permit the user namespace and still
/// refuse the fresh `/proc` every view needs. The build fleet is such a host — on
/// kernel 5.4 the kernel refuses a nested procfs when the caller's own `/proc` carries
/// masked submounts — so the launcher failed there with `mounting a fresh proc …
/// Operation not permitted` and the reaper exited 127, while the weak probe reported
/// the host as usable.
///
/// The probe forks twice for the same reason the launcher does: `unshare(CLONE_NEWPID)`
/// places this process's *children* in the new PID namespace and not this process, and
/// the kernel refuses a procfs for a PID namespace the caller is not in. Mounting in
/// the first child would report `EPERM` on every host and skip these tests everywhere.
///
/// The same measurement exists twice more — in the backend's own unit tests and in
/// `box`'s test fixture. Each copy is forced by a module boundary rather than chosen:
/// an integration test cannot reach a private module, and `box` is another crate.
fn the_host_can_build_a_view() -> bool {
    // SAFETY: the child makes syscalls and `_exit`s only. It allocates nothing,
    // formats nothing, and never returns into test-harness code.
    let child = unsafe { libc::fork() };
    if child < 0 {
        // Unmeasurable rather than refused. Let the test run and report its own
        // failure instead of skipping on a probe that never happened.
        return true;
    }

    if child == 0 {
        // SAFETY: syscall-only child.
        unsafe {
            let namespaces = libc::CLONE_NEWUSER | libc::CLONE_NEWNS | libc::CLONE_NEWPID;
            if libc::unshare(namespaces) != 0 {
                libc::_exit(10);
            }
            let inner = libc::fork();
            if inner < 0 {
                libc::_exit(12);
            }
            if inner == 0 {
                let fstype = c"proc".as_ptr();
                let target = c"/proc".as_ptr();
                if libc::mount(fstype, target, fstype, 0, std::ptr::null()) != 0 {
                    libc::_exit(11);
                }
                libc::_exit(0);
            }
            let mut inner_status = 0;
            libc::waitpid(inner, &mut inner_status, 0);
            let mounted = libc::WIFEXITED(inner_status) && libc::WEXITSTATUS(inner_status) == 0;
            libc::_exit(if mounted { 0 } else { 11 });
        }
    }

    let mut status = 0;
    // SAFETY: waiting on this process's own child.
    unsafe { libc::waitpid(child, &mut status, 0) };
    libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0
}

/// A virtualenv-shaped chain whose program is a copy of `readlink`: `venv/bin/p → p3`,
/// `venv/bin/p3 → <prefix>/bin/p3`, `<prefix>/bin/p3 → real`. Returns
/// `(fixtures, venv, route, real)`; the chain lives as long as `fixtures`.
fn readlink_chain() -> (
    tempfile::TempDir,
    std::path::PathBuf,
    std::path::PathBuf,
    std::path::PathBuf,
) {
    let directory = tempfile::tempdir().expect("chain fixtures");
    let root = directory.path().canonicalize().expect("canonical root");
    let prefix_bin = root.join("prefix/bin");
    let venv_bin = root.join("venv/bin");
    std::fs::create_dir_all(&prefix_bin).expect("prefix");
    std::fs::create_dir_all(&venv_bin).expect("venv");
    let readlink = ["/usr/bin/readlink", "/bin/readlink"]
        .iter()
        .map(Path::new)
        .find(|candidate| candidate.is_file())
        .expect("coreutils readlink");
    let real = prefix_bin.join("real");
    std::fs::copy(readlink, &real).expect("program");
    let middle = prefix_bin.join("p3");
    std::os::unix::fs::symlink("real", &middle).expect("hop 3");
    std::os::unix::fs::symlink(&middle, venv_bin.join("p3")).expect("hop 2");
    let route = venv_bin.join("p");
    std::os::unix::fs::symlink("p3", &route).expect("hop 1");
    (directory, root.join("venv"), route, real)
}

/// Exec `route`, with the working directory granted, and the venv tree too when given.
fn chain_config(route: &Path, work_dir: &Path, venv: Option<&Path>) -> ContainmentConfig {
    let mut config = ContainmentConfig::new()
        .allow(route, Operation::Exec, Scope::File)
        .expect("exec through the chain")
        .allow(work_dir, Operation::Read, Scope::Root)
        .expect("grant the working directory")
        .allow(work_dir, Operation::Write, Scope::Root)
        .expect("grant the working directory");
    if let Some(venv) = venv {
        config = config
            .allow(venv, Operation::Read, Scope::Root)
            .expect("read the venv");
    }
    config
}

/// **A program exec'd through a link chain runs as its identity** (#30 A2): `/proc/self/exe`, and
/// so the loader's `$ORIGIN`, name the file the closure walk resolved against.
#[test]
fn a_program_through_a_link_chain_runs_as_its_identity() {
    if !the_host_can_build_a_view() {
        println!("skipping: this host cannot build a namespace mount view");
        return;
    }
    let (_fixtures, _, route, real) = readlink_chain();
    let work_dir = tempfile::tempdir().expect("work directory");
    let config = chain_config(&route, work_dir.path(), None);
    let route_text = route.display().to_string();
    let (code, stdout, stderr) =
        run_contained(&config, work_dir.path(), &[&route_text, "/proc/self/exe"]);
    assert_eq!(code, 0, "stderr:\n{stderr}");
    assert_eq!(
        stdout.trim(),
        real.display().to_string(),
        "stderr:\n{stderr}"
    );
}

/// **A hop outside every grant is still in the view** (#30 A1): with the venv bound, its links come
/// from the host and the hop under the prefix is reproduced.
#[test]
fn a_link_chain_leaving_a_bound_tree_execs() {
    if !the_host_can_build_a_view() {
        println!("skipping: this host cannot build a namespace mount view");
        return;
    }
    let (_fixtures, venv, route, real) = readlink_chain();
    let work_dir = tempfile::tempdir().expect("work directory");
    let config = chain_config(&route, work_dir.path(), Some(&venv));
    let route_text = route.display().to_string();
    let (code, stdout, stderr) =
        run_contained(&config, work_dir.path(), &[&route_text, "/proc/self/exe"]);
    assert_eq!(code, 0, "stderr:\n{stderr}");
    assert_eq!(
        stdout.trim(),
        real.display().to_string(),
        "stderr:\n{stderr}"
    );
}

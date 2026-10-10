//! `ProcessInfoMode::AllowAll` on a host that masks `/proc`: the workload runs with the container's
//! procfs, and still cannot reach any process outside its own user namespace through it.
//!
//! These run only where the masked condition holds — a non-privileged container with the runtime's
//! default `/proc` masks and no capabilities, the situation of a Kata pod. `~/code/oss-box/bin/masked`
//! builds that environment locally. Everywhere else every test returns at its probe.
//!
//! Reach is tested by *opening*, because the kernel's access check is on open: `exec 3< file` and
//! `cd dir` are `/bin/sh` builtins, and the view grants nothing but the shell.
#![cfg(target_os = "linux")]

use std::io::Write as _;
use std::path::Path;
use std::process::{Child, Command, Output, Stdio};

use containment::{ContainmentConfig, Operation, ProcessInfoMode, Scope};
use sha2::{Digest as _, Sha256};

/// Whether this host masks `/proc` and refuses a fresh procfs in a user namespace, while still
/// allowing the namespaces themselves.
///
/// The same measurement exists in `box`'s test fixture: an integration test cannot share code with
/// another crate. It forks twice for the reason `the_host_can_build_a_view` documents: the kernel
/// refuses a procfs for a PID namespace the caller is not in.
fn masked_proc_host() -> bool {
    let table = std::fs::read_to_string("/proc/self/mounts").unwrap_or_default();
    let masked = table
        .lines()
        .filter_map(|line| line.split_whitespace().nth(1))
        .any(|point| point != "/proc" && Path::new(point).starts_with("/proc"));
    if !masked {
        return false;
    }
    // SAFETY: the child makes syscalls and `_exit`s only.
    let child = unsafe { libc::fork() };
    if child < 0 {
        return false;
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
                let refused = libc::mount(fstype, target, fstype, 0, std::ptr::null()) != 0
                    && std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM);
                libc::_exit(if refused { 0 } else { 11 });
            }
            let mut inner_status = 0;
            libc::waitpid(inner, &mut inner_status, 0);
            let refused = libc::WIFEXITED(inner_status) && libc::WEXITSTATUS(inner_status) == 0;
            libc::_exit(if refused { 0 } else { 11 });
        }
    }
    let mut status = 0;
    // SAFETY: waiting on this process's own child.
    unsafe { libc::waitpid(child, &mut status, 0) };
    libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0
}

macro_rules! needs_a_masked_host {
    () => {
        if !masked_proc_host() {
            eprintln!("SKIPPED: this host does not mask /proc, so this asserted nothing");
            return;
        }
    };
}

/// The shell, its working directory, and the container's `/proc`.
fn shared_proc_config(work_dir: &Path) -> ContainmentConfig {
    ContainmentConfig::new()
        .set_process_info_mode(ProcessInfoMode::AllowAll)
        .allow("/bin/sh", Operation::Read, Scope::File)
        .expect("read the shell")
        .allow("/bin/sh", Operation::Exec, Scope::File)
        .expect("grant the shell")
        .allow(work_dir, Operation::Read, Scope::Root)
        .expect("grant the working directory")
        .allow(work_dir, Operation::Write, Scope::Root)
        .expect("grant the working directory")
}

/// The trampoline, ready to run `script` under `/bin/sh` with a shared `/proc`. The returned
/// tempfile holds the config and must outlive the spawn.
fn trampoline(work_dir: &Path, script: &str) -> (Command, tempfile::NamedTempFile) {
    let config_json = shared_proc_config(work_dir).to_json().expect("config json");
    let digest = Sha256::digest(config_json.as_bytes())
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    let config_file = tempfile::NamedTempFile::new().expect("config file");
    std::fs::write(config_file.path(), config_json).expect("write config");
    let mut command = Command::new(env!("CARGO_BIN_EXE_strands-box-contain-trampoline"));
    command
        .current_dir(work_dir)
        .arg("--config")
        .arg(config_file.path())
        .arg("--config-sha256")
        .arg(digest)
        .arg("--")
        .args(["/bin/sh", "-c", script]);
    (command, config_file)
}

fn run_contained(work_dir: &Path, script: &str) -> Output {
    let (mut command, _config) = trampoline(work_dir, script);
    command.output().expect("spawn the trampoline")
}

fn spawn_contained(work_dir: &Path, script: &str) -> (Child, tempfile::NamedTempFile) {
    let (mut command, config) = trampoline(work_dir, script);
    let child = command
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn the trampoline");
    (child, config)
}

fn make_fifo(path: &Path) -> std::path::PathBuf {
    let made = std::ffi::CString::new(path.to_str().expect("utf-8 path")).expect("no NUL");
    // SAFETY: a NUL-terminated path and a mode.
    assert_eq!(unsafe { libc::mkfifo(made.as_ptr(), 0o600) }, 0, "mkfifo");
    path.to_path_buf()
}

fn stdout(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

/// `sh` that prints `LEAK:<what>` for every node of `/proc/$1` it can open, or `/proc/$1/root`
/// it can enter, and `LEAK:signal` if `kill -0` reaches the process.
const PROBE: &str = r#"p=$1
for f in environ mem fd/0 maps; do (exec 3< /proc/$p/$f) 2>/dev/null && echo LEAK:$f; done
(cd /proc/$p/root) 2>/dev/null && echo LEAK:root
(cd /proc/$p/cwd) 2>/dev/null && echo LEAK:cwd
kill -0 $p 2>/dev/null && echo LEAK:signal
echo DONE"#;

fn probe_script(pid: &str) -> String {
    format!("set -- {pid}\n{PROBE}")
}

#[test]
fn a_shared_proc_workload_runs_on_a_masked_host() {
    needs_a_masked_host!();
    let work_dir = tempfile::tempdir().expect("work directory");
    let out = run_contained(
        work_dir.path(),
        "echo RAN; (exec 3< /proc/self/status) && echo SELF",
    );
    assert!(out.status.success(), "{out:?}");
    assert!(
        stdout(&out).contains("RAN") && stdout(&out).contains("SELF"),
        "{out:?}"
    );
}

/// **The test process is the daemon's stand-in**: same uid, dumpable, outside the workload's user
/// namespace. The workload sees it in the shared `/proc` and reaches none of it.
#[test]
fn a_shared_proc_workload_cannot_reach_an_outside_same_uid_process() {
    needs_a_masked_host!();
    let work_dir = tempfile::tempdir().expect("work directory");
    let outside = std::process::id().to_string();
    let out = run_contained(
        work_dir.path(),
        &format!(
            "(exec 3< /proc/{outside}/status) && echo SEEN\n{}",
            probe_script(&outside)
        ),
    );
    let text = stdout(&out);
    assert!(
        text.contains("SEEN"),
        "the outside process must be visible to make this real: {out:?}"
    );
    assert!(text.contains("DONE") && !text.contains("LEAK"), "{out:?}");
}

/// **Residual pin**: an outside process's `cmdline` IS readable. If this fails, a kernel or design
/// change closed the residual: update the spec's residual section and the docs, do not reopen it.
#[test]
fn a_shared_proc_workload_reads_an_outside_cmdline_residual() {
    needs_a_masked_host!();
    let work_dir = tempfile::tempdir().expect("work directory");
    let outside = std::process::id();
    let out = run_contained(
        work_dir.path(),
        &format!("(exec 3< /proc/{outside}/cmdline) && echo READABLE"),
    );
    assert!(stdout(&out).contains("READABLE"), "{out:?}");
}

/// **The launcher outside the PID namespace is out of reach.** It shares the workload's user
/// namespace and keeps its capabilities, so the capability check refuses the capless workload.
/// Its PID reaches the script through a FIFO, because it is only known once the trampoline runs.
#[test]
fn the_launcher_outside_the_pid_namespace_cannot_be_reached() {
    needs_a_masked_host!();
    let work_dir = tempfile::tempdir().expect("work directory");
    let fifo = make_fifo(&work_dir.path().join("launcher.pid"));
    let script = format!(
        "read pid < {}\n{}",
        fifo.display(),
        PROBE.replace("p=$1", "p=$pid")
    );
    let (child, _config) = spawn_contained(work_dir.path(), &script);
    std::fs::OpenOptions::new()
        .write(true)
        .open(&fifo)
        .and_then(|mut writer| writeln!(writer, "{}", child.id()))
        .expect("hand the launcher's pid to the workload");
    let out = child.wait_with_output().expect("the trampoline exits");
    let text = stdout(&out);
    assert!(text.contains("DONE"), "{out:?}");
    assert!(!text.contains("LEAK"), "{out:?}");
}

/// **A second contained workload is out of reach**: its launcher lives in a sibling user namespace.
/// The probe targets the first *workload*, not its launcher (which the capability check protects
/// regardless): the first shell reads its own PID in the shared `/proc` and hands it over a FIFO.
#[test]
fn a_second_contained_workload_cannot_be_reached() {
    needs_a_masked_host!();
    let first_dir = tempfile::tempdir().expect("work directory");
    let pid_fifo = make_fifo(&first_dir.path().join("pid"));
    let hold = make_fifo(&first_dir.path().join("hold"));
    // The first workload publishes its PID, then blocks reading `hold` until the probe is done.
    let (mut first, _first_config) = spawn_contained(
        first_dir.path(),
        &format!(
            "read p _ < /proc/self/stat\necho $p > {}\nread x < {}",
            pid_fifo.display(),
            hold.display()
        ),
    );
    let first_workload = std::fs::read_to_string(&pid_fifo).expect("the first workload's pid");
    let first_workload = first_workload.trim();
    assert_ne!(
        first_workload,
        first.id().to_string(),
        "the probe must target the workload, not its launcher"
    );

    let second_dir = tempfile::tempdir().expect("work directory");
    let out = run_contained(second_dir.path(), &probe_script(first_workload));

    std::fs::OpenOptions::new()
        .write(true)
        .open(&hold)
        .and_then(|mut writer| writeln!(writer, "go"))
        .expect("release the first workload");
    let _ = first.wait();
    let text = stdout(&out);
    assert!(text.contains("DONE") && !text.contains("LEAK"), "{out:?}");
}

/// **Residual pin**: an outside process's `mountinfo` and `net/tcp` are readable,
/// and an outside same-uid process's `oom_score_adj` is writable (the value is written back
/// unchanged). If this fails, a kernel or design change closed the residual: update the spec's
/// residual section and the docs, do not reopen it.
#[test]
fn a_shared_proc_workload_reads_mounts_and_sockets_and_writes_oom_score_residual() {
    needs_a_masked_host!();
    let work_dir = tempfile::tempdir().expect("work directory");
    let outside = std::process::id();
    let out = run_contained(
        work_dir.path(),
        &format!(
            "(exec 3< /proc/{outside}/mountinfo) && echo MOUNTS\n\
             (exec 3< /proc/{outside}/net/tcp) && echo SOCKETS\n\
             read v < /proc/{outside}/oom_score_adj && echo $v > /proc/{outside}/oom_score_adj \
             && echo OOM"
        ),
    );
    let text = stdout(&out);
    for residual in ["MOUNTS", "SOCKETS", "OOM"] {
        assert!(text.contains(residual), "{residual}: {out:?}");
    }
}

/// **Residual pin**: `/proc` belongs to the container's PID namespace, so `/proc/<getpid()>` is not
/// the workload; only `/proc/self` is. A program that builds `/proc/<its pid>` paths reads the
/// wrong process or nothing.
#[test]
fn a_shared_proc_workload_finds_itself_only_at_proc_self_residual() {
    needs_a_masked_host!();
    let work_dir = tempfile::tempdir().expect("work directory");
    let out = run_contained(
        work_dir.path(),
        "read p _ < /proc/self/stat\n[ \"$p\" != \"$$\" ] && echo MISMATCH",
    );
    assert!(stdout(&out).contains("MISMATCH"), "{out:?}");
}

/// **Positive control for `PROBE`**: pointed at the workload itself, it must report what it can
/// open, or every "no LEAK" assertion above could pass on a probe that never opens anything.
#[test]
fn the_probe_reports_a_process_the_workload_can_reach() {
    needs_a_masked_host!();
    let work_dir = tempfile::tempdir().expect("work directory");
    let out = run_contained(work_dir.path(), &probe_script("self"));
    let text = stdout(&out);
    assert!(
        text.contains("LEAK:environ") && text.contains("LEAK:root"),
        "{out:?}"
    );
}

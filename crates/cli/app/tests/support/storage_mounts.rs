//! Boxy profiles with storage attached after all three process roles start.

use super::Scene;
use nix::libc;
use std::collections::BTreeSet;
use std::io::{Read as _, Seek as _, SeekFrom};
use std::os::fd::{AsRawFd as _, FromRawFd as _, OwnedFd};
use std::os::unix::fs::PermissionsExt as _;
use std::os::unix::process::CommandExt as _;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::time::{Duration, Instant};

const ROOT: &str = "/mnt/boxy-storage";
const OUTPUT: &str = "/mnt/boxy-output";
const ROLES: [&str; 3] = ["agent", "tool", "server"];
const WAIT: Duration = Duration::from_secs(30);

#[test]
#[ignore = "requires native Linux namespaces, BOX_STORAGE_TEST_FUSE and BOX_STORAGE_TEST_PROBE"]
fn late_storage_preserves_agent_program_tool_and_local_server_permissions() {
    isolated(|| exercise(false));
}

#[test]
#[ignore = "requires native Linux namespaces, BOX_STORAGE_TEST_FUSE and BOX_STORAGE_TEST_PROBE"]
fn late_storage_stops_every_role_when_a_required_denial_cannot_compile() {
    isolated(|| exercise(true));
}

fn fixture(name: &str) -> PathBuf {
    let path = PathBuf::from(std::env::var_os(name).unwrap_or_else(|| panic!("set {name}")));
    assert!(
        path.is_absolute() && path.is_file(),
        "{name} must name an absolute fixture file"
    );
    path
}

fn isolated(body: impl FnOnce()) {
    const CHILD: &str = "BOXY_STORAGE_TEST_CHILD";
    let thread = std::thread::current();
    let name = thread.name().unwrap();
    if std::env::var(CHILD).as_deref() == Ok(name) {
        command(&["ip", "link", "set", "lo", "up"]);
        body();
        return;
    }
    fixture("BOX_STORAGE_TEST_FUSE");
    fixture("BOX_STORAGE_TEST_PROBE");
    let temporary = tempfile::tempdir().unwrap();
    let mut child = Process::start(
        Command::new("unshare")
            .args([
                "--user",
                "--map-root-user",
                "--mount",
                "--net",
                "--ipc",
                "--uts",
                "--pid",
                "--fork",
                "--kill-child",
                "--mount-proc",
                "--",
            ])
            .arg(std::env::current_exe().unwrap())
            .args([
                "--exact",
                name,
                "--nocapture",
                "--test-threads=1",
                "--include-ignored",
            ])
            .env(CHILD, name)
            .env("TMPDIR", temporary.path())
            .process_group(0),
    );
    child.wait(true, Duration::from_secs(90));
    let stdout = tail(&mut child.stdout);
    assert!(
        stdout.contains("1 passed; 0 failed; 0 ignored"),
        "selected test did not execute: {stdout}"
    );
    eprintln!("{}", tail(&mut child.stderr));
}

fn command(args: &[&str]) {
    let result = Command::new(args[0]).args(&args[1..]).output().unwrap();
    assert!(
        result.status.success(),
        "{args:?}: {}",
        String::from_utf8_lossy(&result.stderr)
    );
}

fn tail(file: &mut std::fs::File) -> String {
    let end = file.metadata().unwrap().len();
    file.seek(SeekFrom::Start(end.saturating_sub(24000)))
        .unwrap();
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes).unwrap();
    String::from_utf8_lossy(&bytes).into_owned()
}

struct Process {
    child: Child,
    stdout: std::fs::File,
    stderr: std::fs::File,
    finished: bool,
}

impl Process {
    fn start(command: &mut Command) -> Self {
        let stdout = tempfile::tempfile().unwrap();
        let stderr = tempfile::tempfile().unwrap();
        let child = command
            .stdin(Stdio::null())
            .stdout(Stdio::from(stdout.try_clone().unwrap()))
            .stderr(Stdio::from(stderr.try_clone().unwrap()))
            .spawn()
            .unwrap();
        Self {
            child,
            stdout,
            stderr,
            finished: false,
        }
    }

    fn running(&mut self) {
        if let Some(status) = self.child.try_wait().unwrap() {
            self.finished = true;
            panic!(
                "process exited early {status}; stdout: {}; stderr: {}",
                tail(&mut self.stdout),
                tail(&mut self.stderr)
            );
        }
    }

    fn wait(&mut self, success: bool, timeout: Duration) -> ExitStatus {
        let deadline = Instant::now() + timeout;
        loop {
            if let Some(status) = self.child.try_wait().unwrap() {
                self.finished = true;
                assert_eq!(
                    status.success(),
                    success,
                    "{status}; stdout: {}; stderr: {}",
                    tail(&mut self.stdout),
                    tail(&mut self.stderr)
                );
                return status;
            }
            assert!(
                Instant::now() < deadline,
                "process timed out; stdout: {}; stderr: {}",
                tail(&mut self.stdout),
                tail(&mut self.stderr)
            );
            std::thread::sleep(Duration::from_millis(5));
        }
    }
}

impl Drop for Process {
    fn drop(&mut self) {
        if !self.finished {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }
}

fn marker(path: &Path, process: &mut Process) -> serde_json::Value {
    let deadline = Instant::now() + WAIT;
    loop {
        let observed = std::fs::read(path);
        if let Ok(bytes) = &observed
            && let Ok(value) = serde_json::from_slice(bytes)
        {
            return value;
        }
        process.running();
        assert!(
            Instant::now() < deadline,
            "missing or incomplete {} ({observed:?}); stdout: {}; stderr: {}",
            path.display(),
            tail(&mut process.stdout),
            tail(&mut process.stderr)
        );
        std::thread::sleep(Duration::from_millis(5));
    }
}

fn assert_caps(receipt: &serde_json::Value) {
    assert_eq!(receipt["caps"]["checked"], true);
    assert_eq!(receipt["caps"]["zero"], true);
    assert_eq!(receipt["caps"]["no_new_privs"], true);
}

fn exercise(failure: bool) {
    command(&[
        "mount",
        "-t",
        "tmpfs",
        "-o",
        "nosuid,nodev,size=16m",
        "tmpfs",
        "/mnt",
    ]);
    command(&["mount", "--make-shared", "/mnt"]);
    let root = Path::new(ROOT);
    let output = Path::new(OUTPUT);
    std::fs::create_dir(root).unwrap();
    command(&[
        "mount",
        "-t",
        "tmpfs",
        "-o",
        "nosuid,nodev,size=16m",
        "tmpfs",
        ROOT,
    ]);
    std::fs::write(root.join("public"), b"WRONG UNDERLAY BYTES").unwrap();
    std::fs::write(root.join("underlay-marker"), b"must stay inaccessible").unwrap();
    for role in ROLES {
        assert!(
            !root.join(role).exists(),
            "required tool paths must be absent during translation"
        );
        std::fs::create_dir_all(output.join(role)).unwrap();
    }
    let scene = Scene::new();
    let bin = scene.outside().join("bin");
    let backing = scene.outside().join("backing");
    std::fs::create_dir(&bin).unwrap();
    std::fs::create_dir(&backing).unwrap();
    std::fs::write(backing.join("public"), b"captured-roles").unwrap();
    if !failure {
        std::fs::create_dir(backing.join("required-secret")).unwrap();
        std::fs::write(backing.join("required-secret/token"), b"always denied").unwrap();
    }
    for role in ROLES {
        std::fs::create_dir(backing.join(role)).unwrap();
        std::fs::write(backing.join(role).join("value"), format!("captured-{role}")).unwrap();
        let executable = bin.join(format!("storage-{role}"));
        std::fs::copy(fixture("BOX_STORAGE_TEST_PROBE"), &executable).unwrap();
        std::fs::set_permissions(executable, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
    let quote = |path: &Path| toml::Value::String(path.display().to_string()).to_string();
    let filesystem = |role: &str| {
        let denied: Vec<_> = ROLES
            .into_iter()
            .filter(|other| *other != role)
            .map(|other| quote(&root.join(other)))
            .chain(std::iter::once(quote(&root.join("required-secret"))))
            .collect();
        format!(
            "read = [\"/mnt\"]\nwrite = [{}, {}]\ndeny = [{}]\n",
            quote(&root.join(role)),
            quote(&output.join(role)),
            denied.join(", ")
        )
    };
    let mode = if failure { "-failure" } else { "" };
    scene.profile("storage", &format!(
        "[experimental-features]\nlinux-storage-mounts = true\n\
         [project]\naccess = \"none\"\n[agent]\ncommand = [{agent}, \"role-agent{mode}\", {output}, {root}]\n\
         [agent.filesystem]\nmounts = [{root}]\n{agent_fs}\n\
         [tool.storage_probe]\nprogram = \"storage-tool\"\n[tool.storage_probe.filesystem]\nmounts = [{root}]\n{tool_fs}\n\
         [mcp.storage_probe]\ntype = \"stdio\"\ncommand = [\"storage-server\", \"role-server{mode}\", {output}, {root}]\n\
         [mcp.storage_probe.filesystem]\nmounts = [{root}]\n{server_fs}",
        root=quote(root), output=quote(output), agent=quote(&bin.join("storage-agent")),
        agent_fs=filesystem("agent"), tool_fs=filesystem("tool"), server_fs=filesystem("server"),
    ), "permit(principal, action, resource);\n");
    let search = format!("{}:/usr/bin:/bin", bin.display());
    let mut workload = Process::start(
        scene
            .command_with(output, "storage", &["--no-banner"], &[])
            .env("PATH", search),
    );
    let mut pending = std::collections::BTreeMap::new();
    let mut identities = BTreeSet::new();
    for role in ROLES {
        let receipt = marker(&output.join(role).join("pending"), &mut workload);
        assert_eq!(receipt["role"], role);
        assert!(receipt["pending_checks"].as_u64().unwrap() >= 3);
        assert!(identities.insert(receipt["incarnation"].as_str().unwrap().to_owned()));
        assert_caps(&receipt);
        pending.insert(role, receipt);
    }
    let live = marker(&output.join("agent/all-live"), &mut workload);
    assert_eq!(live["mcp_initialized"], true);
    assert_eq!(live["mcp_listed"], true);
    assert_eq!(live["tool_running"], true);
    let monitoring = marker(&output.join("server/monitoring"), &mut workload);
    assert!(monitoring["checks"].as_u64().unwrap() >= 3);
    let processes = descendants(workload.child.id());
    let run = scene
        .runs()
        .into_iter()
        .find(|run| run.join("box.toml").is_file())
        .unwrap();
    let generated: toml::Table =
        toml::from_str(&std::fs::read_to_string(run.join("box.toml")).unwrap()).unwrap();
    for recipient in [
        &generated["agent"],
        &generated["tool"]["storage_probe"],
        &generated["mcp"]["storage_probe"],
    ] {
        assert_eq!(
            recipient["filesystem"]["mounts"],
            toml::Value::from(vec![ROOT])
        );
    }
    assert!(generated.get("storage").is_none());
    assert_eq!(
        generated["experimental-features"]["linux-storage-mounts"].as_bool(),
        Some(true)
    );
    assert!(
        generated["tool"]["storage_probe"]["filesystem"]["write"]
            .as_array()
            .unwrap()
            .contains(&toml::Value::String(format!("{ROOT}/tool")))
    );
    let mut source = Process::start(
        Command::new(fixture("BOX_STORAGE_TEST_FUSE"))
            .arg(&backing)
            .arg(root),
    );
    let deadline = Instant::now() + WAIT;
    while std::fs::read(root.join("public")).ok().as_deref() != Some(b"captured-roles") {
        source.running();
        assert!(Instant::now() < deadline, "FUSE source did not appear");
        std::thread::sleep(Duration::from_millis(5));
    }
    assert!(
        std::fs::read_to_string("/proc/self/mountinfo")
            .unwrap()
            .lines()
            .any(|line| line.split_whitespace().nth(4) == Some(ROOT)
                && line.contains(" - fuse.boxfixture "))
    );
    for role in ROLES {
        assert_eq!(
            std::fs::read(root.join(role).join("value")).unwrap(),
            format!("captured-{role}").as_bytes()
        );
        let path = root.join(role).join("outside-positive");
        std::fs::write(&path, b"provider permits writes").unwrap();
        assert_eq!(std::fs::read(path).unwrap(), b"provider permits writes");
    }
    if failure {
        workload.wait(false, Duration::from_secs(15));
        let stderr = tail(&mut workload.stderr);
        assert!(
            stderr.contains("required-secret") && stderr.contains("does not exist yet"),
            "expected original-rule failure: {stderr}"
        );
        for role in ROLES {
            assert!(!output.join(role).join("passed").exists());
            assert!(!output.join(role).join("unexpected-publication").exists());
            assert!(!backing.join(role).join("created").exists());
        }
    } else {
        let combined = marker(&output.join("agent/all-passed"), &mut workload);
        assert_eq!(combined["status"], "passed");
        for role in ROLES {
            let receipt = marker(&output.join(role).join("passed"), &mut workload);
            assert_eq!(receipt, combined[role]);
            assert_eq!(receipt["incarnation"], pending[role]["incarnation"]);
            assert_eq!(receipt["read"], true);
            assert_eq!(receipt["write"], true);
            assert_caps(&receipt);
            assert_eq!(
                std::fs::read(backing.join(role).join("created")).unwrap(),
                format!("written-by-{role}").as_bytes()
            );
            for other in ROLES.into_iter().filter(|other| *other != role) {
                assert_eq!(receipt["denied"][other]["read"], true);
                assert_eq!(receipt["denied"][other]["write"], true);
                assert!(
                    !backing
                        .join(other)
                        .join(format!("denied-from-{role}"))
                        .exists()
                );
            }
        }
        let final_processes = descendants(workload.child.id());
        std::fs::write(output.join("finish.pending"), b"all roles passed").unwrap();
        std::fs::rename(output.join("finish.pending"), output.join("finish")).unwrap();
        workload.wait(true, WAIT);
        require_exited(&final_processes);
        let joined: serde_json::Value =
            serde_json::from_slice(&std::fs::read(output.join("server/monitor-joined")).unwrap())
                .unwrap();
        assert_eq!(joined["joined"], true);
        eprintln!("Boxy late-storage roles: {combined}");
    }
    require_exited(&processes);
    command(&["umount", "-l", ROOT]);
    source.wait(true, WAIT);
    assert_eq!(
        std::fs::read(root.join("public")).unwrap(),
        b"WRONG UNDERLAY BYTES"
    );
    for role in ROLES {
        assert!(
            !root.join(role).exists(),
            "Boxy must not create the incoming role directories"
        );
    }
}

fn descendant_exited_after_scan(pid: u32, error: &std::io::Error) -> bool {
    match error.raw_os_error() {
        Some(libc::ESRCH) => true,
        Some(libc::EINVAL) => {
            // Linux can retain the PID reference after its task has been reaped. Require an
            // independent absence check so an invalid call never hides a live descendant.
            // SAFETY: signal zero checks existence without delivering a signal.
            let absent = unsafe { libc::kill(pid as libc::pid_t, 0) } == -1;
            absent && std::io::Error::last_os_error().raw_os_error() == Some(libc::ESRCH)
        }
        _ => false,
    }
}

#[test]
fn descendant_exit_race_accepts_a_reaped_child_but_never_a_live_child() {
    let mut child = Command::new("/bin/sleep")
        .arg("30")
        .spawn()
        .expect("start a child that remains alive until killed");
    let pid = child.id();
    let invalid = std::io::Error::from_raw_os_error(libc::EINVAL);
    let accepted_live_child = descendant_exited_after_scan(pid, &invalid);
    child.kill().expect("stop the test-owned child");
    child.wait().expect("reap the test-owned child");
    assert!(
        !accepted_live_child,
        "an invalid call must not hide a live child"
    );
    assert!(
        descendant_exited_after_scan(pid, &invalid),
        "the kernel can return EINVAL when its referenced PID has lost its task"
    );
    assert!(descendant_exited_after_scan(
        pid,
        &std::io::Error::from_raw_os_error(libc::ESRCH)
    ));
    assert!(!descendant_exited_after_scan(
        pid,
        &std::io::Error::from_raw_os_error(libc::EPERM)
    ));
}

fn descendants(parent: u32) -> Vec<OwnedFd> {
    let mut known = BTreeSet::from([parent]);
    loop {
        let before = known.len();
        for entry in std::fs::read_dir("/proc").unwrap().flatten() {
            let Ok(pid) = entry.file_name().to_string_lossy().parse::<u32>() else {
                continue;
            };
            let Ok(status) = std::fs::read_to_string(entry.path().join("status")) else {
                continue;
            };
            let ancestor = status.lines().find_map(|line| {
                line.strip_prefix("PPid:")
                    .and_then(|value| value.trim().parse::<u32>().ok())
            });
            if ancestor.is_some_and(|pid| known.contains(&pid)) {
                known.insert(pid);
            }
        }
        if known.len() == before {
            break;
        }
    }
    assert!(
        known.len() > 1,
        "the running Box must own a workload process"
    );
    known
        .into_iter()
        .filter_map(|pid| {
            // SAFETY: pidfd_open pins only a process observed in this test-owned Box tree.
            let descriptor = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) };
            if descriptor < 0 {
                let error = std::io::Error::last_os_error();
                assert!(
                    descendant_exited_after_scan(pid, &error),
                    "pin Box descendant {pid}: {error}"
                );
                // A completed staging child can be reaped between the process scan and pidfd_open.
                assert_ne!(
                    pid, parent,
                    "the Box owner must remain alive until the finish marker"
                );
                return None;
            }
            // SAFETY: pidfd_open returned a new owned descriptor.
            Some(unsafe { OwnedFd::from_raw_fd(descriptor as i32) })
        })
        .collect()
}

fn require_exited(processes: &[OwnedFd]) {
    let deadline = Instant::now() + WAIT;
    for process in processes {
        let mut event = libc::pollfd {
            fd: process.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        loop {
            let left = deadline.saturating_duration_since(Instant::now());
            assert!(
                !left.is_zero(),
                "a Box-owned process survived normal completion"
            );
            // SAFETY: the pidfd and one-element poll array remain live during the call.
            let ready = unsafe { libc::poll(&mut event, 1, left.as_millis() as i32) };
            if ready < 0 && std::io::Error::last_os_error().raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            assert!(
                ready > 0 && event.revents & libc::POLLIN != 0,
                "Box descendant exit was not observed"
            );
            break;
        }
    }
}

#[test]
#[ignore = "requires native Linux namespaces, BOX_STORAGE_TEST_FUSE and BOX_STORAGE_TEST_PROBE"]
fn late_storage_preserves_file_grants_execute_rules_and_write_denials() {
    isolated(|| exercise_files(false, false));
}

#[test]
#[ignore = "requires native Linux namespaces, BOX_STORAGE_TEST_FUSE and BOX_STORAGE_TEST_PROBE"]
fn late_storage_rejects_a_mutable_symbolic_link_as_a_write_denial() {
    isolated(|| exercise_files(true, false));
}

#[test]
#[ignore = "requires native Linux namespaces, BOX_STORAGE_TEST_FUSE and BOX_STORAGE_TEST_PROBE"]
fn late_storage_preserves_hosted_shell_and_monty_permissions_across_arrival() {
    isolated(|| exercise_files(false, true));
}

const HOSTED_SCRIPT: &str = r#"
set -eu
root=STORAGE_TEST_ROOT
control=STORAGE_TEST_CONTROL
if cat "$root/public" > /dev/null 2>&1; then exit 41; fi
if python3 -c "from pathlib import Path; Path('$root/public').read_text()" </dev/null > /dev/null 2>&1; then exit 42; fi
printf 'HOSTED_PENDING\n' > "$control/hosted-pending"
printf 'HOSTED_PENDING\n'
while ! cat "$root/writable/native-done" > /dev/null 2>&1; do sleep 0.01; done
cat "$root/files/read-only" > /dev/null
cat "$root/files/writable" > /dev/null
cat "$root/writable/frozen/value" > /dev/null
test -f "$root/files/read-only"
if test -f "$root/files/hidden"; then exit 45; fi
ls -1 "$root/files" > "$control/hosted-files"
for denied in "$root/files/hidden" "$root/visible/secret/token" "$root/writable/policy-denied"; do
  if cat "$denied" > /dev/null 2>&1; then printf 'unexpected hosted read: %s\n' "$denied" >&2; exit 43; fi
done
for denied in "$root/files/read-only" "$root/files/new" "$root/writable/frozen/value" "$root/writable/frozen/new" "$root/writable/policy-denied"; do
  if printf forbidden > "$denied" 2>/dev/null; then printf 'unexpected hosted write: %s\n' "$denied" >&2; exit 44; fi
done
printf 'sibling\n' > "$root/writable/sibling"
cat "$root/writable/sibling"
rm "$root/writable/sibling"
python3 -c "
from pathlib import Path
root = Path('$root')
assert (root / 'files/read-only').read_text() == 'captured:files/read-only\\n'
assert (root / 'files/writable').read_text() == 'written:file\\n'
assert (root / 'files/read-only').is_file()
assert not (root / 'files/hidden').exists()
assert sorted([str(path) for path in (root / 'files').iterdir()]) == [str(root / 'files/read-only'), str(root / 'files/writable')]
assert (root / 'writable/frozen/value').read_text() == 'captured:writable/frozen/value\\n'
(root / 'files/writable').write_text('written:file\\n')
(root / 'writable/monty-created').write_text('written:monty\\n')
assert (root / 'writable/monty-created').read_text() == 'written:monty\\n'
for relative in ['files/hidden', 'visible/secret/token', 'writable/policy-denied']:
    try:
        (root / relative).read_text()
    except OSError:
        pass
    else:
        raise AssertionError('unexpected Monty read: ' + relative)
for relative in ['files/read-only', 'files/new', 'writable/frozen/value', 'writable/frozen/new', 'writable/policy-denied']:
    try:
        (root / relative).write_text('forbidden')
    except OSError:
        pass
    else:
        raise AssertionError('unexpected Monty write: ' + relative)
print('MONTY_PASSED')
" </dev/null
printf 'HOSTED_PASSED\n'
"#;

fn exercise_files(aliased_denial: bool, hosted_shell: bool) {
    command(&[
        "mount",
        "-t",
        "tmpfs",
        "-o",
        "nosuid,nodev,size=16m",
        "tmpfs",
        "/mnt",
    ]);
    command(&["mount", "--make-shared", "/mnt"]);
    let root = Path::new(ROOT);
    let output = Path::new(OUTPUT);
    std::fs::create_dir(root).unwrap();
    std::fs::create_dir(output).unwrap();
    std::fs::create_dir("/mnt/placeholder-target").unwrap();
    command(&[
        "mount",
        "-t",
        "tmpfs",
        "-o",
        "nosuid,nodev,size=16m",
        "tmpfs",
        ROOT,
    ]);
    std::fs::write(root.join("public"), b"WRONG UNDERLAY\n").unwrap();
    std::os::unix::fs::symlink("/mnt/placeholder-target", root.join("alias")).unwrap();
    let scene = Scene::new();
    let control = scene.home().join("storage-control");
    std::fs::create_dir(&control).unwrap();
    let backing = scene.outside().join("backing");
    for directory in ["files", "visible/secret", "writable/frozen", "executables"] {
        std::fs::create_dir_all(backing.join(directory)).unwrap();
    }
    for file in [
        "public",
        "files/read-only",
        "files/writable",
        "files/hidden",
        "visible/secret/token",
        "writable/frozen/value",
        "writable/policy-denied",
    ] {
        std::fs::write(backing.join(file), format!("captured:{file}\n")).unwrap();
    }
    std::os::unix::fs::symlink("writable/frozen", backing.join("alias")).unwrap();
    for name in ["allowed", "blocked"] {
        let path = backing.join("executables").join(name);
        std::fs::copy("/bin/true", &path).unwrap();
        assert!(
            Command::new(&path).status().unwrap().success(),
            "source executable must run outside Box"
        );
    }
    let quote = |path: &Path| toml::Value::String(path.display().to_string()).to_string();
    let policy = if hosted_shell {
        format!(
            r#"permit(principal, action, resource);
@id("hosted_storage_read_deny") forbid(principal, action == Box::Action::"fs:read", resource) when {{ context.input.path == "{ROOT}/writable/policy-denied" }};
@id("hosted_storage_write_deny") forbid(principal, action == Box::Action::"fs:write", resource) when {{ context.input.path == "{ROOT}/writable/policy-denied" }};
"#
        )
    } else {
        "permit(principal, action, resource);\n".into()
    };
    scene.profile("storage-files", &format!(
        "[experimental-features]\nlinux-storage-mounts = true\n\
         [project]\naccess = \"none\"\n[agent]\ncommand = [\"/bin/bash\", \"--noprofile\", \"--norc\"]\n\
         [agent.filesystem]\nmounts = [{root}]\nread = [{output}, {control}, {public}, {writable}, {visible}, {executables}]\n\
         write = [{output}, {control}, {writable}]\nread_file = [{read_file}, {write_file}]\n\
         write_file = [{write_file}]\ndeny = [{secret}]\ndeny_write = [{alias}]\nexec = [{allowed}]\n",
        root=quote(root), output=quote(output), control=quote(&control), public=quote(&root.join("public")),
        writable=quote(&root.join("writable")), visible=quote(&root.join("visible")),
        executables=quote(&root.join("executables")), read_file=quote(&root.join("files/read-only")),
        write_file=quote(&root.join("files/writable")), secret=quote(&root.join("visible/secret")),
        alias=quote(&root.join(if aliased_denial { "alias" } else { "writable/frozen" })), allowed=quote(&root.join("executables/allowed")),
    ), &policy);
    let shell_word = |value: &str| format!("'{}'", value.replace(char::from(39), "'\\''"));
    let hosted_script = HOSTED_SCRIPT
        .replace("STORAGE_TEST_ROOT", &shell_word(ROOT))
        .replace(
            "STORAGE_TEST_CONTROL",
            &shell_word(control.to_str().unwrap()),
        );
    let script = r#"
set -eu
out=$1
root=$2
check_read() { IFS= read -r value < "$1" && [[ "$value" == "$2" ]]; }
deny_read() { if IFS= read -r value < "$1"; then printf 'unexpected read: %s\n' "$1" >&2; exit 31; fi; }
deny_write() { if printf 'forbidden\n' > "$1"; then printf 'unexpected write: %s\n' "$1" >&2; exit 32; fi; }
deny_read "$root/public"
if [[ "$3" == hosted ]]; then
  bash -c "$4" > "$out/hosted-status" 2> "$out/hosted-errors" &
  hosted_pid=$!
  while ! check_read "$5/hosted-pending" HOSTED_PENDING 2>/dev/null; do
    if [[ $SECONDS -ge 25 ]]; then
      while IFS= read -r line; do printf '%s\n' "$line" >&2; done < "$out/hosted-errors"
      exit 46
    fi
  done
fi
printf '{"pending":true}\n' > "$out/pending"
while ! check_read "$root/public" captured:public 2>/dev/null; do
  [[ $SECONDS -lt 30 ]] || exit 33
done
check_read "$root/files/read-only" captured:files/read-only
check_read "$root/files/writable" captured:files/writable
deny_read "$root/files/hidden"
deny_read "$root/visible/secret/token"
deny_write "$root/files/read-only"
deny_write "$root/files/new"
printf 'written:file\n' > "$root/files/writable"
check_read "$root/files/writable" written:file
printf 'written:directory\n' > "$root/writable/created"
check_read "$root/writable/created" written:directory
check_read "$root/writable/frozen/value" captured:writable/frozen/value
deny_write "$root/writable/frozen/value"
deny_write "$root/writable/frozen/new"
deny_write "$root/alias/value"
IFS= read -r -N 4 header < "$root/executables/blocked"
[[ "$header" == $'\x7fELF' ]]
"$root/executables/allowed"
if "$root/executables/blocked"; then
  printf 'unexpected execute\n' >&2
  exit 34
else
  [[ $? == 126 ]] || exit 36
fi
if [[ "$3" == hosted ]]; then
check_read "$root/writable/policy-denied" captured:writable/policy-denied
printf 'allowed:native\n' > "$root/writable/policy-denied"
check_read "$root/writable/policy-denied" allowed:native
printf 'native checks passed\n' > "$root/writable/native-done"
if ! wait "$hosted_pid"; then
  while IFS= read -r line; do printf '%s\n' "$line" >&2; done < "$out/hosted-errors"
  exit 47
fi
if bash -c "mv '$root' '${root}-moved'" 2> "$out/ancestor-error"; then
  printf 'unexpected ancestor move\n' >&2
  exit 35
fi
fi
printf '{"passed":true}\n' > "$out/passed"
"#;
    let mut workload = Process::start(&mut scene.command_with(
        output,
        "storage-files",
        &["--no-banner"],
        &[
            "-c",
            script,
            "storage-files",
            OUTPUT,
            ROOT,
            if hosted_shell { "hosted" } else { "native" },
            &hosted_script,
            control.to_str().unwrap(),
        ],
    ));
    let pending = match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        marker(&output.join("pending"), &mut workload)
    })) {
        Ok(pending) => pending,
        Err(error) => {
            for name in ["hosted-status", "hosted-errors"] {
                eprintln!("{name}: {:?}", std::fs::read_to_string(output.join(name)));
            }
            eprintln!(
                "hosted pending: {:?}",
                std::fs::read_to_string(control.join("hosted-pending"))
            );
            std::panic::resume_unwind(error)
        }
    };
    assert_eq!(pending["pending"], true);
    let processes = descendants(workload.child.id());
    let mut source = Process::start(
        Command::new(fixture("BOX_STORAGE_TEST_FUSE"))
            .arg(&backing)
            .arg(root),
    );
    let deadline = Instant::now() + WAIT;
    while std::fs::read(root.join("public")).ok().as_deref() != Some(b"captured:public\n") {
        source.running();
        assert!(Instant::now() < deadline, "FUSE source did not appear");
        std::thread::sleep(Duration::from_millis(5));
    }
    if aliased_denial {
        workload.wait(false, Duration::from_secs(15));
        let error = tail(&mut workload.stderr);
        assert!(
            error.contains("is a symbolic link")
                && error.contains("deny_write")
                && error.contains("name /mnt/boxy-storage/writable/frozen instead"),
            "expected original Core denial validation: {error}"
        );
        assert!(!output.join("passed").exists());
        assert!(!backing.join("writable/created").exists());
        assert_eq!(
            std::fs::read(backing.join("files/writable")).unwrap(),
            b"captured:files/writable\n"
        );
        require_exited(&processes);
        command(&["umount", "-l", ROOT]);
        source.wait(true, WAIT);
        assert_eq!(
            std::fs::read(root.join("public")).unwrap(),
            b"WRONG UNDERLAY\n"
        );
        return;
    }
    assert_eq!(
        std::fs::read(root.join("files/hidden")).unwrap(),
        b"captured:files/hidden\n"
    );
    assert_eq!(
        std::fs::read(root.join("visible/secret/token")).unwrap(),
        b"captured:visible/secret/token\n"
    );
    for directory in ["files", "writable/frozen"] {
        std::fs::write(
            root.join(directory).join("outside-positive"),
            b"source-write",
        )
        .unwrap();
    }
    for name in ["allowed", "blocked"] {
        assert!(
            Command::new(root.join("executables").join(name))
                .status()
                .unwrap()
                .success()
        );
    }
    assert_eq!(
        marker(&output.join("passed"), &mut workload)["passed"],
        true
    );
    workload.wait(true, WAIT);
    require_exited(&processes);
    if hosted_shell {
        let ancestor_error = std::fs::read_to_string(output.join("ancestor-error")).unwrap();
        assert!(
            ancestor_error.contains("deny_write_parent_move_0"),
            "the generated rule must deny the ancestor move, not a filesystem error: {ancestor_error}"
        );
        let [run] = scene.runs().try_into().expect("one Boxy run");
        let decisions = super::decisions(&run);
        assert!(
            decisions
                .iter()
                .any(|(action, path, rule)| action == "fs:move"
                    && path == &format!("{ROOT}-moved")
                    && rule.contains("deny_write_parent_move_0")),
            "the ancestor denial needs an actual policy decision: {decisions:?}"
        );
        assert!(
            root.is_dir(),
            "the protected storage root must remain in place"
        );
        assert!(
            !Path::new(&format!("{ROOT}-moved")).exists(),
            "the refused move must not create its destination"
        );
        let listed = std::fs::read_to_string(control.join("hosted-files")).unwrap();
        let mut entries: Vec<_> = listed.lines().collect();
        entries.sort_unstable();
        assert_eq!(
            entries,
            ["read-only", "writable"],
            "hosted listing must expose only granted file names"
        );
        let hosted_status = std::fs::read_to_string(output.join("hosted-status")).unwrap();
        assert_eq!(
            hosted_status, "HOSTED_PENDING\nsibling\nMONTY_PASSED\nHOSTED_PASSED\n",
            "one hosted Shell must report pending, then complete both interpreters: {hosted_status}"
        );
        assert_eq!(
            std::fs::read(backing.join("writable/monty-created")).unwrap(),
            b"written:monty\n"
        );
        assert_eq!(
            std::fs::read(backing.join("writable/policy-denied")).unwrap(),
            b"allowed:native\n"
        );
        for (action, rule) in [
            ("fs:read", "hosted_storage_read_deny"),
            ("fs:write", "hosted_storage_write_deny"),
        ] {
            let count = decisions
                .iter()
                .filter(|(observed_action, path, observed_rule)| {
                    observed_action == action
                        && path == &format!("{ROOT}/writable/policy-denied")
                        && observed_rule == rule
                })
                .count();
            assert!(
                count >= 2,
                "Shell and Monty each need an explicit {rule} decision: {decisions:?}"
            );
        }
        assert!(!backing.join("writable/sibling").exists());
        assert!(!Path::new(&format!("{ROOT}-moved")).exists());
    }
    for (file, bytes) in [
        ("files/writable", b"written:file\n".as_slice()),
        ("writable/created", b"written:directory\n"),
        ("files/read-only", b"captured:files/read-only\n"),
        ("writable/frozen/value", b"captured:writable/frozen/value\n"),
    ] {
        assert_eq!(std::fs::read(backing.join(file)).unwrap(), bytes);
    }
    for file in ["files/new", "writable/frozen/new"] {
        assert!(!backing.join(file).exists());
    }
    command(&["umount", "-l", ROOT]);
    source.wait(true, WAIT);
    assert_eq!(
        std::fs::read(root.join("public")).unwrap(),
        b"WRONG UNDERLAY\n"
    );
    assert_eq!(
        std::fs::read_link(root.join("alias")).unwrap(),
        Path::new("/mnt/placeholder-target")
    );
}

#[test]
#[ignore = "requires native Linux namespaces, BOX_STORAGE_TEST_FUSE and BOX_STORAGE_TEST_PROBE"]
fn late_storage_stops_active_hosted_shell_and_monty_when_a_required_denial_cannot_compile() {
    isolated(exercise_hosted_failure);
}

const HOSTED_FAILURE_SHELL: &str = r#"
set -eu
root=STORAGE_TEST_ROOT
control=STORAGE_TEST_CONTROL
checks=0
acknowledged=0
while true; do
  if cat "$root/public" > /dev/null 2>&1; then
    printf 'unexpected read\n' > "$control/shell-publication"
    exit 61
  fi
  if printf forbidden > "$root/writable/value" 2>/dev/null; then
    printf 'unexpected write\n' > "$control/shell-write"
    exit 62
  fi
  if printf forbidden > "$root/writable/shell-created" 2>/dev/null; then
    printf 'unexpected write\n' > "$control/shell-write"
    exit 62
  fi
  checks=$((checks + 1))
  if test "$checks" -eq 3; then
    printf '{"interpreter":"shell","checks":3}\n' > "$control/shell-ready"
  fi
  if test "$checks" -ge 6 && test "$acknowledged" -eq 0 && test -f "$control/challenge"; then
    printf '{"interpreter":"shell","checks":%d,"challenge":true}\n' "$checks" > "$control/shell-active"
    acknowledged=1
  fi
  sleep 0.01
done
"#;

const HOSTED_FAILURE_MONTY: &str = r#"
from pathlib import Path
import time
root = Path(STORAGE_TEST_ROOT)
control = Path(STORAGE_TEST_CONTROL)
checks = 0
acknowledged = False
while True:
    try:
        (root / 'public').read_text()
    except OSError:
        pass
    else:
        (control / 'monty-publication').write_text('unexpected read\n')
        raise AssertionError('Monty exposed pending storage')
    for name in ['value', 'monty-created']:
        try:
            (root / 'writable' / name).write_text('forbidden')
        except OSError:
            pass
        else:
            (control / 'monty-write').write_text('unexpected write\n')
            raise AssertionError('Monty wrote pending storage')
    checks += 1
    if checks == 3:
        (control / 'monty-ready').write_text('{"interpreter":"monty","checks":3}\n')
    if checks >= 6 and not acknowledged and (control / 'challenge').is_file():
        (control / 'monty-active').write_text('{"interpreter":"monty","checks":' + str(checks) + ',"challenge":true}\n')
        acknowledged = True
    time.sleep(0.01)
"#;

fn exercise_hosted_failure() {
    command(&[
        "mount",
        "-t",
        "tmpfs",
        "-o",
        "nosuid,nodev,size=16m",
        "tmpfs",
        "/mnt",
    ]);
    command(&["mount", "--make-shared", "/mnt"]);
    let root = Path::new(ROOT);
    let output = Path::new(OUTPUT);
    std::fs::create_dir(root).unwrap();
    std::fs::create_dir(output).unwrap();
    command(&[
        "mount",
        "-t",
        "tmpfs",
        "-o",
        "nosuid,nodev,size=16m",
        "tmpfs",
        ROOT,
    ]);
    std::fs::create_dir(root.join("writable")).unwrap();
    std::fs::write(root.join("public"), b"WRONG UNDERLAY\n").unwrap();
    std::fs::write(root.join("writable/value"), b"UNCHANGED UNDERLAY\n").unwrap();
    let scene = Scene::new();
    let control = scene.home().join("hosted-failure-control");
    let backing = scene.outside().join("backing");
    std::fs::create_dir(&control).unwrap();
    std::fs::create_dir_all(backing.join("writable")).unwrap();
    std::fs::write(backing.join("public"), b"captured:public\n").unwrap();
    std::fs::write(backing.join("writable/value"), b"unchanged:source\n").unwrap();
    assert!(!root.join("required-secret").exists());
    assert!(!backing.join("required-secret").exists());
    let quote = |path: &Path| toml::Value::String(path.display().to_string()).to_string();
    scene.profile("storage-hosted-failure", &format!(
        "[experimental-features]\nlinux-storage-mounts = true\n\
         [project]\naccess = \"none\"\n[agent]\ncommand = [\"/bin/bash\", \"--noprofile\", \"--norc\"]\n\
         [agent.filesystem]\nmounts = [{root}]\nread = [{root}, {output}, {control}]\n\
         write = [{writable}, {output}, {control}]\ndeny = [{secret}]\n",
        root=quote(root), output=quote(output), control=quote(&control),
        writable=quote(&root.join("writable")), secret=quote(&root.join("required-secret")),
    ), "permit(principal, action, resource);\n");
    let shell_word = |value: &str| format!("'{}'", value.replace(char::from(39), "'\\''"));
    let shell_script = HOSTED_FAILURE_SHELL
        .replace("STORAGE_TEST_ROOT", &shell_word(ROOT))
        .replace(
            "STORAGE_TEST_CONTROL",
            &shell_word(control.to_str().unwrap()),
        );
    let monty_program = HOSTED_FAILURE_MONTY
        .replace("STORAGE_TEST_ROOT", &serde_json::to_string(ROOT).unwrap())
        .replace(
            "STORAGE_TEST_CONTROL",
            &serde_json::to_string(control.to_str().unwrap()).unwrap(),
        );
    let monty_script = format!("python3 -c {} </dev/null", shell_word(&monty_program));
    let agent_script = r#"
set -eu
out=$1
bash -c "$2" > "$out/shell-status" 2> "$out/shell-errors" &
shell_pid=$!
bash -c "$3" > "$out/monty-status" 2> "$out/monty-errors" &
monty_pid=$!
printf '{"launched":true,"shell_pid":%d,"monty_pid":%d}\n' "$shell_pid" "$monty_pid" > "$out/launched"
if wait -n "$shell_pid" "$monty_pid"; then status=0; else status=$?; fi
printf '{"unexpected_return":true,"status":%d}\n' "$status" > "$out/returned"
exit 63
"#;
    let mut workload = Process::start(&mut scene.command_with(
        output,
        "storage-hosted-failure",
        &["--no-banner"],
        &[
            "-c",
            agent_script,
            "storage-hosted-failure",
            OUTPUT,
            &shell_script,
            &monty_script,
        ],
    ));
    let launched = marker(&output.join("launched"), &mut workload);
    assert_eq!(launched["launched"], true);
    assert_ne!(launched["shell_pid"], launched["monty_pid"]);
    let active = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        for interpreter in ["shell", "monty"] {
            let ready = marker(&control.join(format!("{interpreter}-ready")), &mut workload);
            assert_eq!(ready["interpreter"], interpreter);
            assert_eq!(ready["checks"], 3);
        }
        std::fs::write(control.join("challenge"), b"continue pending checks\n").unwrap();
        ["shell", "monty"].map(|interpreter| {
            let active = marker(
                &control.join(format!("{interpreter}-active")),
                &mut workload,
            );
            assert_eq!(active["interpreter"], interpreter);
            assert!(active["checks"].as_u64().unwrap() >= 6);
            assert_eq!(active["challenge"], true);
            active
        })
    }));
    let active = match active {
        Ok(active) => active,
        Err(error) => {
            for name in [
                "shell-status",
                "shell-errors",
                "monty-status",
                "monty-errors",
            ] {
                eprintln!("{name}: {:?}", std::fs::read_to_string(output.join(name)));
            }
            std::panic::resume_unwind(error)
        }
    };
    workload.running();
    require_clean_hosted_policy(&workload, output);
    assert!(!output.join("returned").exists());
    let processes = descendants(workload.child.id());
    let [run] = scene.runs().try_into().expect("one Boxy run");
    let generated: toml::Table =
        toml::from_str(&std::fs::read_to_string(run.join("box.toml")).unwrap()).unwrap();
    assert!(
        generated["agent"]["filesystem"]["deny"]
            .as_array()
            .unwrap()
            .contains(&toml::Value::String(format!("{ROOT}/required-secret")))
    );
    let mut source = Process::start(
        Command::new(fixture("BOX_STORAGE_TEST_FUSE"))
            .arg(&backing)
            .arg(root),
    );
    let deadline = Instant::now() + WAIT;
    while std::fs::read(root.join("public")).ok().as_deref() != Some(b"captured:public\n") {
        source.running();
        assert!(Instant::now() < deadline, "FUSE source did not appear");
        std::thread::sleep(Duration::from_millis(5));
    }
    assert!(
        std::fs::read_to_string("/proc/self/mountinfo")
            .unwrap()
            .lines()
            .any(|line| line.split_whitespace().nth(4) == Some(ROOT)
                && line.contains(" - fuse.boxfixture "))
    );
    std::fs::write(
        root.join("writable/outside-positive"),
        b"provider permits writes",
    )
    .unwrap();
    assert_eq!(
        std::fs::read(root.join("writable/outside-positive")).unwrap(),
        b"provider permits writes"
    );
    assert!(!root.join("required-secret").exists());
    workload.wait(false, Duration::from_secs(15));
    let error = tail(&mut workload.stderr);
    assert!(
        error.contains(&format!("{ROOT}/required-secret")) && error.contains("does not exist yet"),
        "expected original required-denial compilation failure: {error}"
    );
    assert!(
        !error.contains("execution timeout exceeded"),
        "hosted timeout must not end the test: {error}"
    );
    require_exited(&processes);
    require_clean_hosted_policy(&workload, output);
    for interpreter in ["shell", "monty"] {
        for violation in ["publication", "write"] {
            assert!(!control.join(format!("{interpreter}-{violation}")).exists());
        }
        let errors = std::fs::read_to_string(output.join(format!("{interpreter}-errors"))).unwrap();
        assert!(
            !errors.contains("execution timeout exceeded"),
            "{interpreter} reached its own deadline: {errors}"
        );
        assert!(
            !backing
                .join(format!("writable/{interpreter}-created"))
                .exists()
        );
    }
    assert_eq!(
        std::fs::read(backing.join("public")).unwrap(),
        b"captured:public\n"
    );
    assert_eq!(
        std::fs::read(backing.join("writable/value")).unwrap(),
        b"unchanged:source\n"
    );
    eprintln!(
        "Boxy hosted admission failure: active={active:?}; descendants={}; error={error}",
        processes.len()
    );
    command(&["umount", "-l", ROOT]);
    source.wait(true, WAIT);
    assert_eq!(
        std::fs::read(root.join("public")).unwrap(),
        b"WRONG UNDERLAY\n"
    );
    assert_eq!(
        std::fs::read(root.join("writable/value")).unwrap(),
        b"UNCHANGED UNDERLAY\n"
    );
    for interpreter in ["shell", "monty"] {
        assert!(
            !root
                .join(format!("writable/{interpreter}-created"))
                .exists()
        );
    }
}

fn require_clean_hosted_policy(workload: &Process, output: &Path) {
    use std::io::BufRead as _;
    let logs = [
        (
            "Box stdout",
            std::fs::File::open(format!("/proc/self/fd/{}", workload.stdout.as_raw_fd())),
        ),
        (
            "Box stderr",
            std::fs::File::open(format!("/proc/self/fd/{}", workload.stderr.as_raw_fd())),
        ),
        (
            "Shell stdout",
            std::fs::File::open(output.join("shell-status")),
        ),
        (
            "Shell stderr",
            std::fs::File::open(output.join("shell-errors")),
        ),
        (
            "Monty stdout",
            std::fs::File::open(output.join("monty-status")),
        ),
        (
            "Monty stderr",
            std::fs::File::open(output.join("monty-errors")),
        ),
    ];
    for (label, file) in logs {
        for line in std::io::BufReader::new(file.unwrap()).lines() {
            let line = line.unwrap();
            assert!(
                !line.contains("policy: warn:")
                    && !line.contains("recursion limit reached")
                    && !line.contains("policy evaluation failed"),
                "{label} invalidates filesystem-denial attribution: {line}"
            );
        }
    }
}

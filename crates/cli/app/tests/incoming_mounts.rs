//! CLI profiles carry mount selections through a real `box run` for each process role.
//!
//! The publisher owns a private test namespace. Each real Box process starts without capabilities;
//! only the publisher mounts fixture filesystems. Pipes order startup and arrivals without sleeps.
#![cfg(target_os = "linux")]

use nix::libc;

include!("../../../box/tests/support/namespace_launcher.rs");

use std::ffi::CString;
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};

use serde_json::Value;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Process {
    Agent,
    Tool,
    Mcp,
}

impl Process {
    fn name(self) -> &'static str {
        match self {
            Self::Agent => "agent",
            Self::Tool => "tool",
            Self::Mcp => "mcp",
        }
    }

    fn table(self) -> &'static str {
        match self {
            Self::Agent => "[agent]",
            Self::Tool => "[tool.receiver]",
            Self::Mcp => "[mcp.receiver]",
        }
    }
}

fn mount(source: Option<&Path>, target: &Path, flags: libc::c_ulong) {
    let source = source.map(|path| CString::new(path.as_os_str().as_bytes()).unwrap());
    let target = CString::new(target.as_os_str().as_bytes()).unwrap();
    // SAFETY: both strings remain live; all mounts are inside the isolated publisher namespace.
    let result = unsafe {
        libc::mount(
            source
                .as_ref()
                .map_or(std::ptr::null(), |value| value.as_ptr()),
            target.as_ptr(),
            std::ptr::null(),
            flags,
            std::ptr::null(),
        )
    };
    assert_eq!(result, 0, "mount: {}", std::io::Error::last_os_error());
}

fn isolated(action: impl FnOnce(&Path)) {
    if !namespace_launcher_is_usable() {
        return;
    }
    // The parent removes fixture files only after the child mount namespace has exited.
    let directory = tempfile::Builder::new()
        .prefix("bx-mount")
        .tempdir_in("/var/tmp")
        .unwrap();
    // SAFETY: the child owns all namespace changes and exits without returning to the harness.
    let child = unsafe { libc::fork() };
    assert!(child >= 0);
    if child == 0 {
        // SAFETY: bound the fixture and preserve its real numeric identity in the publisher namespace.
        unsafe { libc::alarm(90) };
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let (uid, gid) = unsafe { (libc::getuid(), libc::getgid()) };
            assert_eq!(unsafe { libc::unshare(libc::CLONE_NEWUSER) }, 0);
            std::fs::write("/proc/self/setgroups", "deny").unwrap();
            std::fs::write("/proc/self/uid_map", format!("{uid} {uid} 1")).unwrap();
            std::fs::write("/proc/self/gid_map", format!("{gid} {gid} 1")).unwrap();
            assert_eq!(unsafe { libc::unshare(libc::CLONE_NEWNS) }, 0);
            mount(None, Path::new("/"), libc::MS_REC | libc::MS_PRIVATE);
            action(directory.path());
        }));
        // SAFETY: do not reenter the multithreaded test harness after fork.
        unsafe { libc::_exit(i32::from(result.is_err())) };
    }
    let mut status = 0;
    // SAFETY: wait only for this test's isolated child.
    assert_eq!(unsafe { libc::waitpid(child, &mut status, 0) }, child);
    directory
        .close()
        .expect("remove the fixture after namespace exit");
    assert!(
        libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0,
        "incoming-mount fixture status {status}"
    );
}

/// Clear publisher authority before the real Box executable starts.
fn drop_publisher_capabilities() -> std::io::Result<()> {
    #[repr(C)]
    struct Header {
        version: u32,
        pid: i32,
    }
    #[derive(Clone, Copy)]
    #[repr(C)]
    struct Data {
        effective: u32,
        permitted: u32,
        inheritable: u32,
    }
    let header = Header {
        version: 0x2008_0522,
        pid: 0,
    };
    let data = [Data {
        effective: 0,
        permitted: 0,
        inheritable: 0,
    }; 2];
    // SAFETY: prctl and capset operate only on the pre-exec child with correctly sized C structures.
    unsafe {
        for capability in 0..=40 {
            if libc::prctl(libc::PR_CAPBSET_DROP, capability, 0, 0, 0) != 0 {
                return Err(std::io::Error::last_os_error());
            }
        }
        if libc::prctl(
            libc::PR_CAP_AMBIENT,
            libc::PR_CAP_AMBIENT_CLEAR_ALL,
            0,
            0,
            0,
        ) != 0
            || libc::syscall(libc::SYS_capset, &header, data.as_ptr()) != 0
            || libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0
            || libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL, 0, 0, 0) != 0
        {
            return Err(std::io::Error::last_os_error());
        }
    }
    Ok(())
}

struct Publisher {
    directory: PathBuf,
    selected: PathBuf,
    other: PathBuf,
    payload: PathBuf,
    other_payload: PathBuf,
    nested: PathBuf,
    control: PathBuf,
    stderr: PathBuf,
    process: Process,
    receiving: bool,
}

impl Publisher {
    fn new(
        root: &Path,
        process: Process,
        restricted: bool,
        receiving: bool,
        covering_parent: bool,
    ) -> Self {
        let directory = root.to_path_buf();
        let source = root.join("source");
        let selected = source.join("selected");
        let other = source.join("other");
        let payload = root.join("payload");
        let other_payload = root.join("other-payload");
        let nested = root.join("nested");
        let bin = root.join("bin");
        let control = root.join("control");
        let home = root.join("home");
        let agent_home = home.join("agent");
        let workspace = root.join("workspace");
        for path in [
            &selected,
            &other,
            &payload,
            &other_payload,
            &nested,
            &bin,
            &control,
            &agent_home,
            &workspace,
        ] {
            std::fs::create_dir_all(path).unwrap();
        }
        if process == Process::Tool {
            for name in ["events", "release"] {
                let path = CString::new(control.join(name).as_os_str().as_bytes()).unwrap();
                // SAFETY: create a fixture-owned pipe with a live, terminated path.
                assert_eq!(unsafe { libc::mkfifo(path.as_ptr(), 0o600) }, 0);
            }
        }
        for path in [&selected, &other, &payload, &other_payload] {
            std::fs::create_dir(path.join("nested")).unwrap();
        }
        for path in [&selected, &other] {
            std::fs::write(path.join("initial"), "initial").unwrap();
        }
        for path in [&payload, &other_payload] {
            std::fs::write(path.join("value"), "arrived").unwrap();
            std::fs::copy("/bin/true", path.join("program")).unwrap();
        }
        std::fs::write(nested.join("value"), "nested").unwrap();
        mount(Some(&source), &source, libc::MS_BIND | libc::MS_REC);
        mount(None, &source, libc::MS_SHARED);
        for path in [&selected, &other] {
            mount(Some(path), path, libc::MS_BIND);
            mount(None, path, libc::MS_PRIVATE);
            mount(None, path, libc::MS_SHARED);
        }
        mount(Some(&payload), &payload, libc::MS_BIND);
        if restricted {
            mount(
                None,
                &payload,
                libc::MS_BIND | libc::MS_REMOUNT | libc::MS_RDONLY | libc::MS_NOEXEC,
            );
        }
        let python = Path::new("/usr/bin/python3").canonicalize().unwrap();
        let runtime = Command::new(&python)
            .args(["-I", "-c", "import json,sysconfig; print(json.dumps(sorted({sysconfig.get_path('stdlib'),sysconfig.get_path('platstdlib')})))"])
            .output().unwrap();
        assert!(runtime.status.success(), "inspect fixture Python libraries");
        let libraries: Vec<PathBuf> = serde_json::from_slice(&runtime.stdout).unwrap();
        let libraries: Vec<PathBuf> = libraries
            .into_iter()
            .map(|path| path.canonicalize().unwrap())
            .collect();
        let script = format!(
            "#!{}\n{}",
            python.display(),
            include_str!("../../../box/tests/support/incoming_mounts_probe.py")
        );
        for name in ["incoming-agent", "incoming-tool", "incoming-mcp"] {
            let path = bin.join(name);
            std::fs::write(&path, &script).unwrap();
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        let env = format!(
            "{{ HOME = {agent_home:?}, FIXTURE_ROLE = {:?}, FIXTURE_MODE = 'agent', FIXTURE_CONTROL = {control:?}, FIXTURE_SELECTED = {selected:?}, FIXTURE_OTHER = {other:?}, PYTHONDONTWRITEBYTECODE = '1' }}",
            process.name()
        );
        let agent_selection = if receiving {
            vec![if process == Process::Agent {
                &selected
            } else {
                &other
            }]
        } else {
            vec![]
        };
        let grants = if covering_parent {
            vec![source.clone()]
        } else {
            vec![selected.clone(), other.clone()]
        };
        let agent_read = [
            vec![bin.clone(), agent_home.clone()],
            grants.clone(),
            libraries.clone(),
        ]
        .concat();
        let agent_write = [vec![agent_home.clone()], grants.clone()].concat();
        let mut agent_exec = vec![python.clone()];
        agent_exec.extend(libraries.clone());
        agent_exec.extend(agent_selection.iter().map(|path| (*path).clone()));
        let leaf_read = [
            vec![bin.clone(), control.clone()],
            grants.clone(),
            libraries,
        ]
        .concat();
        let leaf_write = [grants.clone(), vec![control.clone()]].concat();
        let mut text = format!(
            "policies = ['policy.dw']\n[project]\naccess = 'none'\n\
             [agent]\ncommand = [{:?}]\nenv = {env}\n\
             [agent.filesystem]\nread = {agent_read:?}\n\
             read_file = [{python:?}]\nwrite = {agent_write:?}\nexec = {agent_exec:?}\n",
            bin.join("incoming-agent")
        );
        if receiving {
            text.push_str(&format!("receive_mounts = {agent_selection:?}\n"));
        }
        if process != Process::Agent {
            let table = if process == Process::Tool {
                "tool.receiver"
            } else {
                "mcp.receiver"
            };
            let leaf_env = env.replace(
                "FIXTURE_MODE = 'agent'",
                &format!("FIXTURE_MODE = '{}'", process.name()),
            );
            let kind = if process == Process::Mcp {
                "type = 'stdio'\n"
            } else {
                ""
            };
            text.push_str(&format!(
                "[{table}]\n{kind}command = [{:?}]\nenv = {leaf_env}\n\
                 [{table}.filesystem]\nread = {leaf_read:?}\n\
                 read_file = [{python:?}]\nwrite = {leaf_write:?}\nreceive_mounts = [{selected:?}]\n",
                bin.join(if process == Process::Tool {
                    "incoming-tool"
                } else {
                    "incoming-mcp"
                })
            ));
        }
        let profile = home.join(".strands/box/profiles/incoming");
        std::fs::create_dir_all(&profile).unwrap();
        let config = profile.join("profile.toml");
        std::fs::write(&config, text).unwrap();
        std::fs::write(
            profile.join("policy.dw"),
            "permit(principal, action, resource);",
        )
        .unwrap();
        let stderr = root.join("stderr");
        Self {
            directory,
            selected,
            other,
            payload,
            other_payload,
            nested,
            control,
            stderr,
            process,
            receiving,
        }
    }

    fn root_arrives(&self) {
        mount(
            Some(&self.payload),
            &self.selected,
            libc::MS_BIND | libc::MS_REC,
        );
        // Ordinary grants still require their requested rights on an unselected source.
        mount(
            Some(&self.other_payload),
            &self.other,
            libc::MS_BIND | libc::MS_REC,
        );
    }

    fn child_arrives(&self) {
        for path in [&self.selected, &self.other] {
            mount(Some(&self.nested), &path.join("nested"), libc::MS_BIND);
        }
    }

    fn start(&self) -> Run {
        let mut command = Command::new(env!("CARGO_BIN_EXE_box"));
        command
            .args(["run", "incoming"])
            .env("HOME", self.directory.as_path().join("home"))
            .env(
                "PATH",
                format!(
                    "{}:/usr/bin:/bin",
                    self.directory.as_path().join("bin").display()
                ),
            )
            .env_remove("EXPERIMENTAL_LINUX_SUPPORT")
            .env_remove("EXPERIMENTAL_X86_SUPPORT")
            .env("TMPDIR", "/var/tmp")
            .current_dir(self.directory.join("workspace"))
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(File::create(&self.stderr).unwrap());
        // SAFETY: the hook invokes only capability/parent-death syscalls in the spawned child.
        unsafe { command.pre_exec(drop_publisher_capabilities) };
        // The hosted Shell captures stdout; dedicated pipes keep tool stages synchronous.
        let tool_channels = (self.process == Process::Tool).then(|| {
            let open = |name| {
                OpenOptions::new()
                    .read(true)
                    .write(true)
                    .open(self.control.join(name))
                    .unwrap()
            };
            (BufReader::new(open("events")), open("release"))
        });
        let mut child = command.spawn().unwrap();
        let input = child.stdin.take().unwrap();
        let output = BufReader::new(child.stdout.take().unwrap());
        Run {
            child,
            input,
            output,
            stderr: self.stderr.clone(),
            tool_channels,
        }
    }

    fn assert_disclosure(&self, process: Process, path: &Path) {
        let text = std::fs::read_to_string(&self.stderr).unwrap();
        let prefix = format!("{} incoming mounts:", process.table());
        assert!(
            text.lines()
                .any(|line| line.contains(&prefix) && line.contains(path.to_str().unwrap())),
            "{text}"
        );
    }
}

struct Run {
    child: Child,
    input: ChildStdin,
    output: BufReader<ChildStdout>,
    stderr: PathBuf,
    tool_channels: Option<(BufReader<File>, File)>,
}

impl Run {
    fn stage(&mut self, expected: &str) -> Value {
        let mut line = String::new();
        let count = if expected.starts_with("receiver-") {
            match self.tool_channels.as_mut() {
                Some((events, _)) => events.read_line(&mut line).unwrap(),
                None => self.output.read_line(&mut line).unwrap(),
            }
        } else {
            self.output.read_line(&mut line).unwrap()
        };
        assert_ne!(
            count,
            0,
            "no {expected}: {}",
            std::fs::read_to_string(&self.stderr).unwrap()
        );
        let frame: Value =
            serde_json::from_str(&line).expect("workload emits one JSON frame per stage");
        assert_eq!(frame["stage"], expected, "{frame}");
        frame["result"].clone()
    }

    fn release(&mut self) {
        self.input.write_all(b"continue\n").unwrap();
        self.input.flush().unwrap();
    }

    fn release_receiver(&mut self) {
        if let Some((_, release)) = &mut self.tool_channels {
            release.write_all(b"continue\n").unwrap();
            release.flush().unwrap();
        } else {
            self.release();
        }
    }

    fn finish(&mut self) {
        let status = self.child.wait().unwrap();
        assert!(
            status.success(),
            "{status}: {}",
            std::fs::read_to_string(&self.stderr).unwrap()
        );
    }
}

impl Drop for Run {
    fn drop(&mut self) {
        if self.child.try_wait().unwrap().is_none() {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }
}

fn assert_snapshot(value: &Value, root: bool, nested: bool, other_root: bool, restricted: bool) {
    assert_eq!(
        value["root"],
        if root {
            Value::from("arrived")
        } else {
            Value::Null
        },
        "{value}"
    );
    assert_eq!(
        value["nested"],
        if nested {
            Value::from("nested")
        } else {
            Value::Null
        },
        "{value}"
    );
    assert_eq!(
        value["other_root"],
        if other_root {
            Value::from("arrived")
        } else {
            Value::Null
        },
        "{value}"
    );
    assert!(
        value["other_nested"].is_null(),
        "unselected directory received a mount: {value}"
    );
    assert_eq!(
        value["initial"],
        if root {
            Value::Null
        } else {
            Value::from("initial")
        },
        "{value}"
    );
    let (write, execute) = if !root {
        (libc::ENOENT, libc::ENOENT)
    } else if restricted {
        (libc::EROFS, libc::EPERM)
    } else {
        (0, 0)
    };
    assert_eq!(value["write_errno"], write, "{value}");
    assert_eq!(value["exec_errno"], execute, "{value}");
}

fn arrival_case(
    root: &Path,
    process: Process,
    before_receiver: bool,
    restricted: bool,
    receiving: bool,
) {
    println!(
        "incoming mounts: process={process:?}, before_receiver={before_receiver}, restricted={restricted}, receiving={receiving}"
    );
    let publisher = Publisher::new(root, process, restricted, receiving, !before_receiver);
    if before_receiver && process == Process::Agent {
        publisher.root_arrives();
    }
    let mut run = publisher.start();
    if process != Process::Agent {
        let before = run.stage("agent-ready");
        assert_snapshot(&before, false, false, false, restricted);
        if process == Process::Mcp {
            publisher.assert_disclosure(Process::Mcp, &publisher.selected);
        }
        if before_receiver {
            publisher.root_arrives();
        }
        run.release();
    }
    let before = run.stage("receiver-ready");
    assert_snapshot(&before, before_receiver, false, before_receiver, restricted);
    if !before_receiver {
        publisher.root_arrives();
    }
    publisher.child_arrives();
    run.release_receiver();
    let after = run.stage("receiver-done");
    assert_snapshot(
        &after,
        receiving || before_receiver,
        receiving,
        before_receiver,
        restricted,
    );
    if process != Process::Agent {
        let agent = run.stage("agent-done");
        assert_snapshot(&agent, true, true, false, false);
        publisher.assert_disclosure(Process::Agent, &publisher.other);
    }
    run.finish();
    if publisher.receiving {
        publisher.assert_disclosure(publisher.process, &publisher.selected);
    } else {
        assert!(
            !std::fs::read_to_string(&publisher.stderr)
                .unwrap()
                .contains("incoming mounts:")
        );
    }
    assert_eq!(
        std::fs::read_to_string(publisher.payload.join("value")).unwrap(),
        "arrived"
    );
}

#[test]
fn a_cli_agent_receives_mounts_and_keeps_the_publishers_restrictions() {
    for before in [false, true] {
        isolated(|root| arrival_case(root, Process::Agent, before, true, true));
    }
}

#[test]
fn a_cli_tool_uses_its_own_selection_before_and_after_storage_arrives() {
    for before in [false, true] {
        isolated(|root| arrival_case(root, Process::Tool, before, false, true));
    }
}

#[test]
fn a_cli_local_mcp_uses_its_own_selection_before_and_after_storage_arrives() {
    for before in [false, true] {
        isolated(|root| arrival_case(root, Process::Mcp, before, false, true));
    }
}

#[test]
fn a_cli_profile_without_selections_keeps_the_private_mount_view() {
    isolated(|root| arrival_case(root, Process::Agent, false, false, false));
}

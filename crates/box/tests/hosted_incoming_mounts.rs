//! Hosted Shell and Monty access incoming storage through normal public configuration and aliases.
#![cfg(target_os = "linux")]

#[path = "support/fixture.rs"]
mod fixture;

use serde_json::{Value, json};
use std::ffi::CString;
use std::fs::File;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};

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
    if !fixture::namespace_launcher_is_usable() {
        return;
    }
    // The parent removes fixture files only after the child mount namespace has exited.
    let directory = tempfile::Builder::new()
        .prefix("sb-hosted")
        .tempdir_in("/var/tmp")
        .unwrap();
    // SAFETY: the child owns all namespace changes and exits without returning to the harness.
    let child = unsafe { libc::fork() };
    assert!(child >= 0);
    if child == 0 {
        // SAFETY: bound the fixture and preserve its real numeric identity in the publisher namespace.
        unsafe { libc::alarm(180) };
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

#[derive(Clone, Copy)]
enum Selection {
    Agent,
    ToolOnly,
    Omitted,
}

struct Publisher {
    root: PathBuf,
    selected: PathBuf,
    other: PathBuf,
    payload: PathBuf,
    nested: PathBuf,
    replacement: PathBuf,
    config: PathBuf,
    stderr: PathBuf,
}

impl Publisher {
    fn new(root: &Path, selection: Selection) -> Self {
        let selected = root.join("source/selected");
        let other = root.join("source/other");
        let payload = root.join("payload");
        let nested = root.join("nested");
        let replacement = root.join("replacement");
        let bin = root.join("bin");
        let home = root.join("home");
        let agent_home = home.join("agent");
        let workspace = root.join("workspace");
        let state = home.join("state");
        for path in [
            &selected,
            &other,
            &payload,
            &nested,
            &replacement,
            &bin,
            &agent_home,
            &workspace,
            &state,
        ] {
            std::fs::create_dir_all(path).unwrap();
        }
        std::fs::set_permissions(&state, std::fs::Permissions::from_mode(0o700)).unwrap();
        for path in [&selected, &payload, &replacement] {
            std::fs::create_dir(path.join("nested")).unwrap();
        }
        for (path, value) in [
            (&selected, "initial"),
            (&other, "outside"),
            (&payload, "arrived"),
            (&nested, "nested"),
            (&replacement, "replacement"),
        ] {
            std::fs::write(path.join("value"), value).unwrap();
        }
        std::fs::write(payload.join("blocked"), "policy-denied").unwrap();
        for path in [&selected, &other] {
            mount(Some(path), path, libc::MS_BIND);
            mount(None, path, libc::MS_SHARED);
        }
        let python = Path::new("/usr/bin/python3").canonicalize().unwrap();
        let runtime = Command::new(&python)
            .args(["-I", "-c", "import json,sysconfig; print(json.dumps(sorted({sysconfig.get_path('stdlib'),sysconfig.get_path('platstdlib')})))"])
            .output().unwrap();
        assert!(runtime.status.success());
        let libraries: Vec<PathBuf> = serde_json::from_slice(&runtime.stdout).unwrap();
        let libraries: Vec<_> = libraries
            .into_iter()
            .map(|path| path.canonicalize().unwrap())
            .collect();
        let command = bin.join("hosted-mount-agent");
        std::fs::write(
            &command,
            format!(
                "#!{}\n{}",
                python.display(),
                include_str!("support/hosted_incoming_mounts_agent.py")
            ),
        )
        .unwrap();
        std::fs::set_permissions(&command, std::fs::Permissions::from_mode(0o755)).unwrap();
        let read = [
            vec![
                bin.clone(),
                agent_home.clone(),
                selected.clone(),
                other.clone(),
            ],
            libraries.clone(),
        ]
        .concat();
        let exec = [
            vec![python.clone(), selected.clone(), other.clone()],
            libraries,
        ]
        .concat();
        let receive = match selection {
            Selection::Agent => format!("receive_mounts = [{selected:?}]\n"),
            _ => String::new(),
        };
        let mut text = format!(
            "name = 'hosted-incoming'\nbox_dir = {state:?}\npolicy = 'policy.dw'\n\
             [agent]\ncommand = [{command:?}]\nworkspace = {workspace:?}\n\
             env = {{ HOME = {agent_home:?}, PYTHONDONTWRITEBYTECODE = '1' }}\n\
             [agent.filesystem]\nread = {read:?}\nread_file = [{python:?}]\n\
             write = [{agent_home:?}, {selected:?}, {other:?}]\nexec = {exec:?}\n{receive}"
        );
        if matches!(selection, Selection::ToolOnly) {
            text.push_str(&format!(
                "[tool.reader]\ncommand = ['/bin/true']\n\
                 [tool.reader.filesystem]\nread = [{selected:?}]\nwrite = [{selected:?}]\n\
                 receive_mounts = [{selected:?}]\n"
            ));
        }
        let config = workspace.join("box.toml");
        std::fs::write(&config, text).unwrap();
        std::fs::write(workspace.join("policy.dw"),
            "permit(principal, action, resource);\n\
             forbid(principal, action in [Box::Action::\"fs:read\", Box::Action::\"fs:write\"], resource) when { context.input.path like \"*/blocked\" };\n"
        ).unwrap();
        Self {
            root: root.to_path_buf(),
            selected,
            other,
            payload,
            nested,
            replacement,
            config,
            stderr: root.join("stderr"),
        }
    }

    fn start(&self) -> Run {
        let mut command = Command::new(fixture::box_binary());
        command
            .args(["run", "--config"])
            .arg(&self.config)
            .env("HOME", self.root.join("home"))
            .env(
                "PATH",
                format!("{}:/usr/bin:/bin", self.root.join("bin").display()),
            )
            .env("TMPDIR", "/var/tmp")
            .env_remove("EXPERIMENTAL_LINUX_SUPPORT")
            .env_remove("EXPERIMENTAL_X86_SUPPORT")
            .current_dir(self.config.parent().unwrap())
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(File::create(&self.stderr).unwrap());
        // SAFETY: the hook only drops capabilities and sets the child death signal before exec.
        unsafe { command.pre_exec(drop_publisher_capabilities) };
        let mut child = command.spawn().unwrap();
        let input = child.stdin.take().unwrap();
        let output = BufReader::new(child.stdout.take().unwrap());
        let mut run = Run {
            child,
            input: Some(input),
            output,
            stderr: self.stderr.clone(),
        };
        assert_eq!(run.frame(), json!({"ready": true}));
        run
    }

    fn arrive(&self, readonly: bool) {
        mount(Some(&self.payload), &self.payload, libc::MS_BIND);
        if readonly {
            mount(
                None,
                &self.payload,
                libc::MS_BIND | libc::MS_REMOUNT | libc::MS_RDONLY,
            );
        }
        mount(
            Some(&self.payload),
            &self.selected,
            libc::MS_BIND | libc::MS_REC,
        );
    }
}

struct Run {
    child: Child,
    input: Option<ChildStdin>,
    output: BufReader<ChildStdout>,
    stderr: PathBuf,
}

impl Run {
    fn frame(&mut self) -> Value {
        let mut line = String::new();
        assert_ne!(
            self.output.read_line(&mut line).unwrap(),
            0,
            "workload closed: {}",
            std::fs::read_to_string(&self.stderr).unwrap()
        );
        serde_json::from_str(&line).unwrap_or_else(|error| panic!("{error}: {line}"))
    }

    fn request(&mut self, interpreter: &str, operation: &str, path: &Path, text: &str) -> Value {
        let request =
            json!({"interpreter": interpreter, "operation": operation, "path": path, "text": text});
        let input = self.input.as_mut().unwrap();
        writeln!(input, "{request}").unwrap();
        input.flush().unwrap();
        self.frame()
    }

    fn read(&mut self, interpreter: &str, path: &Path, expected: &str) {
        let result = self.request(interpreter, "read", path, "");
        assert_eq!(result["status"], 0, "{interpreter}: {result}");
        assert_eq!(result["stdout"], expected, "{interpreter}: {result}");
    }

    fn refused(&mut self, interpreter: &str, operation: &str, path: &Path) {
        let result = self.request(interpreter, operation, path, "forbidden-change");
        assert_ne!(result["status"], 0, "{interpreter} {operation}: {result}");
        assert_eq!(
            result["stdout"], "",
            "a refused read exposes no content: {result}"
        );
    }

    fn finish(mut self) {
        self.input.take();
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

#[test]
fn hosted_interpreters_follow_selected_live_root_nested_and_replacement_mounts() {
    isolated(|root| {
        let publisher = Publisher::new(root, Selection::Agent);
        let mut run = publisher.start();
        for interpreter in ["shell", "monty"] {
            run.read(interpreter, &publisher.selected.join("value"), "initial");
            run.refused(interpreter, "read", &publisher.other.join("value"));
        }
        assert_eq!(
            std::fs::read_to_string(publisher.other.join("value")).unwrap(),
            "outside"
        );
        publisher.arrive(false);
        for interpreter in ["shell", "monty"] {
            run.read(interpreter, &publisher.selected.join("value"), "arrived");
            let created = publisher.selected.join(format!("{interpreter}-created"));
            let result = run.request(interpreter, "write", &created, "written");
            assert_eq!(result["status"], 0, "{result}");
            assert_eq!(
                std::fs::read_to_string(publisher.payload.join(format!("{interpreter}-created")))
                    .unwrap(),
                "written"
            );
        }
        mount(
            Some(&publisher.nested),
            &publisher.selected.join("nested"),
            libc::MS_BIND,
        );
        for interpreter in ["shell", "monty"] {
            run.read(
                interpreter,
                &publisher.selected.join("nested/value"),
                "nested",
            );
        }
        mount(
            Some(&publisher.replacement),
            &publisher.selected,
            libc::MS_BIND | libc::MS_REC,
        );
        for interpreter in ["shell", "monty"] {
            run.read(
                interpreter,
                &publisher.selected.join("value"),
                "replacement",
            );
            run.refused(
                interpreter,
                "read",
                &publisher.selected.join("nested/value"),
            );
        }
        run.finish();
    });
}

#[test]
fn hosted_interpreters_do_not_inherit_tool_selections_or_ordinary_native_grants() {
    for selection in [Selection::Omitted, Selection::ToolOnly] {
        isolated(|root| {
            let publisher = Publisher::new(root, selection);
            let mut run = publisher.start();
            publisher.arrive(false);
            assert_eq!(
                std::fs::read_to_string(publisher.selected.join("value")).unwrap(),
                "arrived"
            );
            for interpreter in ["shell", "monty"] {
                run.refused(interpreter, "read", &publisher.selected.join("value"));
            }
            run.finish();
        });
    }
}

#[test]
fn hosted_incoming_storage_keeps_policy_and_protected_identity_floors() {
    isolated(|root| {
        let publisher = Publisher::new(root, Selection::Agent);
        let mut run = publisher.start();
        let policy = publisher.config.parent().unwrap().join("policy.dw");
        let policy_before = std::fs::read_to_string(&policy).unwrap();
        std::fs::hard_link(&policy, publisher.payload.join("authority-alias")).unwrap();
        std::os::unix::fs::symlink(&publisher.other, publisher.payload.join("escape")).unwrap();
        let state_marker = root.join("home/state/hosted-floor-marker");
        std::fs::write(&state_marker, "protected-state").unwrap();
        std::os::unix::fs::symlink(
            root.join("home/state"),
            publisher.payload.join("state-alias"),
        )
        .unwrap();
        publisher.arrive(false);
        for interpreter in ["shell", "monty"] {
            run.read(interpreter, &publisher.selected.join("value"), "arrived");
            // The operator home is already reachable, so only the state floor refuses this path.
            assert_eq!(
                std::fs::read_to_string(&state_marker).unwrap(),
                "protected-state"
            );
            run.refused(interpreter, "read", &state_marker);
            run.refused(interpreter, "write", &state_marker);
            for relative in [
                "blocked",
                "authority-alias",
                "escape/value",
                "state-alias/hosted-floor-marker",
            ] {
                let path = publisher.selected.join(relative);
                assert!(
                    std::fs::read_to_string(&path).is_ok(),
                    "outside control: {}",
                    path.display()
                );
                run.refused(interpreter, "read", &path);
                run.refused(interpreter, "write", &path);
            }
        }
        assert_eq!(std::fs::read_to_string(&policy).unwrap(), policy_before);
        assert_eq!(
            std::fs::read_to_string(&state_marker).unwrap(),
            "protected-state"
        );
        assert_eq!(
            std::fs::read_to_string(publisher.payload.join("blocked")).unwrap(),
            "policy-denied"
        );
        assert_eq!(
            std::fs::read_to_string(publisher.other.join("value")).unwrap(),
            "outside"
        );
        run.finish();
    });
}

#[test]
fn hosted_interpreters_obey_readonly_options_on_arriving_mounts() {
    isolated(|root| {
        let publisher = Publisher::new(root, Selection::Agent);
        let mut run = publisher.start();
        publisher.arrive(true);
        assert!(std::fs::write(publisher.selected.join("value"), "outside-write").is_err());
        for interpreter in ["shell", "monty"] {
            run.read(interpreter, &publisher.selected.join("value"), "arrived");
            run.refused(interpreter, "write", &publisher.selected.join("value"));
        }
        assert_eq!(
            std::fs::read_to_string(publisher.payload.join("value")).unwrap(),
            "arrived"
        );
        run.finish();
    });
}

//! Nested user namespaces retain the workload's mount restrictions.
#![cfg(all(
    target_os = "linux",
    any(target_arch = "aarch64", target_arch = "x86_64")
))]

use std::fs::File;
use std::os::unix::process::CommandExt;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use containment::{ContainmentConfig, Operation, Scope};
use serde_json::Value;
use sha2::{Digest as _, Sha256};

const ROUTES: [&str; 7] = [
    "unshare-user",
    "unshare-user-mount",
    "clone-user",
    "clone3-user",
    "setns-explicit",
    "setns-zero",
    "setns-pidfd",
];

struct Fixture {
    root: tempfile::TempDir,
    work: PathBuf,
    mount: PathBuf,
}

struct Running(Child);

impl Drop for Running {
    fn drop(&mut self) {
        if matches!(self.0.try_wait(), Ok(None)) {
            // SAFETY: this live child owns a fresh process group with its identifier.
            unsafe { libc::kill(-(self.0.id() as i32), libc::SIGKILL) };
            let _ = self.0.wait();
        }
    }
}

impl Fixture {
    fn new() -> Self {
        let root = tempfile::Builder::new()
            .prefix("nested-user-ns-")
            .tempdir_in("/var/tmp")
            .unwrap();
        let work = root.path().join("work");
        let mount = work.join("mount");
        std::fs::create_dir(&work).unwrap();
        std::fs::create_dir(&mount).unwrap();
        Self { root, work, mount }
    }

    fn run(&self, route: &str, contained: bool) -> Value {
        let probe = env!("CARGO_BIN_EXE_containment-test-probe");
        let mut command = if contained {
            let config = ContainmentConfig::new()
                .allow(probe, Operation::Read, Scope::File)
                .unwrap()
                .allow(probe, Operation::Exec, Scope::File)
                .unwrap()
                .allow(&self.work, Operation::Read, Scope::Root)
                .unwrap()
                .allow(&self.work, Operation::Write, Scope::Root)
                .unwrap();
            let json = config.to_json().unwrap();
            let digest = Sha256::digest(json.as_bytes())
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>();
            let path = self.root.path().join("containment.json");
            std::fs::write(&path, json).unwrap();
            let mut command = Command::new(env!("CARGO_BIN_EXE_strands-box-contain-trampoline"));
            command
                .arg("--config")
                .arg(path)
                .arg("--config-sha256")
                .arg(digest)
                .args(["--target-env-json", "{}", "--", probe]);
            command
        } else {
            Command::new(probe)
        };
        let stdout = self.root.path().join("stdout");
        let stderr = self.root.path().join("stderr");
        command
            .args(["--user-namespace", route])
            .arg(&self.mount)
            .current_dir(&self.work)
            .env_clear()
            .process_group(0)
            .stdin(Stdio::null())
            .stdout(File::create(&stdout).unwrap())
            .stderr(File::create(&stderr).unwrap());
        let mut child = Running(command.spawn().unwrap());
        let deadline = Instant::now() + Duration::from_secs(20);
        let status = loop {
            if let Some(status) = child.0.try_wait().unwrap() {
                break status;
            }
            assert!(
                Instant::now() < deadline,
                "{route}, contained={contained}: probe exceeded 20 seconds"
            );
            std::thread::sleep(Duration::from_millis(20));
        };
        let out = std::fs::read_to_string(stdout).unwrap();
        let err = std::fs::read_to_string(stderr).unwrap();
        assert!(
            status.success(),
            "{route}, contained={contained}: {status}, stdout={out}, stderr={err}"
        );
        let report: Value = serde_json::from_str(&out)
            .unwrap_or_else(|error| panic!("{route}: invalid report: {error}; {out}; {err}"));
        assert_eq!(
            report["state_error"], 0,
            "{route}: state observation failed: {report}"
        );
        assert_eq!(
            report["child_error"], 0,
            "{route}: child protocol failed: {report}"
        );
        report
    }

    fn supported(&self) -> bool {
        let control = self.run("view-control", false);
        available(
            "view-control",
            &control,
            &["operation_error", "mount_error"],
        )
    }
}

fn available(route: &str, report: &Value, fields: &[&str]) -> bool {
    for field in fields {
        let error = report[*field].as_u64().unwrap();
        if error == 0 {
            continue;
        }
        assert!(
            [
                libc::EPERM,
                libc::EACCES,
                libc::ENOSYS,
                libc::ENOSPC,
                libc::EUSERS
            ]
            .iter()
            .any(|value| *value as u64 == error)
                || (route == "view-control"
                    && *field == "operation_error"
                    && error == libc::EINVAL as u64),
            "{route}: unexpected control failure in {field}: {report}"
        );
        eprintln!("skipping: {route}: uncontained control cannot complete {field}, errno={error}");
        return false;
    }
    true
}

fn cleared(state: &Value) {
    for field in [
        "inheritable",
        "permitted",
        "effective",
        "bounding",
        "ambient",
    ] {
        assert_eq!(state[field], 0, "startup {field} was not cleared: {state}");
    }
    assert_eq!(state["no_new_privs"], 1, "{state}");
    assert_eq!(state["seccomp"], 2, "{state}");
}

#[test]
fn nested_user_namespaces_restore_scoped_capabilities_and_keep_mount_refusals() {
    let fixture = Fixture::new();
    if !fixture.supported() {
        return;
    }
    let last_capability: u32 = std::fs::read_to_string("/proc/sys/kernel/cap_last_cap")
        .unwrap()
        .trim()
        .parse()
        .unwrap();
    let full = u64::MAX
        .checked_shr(63 - last_capability)
        .expect("capability set fits in u64");
    for route in ROUTES {
        let control = fixture.run(route, false);
        if !available(
            route,
            &control,
            &[
                "operation_error",
                "private_mount_error",
                "mount_error",
                "fsopen_error",
            ],
        ) {
            continue;
        }
        let contained = fixture.run(route, true);
        cleared(&contained["before"]);
        for field in ["inheritable", "ambient"] {
            assert_eq!(
                contained["after"][field], 0,
                "{route}: {field}: {contained}"
            );
        }
        for report in [&control, &contained] {
            assert_eq!(report["operation_error"], 0, "{route}: {report}");
            assert_eq!(report["private_mount_error"], 0, "{route}: {report}");
            assert_ne!(
                report["before"]["user_namespace"], report["after"]["user_namespace"],
                "{route}: {report}"
            );
            for field in ["permitted", "effective", "bounding"] {
                assert_eq!(report["after"][field], full, "{route}: {field}: {report}");
            }
            for field in ["no_new_privs", "seccomp"] {
                assert_eq!(
                    report["before"][field], report["after"][field],
                    "{route}: {field}: {report}"
                );
            }
            if route.starts_with("setns") {
                assert_eq!(
                    report["target_namespace"], report["after"]["user_namespace"],
                    "{route}: {report}"
                );
            }
        }
        for field in ["mount_error", "fsopen_error"] {
            assert_eq!(
                contained[field],
                libc::EPERM as u64,
                "{route}: {field}: {contained}"
            );
        }
        println!(
            "verified {route}: scoped capabilities restored; mount and fsopen refused; both controls permitted"
        );
    }
}

#[test]
fn ordinary_process_and_thread_creation_remain_available() {
    let fixture = Fixture::new();
    if !fixture.supported() {
        return;
    }
    for contained in [false, true] {
        let report = fixture.run("ordinary", contained);
        if contained {
            cleared(&report["before"]);
        }
        for field in ["fork_error", "thread_error", "spawn_error"] {
            assert_eq!(report[field], 0, "contained={contained}, {field}: {report}");
        }
        assert_eq!(
            report["before"], report["after"],
            "contained={contained}: {report}"
        );
    }
}

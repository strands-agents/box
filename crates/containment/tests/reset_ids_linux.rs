//! A workload resets its ids to the ones it has, as `posix_spawn` with `POSIX_SPAWN_RESETIDS` does,
//! and cannot change them.
#![cfg(target_os = "linux")]

use std::ffi::CString;
use std::io::{self, Write as _};
use std::process::Command;

use containment::{ContainmentConfig, Operation, Scope};
use sha2::{Digest, Sha256};

const MARKER: &str = "RESET_IDS_RESULT=";

/// The errno of a call that answered `-1`, or `None` when it succeeded.
fn refusal(answer: libc::c_int) -> Option<i32> {
    (answer == -1).then(|| io::Error::last_os_error().raw_os_error().unwrap())
}

/// Start this test binary with `posix_spawn` and `flags`, and answer the spawn's error or the
/// child's exit status.
fn spawn_self(flags: libc::c_int) -> serde_json::Value {
    let executable = CString::new(
        std::env::current_exe()
            .unwrap()
            .into_os_string()
            .into_encoded_bytes(),
    )
    .unwrap();
    let arguments = [
        executable.clone(),
        CString::new("--exact").unwrap(),
        CString::new("no_test_has_this_name").unwrap(),
    ];
    let mut argv: Vec<*mut libc::c_char> = arguments
        .iter()
        .map(|argument| argument.as_ptr().cast_mut())
        .collect();
    argv.push(std::ptr::null_mut());
    let environment: [*mut libc::c_char; 1] = [std::ptr::null_mut()];
    // SAFETY: the attributes are initialized before use and destroyed after, every string outlives
    // the call, and both arrays end in a null pointer.
    unsafe {
        let mut attributes = std::mem::zeroed::<libc::posix_spawnattr_t>();
        assert_eq!(libc::posix_spawnattr_init(&mut attributes), 0);
        assert_eq!(
            libc::posix_spawnattr_setflags(&mut attributes, flags as libc::c_short),
            0
        );
        let mut child = 0;
        let answer = libc::posix_spawn(
            &mut child,
            executable.as_ptr(),
            std::ptr::null(),
            &attributes,
            argv.as_ptr(),
            environment.as_ptr(),
        );
        libc::posix_spawnattr_destroy(&mut attributes);
        if answer != 0 {
            return serde_json::json!({ "spawn_errno": answer });
        }
        let mut status = 0;
        assert_eq!(libc::waitpid(child, &mut status, 0), child);
        if !libc::WIFEXITED(status) {
            return serde_json::json!({ "signal": libc::WTERMSIG(status) });
        }
        serde_json::json!({ "exit_status": libc::WEXITSTATUS(status) })
    }
}

/// The `Uid:` and `Gid:` lines of `/proc/self/status`: the real, effective, saved, and filesystem
/// ids. The filter refuses `getresuid`, so this is how a workload reads its saved ids.
fn status_ids() -> Vec<String> {
    std::fs::read_to_string("/proc/self/status")
        .unwrap()
        .lines()
        .filter(|line| line.starts_with("Uid:") || line.starts_with("Gid:"))
        .map(|line| line.split_whitespace().collect::<Vec<_>>().join(" "))
        .collect()
}

/// The id values a probe passes: the workload's own `0`, `-1` for "leave it", and `1`, which the
/// workload does not have.
const IDS: [libc::uid_t; 3] = [0, !0, 1];

/// Each `setresuid` and `setresgid` call with every mix of `IDS` in its three positions, as
/// `[name, real, effective, saved, errno or null]`.
fn identity_calls() -> Vec<serde_json::Value> {
    let mut calls = Vec::new();
    for name in ["setresuid", "setresgid"] {
        for real in IDS {
            for effective in IDS {
                for saved in IDS {
                    // SAFETY: each call sets this process's own ids inside its own user namespace,
                    // where every id the filter admits is the one the process already has.
                    let answer = unsafe {
                        if name == "setresuid" {
                            libc::setresuid(real, effective, saved)
                        } else {
                            libc::setresgid(real, effective, saved)
                        }
                    };
                    calls.push(serde_json::json!([
                        name,
                        real,
                        effective,
                        saved,
                        refusal(answer)
                    ]));
                }
            }
        }
    }
    calls
}

#[test]
fn reset_ids_probe() {
    if std::env::var_os("BOX_RESET_IDS_PROBE").is_none() {
        return;
    }
    // SAFETY: each call reads or sets this process's own ids, inside its own user namespace.
    let report = unsafe {
        serde_json::json!({
            "ids": [libc::getuid(), libc::geteuid(), libc::getgid(), libc::getegid()],
            "spawn": spawn_self(0),
            "spawn_resetting_ids": spawn_self(libc::POSIX_SPAWN_RESETIDS),
            "identity_calls": identity_calls(),
            "ids_after": status_ids(),
        })
    };
    println!("{MARKER}{report}");
    io::stdout().flush().unwrap();
}

/// Run the probe in a real box, and return what it reports.
fn probe() -> serde_json::Value {
    let executable = std::env::current_exe().unwrap();
    let json = ContainmentConfig::new()
        .allow(&executable, Operation::Read, Scope::File)
        .unwrap()
        .allow(&executable, Operation::Exec, Scope::File)
        .unwrap()
        .to_json()
        .unwrap();
    let config_file = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(config_file.path(), &json).unwrap();
    let digest = Sha256::digest(json.as_bytes())
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    let output = Command::new(env!("CARGO_BIN_EXE_strands-box-contain-trampoline"))
        .arg("--config")
        .arg(config_file.path())
        .arg("--config-sha256")
        .arg(digest)
        .arg("--target-env-json")
        .arg(serde_json::json!({ "BOX_RESET_IDS_PROBE": "1" }).to_string())
        .arg("--")
        .arg(&executable)
        .args([
            "--exact",
            "reset_ids_probe",
            "--nocapture",
            "--test-threads=1",
        ])
        .output()
        .expect("launch the real containment trampoline");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let report = stdout
        .lines()
        .find_map(|line| line.split_once(MARKER).map(|(_, report)| report))
        .unwrap_or_else(|| {
            panic!(
                "the probe reported nothing: status {}\nstdout:\n{stdout}\nstderr:\n{}",
                output.status,
                String::from_utf8_lossy(&output.stderr)
            )
        });
    serde_json::from_str(report).expect("the probe reports JSON")
}

#[test]
fn a_workload_resets_its_own_ids_and_cannot_change_them() {
    let report = probe();
    assert_eq!(report["ids"], serde_json::json!([0, 0, 0, 0]), "{report}");
    assert_eq!(
        report["spawn"],
        serde_json::json!({ "exit_status": 0 }),
        "{report}"
    );
    assert_eq!(
        report["spawn_resetting_ids"],
        serde_json::json!({ "exit_status": 0 }),
        "glibc's posix_spawn with POSIX_SPAWN_RESETIDS, as GNU make starts a recipe: {report}"
    );
    let calls = report["identity_calls"]
        .as_array()
        .expect("the identity calls");
    assert_eq!(calls.len(), 2 * IDS.len().pow(3), "{report}");
    for call in calls {
        // A call that names only `0` and `-1` leaves every id as it is. One that names `1` is
        // refused by the filter with `EPERM`; the kernel would answer `EINVAL` for an unmapped id.
        let names_another_id = (1..=3).any(|position| call[position] == serde_json::json!(1));
        let expected = if names_another_id {
            serde_json::json!(libc::EPERM)
        } else {
            serde_json::Value::Null
        };
        assert_eq!(call[4], expected, "{call}");
    }
    assert_eq!(
        report["ids_after"],
        serde_json::json!(["Uid: 0 0 0 0", "Gid: 0 0 0 0"]),
        "every id, the saved ones included, is unchanged after the admitted calls: {report}"
    );
}

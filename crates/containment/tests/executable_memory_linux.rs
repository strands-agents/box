//! Executable memory lifts only the two W^X routes a JIT runtime takes.
#![cfg(target_os = "linux")]

use std::io::{self, Write as _};
use std::process::Command;

use containment::{ContainmentConfig, Operation, Scope};
use sha2::{Digest, Sha256};

const MARKER: &str = "EXECUTABLE_MEMORY_RESULT=";
const LENGTH: usize = 4096;

/// The errno of a call that failed, or `None`.
fn refusal(failed: bool) -> Option<i32> {
    failed.then(|| io::Error::last_os_error().raw_os_error().unwrap())
}

fn map(protection: libc::c_int) -> *mut libc::c_void {
    // SAFETY: an anonymous private mapping touches no existing memory.
    unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            LENGTH,
            protection,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
            -1,
            0,
        )
    }
}

#[test]
fn executable_memory_probe() {
    if std::env::var_os("BOX_EXECUTABLE_MEMORY_PROBE").is_none() {
        return;
    }
    let page = map(libc::PROT_READ | libc::PROT_WRITE);
    assert_ne!(page, libc::MAP_FAILED);
    // SAFETY: each call names the page mapped above, or creates a descriptor the process owns.
    let report = unsafe {
        serde_json::json!({
            "mmap": refusal(
                map(libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC) == libc::MAP_FAILED
            ),
            "mprotect": refusal(libc::mprotect(page, LENGTH, libc::PROT_READ | libc::PROT_EXEC) != 0),
            "pkey_mprotect": refusal(
                libc::syscall(libc::SYS_pkey_mprotect, page, LENGTH, libc::PROT_READ, -1) != 0
            ),
            "memfd_create": refusal(libc::syscall(libc::SYS_memfd_create, c"jit".as_ptr(), 0) < 0),
        })
    };
    println!("{MARKER}{report}");
    io::stdout().flush().unwrap();
}

/// Run the probe in a real box under `config`, and return what it reports.
fn probe(config: ContainmentConfig) -> serde_json::Value {
    let executable = std::env::current_exe().unwrap();
    let json = config
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
        .arg(serde_json::json!({ "BOX_EXECUTABLE_MEMORY_PROBE": "1" }).to_string())
        .arg("--")
        .arg(&executable)
        .args([
            "--exact",
            "executable_memory_probe",
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
                "the contained probe did not report: {stdout}\n{}",
                String::from_utf8_lossy(&output.stderr)
            )
        });
    serde_json::from_str(report).unwrap()
}

#[test]
fn executable_memory_lifts_only_the_jit_routes() {
    assert_eq!(
        probe(ContainmentConfig::new()),
        serde_json::json!({
            "mmap": libc::EPERM,
            "mprotect": libc::EPERM,
            "pkey_mprotect": libc::EPERM,
            "memfd_create": libc::EPERM,
        })
    );
    assert_eq!(
        probe(ContainmentConfig::new().allow_executable_memory()),
        serde_json::json!({
            "mmap": null,
            "mprotect": null,
            "pkey_mprotect": libc::EPERM,
            "memfd_create": libc::EPERM,
        })
    );
}

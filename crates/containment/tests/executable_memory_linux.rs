//! A JIT runtime maps executable memory by default on Linux, and code it writes stays contained.
#![cfg(target_os = "linux")]

use std::io::{self, Write as _};
use std::process::Command;

use containment::{ContainmentConfig, Operation, Scope};
use sha2::{Digest, Sha256};

const MARKER: &str = "EXECUTABLE_MEMORY_RESULT=";
const LENGTH: usize = 4096;

// A function that returns 42: the bytes a JIT would write before running them.
#[cfg(target_arch = "aarch64")]
const RETURN_42: &[u8] = &[0x40, 0x05, 0x80, 0x52, 0xc0, 0x03, 0x5f, 0xd6]; // mov w0, #42 ; ret
#[cfg(target_arch = "x86_64")]
const RETURN_42: &[u8] = &[0xb8, 0x2a, 0x00, 0x00, 0x00, 0xc3]; // mov eax, 42 ; ret

/// The errno of a call that failed, or `None`.
fn refusal(failed: bool) -> Option<i32> {
    failed.then(|| io::Error::last_os_error().raw_os_error().unwrap())
}

/// Map writable memory, write a function into it, make it executable, and call it.
///
/// This is what a JIT runtime does: the bytes come from the process, not from a file the mount
/// view approved. Returns what the generated function returned.
unsafe fn run_generated_code() -> i32 {
    // SAFETY: an anonymous private mapping touches no existing memory.
    let page = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            LENGTH,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
            -1,
            0,
        )
    };
    assert_ne!(
        page,
        libc::MAP_FAILED,
        "a writable mapping is always permitted"
    );
    // SAFETY: the mapping is `LENGTH` bytes and `RETURN_42` is far shorter.
    unsafe { std::ptr::copy_nonoverlapping(RETURN_42.as_ptr(), page.cast(), RETURN_42.len()) };
    // SAFETY: the page was mapped above with this length.
    assert_eq!(
        unsafe { libc::mprotect(page, LENGTH, libc::PROT_READ | libc::PROT_EXEC) },
        0,
        "a JIT runtime must be able to make its code executable",
    );
    // aarch64 needs the instruction cache cleared before it runs freshly written code. The
    // function fits in one cache line, so cleaning its first address covers it.
    #[cfg(target_arch = "aarch64")]
    // SAFETY: cache-maintenance instructions on a mapped, owned address; they make no syscall.
    unsafe {
        std::arch::asm!(
            "dc cvau, {addr}",
            "dsb ish",
            "ic ivau, {addr}",
            "dsb ish",
            "isb",
            addr = in(reg) page,
            options(nostack, preserves_flags),
        );
    }
    // SAFETY: the page now holds a valid parameterless function returning an int.
    let generated: extern "C" fn() -> i32 = unsafe { std::mem::transmute(page) };
    generated()
}

#[test]
fn executable_memory_probe() {
    if std::env::var_os("BOX_EXECUTABLE_MEMORY_PROBE").is_none() {
        return;
    }
    // SAFETY: the generated function returns an int and makes no syscall; each check below is a
    // single syscall on this process's own descriptors or an anonymous page.
    let report = unsafe {
        let generated = run_generated_code();
        let page = libc::mmap(
            std::ptr::null_mut(),
            LENGTH,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
            -1,
            0,
        );
        serde_json::json!({
            "generated_code_returned": generated,
            // Code the process wrote still meets every other restriction:
            "pkey_mprotect": refusal(
                libc::syscall(libc::SYS_pkey_mprotect, page, LENGTH, libc::PROT_EXEC, -1) != 0
            ),
            "memfd_create": refusal(libc::syscall(libc::SYS_memfd_create, c"jit".as_ptr(), 0) < 0),
            "ipv6_socket": refusal(libc::socket(libc::AF_INET6, libc::SOCK_STREAM, 0) < 0),
            "ungranted_open": refusal(libc::open(c"/etc/hostname".as_ptr(), libc::O_RDONLY) < 0),
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

/// **A box runs code the process wrote, and that code stays inside every other restriction.** The
/// generated function runs, while `pkey_mprotect`, `memfd_create`, an IPv6 socket, and an
/// ungranted path stay refused for the same process.
#[test]
fn a_box_runs_generated_code_that_stays_contained() {
    if !the_host_can_build_a_view() {
        println!("skipping: this host cannot build a namespace mount view");
        return;
    }
    assert_eq!(
        probe(),
        serde_json::json!({
            "generated_code_returned": 42,
            "pkey_mprotect": libc::EPERM,
            "memfd_create": libc::EPERM,
            "ipv6_socket": libc::EPERM,
            "ungranted_open": libc::ENOENT,
        })
    );
}

fn the_host_can_build_a_view() -> bool {
    // SAFETY: the child uses syscalls only and calls `_exit`.
    let child = unsafe { libc::fork() };
    if child < 0 {
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
                if libc::mount(
                    c"proc".as_ptr(),
                    c"/proc".as_ptr(),
                    c"proc".as_ptr(),
                    0,
                    std::ptr::null(),
                ) != 0
                {
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
    // SAFETY: wait for this process's child.
    unsafe { libc::waitpid(child, &mut status, 0) };
    libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0
}

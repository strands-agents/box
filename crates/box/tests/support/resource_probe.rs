//! Test-only workload that reports its cgroup, starts processes until one fails, or takes memory.

// A test probe's stdout is the probe's own report to its test, not a Box Core message.
#![allow(clippy::print_stdout, clippy::print_stderr)]

#[cfg(target_os = "linux")]
use std::io::Write as _;

#[cfg(target_os = "linux")]
fn main() {
    let arguments: Vec<String> = std::env::args().skip(1).collect();
    match arguments
        .iter()
        .map(String::as_str)
        .collect::<Vec<_>>()
        .as_slice()
    {
        ["cgroup"] => println!("cgroup={}", own_cgroup()),
        ["fork", most] => fork(most.parse().unwrap_or_else(|_| usage())),
        ["memory", mebibytes] => memory(mebibytes.parse().unwrap_or_else(|_| usage())),
        _ => usage(),
    }
}

#[cfg(not(target_os = "linux"))]
fn main() {
    usage()
}

fn usage() -> ! {
    eprintln!("usage: box-resource-probe cgroup | fork <most> | memory <MiB>");
    std::process::exit(2)
}

/// The cgroup v2 path of this process, or empty on a host without one.
#[cfg(target_os = "linux")]
fn own_cgroup() -> String {
    std::fs::read_to_string("/proc/self/cgroup")
        .unwrap_or_default()
        .lines()
        .find_map(|line| line.strip_prefix("0::"))
        .unwrap_or_default()
        .to_string()
}

/// Start up to `most` children that each wait for this process's stdin to close, and report how
/// many started and the error of the first start that failed. The children stay alive until stdin
/// closes, so the test can look at the box while its workload sits at the limit.
#[cfg(target_os = "linux")]
fn fork(most: usize) {
    let mut children = Vec::new();
    let mut failure = 0;
    for _ in 0..most {
        // SAFETY: the child calls only async-signal-safe `read` and `_exit`.
        match unsafe { libc::fork() } {
            -1 => {
                failure = std::io::Error::last_os_error().raw_os_error().unwrap_or(-1);
                break;
            }
            0 => {
                let mut byte = 0_u8;
                // SAFETY: one read into a local byte, then exit without unwinding.
                unsafe {
                    while libc::read(0, (&raw mut byte).cast(), 1) > 0 {}
                    libc::_exit(0);
                }
            }
            child => children.push(child),
        }
    }
    println!(
        "cgroup={} forked={} errno={failure}",
        own_cgroup(),
        children.len()
    );
    let _ = std::io::stdout().flush();
    let mut rest = String::new();
    let _ = std::io::stdin().read_line(&mut rest);
    for child in children {
        // SAFETY: waits for this process's own child.
        unsafe { libc::waitpid(child, std::ptr::null_mut(), 0) };
    }
}

/// Take `mebibytes` of memory one mebibyte at a time, touching every page.
#[cfg(target_os = "linux")]
fn memory(mebibytes: usize) {
    println!("cgroup={}", own_cgroup());
    let mut held: Vec<Vec<u8>> = Vec::new();
    for taken in 1..=mebibytes {
        held.push(vec![1_u8; 1 << 20]);
        if taken % 16 == 0 {
            println!("taken={taken}");
            let _ = std::io::stdout().flush();
        }
    }
    println!("TOOK_ALL={}", held.len());
}

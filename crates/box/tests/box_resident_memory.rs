//! The resident memory of the run process, at startup and after twenty thousand decisions.

use std::io::Write as _;
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

#[path = "support/fixture.rs"]
mod fixture;

use fixture::Request;

const PERMIT_EXEC: &str = r#"
permit(principal == Box::Agent::"self", action == Box::Action::"shell:exec", resource);
permit(principal, action == Box::Action::"fs:write", resource);
"#;

/// Decisions in each of the two measured phases.
const DECISIONS: usize = 10_000;
const STARTUP: Duration = Duration::from_secs(60);
const DECIDING: Duration = Duration::from_secs(1200);
/// A loose sanity bound on growth over the whole run, not the 20 MB requirement.
const LARGEST_GROWTH_KIB: u64 = 64 * 1024;

fn wait_for(path: &Path, patience: Duration, what: &str) {
    let deadline = Instant::now() + patience;
    while !path.exists() {
        assert!(
            Instant::now() < deadline,
            "{what} did not appear within {patience:?}"
        );
        std::thread::sleep(Duration::from_millis(20));
    }
}

/// Ends the run when the harness leaves early, so a failed wait strands no spinning workload.
struct RunGuard {
    pid: Option<u32>,
}

impl Drop for RunGuard {
    fn drop(&mut self) {
        if let Some(pid) = self.pid {
            // SAFETY: a plain signal to a pid this test spawned.
            unsafe { libc::kill(pid as i32, libc::SIGTERM) };
        }
    }
}

/// The resident set of `pid` in KiB, as `ps` reports it on Linux and macOS.
fn resident_kib(pid: u32) -> u64 {
    let output = Command::new("ps")
        .args(["-o", "rss=", "-p", &pid.to_string()])
        .output()
        .expect("ps runs");
    String::from_utf8_lossy(&output.stdout)
        .trim()
        .parse()
        .unwrap_or_else(|error| panic!("ps reports a resident set for {pid}: {error}: {output:?}"))
}

#[test]
#[ignore = "twenty thousand hosted decisions, minutes long in a debug build: run by hand with --ignored"]
fn the_run_process_grows_by_a_bounded_amount_over_twenty_thousand_decisions() {
    if !fixture::namespace_launcher_is_usable() {
        return;
    }
    let box_ = Request::with_policy("resident-memory", PERMIT_EXEC).expect();
    let home = box_.box_home();
    let hundred = "for a in 1 2 3 4 5 6 7 8 9 10; do for b in 1 2 3 4 5 6 7 8 9 10; do printf \"\"; done; done";
    let calls = (0..DECISIONS / 100)
        .map(|_| format!("zsh -c '{hundred}'\n"))
        .collect::<String>();
    let phase = |marker: &str, release: &str| {
        format!(
            "{calls}: > \"$BOX_HOME/{marker}\"\nwhile [ ! -e \"$BOX_HOME/{release}\" ]; do :; done\n"
        )
    };
    let script = format!(
        "BOX_HOME={}; export BOX_HOME\n: > \"$BOX_HOME/started\"\n\
         while [ ! -e \"$BOX_HOME/measured-start\" ]; do :; done\n{}{}",
        home.display(),
        phase("decided", "measured-middle"),
        phase("decided-again", "measured-end"),
    );
    let mut command = box_.command_for("/bin/bash");
    let child = command
        .arg("-c")
        .arg(&script)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn strands-box run");
    let pid = child.id();
    let drained = std::thread::spawn(move || child.wait_with_output().expect("the run finishes"));
    let mut guard = RunGuard { pid: Some(pid) };

    wait_for(
        &home.join("started"),
        STARTUP,
        "the workload's start marker",
    );
    let at_start = resident_kib(pid);
    std::fs::write(home.join("measured-start"), b"").expect("release the workload");
    let deciding = Instant::now();
    wait_for(&home.join("decided"), DECIDING, "the first decided marker");
    let decided_in = deciding.elapsed();
    let at_middle = resident_kib(pid);
    std::fs::write(home.join("measured-middle"), b"").expect("release the workload");
    wait_for(
        &home.join("decided-again"),
        DECIDING,
        "the second decided marker",
    );
    let at_end = resident_kib(pid);
    std::fs::write(home.join("measured-end"), b"").expect("release the workload");
    guard.pid = None;
    let output = drained.join().expect("the drain thread finishes");

    let first_growth = at_middle.saturating_sub(at_start);
    let second_growth = at_end.saturating_sub(at_middle);
    let growth = at_end.saturating_sub(at_start);
    let _ = writeln!(
        std::io::stderr().lock(),
        "NFR-07 run process resident set: {at_start} KiB after startup, {at_middle} KiB after \
         {DECISIONS} decisions in {decided_in:?} (growth {first_growth} KiB), {at_end} KiB after \
         {} decisions (growth {second_growth} KiB more; {growth} KiB in all, limit \
         {LARGEST_GROWTH_KIB}); {} build; the run wrote {} stdout and {} stderr bytes",
        2 * DECISIONS,
        if cfg!(debug_assertions) {
            "debug"
        } else {
            "release"
        },
        output.stdout.len(),
        output.stderr.len()
    );
    assert!(
        output.status.success(),
        "the measured run must finish cleanly: {output:?}"
    );
    assert!(
        !String::from_utf8_lossy(&output.stderr).contains("timeout"),
        "no call may be left waiting past its deadline: {output:?}"
    );
    assert!(
        growth <= LARGEST_GROWTH_KIB,
        "the run process grew by {growth} KiB over {} decisions, past the {LARGEST_GROWTH_KIB} KiB \
         sanity bound: something retains per-decision state",
        2 * DECISIONS
    );
}

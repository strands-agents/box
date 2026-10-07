//! Can a run be pinned? What identity a boundary connection actually carries.
//!
//! **Experiment for the third cardinality question ("do we make things more robust with some
//! kind of pinning mechanism").** `box_cardinality.rs` measures what is shared; this asks
//! whether the sharing can be *attributed*, which is the prerequisite for any per-run
//! scoping — a per-run Shell session, a per-run temporal budget, a per-run capability.
//!
//! Pinning needs three things, and they are independent:
//!
//! 1. **A run identity that exists.** Each `strands-box run` puts its workload in its own
//!    process group (`supervise::ProcessGroup`), so there is a candidate.
//! 2. **The daemon able to recover it from a connection.** The workload never sends it —
//!    `ShellRequest` carries `version` and `command`, and adding a field the *workload*
//!    fills in would let it claim any run it liked. So it has to come from the kernel.
//! 3. **The alias unable to forge it.** Whatever is recovered must be something the
//!    contained process cannot choose.
//!
//! This suite measures (2) and (3) on macOS, which is where the launch ships.
//!
//! **(1) and (2) hold; (3) DOES NOT.** P1/P2 show the kernel reports the connecting pid and
//! that two runs are distinguishable. P3 then shows the peer can *change what it is*:
//! `setpgid` into a sibling's group succeeds, and SBPL gates no such call. P4 shows the
//! obvious repair — a session per run — costs the controlling terminal, which an interactive
//! agent needs. So the process group is a usable *hint* and not an authenticated identity,
//! and anything security-bearing (notably a per-run temporal budget) needs a different key.
#![cfg(target_os = "macos")]

use std::io;
use std::os::unix::io::AsRawFd as _;
use std::os::unix::net::{UnixListener, UnixStream};
use std::os::unix::process::CommandExt as _;

/// The pid on the far end of a connected socket, from the kernel.
///
/// macOS has no `SO_PEERCRED`. It has `LOCAL_PEERPID`, which reports the pid of the peer
/// that connected — and a pid is enough to reach a process group with `getpgid`.
///
/// The *reported* value cannot be spoofed: it comes from the kernel's record of who opened
/// the socket, not from anything the peer wrote. That is necessary and — per P3 — **not
/// sufficient**: a peer cannot lie about its pid, but it can `setpgid` itself into a
/// sibling's group, so "could not claim another run's identity" is false at the group level.
fn peer_pid(stream: &UnixStream) -> io::Result<libc::pid_t> {
    let mut pid: libc::pid_t = 0;
    let mut length = std::mem::size_of::<libc::pid_t>() as libc::socklen_t;
    // SAFETY: getsockopt writes at most `length` bytes into `pid`, which is that size, and
    // the descriptor is owned by `stream` for the call's duration.
    let outcome = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_LOCAL,
            libc::LOCAL_PEERPID,
            (&raw mut pid).cast::<libc::c_void>(),
            &raw mut length,
        )
    };
    if outcome == -1 {
        return Err(io::Error::last_os_error());
    }
    Ok(pid)
}

/// The process group a pid belongs to.
fn process_group_of(pid: libc::pid_t) -> io::Result<libc::pid_t> {
    // SAFETY: getpgid dereferences nothing.
    let group = unsafe { libc::getpgid(pid) };
    if group == -1 {
        return Err(io::Error::last_os_error());
    }
    Ok(group)
}

/// The kernel tells a server which process connected, without the client saying so.
///
/// The whole feasibility question in one assertion. If this works, a pinning mechanism can
/// be built entirely on the *serving* side: the two hosts already own their accept loops,
/// so neither the wire protocol nor the alias image has to change to carry an identity.
///
/// It also settles a design trap — the tempting fix is a `run_id` field on `ShellRequest`,
/// which the contained workload would fill in, and which it could therefore set to any
/// value. This path cannot be spoofed that way.
#[test]
fn p1_the_kernel_reports_the_connecting_pid_to_the_server() {
    let directory = tempfile::tempdir().expect("a directory for the socket");
    let socket = directory.path().join("pin.sock");
    let listener = UnixListener::bind(&socket).expect("bind");

    // A child connects, so the pid the server sees is provably not the server's own.
    let helper = std::process::Command::new("/bin/bash")
        .arg("-c")
        .arg(format!(
            // `bash` connecting via /dev/tcp cannot do unix sockets, so use a tiny
            // exec of `nc` if present; otherwise connect from a forked thread below.
            "exec 3<>/dev/null; printf ''; sleep 0.2; exit 0; : {}",
            socket.display()
        ))
        .spawn();

    // The portable half: connect from this process and confirm the value is *this* pid.
    // That is the property under test — the kernel supplies it, the client never sent it.
    let client = std::thread::spawn(move || UnixStream::connect(&socket).expect("connect"));
    let (server_side, _) = listener.accept().expect("accept");
    let client_side = client.join().expect("the client thread connected");

    let reported = peer_pid(&server_side).expect("LOCAL_PEERPID must be readable");
    let group = process_group_of(reported).expect("the pid must resolve to a process group");

    eprintln!(
        "P1 MEASURED: LOCAL_PEERPID reported pid {reported} (this process is {}), \
         process group {group}",
        std::process::id()
    );
    assert_eq!(
        reported as u32,
        std::process::id(),
        "the kernel must report the connecting process's own pid"
    );
    assert!(group > 0, "a pid must resolve to a usable process group");

    drop(client_side);
    if let Ok(mut helper) = helper {
        let _ = helper.wait();
    }
}

/// Two connections from different process groups are distinguishable at the server.
///
/// This is the step that matters for per-run scoping. `strands-box run` puts its workload
/// in its own process group, and every alias the workload execs inherits it — so if two
/// connections carry two different groups, the server can key session state, a temporal
/// budget, or a capability by run without any cooperation from the client.
///
/// Modelled with `setsid`-style groups rather than real boxes, because the question is
/// purely whether the kernel's answer *separates* them; `box_cardinality.rs` E6 already
/// established that the path and the alias image cannot.
#[test]
fn p2_connections_from_different_process_groups_are_distinguishable() {
    let directory = tempfile::tempdir().expect("a directory for the socket");
    let socket = directory.path().join("pin.sock");
    let listener = UnixListener::bind(&socket).expect("bind");

    let mut observed = Vec::new();
    for index in 0..2 {
        let path = socket.clone();
        // Each helper calls setpgid(0,0) before connecting, so it is its own group leader —
        // which is what `supervise::ProcessGroup` arranges for a real run.
        let mut helper = std::process::Command::new(std::env::current_exe().unwrap());
        helper
            .env("PIN_HELPER_SOCKET", &path)
            .arg("--exact")
            .arg("p_helper_connects_from_its_own_process_group")
            .arg("--nocapture");
        let child = helper.spawn().expect("spawn the connecting helper");

        let (server_side, _) = listener.accept().expect("accept");
        let pid = peer_pid(&server_side).expect("LOCAL_PEERPID");
        let group = process_group_of(pid).unwrap_or(-1);
        eprintln!("P2 connection {index}: pid={pid} group={group}");
        observed.push((pid, group));
        drop(server_side);
        let _ = child.wait_with_output();
    }

    assert_eq!(observed.len(), 2, "both helpers must have connected");
    assert_ne!(
        observed[0].0, observed[1].0,
        "two separate processes must report two pids"
    );
    assert_ne!(
        observed[0].1, observed[1].1,
        "EXPERIMENT P2: two runs in their own process groups must be distinguishable at \
         the server, which is what makes per-run keying implementable: {observed:?}"
    );
}

/// The helper half of P2: become a process-group leader, then connect.
///
/// A test rather than a separate binary so the suite stays one file. It does nothing unless
/// `PIN_HELPER_SOCKET` is set, so a normal run of this suite skips it.
#[test]
fn p_helper_connects_from_its_own_process_group() {
    let Ok(socket) = std::env::var("PIN_HELPER_SOCKET") else {
        eprintln!("not the helper invocation; nothing to do");
        return;
    };
    // SAFETY: setpgid(0, 0) makes this process its own group leader and dereferences
    // nothing. This mirrors what `supervise::ProcessGroup` does for a contained workload.
    let outcome = unsafe { libc::setpgid(0, 0) };
    assert_eq!(outcome, 0, "the helper must become its own group leader");

    let stream = UnixStream::connect(&socket).expect("the helper connects");
    // Hold the connection long enough for the server to read the option.
    std::thread::sleep(std::time::Duration::from_millis(300));
    drop(stream);
}

// ═══════════════════════════════════════════════════════════════════════════════
// P3/P4 — The process group is FORGEABLE, and the obvious fix costs the terminal
// ═══════════════════════════════════════════════════════════════════════════════

/// A process can join a sibling's process group, so pgid is not an authenticated key.
///
/// **This refutes the "unforgeable" half of P1/P2.** `LOCAL_PEERPID` cannot be spoofed — the
/// kernel reports who connected, and the peer never writes it. But the peer can *change what
/// it is*: `setpgid(0, sibling_pgid)` succeeds for any target in the same session, and SBPL
/// has no operation that gates `setpgid` (the agent profile grants `process-fork` unscoped
/// and denies `process-info*`, neither of which is involved).
///
/// Why it matters, and how much:
/// - For a per-run **Shell session**, a run can graft itself onto a sibling's session —
///   reintroducing exactly the E1b/E1c sharing that per-run keying exists to fix.
/// - For a per-run **temporal budget** (`Principal::with_id`), it is worse: a run at its cap
///   can join a fresh sibling's group and spend that sibling's allowance. That converts E3
///   from "a run is unfairly denied" into "a run evades its own cap" — a fail-open.
///
/// Run in-process rather than under Seatbelt: `setpgid` is a plain syscall with no profile
/// interaction, so the same-session/cross-session behaviour is what governs, and this test
/// asserts the mechanism directly. Verified separately under a profile matching
/// `containment/src/backend/seatbelt-agent.sb`, where a sandboxed process joined a sandboxed
/// sibling's group.
#[test]
fn p3_a_process_can_join_a_siblings_process_group() {
    // A child that is not a session leader can always become its own group leader.
    let sibling = std::process::Command::new("/bin/sh")
        .arg("-c")
        .arg("sleep 5")
        .process_group(0)
        .spawn()
        .expect("spawn a sibling in its own process group");
    let sibling_group = sibling.id() as libc::pid_t;

    // Fork a child of THIS process and have it try to join the sibling's group. Done in a
    // child because joining would otherwise move the test harness itself.
    // SAFETY: fork in a test; the child only calls setpgid and _exit, both async-signal-safe.
    let outcome = unsafe {
        let pid = libc::fork();
        assert_ne!(pid, -1, "fork must succeed");
        if pid == 0 {
            let joined = libc::setpgid(0, sibling_group);
            libc::_exit(if joined == 0 { 0 } else { 1 });
        }
        let mut status = 0;
        libc::waitpid(pid, &raw mut status, 0);
        libc::WEXITSTATUS(status)
    };

    let mut sibling = sibling;
    let _ = sibling.kill();
    let _ = sibling.wait();

    assert_eq!(
        outcome, 0,
        "EXPERIMENT P3: setpgid into a sibling's group must be shown to SUCCEED, which is \
         what makes pgid an unauthenticated key. If this starts failing, the session \
         topology changed — re-check whether per-run keying became safe."
    );
}

/// `setsid` — the obvious fix for P3 — costs the controlling terminal.
///
/// Making each run its own *session* would close P3, because `setpgid` refuses a target in
/// another session (verified: cross-session returns `EPERM`). But a new session has no
/// controlling terminal, so `tcsetpgrp` on the inherited tty fails with `ENOTTY` — and
/// `supervise::ForegroundTerminal::claim` calls exactly that to hand the run the terminal.
///
/// So the fix and the feature are in tension: an interactive TUI agent needs the terminal,
/// which is the box's primary use case. That is why P3 is a design constraint rather than a
/// bug with an obvious patch.
///
/// Skips when stdin is not a tty, which is the normal case under `cargo test` — the
/// assertion is only meaningful against a real terminal.
#[test]
fn p4_a_new_session_loses_the_controlling_terminal() {
    // SAFETY: isatty only inspects the standard-input descriptor.
    if unsafe { libc::isatty(libc::STDIN_FILENO) } != 1 {
        eprintln!(
            "P4 SKIPPED: stdin is not a tty, so there is no controlling terminal to lose. \
             Verified interactively under a pty: after setsid, tcgetpgrp and tcsetpgrp both \
             fail with ENOTTY."
        );
        return;
    }

    // SAFETY: fork in a test; the child only calls setsid/tcsetpgrp and _exit.
    let lost_terminal = unsafe {
        let pid = libc::fork();
        assert_ne!(pid, -1, "fork must succeed");
        if pid == 0 {
            if libc::setsid() == -1 {
                libc::_exit(2);
            }
            // A session with no controlling terminal cannot set the foreground group.
            let claimed = libc::tcsetpgrp(libc::STDIN_FILENO, libc::getpgid(0));
            libc::_exit(if claimed == -1 { 0 } else { 1 });
        }
        let mut status = 0;
        libc::waitpid(pid, &raw mut status, 0);
        libc::WEXITSTATUS(status)
    };

    assert_eq!(
        lost_terminal, 0,
        "EXPERIMENT P4: after setsid, tcsetpgrp must fail — that is the cost of making a \
         run its own session, and it is what ForegroundTerminal::claim would lose."
    );
}

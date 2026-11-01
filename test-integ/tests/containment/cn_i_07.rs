use strands_det_harness::det_case;

// Containment CN-I (process isolation)
//
// Process isolation is a kernel property (a Linux PID namespace and seccomp; Seatbelt's isolated
// signal mode), so it is probed natively: a binary the case compiles into the exec tree, spawned
// by the hosted Shell into the agent's own boundary, sends signal 0 — existence only, no effect —
// to this test process, a real host process foreign to the box. The probe reports its own pid
// and whether it may signal itself, as observations; the assertion is that the foreign process
// is not reached. Measured on the native Linux run: the probe's pid was 2 (a fresh PID
// namespace), self-signal answered EPERM (the Linux filter refuses `kill` outright), and the
// foreign signal answered EPERM. macOS is expected to refuse with EPERM too. The old form ran a
// host CPython that failed before any signal was attempted.
const PROBE: &str = r#"
unsafe extern "C" {
    fn kill(pid: i32, sig: i32) -> i32;
    fn getpid() -> i32;
}

fn main() {
    let target: i32 = std::env::args().nth(1).and_then(|a| a.parse().ok()).expect("target pid");
    println!("PROBE_ENTERED");
    let me = unsafe { getpid() };
    println!("PROBE_PID {me}");
    if unsafe { kill(me, 0) } == 0 {
        println!("SELF_OK {me}");
    } else {
        println!("SELF_REFUSED {me}: {}", std::io::Error::last_os_error());
    }
    if unsafe { kill(target, 0) } == 0 {
        println!("SIGNAL_REACHED {target}");
    } else {
        println!("SIGNAL_REFUSED {target}: {}", std::io::Error::last_os_error());
    }
}
"#;

det_case! {
    name: cn_i_07,
    id:   "CN-I-07",
    desc: "Process isolation: a native probe in the box cannot signal a foreign host process (signal 0 answers ESRCH or EPERM, never success)",
    run: |b| {
        b.apply_policy(
            r#"@id("workspace_spawn") permit (principal, action == Box::Action::"shell:spawn", resource);"#,
        );
        let probe = b.compile_probe("sigprobe", PROBE);
        let host_pid = std::process::id();
        // Mediated launch: the hosted Shell spawns the probe (journaled shell:spawn permit) into
        // the agent's own boundary, where the probe's syscalls are native.
        let r = b.run_mediated_with_config(
            b.with_exec_tree(),
            &format!("{} {host_pid}", probe.display()),
        );
        r.assert_mediated_permitted("shell:spawn", "sigprobe");
        r.assert_contains("PROBE_ENTERED");
        r.assert_contains("PROBE_PID ");
        r.assert_contains_any(&["SELF_OK", "SELF_REFUSED"]);
        r.assert_contains(&format!("SIGNAL_REFUSED {host_pid}: "));
        r.assert_contains_any(&["No such process", "Operation not permitted"]);
        r.assert_absent("SIGNAL_REACHED");
        if strands_det_harness::Platform::current() == strands_det_harness::Platform::Macos {
            // Preserve the mainline macOS self/foreign distinction, using a known live,
            // same-owner host process and signal 0 rather than sending SIGTERM to host pid 1.
            r.assert_contains("SELF_OK");
            r.assert_contains(&format!("SIGNAL_REFUSED {host_pid}: Operation not permitted"));
        }
    }
}

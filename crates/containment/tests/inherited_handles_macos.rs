//! macOS end-to-end proof and measurements for no inherited handles.
//!
//! Each test launches `strands-box-contain-trampoline`, so containment is applied and the target is
//! `exec`'d — which is what makes "across program replacement" observable. A probe that contained
//! itself would never replace its program, and would still hold the test harness's own descriptors.

#![cfg(target_os = "macos")]

use std::os::fd::{AsRawFd as _, FromRawFd as _, OwnedFd};
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

use containment::{ContainmentConfig, Network, Operation, Scope};
use sha2::{Digest as _, Sha256};

/// The probe, and a containment config that lets it start and print.
///
/// `/` and `/etc` are grants rather than profile text, so a direct caller states them: without the
/// root's own entry no absolute path resolves and the target dies producing nothing.
fn launch(work_directory: &Path) -> Command {
    let probe = PathBuf::from(env!("CARGO_BIN_EXE_containment-test-probe"))
        .canonicalize()
        .expect("the probe's executable identity");
    let config = ContainmentConfig::new()
        .allow(&probe, Operation::Exec, Scope::File)
        .expect("execute the probe")
        .allow(work_directory, Operation::Read, Scope::Root)
        .expect("read the working directory")
        .allow(work_directory, Operation::Write, Scope::Root)
        .expect("write the working directory")
        .allow(Path::new("/"), Operation::Read, Scope::Dir)
        .expect("the root's own entry")
        .allow(Path::new("/etc"), Operation::Metadata, Scope::Dir)
        .expect("the /etc entry")
        .allow(Path::new("/dev/null"), Operation::Read, Scope::File)
        .expect("read the null device")
        .allow(Path::new("/dev/null"), Operation::Write, Scope::File)
        .expect("write the null device")
        .set_network(Network::localhost().connect(43123))
        .expect("one proxy port");
    let config_json = config.to_json().expect("config JSON");
    let digest = Sha256::digest(config_json.as_bytes())
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    let config_path = work_directory.join("containment.json");
    std::fs::write(&config_path, config_json).expect("write the config");

    let mut command = Command::new(env!("CARGO_BIN_EXE_strands-box-contain-trampoline"));
    command
        .arg("--config")
        .arg(&config_path)
        .arg("--config-sha256")
        .arg(digest)
        .arg("--")
        .arg(&probe)
        .current_dir(work_directory);
    command
}

/// Two descriptor numbers to plant: one ordinary, and one as high as this host allows.
///
/// **The high number cannot be a constant.** `F_DUPFD` fails with `EINVAL` when the minimum is at or
/// above the soft `RLIMIT_NOFILE`, and macOS ships that limit at 256 — so the 900 the Linux suite uses
/// aborts this test at setup on a stock host. This raises the soft limit toward the hard one, then
/// asks for what the table actually allows.
fn planted_numbers() -> (i32, i32) {
    raise_descriptor_limit();
    // SAFETY: `getdtablesize` takes no argument and only reports a limit.
    let table = unsafe { libc::getdtablesize() };
    let high = 900.min(table - 16);
    assert!(
        high > 32,
        "this host's descriptor table holds {table} entries, too few to plant a high descriptor"
    );
    (10, high)
}

/// Raise the soft descriptor limit toward the hard one, so a high descriptor number exists.
fn raise_descriptor_limit() {
    let mut limit = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: `limit` is a live local the call writes through.
    if unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut limit) } != 0 || limit.rlim_cur >= 1024 {
        return;
    }
    limit.rlim_cur = limit.rlim_max.min(1024);
    // SAFETY: the new soft limit never exceeds the hard limit the call above read.
    unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &limit) };
}

/// A second descriptor for the same open file, at or above `minimum`.
fn duplicate_at_or_above(source: i32, minimum: i32) -> OwnedFd {
    // SAFETY: `source` is open, and `F_DUPFD` returns a new owned descriptor.
    let descriptor = unsafe { libc::fcntl(source, libc::F_DUPFD, minimum) };
    assert!(
        descriptor >= minimum,
        "duplicate descriptor at or above {minimum}"
    );
    // SAFETY: `F_DUPFD` returned a new descriptor that this value now owns.
    unsafe { OwnedFd::from_raw_fd(descriptor) }
}

/// Clear close-on-exec, so the descriptor survives every `exec` unless something closes it.
fn make_inheritable(descriptor: &OwnedFd) {
    // SAFETY: `F_SETFD` only updates the flags of a descriptor this test owns.
    assert_eq!(
        unsafe { libc::fcntl(descriptor.as_raw_fd(), libc::F_SETFD, 0) },
        0,
        "clear FD_CLOEXEC"
    );
}

/// Seatbelt containment and one further `exec` leave the workload holding only its standard streams.
///
/// **The uncontained control is not optional.** A census that enumerates nothing reports no leak, so
/// without a launch that *does* see the planted descriptors this test would pass on a broken probe.
#[test]
fn seatbelt_and_reexec_remove_inherited_handles() {
    let (ordinary_minimum, high_minimum) = planted_numbers();
    let sentinel = tempfile::tempfile().expect("sentinel file");
    let ordinary = duplicate_at_or_above(sentinel.as_raw_fd(), ordinary_minimum);
    let high = duplicate_at_or_above(sentinel.as_raw_fd(), high_minimum);
    make_inheritable(&ordinary);
    make_inheritable(&high);
    let ordinary_argument = ordinary.as_raw_fd().to_string();
    let high_argument = high.as_raw_fd().to_string();

    let probe = PathBuf::from(env!("CARGO_BIN_EXE_containment-test-probe"));
    let uncontained = Command::new(&probe)
        .args([
            "--verify-no-inherited-handles",
            "initial",
            &ordinary_argument,
            &high_argument,
        ])
        .output()
        .expect("launch the uncontained control");
    let uncontained_stderr = String::from_utf8_lossy(&uncontained.stderr);
    assert_eq!(
        uncontained.status.code(),
        Some(1),
        "the control did not receive the planted descriptors:\n{uncontained_stderr}"
    );
    assert!(
        uncontained_stderr.contains(&format!(
            "descriptors remained readable during initial: [{}, {}]",
            ordinary.as_raw_fd(),
            high.as_raw_fd()
        )),
        "the control did not observe both planted descriptors:\n{uncontained_stderr}"
    );

    let work = tempfile::tempdir().expect("work directory");
    // Canonical, because `$TMPDIR` reaches `/private` through a symbolic link and Seatbelt matches
    // the path the kernel resolves.
    let work = work
        .path()
        .canonicalize()
        .expect("canonical work directory");
    let mut command = launch(&work);
    let output = command
        .args([
            "--verify-no-inherited-handles",
            "initial",
            &ordinary_argument,
            &high_argument,
        ])
        .output()
        .expect("launch the containment trampoline");

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(
        output.status.code(),
        Some(0),
        "descriptor proof failed:\n{stderr}"
    );
    assert!(
        stderr.contains("no inherited handles survived containment or re-exec"),
        "the probe did not complete its post-reexec check:\n{stderr}"
    );
}

/// A standard stream redirected to a file no grant names is still statable inside the box.
///
/// `fstat` on an inherited descriptor is `file-read-metadata` on the vnode behind it, and the
/// profile knew nothing of a file the operator named on the command line. CPython 3.9 tests each
/// standard stream with `fstat` before it builds `sys.stdout`, so the stream was `None` and every
/// `print` was lost. The profile now names the regular files behind descriptors 0, 1, and 2 at
/// apply time, metadata only.
#[test]
fn a_standard_stream_redirected_outside_every_grant_is_statable() {
    let work = tempfile::tempdir().expect("work directory");
    let work = work
        .path()
        .canonicalize()
        .expect("canonical work directory");
    // A second directory the config never names, so the redirect target is outside every grant.
    let outside = tempfile::tempdir().expect("redirect directory");
    let redirected = outside
        .path()
        .canonicalize()
        .expect("canonical redirect directory")
        .join("agent.out");
    let target = std::fs::File::create(&redirected).expect("redirect target");

    let output = launch(&work)
        .arg("--report-standard-streams")
        .stdin(Stdio::null())
        .stdout(Stdio::from(target))
        .output()
        .expect("launch the containment trampoline");

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(
        output.status.code(),
        Some(0),
        "a standard stream refused fstat inside the box:\n{stderr}"
    );
    assert!(
        stderr.contains("standard stream 1: fstat ok, kind 100000"),
        "the redirected stdout was not reported as a statable regular file:\n{stderr}"
    );
}

/// The inherited Mach bootstrap right reaches no service, and the profile is what refuses it.
///
/// **The no-inherited-handle rule cannot be met literally here, and the measurement says why.** A
/// Mach right lives in the task's port namespace, `exec` preserves it, and no close-on-exec flag
/// applies to one — so a task holds a bootstrap right whatever the launch does, and the descriptor
/// sweep cannot touch it. What the profile carries instead is that the inherited right authorizes
/// nothing: it opens with `(deny default)` and grants no `mach-lookup`.
///
/// **The uncontained control is what attributes the refusal.** It runs the same lookups with no
/// containment, so a refusal inside the box is the profile answering rather than a service that is
/// absent or a name that is wrong. Without it a typo in a service name would pass as a refusal.
#[test]
fn the_inherited_mach_bootstrap_right_reaches_no_service() {
    const SERVICES: [&str; 3] = [
        "com.apple.pasteboard.1",
        "com.apple.system.notification_center",
        "com.apple.SecurityServer",
    ];

    let uncontained = Command::new(env!("CARGO_BIN_EXE_containment-test-probe"))
        .arg("--report-inherited-mach")
        .args(SERVICES)
        .output()
        .expect("launch the uncontained control");
    let uncontained = report_of(&uncontained);
    let reached: Vec<&str> = SERVICES
        .into_iter()
        .filter(|service| lookup_line(&uncontained, service).contains("code 0,"))
        .collect();
    // Every service, not merely one. A retired or misspelled name is unreachable without containment
    // too, so its refusal inside the box would measure nothing and pass anyway.
    assert_eq!(
        reached.len(),
        SERVICES.len(),
        "every named service must be reachable without containment, or its refusal inside the box \
         measures nothing; reached {reached:?} of {SERVICES:?}:\n{uncontained}"
    );

    let work = tempfile::tempdir().expect("work directory");
    let work = work
        .path()
        .canonicalize()
        .expect("canonical work directory");
    let mut command = launch(&work);
    let output = command
        .arg("--report-inherited-mach")
        .args(SERVICES)
        .output()
        .expect("launch the containment trampoline");
    let report = report_of(&output);

    let census = report
        .lines()
        .find(|line| line.starts_with("mach: inherited port rights:"))
        .unwrap_or_else(|| panic!("the census must report a right count:\n{report}"));
    assert!(
        report.contains("mach: bootstrap right present"),
        "the bootstrap right is the handle under measurement, so it must be held:\n{report}"
    );
    // Every service, not only the reachable ones: a lookup the control could not reach must stay
    // refused as well.
    for service in SERVICES {
        let line = lookup_line(&report, service);
        assert!(
            !line.contains("code 0,"),
            "the inherited bootstrap right reached {service}: {line}"
        );
        assert!(
            line.ends_with(", port 0"),
            "a refused lookup must return no port: {line}"
        );
    }
    println!("measured: {census}; reachable without containment: {reached:?}");
}

/// One service's lookup line, or a panic naming what the report held instead.
fn lookup_line<'report>(report: &'report str, service: &str) -> &'report str {
    let prefix = format!("mach: look up {service}:");
    report
        .lines()
        .find(|line| line.starts_with(&prefix))
        .unwrap_or_else(|| panic!("no lookup line for {service}:\n{report}"))
}

/// A box cannot push input into the terminal on descriptor 0, and the platform is what refuses it.
///
/// **Why measure at all.** The no-inherited-handle rule permits the standard streams, and the
/// profile grants `file-ioctl` on an inherited PTY slave because an interactive agent needs it.
/// `TIOCSTI` is the operation that would turn that permission into a write into the terminal's
/// *input* queue — the operator's next keystrokes — so the outcome is stated rather than assumed.
///
/// **The uncontained control is what attributes the refusal.** A refusal inside a box does not say
/// *what* refused: this operation is also unavailable to an ordinary process on a current macOS. So
/// the control runs the same probe on the same terminal with no containment at all, and the test
/// records which layer answered. It asserts the box is refused either way, because that is the claim
/// the rule needs; it does not assert the profile is the cause.
#[test]
fn a_box_cannot_inject_input_into_the_inherited_terminal() {
    let uncontained = {
        let (master, slave) = open_pseudo_terminal();
        let output = Command::new(env!("CARGO_BIN_EXE_containment-test-probe"))
            .arg("--attempt-terminal-injection")
            .stdin(Stdio::from(slave))
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
            .expect("launch the uncontained control");
        drop(master);
        report_of(&output)
    };
    assert!(
        uncontained.contains("tty: descriptor 0 is a terminal: true"),
        "the control needs a real terminal on descriptor 0:\n{uncontained}"
    );

    let (master, slave) = open_pseudo_terminal();
    let work = tempfile::tempdir().expect("work directory");
    let work = work
        .path()
        .canonicalize()
        .expect("canonical work directory");
    let mut command = launch(&work);
    // The terminal is the child's stdin alone, so its report arrives on a pipe and cannot be
    // confused with a byte the injection put into the terminal.
    let output = command
        .arg("--attempt-terminal-injection")
        .stdin(Stdio::from(slave))
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("launch the containment trampoline");
    drop(master);
    let contained = report_of(&output);

    assert!(
        contained.contains("tty: descriptor 0 is a terminal: true"),
        "the measurement needs a real terminal on descriptor 0:\n{contained}"
    );
    assert!(
        contained.contains("tty: TIOCSTI refused"),
        "a box pushed a byte into the terminal's input queue:\n{contained}"
    );
    assert!(
        !contained.contains("tty: the pushed byte came back as input"),
        "a byte a box pushed became terminal input:\n{contained}"
    );

    let refused_uncontained = uncontained.contains("tty: TIOCSTI refused");
    println!(
        "measured: the platform refuses TIOCSTI to an uncontained process: {refused_uncontained}"
    );
}

/// A pseudo-terminal, master first. The master must stay open for the slave to work.
fn open_pseudo_terminal() -> (OwnedFd, OwnedFd) {
    let mut master: libc::c_int = -1;
    let mut slave: libc::c_int = -1;
    // SAFETY: both out-parameters are live locals; no name, settings, or window size is requested.
    let opened = unsafe {
        libc::openpty(
            &mut master,
            &mut slave,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        )
    };
    assert_eq!(
        opened,
        0,
        "open a pseudo-terminal: {}",
        std::io::Error::last_os_error()
    );
    // SAFETY: `openpty` returned two fresh descriptors these values now own.
    unsafe { (OwnedFd::from_raw_fd(master), OwnedFd::from_raw_fd(slave)) }
}

/// One probe's report, both streams, with the launch asserted first.
///
/// A trampoline setup failure exits 2, 3, or 4 and prints no report at all, so a test asserting on
/// absent text would fail without naming the reason.
fn report_of(output: &Output) -> String {
    assert_eq!(
        output.status.code(),
        Some(0),
        "the measurement did not run:\nstdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

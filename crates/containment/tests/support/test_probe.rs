//! Single-threaded test probe binary for enforcement integration tests.
//!
//! Usage:
//!
//! ```text
//! containment-test-probe <config-json-file> <probe>...
//! ```
//!
//! On macOS, this exercises the full public
//! [`Containment::apply`](containment::Containment::apply) path, then runs each probe in-process
//! and exits:
//!
//! - `0`  — every probe behaved as its `expect-` prefix demanded
//! - `1`  — a probe outcome contradicted its expectation
//! - `2`  — usage / setup error (before apply)
//! - `3`  — apply() failed
//!
//! On Linux the mechanism is the namespace launcher, which the harness applies to a child rather
//! than to this process, so the Linux arm serves the child-side modes (`--unix-ipc`,
//! `--shell-child`, `--verify-no-inherited-handles`) and no probe list.
//!
//! Probe syntax (comma-free, one per argv slot):
//!
//! ```text
//! expect-ok:read:<path>          reading <path> must succeed
//! expect-deny:read:<path>        reading <path> must fail
//! expect-ok:write:<path>         writing <path> must succeed
//! expect-deny:write:<path>       writing <path> must fail
//! expect-ok:connect:<addr>       (macOS) TCP connect to <addr> (host:port) must succeed
//! expect-deny:connect:<addr>     (macOS) TCP connect to <addr> must fail
//! expect-ok:http:<host>[:port]   (macOS) HTTP CONNECT to <host> through $HTTP_PROXY,
//!                                then GET / carrying Authorization: Bearer
//!                                $HTTP_PHANTOM_TOKEN must return 200
//! expect-deny:http:<host>[:port] (macOS) same flow must fail (proxy 403, upstream
//!                                phantom rejection, or connect refused)
//! expect-deny:rmdir:<path>       (macOS) removing the directory <path> ITSELF must
//!                                fail; emptied first, so ENOTEMPTY cannot answer it
//! expect-deny:create-over:<path> (macOS) creating a symbolic link AT <path> must
//!                                fail. Counts only EPERM: Seatbelt decides create
//!                                authorization before existence, so an occupied
//!                                name still measures the rule, while EEXIST says
//!                                nothing about whether creating was permitted
//! expect-deny:chflags-uf:<path>  (macOS) setting UF_IMMUTABLE on <path> must fail
//! expect-deny:chflags-sf:<path>  (macOS) setting SF_IMMUTABLE on <path> must fail. Only
//!                                meaningful as root: an ordinary user is refused at the
//!                                privilege check, before the profile is consulted
//! expect-ok:exists-access:<path>  (macOS) access(<path>, F_OK) must answer that it exists
//! expect-deny:exists-access:<path> (macOS) the same call must be refused with EPERM. ENOENT is
//!                                inconclusive, not a pass: it is what an absent path reports
//!                                with no rule in play
//! expect-ok:exists-stat:<path>   (macOS) stat(<path>) must be refused with EPERM, which an
//!                                absent path reports too, so it discloses nothing
//! expect-deny:exists-stat:<path> (macOS) stat(<path>) returned ENOENT, so the errno has
//!                                disclosed that the path is absent
//! expect-deny:setuid-bit:<path>  (macOS) setting S_ISUID on <path> must not store the bit.
//!                                The verdict is the stored bit, not the return code: Seatbelt
//!                                fails `fchmodat(2)` with EPERM and lets `chmod(2)` return 0
//!                                while storing nothing
//! expect-deny:setgid-bit:<path>  (macOS) the S_ISGID counterpart. Attributable only when the
//!                                fixture controls the file's group, because POSIX lets the
//!                                kernel clear this bit silently
//! expect-deny:chmod-mode:<path>  (macOS) setting an ordinary permission bit on <path> must not
//!                                store it. A different Seatbelt operation from the two above,
//!                                so a cell may carry either without the other
//! expect-deny:chown-self:<path>  (macOS) moving <path> to another group this process belongs to
//!                                must not store it. The group moves and the owner does not,
//!                                because that is the one ownership change DAC grants an
//!                                ordinary caller
//! expect-deny:acl:<path>         (macOS) putting a deny-write entry in <path>'s access-control
//!                                list must not store it. Needs no root: the owner may set a list
//!                                on their own file, so a refusal is the profile answering
//! expect-deny:unlink:<path>      (macOS) removing the file <path> itself must fail. The file
//!                                cell's counterpart to rmdir on a write root
//! expect-ok:write-open-modes:<path>
//!                                (macOS) opening an EXISTING <path> for writing five ways —
//!                                O_WRONLY, +O_TRUNC, +O_CREAT, +O_CREAT|O_TRUNC, +O_APPEND —
//!                                must all write. A canary on the file cell's create deny: it
//!                                measures the kernel rather than the rendering, so removing the
//!                                deny leaves it green
//! ```
//!
//! The view verbs below measure whether the contained process can build a second view of the
//! surrounding OS. Each one reports an inconclusive outcome as an `Err` rather than as a
//! refusal, because every route here fails for a second reason as an ordinary user:
//!
//! ```text
//! expect-deny:read-errno:<path>            reading <path> must fail with EPERM or EACCES.
//!                                          An absent target is an Err, so ENOENT cannot
//!                                          answer a refusal assertion
//! expect-deny:sandbox-loosen:<path>        a second raw sandbox_init carrying
//!                                          "(allow default)" must not make <path> readable
//! expect-deny:link:<src>|<dst>             hard-linking <src> to <dst> must not put the
//!                                          source's bytes inside a granted path
//! expect-deny:symlink-escape:<link>|<to>   a symbolic link the process creates at <link>
//!                                          must not read <to> through it
//! expect-deny:openat-escape:<dir>|<rel>    <rel>, resolved from a descriptor on <dir>,
//!                                          must not escape the grant on <dir>
//! expect-deny:mach-lookup:<service>        the Mach service <service> must not answer, so
//!                                          no root daemon mounts on the box's behalf
//! expect-deny:mount:<path>                 mount(2) over <path> must fail
//! expect-deny:unmount:<path>               unmount(2) of <path> must fail
//! expect-deny:chroot:<path>                chroot(2) to <path> must fail
//! ```
//!
//! The last three reach the privilege check before the profile, so as an ordinary user they
//! measure `euid` rather than the rule. `measure-i3-as-root.sh` beside this file drives the
//! `chroot` leg, on the pattern `chflags-sf` already follows. `containment/AGENTS.md` states why
//! `mount` and `unmount` have no root probe.
//!
//! The two path-identity verbs above pair with the fixed profile's denies on the home
//! literal: a `(subpath X)` grant covers `X` itself, so they are what distinguishes
//! "the Agent owns its home's contents" from "the Agent may replace the home". One verb
//! per rule — `rmdir` measures the unlink deny, `create-over` the create deny — so each
//! is separately falsifiable.
//!
//! `chmod-mode`, `chown-self`, and `acl` each refuse a target this process does not own, because
//! all three operations are owner-or-root and DAC would answer before the profile did.
//!
//! The two `chflags` verbs pair with the write cells' flags deny, one per flag class, and
//! `measure-sf-flags-as-root.sh` beside this file drives the root half. `containment/AGENTS.md`
//! states what each measures and which outcomes are inconclusive.
//!
//! The write-xor-exec verbs below measure whether a file the contained process **wrote** into a
//! granted write root is then executable, or mappable as code. Each one writes its destination from
//! a seed the caller names, because an exec grant renders `file-read-metadata` and never
//! `file-read*`, so the probe cannot read its own image to copy:
//!
//! ```text
//! expect-deny:exec-written:<seed>|<dst>  copy <seed> to <dst> at mode 0700, then exec <dst>. The
//!                                        child is this same binary invoked as `--exec-target`,
//!                                        which exits 0 and touches nothing, so a zero exit is the
//!                                        bytes having run. An exec failing with anything but
//!                                        EPERM is an Err
//! expect-deny:map-exec:<seed>|<dst>      copy <seed> to <dst>, then mmap it PROT_READ|PROT_EXEC.
//!                                        The mapped pages are never touched, so this measures the
//!                                        MAPPING authority and never whether the bytes would run
//! expect-deny:dlopen-written:<seed>|<dst> copy <seed> to <dst>, then dlopen it. <seed> must be a
//!                                        dynamic library, and this is the route that matters for
//!                                        the library-load half of write-xor-exec: dyld maps executable
//!                                        where a plain mmap on this platform cannot
//! expect-ok:dlopen:<path>                load <path>, writing nothing. The BOUND on the rule
//!                                        above: a read-only root must keep loading libraries, or
//!                                        the deny is a refuse-all rather than one path subtracted
//! ```
//!
//! Every deny verb here needs its `--uncontained` control, because macOS code signing and the
//! profile both answer `EPERM`: a refusal inside a box says which layer refused only when the same
//! route is permitted outside one. `run-i1-matrix.sh` beside this file drives every route, controls
//! included.
//!
//! Three macOS modes measure what a box inherits. Each is a flag rather than a probe spec,
//! because a spec runs after this process contains *itself* and therefore never `exec`s, so it
//! cannot observe what survives program replacement. The trampoline launches these instead:
//!
//! ```text
//! --verify-no-inherited-handles <initial|reexec> <fd> <fd>
//!                                  the two planted descriptors must be gone, and the census must
//!                                  hold only the standard streams, before and after one re-exec
//! --report-inherited-mach <service>...
//!                                  print the inherited Mach port right count, whether the
//!                                  bootstrap right is present, and one `bootstrap_look_up` result
//!                                  per service. A measurement: it always exits 0
//! --attempt-terminal-injection     push one byte into the terminal on descriptor 0 with
//!                                  `TIOCSTI`, then report whether it came back as input. A
//!                                  measurement: it always exits 0
//! ```
//!
//! Builds on Windows/other targets emit a stub `main` that prints and exits with
//! code 2, preserving the binary target's build on any host without an
//! enforcement backend.

use std::process::ExitCode;

#[cfg(target_os = "macos")]
fn main() -> ExitCode {
    macos_main()
}

#[cfg(target_os = "linux")]
fn main() -> ExitCode {
    linux_main()
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
fn main() -> ExitCode {
    eprintln!("containment-test-probe: only implemented on macOS and Linux");
    ExitCode::from(2)
}

#[cfg(target_os = "macos")]
fn macos_main() -> ExitCode {
    use containment::{Containment, ContainmentConfig, ContainmentError};

    let args: Vec<String> = std::env::args().collect();

    // `--victim <fifo>` mode: do NOT contain this process. Park it alive with a
    // marker secret in its environment so an enforcement test can try to read
    // its argv/env across the sandbox boundary. Opening a FIFO for read blocks
    // until a writer arrives; the test never opens the write end, so the victim
    // stays alive until killed.
    //
    // The victim must be this binary rather than a system tool: macOS redacts
    // cross-process environments for PLATFORM binaries (`/bin/sleep` yields
    // argv only), so a platform victim would make the leak test pass while the
    // leak was live. This binary is an unsigned Cargo artifact — the same class
    // as the supervisor whose secrets are actually at risk.
    if args.len() == 3 && args[1] == "--victim" {
        eprintln!("victim: parking on {}", args[2]);
        let _ = std::fs::File::open(&args[2]);
        return ExitCode::SUCCESS;
    }

    // `--exec-target` mode: the program `exec-written` tries to run. It exits 0 and touches
    // nothing, so the caller reads "the written bytes executed" off a zero exit rather than off
    // `exec` merely returning. It must come before the usage check below, because it takes one
    // argument.
    if args.len() == 2 && args[1] == "--exec-target" {
        return ExitCode::SUCCESS;
    }

    // `--uncontained <probe>...` mode: run each probe with NO containment applied. This is the
    // control half of a deny measurement. A refusal inside a box says nothing on its own, because
    // an absent path and an unreachable service fail the same way for every caller.
    if args.len() >= 3 && args[1] == "--uncontained" {
        let probes: Vec<&str> = args[2..].iter().map(String::as_str).collect();
        if let Err(refusal) = control_probes_only(&probes) {
            eprintln!("probe: {refusal}");
            return ExitCode::from(2);
        }
        eprintln!("uncontained: no containment applied");
        return run_all(&probes);
    }

    // The three inherited-handle modes. Each runs as the trampoline's exec target, so containment
    // is already applied and this process holds exactly what a box inherits. None of them applies
    // containment again, and none reads a config file.
    match args.get(1).map(String::as_str) {
        Some("--unix-ipc") => return unix_ipc(&args[2..]),
        Some("--shell-child") => return shell_child(&args[2..]),
        Some("--verify-no-inherited-handles") => return verify_no_inherited_handles(&args),
        Some("--report-inherited-mach") => return report_inherited_mach(&args[2..]),
        Some("--attempt-terminal-injection") => return attempt_terminal_injection(b'X'),
        Some("--report-standard-streams") => return report_standard_streams(),
        _ => {}
    }

    if args.len() < 3 {
        eprintln!(
            "usage: containment-test-probe <config-json-file> <probe>...\n   \
             or: containment-test-probe --victim <fifo-path>\n   \
             or: containment-test-probe --uncontained <probe>...\n   \
             or: containment-test-probe --exec-target"
        );
        return ExitCode::from(2);
    }

    // Parse the containment config (always first positional arg).
    let config_json = match std::fs::read_to_string(&args[1]) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("probe: cannot read config file {}: {e}", args[1]);
            return ExitCode::from(2);
        }
    };
    let config = match ContainmentConfig::from_json(&config_json) {
        Ok(config) => config,
        Err(e) => {
            eprintln!("probe: cannot load config: {e}");
            return ExitCode::from(2);
        }
    };

    let probes: Vec<&str> = args[2..].iter().map(String::as_str).collect();

    // Detect the host backend and contain THIS process in one operation. This
    // exercises exactly the path `strands-box-contain-trampoline` takes in production.
    // No egress handoff: the probe exercises the macOS Seatbelt path, which pins the
    // workload to the proxy port directly and has no namespace to relay across; and no
    // exec-confirm fd (that signal is only read by the Linux reaper path).
    match Containment::apply(&config, None, None) {
        Ok(()) => {}
        Err(e @ ContainmentError::PlatformUnsupported { .. }) => {
            eprintln!("probe: containment refused: {e}");
            return ExitCode::from(2);
        }
        Err(e) => {
            eprintln!("probe: apply failed: {e}");
            return ExitCode::from(3);
        }
    };

    // Run probes (sandbox is now enforced).
    run_all(&probes)
}

fn unix_ipc(args: &[String]) -> ExitCode {
    use std::io::{Read as _, Write as _};
    use std::os::unix::net::{UnixListener, UnixStream};
    use std::path::Path;

    println!("IPC_READY");
    let result = (|| -> std::io::Result<()> {
        match args[0].as_str() {
            "connect" => {
                let _stream = UnixStream::connect(&args[1])?;
            }
            "roundtrip" => {
                let listener = UnixListener::bind(&args[1])?;
                listener.set_nonblocking(true)?;
                let mut client = UnixStream::connect(&args[1])?;
                let (mut server, _) = listener.accept()?;
                server.set_read_timeout(Some(std::time::Duration::from_secs(2)))?;
                assert_eq!(
                    listener.local_addr()?.as_pathname(),
                    Some(Path::new(&args[1]))
                );
                assert_eq!(client.peer_addr()?.as_pathname(), Some(Path::new(&args[1])));
                client.write_all(b"ipc")?;
                let mut bytes = [0; 3];
                server.read_exact(&mut bytes)?;
                assert_eq!(&bytes, b"ipc");
            }
            _ => return Err(std::io::Error::other("unknown IPC probe")),
        }
        Ok(())
    })();
    match result {
        Ok(()) => {
            println!("IPC_OK");
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("IPC_ERROR errno={:?}: {error}", error.raw_os_error());
            ExitCode::from(1)
        }
    }
}

fn shell_child(args: &[String]) -> ExitCode {
    println!("CHILD_READY");
    match std::process::Command::new("/bin/sh")
        .args([
            "-c",
            "/bin/bash -c 'printf hooked > \"$1\"; if read -r value < \"$2\"; then exit 44; fi' child \"$1\" \"$2\"",
            "child",
            &args[0],
            &args[1],
        ])
        .status()
    {
        Ok(status) if status.success() => ExitCode::SUCCESS,
        Ok(_) => ExitCode::from(1),
        Err(error) => {
            eprintln!("CHILD_ERROR: {error}");
            ExitCode::from(1)
        }
    }
}

/// Refuse any probe that `--uncontained` must not run.
///
/// Two classes are refused. An `expect-deny` measures no rule with no containment applied, and for
/// `mach-lookup` it would even pass. A side-effecting verb would reach the operator's real machine
/// with no sandbox between, and `chroot` or `unmount` there is not a control.
///
/// **The four write-xor-exec verbs are on the list, and they are the exception the rule allows.**
/// Each writes a file, one creates a process, and one loads code, so none is read-only. Without the
/// control they measure nothing: macOS code signing and the profile both answer `EPERM`, so a
/// refusal inside a box does not say which layer refused.
///
/// **What bounds them is `write_executable_copy` refusing a destination that already exists**, so no
/// verb here can overwrite a file of the operator's. The destination being caller-named is not the
/// bound — `exec-written` runs bytes from a caller-named seed with no sandbox between.
#[cfg(target_os = "macos")]
fn control_probes_only(probes: &[&str]) -> Result<(), String> {
    const CONTROL_VERBS: [&str; 7] = [
        "read",
        "read-errno",
        "mach-lookup",
        "exec-written",
        "map-exec",
        "dlopen-written",
        "dlopen",
    ];

    for probe in probes {
        let (expectation, rest) = probe
            .split_once(':')
            .ok_or_else(|| format!("malformed probe: {probe}"))?;
        if expectation != "expect-ok" {
            return Err(format!(
                "--uncontained runs controls, so it takes expect-ok only: {probe}"
            ));
        }
        let verb = rest.split(':').next().unwrap_or_default();
        if !CONTROL_VERBS.contains(&verb) {
            return Err(format!(
                "--uncontained runs {} and nothing else, because every other verb changes the \
                 operator's own machine with no sandbox between: {probe}",
                CONTROL_VERBS.join(", ")
            ));
        }
    }
    Ok(())
}

/// Run each probe in order, and stop at the first outcome that contradicts its expectation.
#[cfg(target_os = "macos")]
fn run_all(probes: &[&str]) -> ExitCode {
    for probe in probes {
        let ok = match run_probe(probe) {
            Ok(ok) => ok,
            Err(msg) => {
                eprintln!("probe: {msg}");
                return ExitCode::from(2);
            }
        };
        if !ok {
            eprintln!("probe FAILED: {probe}");
            return ExitCode::from(1);
        }
        eprintln!("probe ok: {probe}");
    }

    ExitCode::SUCCESS
}

// ── No inherited handles: the macOS measurements ──────────────────────────────────────────────

/// The macOS descriptor proof. The trampoline applied containment and exec'd this image, so what
/// this process holds is what a box inherits.
#[cfg(target_os = "macos")]
fn verify_no_inherited_handles(args: &[String]) -> ExitCode {
    use std::os::unix::process::CommandExt as _;

    if args.len() != 5 || !matches!(args[2].as_str(), "initial" | "reexec") {
        eprintln!(
            "usage: containment-test-probe --verify-no-inherited-handles \
             <initial|reexec> <ordinary-fd> <high-fd>"
        );
        return ExitCode::from(2);
    }
    let phase = args[2].as_str();

    let sentinels = match (args[3].parse::<i32>(), args[4].parse::<i32>()) {
        (Ok(ordinary), Ok(high)) => [ordinary, high],
        _ => {
            eprintln!("probe: inherited handle numbers must be decimal integers");
            return ExitCode::from(2);
        }
    };
    let readable: Vec<i32> = sentinels
        .into_iter()
        .filter(|descriptor| {
            let mut byte = 0_u8;
            // SAFETY: `byte` is writable for one byte, and `descriptor` is only probed.
            let result = unsafe {
                libc::read(
                    *descriptor,
                    (&mut byte as *mut u8).cast::<libc::c_void>(),
                    1,
                )
            };
            result != -1 || std::io::Error::last_os_error().raw_os_error() != Some(libc::EBADF)
        })
        .collect();
    if !readable.is_empty() {
        eprintln!(
            "probe FAILED: inherited descriptors remained readable during {phase}: {readable:?}"
        );
        return ExitCode::from(1);
    }

    let open = match open_descriptors() {
        Ok(open) => open,
        Err(reason) => {
            eprintln!("probe: {reason}");
            return ExitCode::from(2);
        }
    };
    // The census must enumerate before its emptiness means anything: stderr is open, so it appears.
    // Without this an unavailable census would find no leak and read as a pass.
    if !open.contains(&libc::STDERR_FILENO) {
        eprintln!("probe: the census found no stderr during {phase}, so it enumerated nothing");
        return ExitCode::from(2);
    }
    let unexpected: Vec<i32> = open
        .into_iter()
        .filter(|descriptor| *descriptor > libc::STDERR_FILENO)
        .collect();
    if !unexpected.is_empty() {
        eprintln!("probe FAILED: unexpected descriptors survived during {phase}: {unexpected:?}");
        return ExitCode::from(1);
    }

    if phase == "reexec" {
        eprintln!("probe ok: no inherited handles survived containment or re-exec");
        return ExitCode::SUCCESS;
    }

    let error = std::process::Command::new(&args[0])
        .args([
            "--verify-no-inherited-handles",
            "reexec",
            &args[3],
            &args[4],
        ])
        .exec();
    eprintln!("probe: re-exec failed: {error}");
    ExitCode::from(2)
}

/// Every descriptor this process holds, standard streams included.
///
/// The box grants no read on `/dev/fd`, so this asks the kernel about this process rather than
/// reading a directory. The profile permits `process-info*` on `(target self)`.
#[cfg(target_os = "macos")]
fn open_descriptors() -> Result<Vec<i32>, String> {
    let pid = libc::c_int::try_from(std::process::id()).map_err(|error| {
        format!("this process's id does not fit a descriptor argument: {error}")
    })?;
    // SAFETY: a null buffer of size zero asks only how many bytes the list needs.
    let needed =
        unsafe { libc::proc_pidinfo(pid, libc::PROC_PIDLISTFDS, 0, std::ptr::null_mut(), 0) };
    if needed <= 0 {
        // The list is unavailable, so sweep the table rather than report an empty census.
        return swept_descriptors();
    }
    // Headroom, because the table can grow between the two calls.
    let capacity = usize::try_from(needed / libc::PROC_PIDLISTFD_SIZE).unwrap_or_default() + 16;
    let mut buffer = vec![
        libc::proc_fdinfo {
            proc_fd: 0,
            proc_fdtype: 0,
        };
        capacity
    ];
    let size = libc::c_int::try_from(capacity * std::mem::size_of::<libc::proc_fdinfo>())
        .map_err(|error| format!("the descriptor list is larger than one call reports: {error}"))?;
    // SAFETY: `buffer` owns `size` writable bytes for the duration of the call.
    let written = unsafe {
        libc::proc_pidinfo(
            pid,
            libc::PROC_PIDLISTFDS,
            0,
            buffer.as_mut_ptr().cast::<libc::c_void>(),
            size,
        )
    };
    // A full buffer means the list may be truncated, and a census that under-reports is the one
    // failure this whole test rests on not having. Sweep instead of trusting it.
    if written <= 0 || written >= size {
        return swept_descriptors();
    }
    let reported = usize::try_from(written / libc::PROC_PIDLISTFD_SIZE).unwrap_or_default();
    Ok(buffer[..reported.min(capacity)]
        .iter()
        .map(|entry| entry.proc_fd)
        .filter(|descriptor| descriptor_is_open(*descriptor))
        .collect())
}

/// Every open descriptor, found by probing each number in the table.
#[cfg(target_os = "macos")]
fn swept_descriptors() -> Result<Vec<i32>, String> {
    // SAFETY: `getdtablesize` takes no argument and only reports a limit.
    let maximum = unsafe { libc::getdtablesize() };
    if maximum < 0 {
        return Err(format!(
            "cannot read the descriptor table size: {}",
            std::io::Error::last_os_error()
        ));
    }
    Ok((0..maximum).filter(|d| descriptor_is_open(*d)).collect())
}

/// Whether one descriptor number is open.
#[cfg(target_os = "macos")]
fn descriptor_is_open(descriptor: i32) -> bool {
    // SAFETY: `F_GETFD` only inspects a descriptor number.
    unsafe { libc::fcntl(descriptor, libc::F_GETFD) != -1 }
}

/// `mach/task_special_ports.h`.
#[cfg(target_os = "macos")]
const TASK_BOOTSTRAP_PORT: libc::c_int = 4;

// These are in libSystem. `libc` names none of the three calls, and its `mach_task_self` wrapper is
// deprecated in favour of a separate crate, so the underlying global is declared here instead.
#[cfg(target_os = "macos")]
unsafe extern "C" {
    static mach_task_self_: libc::mach_port_t;
    fn task_get_special_port(
        task: libc::mach_port_t,
        which: libc::c_int,
        port: *mut libc::mach_port_t,
    ) -> libc::c_int;
    fn mach_port_names(
        task: libc::mach_port_t,
        names: *mut *mut libc::c_uint,
        names_count: *mut libc::c_uint,
        types: *mut *mut libc::c_uint,
        types_count: *mut libc::c_uint,
    ) -> libc::c_int;
    fn bootstrap_look_up(
        bootstrap: libc::mach_port_t,
        service: *const libc::c_char,
        port: *mut libc::mach_port_t,
    ) -> libc::c_int;
}

/// Report the Mach port rights this process inherited, and what the bootstrap right reaches.
///
/// A measurement rather than an assertion. A Mach right lives in the task's port namespace, `exec`
/// preserves it, and no close-on-exec flag applies to one — so the count is never zero and "no
/// inherited Mach handle" is not a reachable state on this platform. What a test can pin is that
/// the inherited bootstrap right reaches no service.
#[cfg(target_os = "macos")]
fn report_inherited_mach(services: &[String]) -> ExitCode {
    let mut names: *mut libc::c_uint = std::ptr::null_mut();
    let mut names_count: libc::c_uint = 0;
    let mut types: *mut libc::c_uint = std::ptr::null_mut();
    let mut types_count: libc::c_uint = 0;
    // SAFETY: every out-parameter is a live local, and the call only writes through them.
    let listed = unsafe {
        mach_port_names(
            mach_task_self_,
            &mut names,
            &mut names_count,
            &mut types,
            &mut types_count,
        )
    };
    if listed == 0 {
        println!("mach: inherited port rights: {names_count}");
    } else {
        println!("mach: port right census unavailable: kern_return {listed}");
    }

    let mut bootstrap: libc::mach_port_t = 0;
    // SAFETY: `bootstrap` is a live local the call writes through.
    let held =
        unsafe { task_get_special_port(mach_task_self_, TASK_BOOTSTRAP_PORT, &mut bootstrap) };
    if held != 0 || bootstrap == 0 {
        println!("mach: bootstrap right absent: kern_return {held}");
        return ExitCode::SUCCESS;
    }
    println!("mach: bootstrap right present");

    for service in services {
        let Ok(name) = std::ffi::CString::new(service.as_str()) else {
            println!("mach: service name {service} holds a NUL");
            continue;
        };
        let mut port: libc::mach_port_t = 0;
        // SAFETY: `name` outlives the call, and `port` is a live local it writes through.
        let code = unsafe { bootstrap_look_up(bootstrap, name.as_ptr(), &mut port) };
        println!("mach: look up {service}: code {code}, port {port}");
    }
    ExitCode::SUCCESS
}

/// Report `fstat` on each standard stream, as the trampoline's exec target.
#[cfg(target_os = "macos")]
fn report_standard_streams() -> ExitCode {
    let mut refused = false;
    for descriptor in [libc::STDIN_FILENO, libc::STDOUT_FILENO, libc::STDERR_FILENO] {
        // SAFETY: `stat` is a plain C struct, and `fstat` writes only into it.
        let mut stat: libc::stat = unsafe { std::mem::zeroed() };
        // SAFETY: the descriptor is a number, and `stat` is writable for the call.
        if unsafe { libc::fstat(descriptor, &raw mut stat) } == 0 {
            eprintln!(
                "standard stream {descriptor}: fstat ok, kind {:o}",
                stat.st_mode & libc::S_IFMT
            );
        } else {
            refused = true;
            eprintln!(
                "standard stream {descriptor}: fstat refused: {}",
                std::io::Error::last_os_error()
            );
        }
    }
    if refused {
        ExitCode::from(1)
    } else {
        ExitCode::SUCCESS
    }
}

/// Push one byte into the terminal on descriptor 0 as if the operator typed it, then report whether
/// it came back as input.
///
/// A measurement rather than an assertion. Descriptor 0 is a permitted inherited handle, and this
/// states what that permission carries when the descriptor is the operator's own terminal.
#[cfg(target_os = "macos")]
fn attempt_terminal_injection(byte: u8) -> ExitCode {
    // `_IOW('t', 114, char)`, which `libc` does not name for this target.
    const TIOCSTI: libc::c_ulong = 0x8001_7472;

    // SAFETY: `isatty` only inspects a descriptor number.
    let terminal = unsafe { libc::isatty(libc::STDIN_FILENO) } == 1;
    println!("tty: descriptor 0 is a terminal: {terminal}");

    // SAFETY: the request reads one byte through the pointer, and `byte` is a live local.
    let pushed = unsafe {
        libc::ioctl(
            libc::STDIN_FILENO,
            TIOCSTI,
            std::ptr::from_ref(&byte).cast::<libc::c_void>(),
        )
    };
    if pushed != 0 {
        println!("tty: TIOCSTI refused: {}", std::io::Error::last_os_error());
        return ExitCode::SUCCESS;
    }
    println!("tty: TIOCSTI accepted");

    // Read back without blocking, so a refused injection does not hang the measurement.
    let mut poll = libc::pollfd {
        fd: libc::STDIN_FILENO,
        events: libc::POLLIN,
        revents: 0,
    };
    // SAFETY: one live `pollfd`, and a bounded wait.
    let ready = unsafe { libc::poll(&mut poll, 1, 500) };
    if ready != 1 {
        println!("tty: the pushed byte did not come back as input");
        return ExitCode::SUCCESS;
    }
    let mut back = 0_u8;
    // SAFETY: `back` is writable for one byte.
    let read = unsafe {
        libc::read(
            libc::STDIN_FILENO,
            (&mut back as *mut u8).cast::<libc::c_void>(),
            1,
        )
    };
    if read == 1 && back == byte {
        println!("tty: the pushed byte came back as input");
    } else {
        println!("tty: the read after the push returned {read}, byte {back}");
    }
    ExitCode::SUCCESS
}

/// Linux entry point. The Linux mechanism is the namespace launcher, which the harness applies to
/// a child rather than to this process, so this arm serves the child-side modes only.
#[cfg(target_os = "linux")]
fn linux_main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("--unix-ipc") => unix_ipc(&args[2..]),
        Some("--shell-child") => shell_child(&args[2..]),
        Some("--verify-no-inherited-handles") => verify_no_inherited_handles(&args),
        Some("--refused-calls") => refused_calls(),
        Some("--report-handles") => report_handles(&args[2..]),
        _ => {
            eprintln!(
                "usage: containment-test-probe \
                 (--unix-ipc | --shell-child | --verify-no-inherited-handles | --refused-calls \
                 | --report-handles <relay-fd>) ..."
            );
            ExitCode::from(2)
        }
    }
}

/// Make two calls the filter refuses and print each errno: an argument-scoped one and an unlisted
/// one.
#[cfg(target_os = "linux")]
fn refused_calls() -> ExitCode {
    // SAFETY: plain syscalls with scalar arguments.
    let socket = unsafe { libc::socket(libc::AF_PACKET, libc::SOCK_RAW, 0) };
    let socket_errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
    // SAFETY: `bpf` with a null attribute pointer is refused before it is read.
    let bpf = unsafe { libc::syscall(libc::SYS_bpf, 0, std::ptr::null::<u8>(), 0) };
    let bpf_errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
    println!("socket rc={socket} errno={socket_errno}");
    println!("bpf rc={bpf} errno={bpf_errno}");
    ExitCode::SUCCESS
}

/// Print how many open descriptors are seccomp listeners, and whether `relay` is open.
#[cfg(target_os = "linux")]
fn report_handles(args: &[String]) -> ExitCode {
    let relay: i32 = args.first().and_then(|a| a.parse().ok()).unwrap_or(-1);
    let mut listeners = 0;
    let mut relay_open = false;
    for entry in std::fs::read_dir("/proc/self/fd")
        .expect("fd table")
        .flatten()
    {
        let target = std::fs::read_link(entry.path()).unwrap_or_default();
        if target.to_string_lossy().contains("seccomp notify") {
            listeners += 1;
        }
        if entry.file_name().to_string_lossy() == relay.to_string() {
            relay_open = true;
        }
    }
    println!("listeners={listeners} relay_open={relay_open}");
    ExitCode::SUCCESS
}

#[cfg(target_os = "linux")]
fn verify_no_inherited_handles(args: &[String]) -> ExitCode {
    use std::os::unix::process::CommandExt as _;

    if args.len() != 5 || !matches!(args[2].as_str(), "initial" | "reexec") {
        eprintln!(
            "usage: containment-test-probe --verify-no-inherited-handles \
             <initial|reexec> <ordinary-fd> <high-fd>"
        );
        return ExitCode::from(2);
    }

    let sentinels = match (args[3].parse::<i32>(), args[4].parse::<i32>()) {
        (Ok(ordinary), Ok(high)) => [ordinary, high],
        _ => {
            eprintln!("probe: inherited handle numbers must be decimal integers");
            return ExitCode::from(2);
        }
    };

    let readable: Vec<i32> = sentinels
        .into_iter()
        .filter(|descriptor| {
            let mut byte = 0_u8;
            // SAFETY: `byte` is writable for one byte, and `descriptor` is only probed.
            let result = unsafe {
                libc::read(
                    *descriptor,
                    (&mut byte as *mut u8).cast::<libc::c_void>(),
                    1,
                )
            };
            result != -1 || std::io::Error::last_os_error().raw_os_error() != Some(libc::EBADF)
        })
        .collect();
    if !readable.is_empty() {
        eprintln!(
            "probe FAILED: inherited descriptors remained readable during {}: {readable:?}",
            args[2]
        );
        return ExitCode::from(1);
    }

    let entries = match std::fs::read_dir("/proc/self/fd") {
        Ok(entries) => entries,
        Err(error) => {
            eprintln!("probe: cannot enumerate /proc/self/fd: {error}");
            return ExitCode::from(2);
        }
    };
    let candidates: Vec<i32> = entries
        .flatten()
        .filter_map(|entry| entry.file_name().to_str()?.parse().ok())
        .collect();
    // The census must enumerate before its emptiness means anything: stderr is open, so it appears.
    // Without this an unreadable directory would find no leak and read as a pass.
    if !candidates.contains(&libc::STDERR_FILENO) {
        eprintln!(
            "probe: the census found no stderr during {}, so it enumerated nothing",
            args[2]
        );
        return ExitCode::from(2);
    }
    let unexpected: Vec<i32> = candidates
        .into_iter()
        .filter(|descriptor| *descriptor > libc::STDERR_FILENO)
        // The directory descriptor appears in its own listing, but is closed when collection ends.
        .filter(|descriptor| unsafe { libc::fcntl(*descriptor, libc::F_GETFD) } != -1)
        .collect();
    if !unexpected.is_empty() {
        eprintln!(
            "probe FAILED: unexpected descriptors survived during {}: {unexpected:?}",
            args[2]
        );
        return ExitCode::from(1);
    }

    if args[2] == "reexec" {
        eprintln!("probe ok: no inherited handles survived containment or re-exec");
        return ExitCode::SUCCESS;
    }

    let error = std::process::Command::new(&args[0])
        .args([
            "--verify-no-inherited-handles",
            "reexec",
            &args[3],
            &args[4],
        ])
        .exec();
    eprintln!("probe: re-exec failed: {error}");
    ExitCode::from(2)
}

#[cfg(target_os = "macos")]
fn run_probe(spec: &str) -> Result<bool, String> {
    let (expectation, rest) = spec
        .split_once(':')
        .ok_or_else(|| format!("malformed probe: {spec}"))?;
    let expect_ok = match expectation {
        "expect-ok" => true,
        "expect-deny" => false,
        other => return Err(format!("unknown expectation: {other}")),
    };

    let (op, target) = rest
        .split_once(':')
        .ok_or_else(|| format!("malformed probe operation: {rest}"))?;

    let succeeded = match op {
        "read" => read_probe(target),
        "write" => std::fs::write(target, b"containment-test-probe").is_ok(),
        // Enumerate a directory's entries, which is what a `List` grant permits and a `Read` grant
        // also carries; reading a file's bytes under a `List` grant is the separate `read` probe.
        "list" => std::fs::read_dir(target)
            .map(|entries| entries.count() > 0)
            .unwrap_or(false),
        "connect" => {
            use std::net::TcpStream;
            use std::time::Duration;
            match target.parse::<std::net::SocketAddr>() {
                Ok(addr) => TcpStream::connect_timeout(&addr, Duration::from_secs(2)).is_ok(),
                Err(e) => return Err(format!("bad addr {target}: {e}")),
            }
        }
        "http" => http_probe(target)?,
        // `procargs:self` reads this process's own argv/environment,
        // `procargs:child` a child forked inside this same box, and
        // `procargs:<pid>` a foreign process's. Under
        // ProcessInfoMode::Isolated the first two must succeed and the last must
        // be denied — a foreign read recovers the supervisor's real `env://`
        // secrets out of its environment.
        "procargs" => match target {
            "self" => procargs_probe(std::process::id() as libc::pid_t),
            "child" => procargs_child_probe(),
            other => procargs_probe(
                other
                    .parse::<libc::pid_t>()
                    .map_err(|e| format!("bad pid {other}: {e}"))?,
            ),
        },
        // Replacing a granted directory itself, rather than writing inside it. A
        // `(subpath X)` grant covers `X` as well as its descendants, so these are the
        // operations that decide whether the granted path keeps its identity. Called
        // directly rather than through a shell: the profile grants one exec literal, so
        // `rmdir`/`ln` are unreachable as executables and `/bin/sh` cannot even boot
        // (it re-execs `/bin/bash` through `/private/var/select/sh`, which is denied).
        //
        // One verb per profile rule, so each is separately falsifiable: `rmdir` measures
        // the unlink deny and `create-over` the create deny. A single combined probe
        // could not tell them apart — with unlink denied the directory survives, so the
        // create attempt returns `EEXIST` and the probe passes whether or not creating
        // was permitted.
        "rmdir" => rmdir_probe(target),
        "create-over" => create_over_probe(target),
        // Setting a BSD file flag inside a granted write root. One verb per flag class,
        // because the two are refused by different layers when the caller is not root and
        // a single verb could not say which layer answered: the owner class reaches the
        // profile, and the super-user class is refused at the privilege check first. Run
        // as root the privilege check passes and both reach the profile, which is what
        // makes `chflags-sf` a measurement of the deny rather than of `euid`.
        "chflags-uf" => chflags_probe(target, libc::UF_IMMUTABLE)?,
        "chflags-sf" => chflags_probe(target, libc::SF_IMMUTABLE)?,
        // Existence, over the two operations that answer it. One verb per operation, because
        // they answer differently and a combined verb could not say which one leaked: denying
        // by default leaves `access` permitted, and `stat` distinguishes a refusal from an
        // absence by errno alone. `containment/AGENTS.md` holds the measurement.
        "exists-access" => exists_access_probe(target)?,
        "exists-stat" => exists_stat_probe(target)?,
        // Setting a set-user-ID bit inside a granted write root. Unlike the super-user flag
        // class this needs no root: the owner may set it on their own file, so a refusal is the
        // profile answering rather than the privilege check.
        "setuid-bit" => chmod_bit_probe(target, libc::S_ISUID)?,
        // The group counterpart, unwired for the same reason `chflags-sf` is: POSIX lets the
        // kernel clear this bit silently when the caller is not in the file's group, so a
        // refusal here cannot be attributed to the profile. It exists for a measured run whose
        // fixture controls the group.
        "setgid-bit" => chmod_bit_probe(target, libc::S_ISGID)?,
        // An ORDINARY permission bit, which is what separates `file-write-mode` from the two
        // above: they are one Seatbelt operation and this is another, so a cell may carry either
        // without the other. The group-write bit is arbitrary and carries no authority itself.
        "chmod-mode" => chmod_bit_probe(target, 0o020)?,
        // Changing the target's group to one this process already belongs to. Ownership is the
        // authority `file-write-owner` carries, and a group the caller holds is the one change
        // DAC permits them, so a refusal is the profile answering.
        "chown-self" => chown_probe(target)?,
        // Putting a deny entry in the target's access-control list. This reaches the same harm as
        // a BSD file flag and needs no root: an entry the workload writes refuses the operator,
        // who owns the file, so `remove_dir_all` over the box home fails.
        "acl" => acl_probe(target)?,
        // Removing the granted file itself, rather than writing its contents. The file cell's
        // counterpart to `rmdir` on a write root.
        "unlink" => unlink_probe(target)?,
        // Moving the target to a sibling name and back. The verb behind a parent rename: a directory
        // between a write root and a refused path must refuse it, and its contents must not.
        "rename-away" => rename_away_probe(target)?,
        // Every way an ordinary program opens an EXISTING file for writing. This is the guard on
        // the file cell's create deny: a shell redirect passes `O_CREAT` on a file that already
        // exists, so a deny the kernel consulted there would break `> /dev/null` for every
        // workload while every other probe still passed.
        "write-open-modes" => write_open_modes_probe(target)?,
        // The view routes: each one asks whether the contained process can reach an object
        // through a name, a descriptor, or a profile the grant set never approved.
        "read-errno" => read_errno_probe(target)?,
        "sandbox-loosen" => sandbox_loosen_probe(target)?,
        "link" => {
            let (source, destination) = pair(target)?;
            link_probe(source, destination)?
        }
        "symlink-escape" => {
            let (link, points_to) = pair(target)?;
            symlink_escape_probe(link, points_to)?
        }
        "openat-escape" => {
            let (directory, relative) = pair(target)?;
            openat_escape_probe(directory, relative)?
        }
        "mach-lookup" => mach_lookup_probe(target)?,
        // The write-xor-exec routes: whether a path the process can WRITE is also a path it can
        // run. Two verbs rather than one, because the two authorities are separate operations —
        // `process-exec` covers replacing a process image, and a library load is a file-backed
        // executable mapping — and a single verb could not say which of them the profile leaves
        // open.
        "exec-written" => {
            let (seed, destination) = pair(target)?;
            exec_written_probe(seed, destination)?
        }
        "map-exec" => {
            let (seed, destination) = pair(target)?;
            map_exec_probe(seed, destination)?
        }
        "dlopen-written" => {
            let (seed, destination) = pair(target)?;
            dlopen_written_probe(seed, destination)?
        }
        "dlopen" => dlopen_probe(target)?,
        "mount" => mount_probe(target)?,
        "unmount" => unmount_probe(target)?,
        "chroot" => chroot_probe(target)?,
        other => return Err(format!("unknown probe operation: {other}")),
    };

    Ok(succeeded == expect_ok)
}

/// Read `KERN_PROCARGS2` for `pid` via the numeric `sysctl(3)` MIB — the same
/// path `ps` uses. Returns true iff the kernel handed back a block that actually
/// contains the target's environment, proven by finding
/// [`VICTIM_SECRET_MARKER`] in it.
///
/// Content, not just a zero return code, is the success condition, because three
/// distinct setup failures all yield "no secret" while looking like a denial:
/// a dead or wrong pid fails with `EINVAL` rather than `EPERM`, and a macOS
/// *platform* binary target returns `rc == 0` with argv only and its environment
/// redacted (~34 bytes). Keying on the marker makes the deny-side probe assert
/// the thing that matters — the secret is unreachable — and makes the allow-side
/// probe fail loudly on a broken victim instead of passing.
///
/// Deliberately raw `sysctl(2)`: this asserts what the kernel permits, so it
/// must not route through a libproc helper that could fail for its own reasons.
#[cfg(target_os = "macos")]
fn procargs_probe(pid: libc::pid_t) -> bool {
    let mut mib = [libc::CTL_KERN, libc::KERN_PROCARGS2, pid];
    // 256 KiB comfortably exceeds ARG_MAX-bounded argv+environ (observed ~6.5 KiB).
    let mut buf = vec![0u8; 256 * 1024];
    let mut len = buf.len();
    // SAFETY: `mib` is a 3-element MIB matching the passed count; `buf`/`len`
    // describe one owned allocation the kernel only writes within, and the
    // new-value pointer is null (a pure read).
    let rc = unsafe {
        libc::sysctl(
            mib.as_mut_ptr(),
            mib.len() as libc::c_uint,
            buf.as_mut_ptr().cast(),
            &mut len,
            std::ptr::null_mut(),
            0,
        )
    };
    if rc != 0 {
        let err = std::io::Error::last_os_error();
        let errno = err.raw_os_error().unwrap_or(0);
        // Only EPERM is the sandbox refusing. Anything else — notably EINVAL for
        // a dead or wrong pid — is a broken probe setup, not an enforced deny,
        // so report it as reachable and let the caller's `expect-deny` fail
        // loudly rather than pass for the wrong reason.
        if errno != libc::EPERM {
            eprintln!(
                "PROCARGS2({pid}) failed with errno {errno} ({err}), expected EPERM \
                 — not a sandbox denial; check the victim is alive"
            );
            return true;
        }
        eprintln!("PROCARGS2({pid}) denied: {err}");
        return false;
    }
    buf.truncate(len);
    let found = buf
        .windows(VICTIM_SECRET_MARKER.len())
        .any(|w| w == VICTIM_SECRET_MARKER.as_bytes());
    eprintln!("PROCARGS2({pid}) returned {len} bytes, secret marker found: {found}");
    found
}

/// Fork a child inside this same box and read ITS argv+environment, exercising
/// the `(allow process-info* (target same-sandbox))` carve-out.
///
/// The child must still be running when the read happens: a reaped pid fails
/// with `EINVAL`, which `procargs_probe` reports as reachable, so this would fail
/// loudly rather than pass. The child therefore sleeps while the parent reads it,
/// and is reaped only afterwards. Read BEFORE `waitpid`, deliberately.
///
/// `fork()` is safe here: this helper binary is single-threaded, and the parent
/// does the allocating work while the child only sleeps and `_exit`s.
#[cfg(target_os = "macos")]
fn procargs_child_probe() -> bool {
    // SAFETY: single-threaded process; the child path below calls only
    // async-signal-safe `sleep`/`_exit`.
    let child = unsafe { libc::fork() };
    if child < 0 {
        eprintln!("fork failed: {}", std::io::Error::last_os_error());
        return false;
    }
    if child == 0 {
        // SAFETY: async-signal-safe calls only, then immediate _exit.
        unsafe {
            libc::sleep(5);
            libc::_exit(0);
        }
    }
    let readable = procargs_probe(child);
    // SAFETY: `child` is our own live child; we reap it so it cannot outlive us.
    unsafe {
        libc::kill(child, libc::SIGKILL);
        let mut status = 0;
        libc::waitpid(child, &mut status, 0);
    }
    readable
}

/// Value the `procargs` probe searches for inside a target's argv+environment block.
#[cfg(target_os = "macos")]
const VICTIM_SECRET_MARKER: &str = "phantom-defeating-real-secret";

#[cfg(target_os = "macos")]
fn read_probe(target: &str) -> bool {
    use std::io::Read as _;
    // Read a byte (open alone can succeed on metadata-only access).
    match std::fs::File::open(target) {
        Ok(mut f) => {
            let mut buf = [0u8; 1];
            f.read(&mut buf).is_ok()
        }
        Err(_) => false,
    }
}

/// Whether `outcome` failed *because the kernel refused it*.
///
/// An `expect-deny` probe reports success only for `EPERM`. Every other failure means
/// the operation could not be attempted in the state the probe left behind — a
/// directory still occupied, an entry already present — and reporting those as "denied"
/// makes the probe pass whether or not the profile enforces anything.
#[cfg(target_os = "macos")]
fn refused_by_kernel(outcome: std::io::Result<()>) -> bool {
    match outcome {
        Ok(()) => false,
        Err(error) => error.raw_os_error() == Some(libc::EPERM),
    }
}

/// Refuse to measure a target this process does not own.
///
/// `chmod`, `chown`, and `acl_set_file` are all owner-or-root operations, so DAC refuses a caller
/// who is neither before the profile is consulted. A probe run against a foreign file would report
/// that `EPERM` as the rule answering, and `/dev/null` is exactly that shape.
#[cfg(target_os = "macos")]
fn require_owned(target: &str, what: &str) -> Result<(), String> {
    use std::os::unix::fs::MetadataExt as _;

    let owner = std::fs::metadata(target)
        .map_err(|error| format!("cannot stat {target} before {what}: {error}"))?
        .uid();
    // SAFETY: no arguments, and the value is this process's own.
    let us = unsafe { libc::getuid() };
    if owner != us {
        return Err(format!(
            "{target} is owned by uid {owner} and this process is uid {us}, so {what} is refused \
             by the ownership check before the profile is consulted"
        ));
    }
    Ok(())
}

/// Remove the directory at `target` itself.
///
/// Emptied first so the removal is attemptable: `ENOTEMPTY` is not a refusal, and
/// `refused_by_kernel` would reject it as inconclusive rather than count it.
#[cfg(target_os = "macos")]
fn rmdir_probe(target: &str) -> bool {
    if let Ok(entries) = std::fs::read_dir(target) {
        for entry in entries.flatten() {
            let _ = std::fs::remove_file(entry.path());
        }
    }
    !refused_by_kernel(std::fs::remove_dir(target)) && std::fs::symlink_metadata(target).is_err()
}

/// Create a symbolic link **at** `target`, which is what would redirect a reader that
/// resolves this path by name.
///
/// `target` is deliberately left in place: **Seatbelt decides create authorization
/// before existence** — measured, `symlink(2)` over a granted directory returns `EPERM`
/// when the create rule denies it and `EEXIST` when it does not — so an occupied name
/// still measures the rule. That is what makes this verb independent of whether removal
/// succeeded, and therefore separately falsifiable from [`rmdir_probe`].
///
/// `EEXIST` is reported as *not* denied, because it says nothing about permission —
/// counting it as a refusal is the "refused by luck rather than by the profile" mistake
/// these rules exist to prevent. The link destination is unimportant and is a path the probe can
/// name without extra grants.
#[cfg(target_os = "macos")]
fn create_over_probe(target: &str) -> bool {
    let path = std::path::Path::new(target);
    let Some(parent) = path.parent() else {
        return false;
    };
    !refused_by_kernel(std::os::unix::fs::symlink(parent, path))
}

/// Whether `access(target, F_OK)` answers that the path exists.
///
/// False is `EPERM` alone. `ENOENT` is an `Err`, because it is what an ungranted absent path
/// reports with no rule in play, so counting it as a refusal would pass for a reason that is not
/// the profile.
#[cfg(target_os = "macos")]
fn exists_access_probe(target: &str) -> Result<bool, String> {
    let name = std::ffi::CString::new(target)
        .map_err(|error| format!("target is not a C string: {target}: {error}"))?;
    // SAFETY: `name` is NUL terminated and outlives the call.
    if unsafe { libc::access(name.as_ptr(), libc::F_OK) } == 0 {
        return Ok(true);
    }
    match std::io::Error::last_os_error().raw_os_error() {
        Some(libc::EPERM) => Ok(false),
        Some(libc::ENOENT) => Err(format!(
            "access({target}, F_OK) reported ENOENT, which an absent path reports with no rule \
             in play, so no refusal was measured"
        )),
        other => Err(format!(
            "access({target}, F_OK) failed with {other:?}, which measures no rule"
        )),
    }
}

/// Whether `stat(target)` refuses without disclosing whether the path is there.
///
/// True is `EPERM`, which an absent path and a present one both report. False is `ENOENT`,
/// which only an absent path reports, so the errno itself has answered the existence
/// question. A `stat` that succeeds is an `Err`: there is no refusal to measure.
#[cfg(target_os = "macos")]
fn exists_stat_probe(target: &str) -> Result<bool, String> {
    match std::fs::metadata(target) {
        Ok(_) => Err(format!(
            "stat({target}) succeeded, so no refusal was measured"
        )),
        Err(error) => match error.raw_os_error() {
            Some(libc::EPERM) => Ok(true),
            Some(libc::ENOENT) => Ok(false),
            other => Err(format!(
                "stat({target}) failed with {other:?}, which measures no rule"
            )),
        },
    }
}

/// Set the BSD file flag `flag` on `target`, and report whether it stuck.
///
/// Every inconclusive outcome is an `Err`, and the restore puts back the flag set the target
/// arrived with. `containment/AGENTS.md` holds the rest.
#[cfg(target_os = "macos")]
fn chflags_probe(target: &str, flag: libc::c_uint) -> Result<bool, String> {
    use std::os::macos::fs::MetadataExt as _;

    let name = std::ffi::CString::new(target)
        .map_err(|error| format!("target is not a C string: {target}: {error}"))?;
    let flags_now = |what: &str| -> Result<libc::c_uint, String> {
        std::fs::metadata(target)
            .map(|metadata| metadata.st_flags())
            .map_err(|error| format!("cannot read flags {what} chflags on {target}: {error}"))
    };
    // SAFETY (every call below): `name` is NUL terminated and outlives the call.
    let set = |value: libc::c_uint| -> std::io::Result<()> {
        match unsafe { libc::chflags(name.as_ptr(), value) } {
            0 => Ok(()),
            _ => Err(std::io::Error::last_os_error()),
        }
    };

    let before = flags_now("before")?;
    if before & flag != 0 {
        return Err(format!(
            "{target} already carries flag {flag:#x}, so a refusal cannot be told from a success"
        ));
    }
    let outcome = set(before | flag);
    let after = flags_now("after")?;
    let stored = after & flag != 0;
    if stored {
        // Back to `before`, never to zero: a target may carry an unrelated flag this probe did
        // not set, and zeroing would clear that too.
        set(before).map_err(|error| {
            format!(
                "cannot restore flags {before:#x} on {target}: {error}; it may now be undeletable"
            )
        })?;
    }
    match &outcome {
        // A grant that stored nothing says nothing about authority, so it cannot be reported as a
        // refusal. One defined bit behaves this way, and no caller wires it today.
        Ok(()) if !stored => Err(format!(
            "chflags {flag:#x} on {target} returned 0 and stored nothing, so the call was permitted \
             while the flag was not kept"
        )),
        Err(error) if error.raw_os_error() != Some(libc::EPERM) => Err(format!(
            "chflags on {target} failed with {error}, which is neither a grant nor a refusal"
        )),
        _ => Ok(!refused_by_kernel(outcome) && stored),
    }
}

/// Split a two-path probe target on its `|` separator.
#[cfg(target_os = "macos")]
fn pair(target: &str) -> Result<(&str, &str), String> {
    target
        .split_once('|')
        .ok_or_else(|| format!("this probe needs two paths separated by '|': {target}"))
}

/// Whether `errno` is the kernel refusing an access rather than answering about the object.
#[cfg(target_os = "macos")]
fn is_refusal(errno: i32) -> bool {
    errno == libc::EPERM || errno == libc::EACCES
}

/// The `errno` of the last failed call, and its text.
#[cfg(target_os = "macos")]
fn last_error() -> (i32, std::io::Error) {
    let error = std::io::Error::last_os_error();
    (error.raw_os_error().unwrap_or(0), error)
}

/// Read one byte of `target`, and separate a refusal from every other failure.
///
/// `read_probe` cannot do this: it answers `false` for an absent target as well as a refused
/// one, so an `expect-deny` on a path that does not exist passes without measuring a rule.
#[cfg(target_os = "macos")]
fn read_errno_probe(target: &str) -> Result<bool, String> {
    use std::io::Read as _;
    match std::fs::File::open(target) {
        Ok(mut file) => {
            let mut byte = [0u8; 1];
            match file.read(&mut byte) {
                // A granted empty file reads nothing and is readable, so the count is reported
                // rather than required.
                Ok(count) => {
                    eprintln!("read({target}) returned {count} bytes");
                    Ok(true)
                }
                Err(error) => {
                    let errno = error.raw_os_error().unwrap_or(0);
                    if is_refusal(errno) {
                        eprintln!("read({target}) refused after open: {error}");
                        Ok(false)
                    } else {
                        Err(format!("read({target}) failed with {error}, not a refusal"))
                    }
                }
            }
        }
        Err(error) => {
            let errno = error.raw_os_error().unwrap_or(0);
            if is_refusal(errno) {
                eprintln!("open({target}) refused: {error}");
                Ok(false)
            } else {
                Err(format!(
                    "open({target}) failed with {error}, which is not a refusal — an absent \
                     target measures no rule"
                ))
            }
        }
    }
}

/// Apply a second, fully permissive profile, then read `target` through it.
///
/// Two outcomes are both refusals of the route, and the probe prints which one happened:
/// `sandbox_init` rejects the second profile, or it accepts one that widens nothing.
#[cfg(target_os = "macos")]
fn sandbox_loosen_probe(target: &str) -> Result<bool, String> {
    use std::ffi::{CStr, CString};
    use std::os::raw::c_char;

    unsafe extern "C" {
        fn sandbox_init(profile: *const c_char, flags: u64, errorbuf: *mut *mut c_char) -> i32;
        fn sandbox_free_error(errorbuf: *mut c_char);
    }

    let permissive = CString::new("(version 1)\n(allow default)\n").expect("no interior NUL");
    let mut error_buffer = std::ptr::null_mut();
    // SAFETY: the profile is NUL terminated and `error_buffer` is writable.
    let result = unsafe { sandbox_init(permissive.as_ptr(), 0, &mut error_buffer) };
    if result == 0 {
        eprintln!("a second sandbox_init carrying (allow default) returned 0");
    } else {
        let reason = if error_buffer.is_null() {
            format!("code {result}")
        } else {
            // SAFETY: sandbox_init owns this string until sandbox_free_error runs.
            let text = unsafe { CStr::from_ptr(error_buffer).to_string_lossy().into_owned() };
            // SAFETY: the buffer came from the call above and is freed once.
            unsafe { sandbox_free_error(error_buffer) };
            text
        };
        eprintln!("a second sandbox_init carrying (allow default) was refused: {reason}");
    }
    read_errno_probe(target)
}

/// Hard-link `source` to `destination`, then read the source's bytes at the new name.
///
/// `containment/AGENTS.md` records that this verb has no time bound and that one macOS file hangs
/// `link(2)` outright, so no test calls it yet.
#[cfg(target_os = "macos")]
fn link_probe(source: &str, destination: &str) -> Result<bool, String> {
    if std::path::Path::new(destination).symlink_metadata().is_ok() {
        return Err(format!(
            "{destination} already exists, so link(2) cannot be attempted"
        ));
    }
    // macOS refuses `link(2)` on a directory with EPERM whatever any rule says, so such a source
    // would report a refusal it never measured.
    if std::path::Path::new(source)
        .symlink_metadata()
        .is_ok_and(|metadata| metadata.is_dir())
    {
        return Err(format!(
            "{source} is a directory, and link(2) refuses one before any rule is consulted"
        ));
    }
    match std::fs::hard_link(source, destination) {
        Ok(()) => {
            let readable = read_errno_probe(destination);
            let _ = std::fs::remove_file(destination);
            readable
        }
        Err(error) => {
            let errno = error.raw_os_error().unwrap_or(0);
            if is_refusal(errno) {
                eprintln!("link({source} -> {destination}) refused: {error}");
                Ok(false)
            } else {
                Err(format!(
                    "link({source} -> {destination}) failed with {error}, not a refusal"
                ))
            }
        }
    }
}

/// Create a symbolic link at `link` naming `points_to`, then read through the link.
#[cfg(target_os = "macos")]
fn symlink_escape_probe(link: &str, points_to: &str) -> Result<bool, String> {
    if std::path::Path::new(link).symlink_metadata().is_ok() {
        return Err(format!(
            "{link} already exists, so symlink(2) cannot be attempted"
        ));
    }
    match std::os::unix::fs::symlink(points_to, link) {
        Ok(()) => {
            let readable = read_errno_probe(link);
            let _ = std::fs::remove_file(link);
            readable
        }
        Err(error) => {
            let errno = error.raw_os_error().unwrap_or(0);
            if is_refusal(errno) {
                eprintln!("symlink({points_to} at {link}) refused: {error}");
                Ok(false)
            } else {
                Err(format!(
                    "symlink({points_to} at {link}) failed with {error}, not a refusal"
                ))
            }
        }
    }
}

/// Resolve `relative` from a descriptor on `directory`, and read a byte of the result.
#[cfg(target_os = "macos")]
fn openat_escape_probe(directory: &str, relative: &str) -> Result<bool, String> {
    use std::os::fd::AsRawFd as _;

    let handle = std::fs::File::open(directory)
        .map_err(|error| format!("cannot open the granted directory {directory}: {error}"))?;
    let name = std::ffi::CString::new(relative)
        .map_err(|error| format!("relative path is not a C string: {relative}: {error}"))?;
    // SAFETY: `handle` stays alive for the call and `name` is NUL terminated.
    let opened = unsafe { libc::openat(handle.as_raw_fd(), name.as_ptr(), libc::O_RDONLY) };
    if opened < 0 {
        let (errno, error) = last_error();
        return if is_refusal(errno) {
            eprintln!("openat({directory}, {relative}) refused: {error}");
            Ok(false)
        } else {
            Err(format!(
                "openat({directory}, {relative}) failed with {error}, not a refusal"
            ))
        };
    }
    let mut byte = [0u8; 1];
    // SAFETY: `opened` is a live descriptor and the buffer holds the requested length.
    let read = unsafe { libc::read(opened, byte.as_mut_ptr().cast(), 1) };
    let outcome = if read < 0 {
        let (errno, error) = last_error();
        if is_refusal(errno) {
            eprintln!("read through openat({directory}, {relative}) refused: {error}");
            Ok(false)
        } else {
            Err(format!(
                "read through openat({directory}, {relative}) failed with {error}"
            ))
        }
    } else {
        Ok(true)
    };
    // SAFETY: `opened` is this probe's own descriptor and is closed once.
    unsafe { libc::close(opened) };
    outcome
}

/// Copy `seed` to `destination` at mode `0700`, and report how many bytes landed.
///
/// **Bytes rather than `std::fs::copy`.** That call reaches `copyfile(COPYFILE_ALL)` on macOS, which
/// ends in `chflags(2)`, and every write cell denies the flag operation — so it fails with `EPERM`
/// inside a box and the caller would report the *write* as refused while measuring the flags rule.
/// Reading and writing the bytes touches only the two operations the write cell grants.
///
/// Every failure here is an `Err`, because the write half is this verb's premise rather than its
/// measurement: a destination the process could not write measures no exec rule at all.
#[cfg(target_os = "macos")]
fn write_executable_copy(seed: &str, destination: &str) -> Result<usize, String> {
    use std::os::unix::fs::PermissionsExt as _;

    if std::path::Path::new(destination).symlink_metadata().is_ok() {
        return Err(format!(
            "{destination} already exists, so a fresh write cannot be attempted"
        ));
    }
    let bytes = std::fs::read(seed).map_err(|error| {
        format!("cannot read the seed {seed}: {error}; without it no exec route is measured")
    })?;
    if bytes.is_empty() {
        return Err(format!(
            "the seed {seed} is empty, so nothing executable is written"
        ));
    }
    std::fs::write(destination, &bytes).map_err(|error| {
        format!(
            "cannot write {destination}: {error}; this is the write cell refusing, which is a \
             different rule from the one this verb measures"
        )
    })?;
    std::fs::set_permissions(destination, std::fs::Permissions::from_mode(0o700))
        .map_err(|error| format!("cannot make {destination} executable: {error}"))?;
    Ok(bytes.len())
}

/// Write `seed` into `destination`, then execute `destination`.
///
/// Reports permitted only when the child **ran**, proven by the zero exit of `--exec-target`, so an
/// `exec` that returned while the image never started cannot read as a grant. Only `EPERM` counts as
/// a refusal: every other failure means the route was not attempted in the state the probe built.
#[cfg(target_os = "macos")]
fn exec_written_probe(seed: &str, destination: &str) -> Result<bool, String> {
    let written = write_executable_copy(seed, destination)?;
    let outcome = std::process::Command::new(destination)
        .arg("--exec-target")
        .status();
    let _ = std::fs::remove_file(destination);
    match outcome {
        Ok(status) if status.success() => {
            eprintln!("exec({destination}) ran {written} written bytes and exited 0");
            Ok(true)
        }
        Ok(status) => Err(format!(
            "exec({destination}) started and exited {status}, so the image ran and the probe's own \
             no-op mode did not answer"
        )),
        Err(error) if error.raw_os_error() == Some(libc::EPERM) => {
            eprintln!("exec({destination}) refused: {error}");
            Ok(false)
        }
        Err(error) => Err(format!(
            "exec({destination}) failed with {error}, which is neither a grant nor a refusal"
        )),
    }
}

/// Write `seed` into `destination`, then map `destination` `PROT_READ | PROT_EXEC`.
///
/// **This measures the mapping authority and nothing else.** A library load is a file-backed
/// executable mapping, so the mapping is the operation a profile can refuse. The mapped pages are
/// never touched: on this platform a page fault against an image whose signature does not validate
/// kills the process, which would end the run rather than report an outcome.
#[cfg(target_os = "macos")]
fn map_exec_probe(seed: &str, destination: &str) -> Result<bool, String> {
    use std::os::fd::AsRawFd as _;

    let written = write_executable_copy(seed, destination)?;
    let handle = std::fs::File::open(destination)
        .map_err(|error| format!("cannot reopen {destination} after writing it: {error}"))?;
    // SAFETY: `handle` stays alive across the call, the length is the file's own, and the mapping is
    // private, so nothing outside this process observes it.
    let mapped = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            written,
            libc::PROT_READ | libc::PROT_EXEC,
            libc::MAP_PRIVATE,
            handle.as_raw_fd(),
            0,
        )
    };
    if mapped == libc::MAP_FAILED {
        let (errno, error) = last_error();
        let _ = std::fs::remove_file(destination);
        return if is_refusal(errno) {
            eprintln!("mmap(PROT_EXEC) on {destination} refused: {error}");
            Ok(false)
        } else {
            Err(format!(
                "mmap(PROT_EXEC) on {destination} failed with {error}, not a refusal"
            ))
        };
    }
    // SAFETY: unmapping this process's own mapping, at the address and length it was made with.
    unsafe { libc::munmap(mapped, written) };
    let _ = std::fs::remove_file(destination);
    eprintln!("mmap(PROT_EXEC) on {destination} mapped {written} written bytes");
    Ok(true)
}

/// Write `seed` into `destination`, then load `destination` as a dynamic library.
///
/// **This is the route the library-load half of write-xor-exec turns on.** A plain
/// `mmap(PROT_EXEC)` on a file is unavailable to an ordinary process on this platform, so
/// `map_exec_probe` measures the platform rather than the profile. `dlopen` goes through dyld,
/// which does map executable, so a refusal here is a refusal of an executable mapping.
///
/// No `dlclose`: unloading a library that ran an initializer is not a safe thing to do for a
/// measurement, and the process exits immediately after.
#[cfg(target_os = "macos")]
fn dlopen_written_probe(seed: &str, destination: &str) -> Result<bool, String> {
    write_executable_copy(seed, destination)?;
    let loaded = dlopen_probe(destination);
    let _ = std::fs::remove_file(destination);
    loaded
}

/// Load `library` as a dynamic library, writing nothing.
///
/// **The bound on the write cells' executable-mapping deny.** Every runtime library a workload needs
/// comes from a read-only root, so that deny is correct only while a load from one still works — a
/// blanket `(deny file-map-executable)` was measured to refuse those too.
#[cfg(target_os = "macos")]
fn dlopen_probe(library: &str) -> Result<bool, String> {
    /// `RTLD_NOW | RTLD_LOCAL`: resolve every symbol now, so a refusal cannot hide behind laziness.
    const MODE: std::os::raw::c_int = 0x2 | 0x4;
    /// The text dyld reports when the profile refuses the executable mapping, and the only refusal
    /// this verb counts.
    const REFUSED_MAPPING: &str = "sandbox blocked mmap()";

    let name = std::ffi::CString::new(library)
        .map_err(|error| format!("{library} is not a C string: {error}"))?;
    // SAFETY: `name` is NUL terminated and outlives the call, and `dlerror` is read before any other
    // call can replace its message.
    let (handle, message) = unsafe {
        let handle = libc::dlopen(name.as_ptr(), MODE);
        let text = libc::dlerror();
        let message = if text.is_null() {
            String::new()
        } else {
            std::ffi::CStr::from_ptr(text)
                .to_string_lossy()
                .into_owned()
        };
        (handle, message)
    };
    if !handle.is_null() {
        eprintln!("dlopen({library}) loaded");
        return Ok(true);
    }
    // **One message counts as a refusal, and it is the one that names this rule.** `dlopen` reports
    // through its own text rather than `errno`, and a broader match is how this verb passes for a
    // reason that is not the mapping rule: a refused *read* also reads `Permission denied`, so an
    // `expect-deny` would measure the read grant while the uncontained control, where reads always
    // succeed, stayed green. Every other failure is inconclusive and says so.
    if message.contains(REFUSED_MAPPING) {
        eprintln!("dlopen({library}) refused: {message}");
        return Ok(false);
    }
    Err(format!(
        "dlopen({library}) failed with \"{message}\", which does not name the mapping rule, so it \
         is neither a grant nor a refusal of it"
    ))
}

/// `BOOTSTRAP_NOT_PRIVILEGED`, which is the sandbox refusing a lookup.
#[cfg(target_os = "macos")]
const BOOTSTRAP_NOT_PRIVILEGED: i32 = 1100;

/// `BOOTSTRAP_UNKNOWN_SERVICE`, which says the namespace holds no such name.
#[cfg(target_os = "macos")]
const BOOTSTRAP_UNKNOWN_SERVICE: i32 = 1102;

/// Look up the Mach service `target` in this process's bootstrap namespace.
///
/// A port here is a route to a root daemon that mounts, so the mount routes a privilege check
/// closes are only closed while this returns nothing. Only `BOOTSTRAP_NOT_PRIVILEGED` counts as a
/// refusal: an unknown service measures the namespace's contents rather than any rule.
#[cfg(target_os = "macos")]
fn mach_lookup_probe(target: &str) -> Result<bool, String> {
    type MachPort = u32;

    unsafe extern "C" {
        static bootstrap_port: MachPort;
        fn bootstrap_look_up(
            bootstrap: MachPort,
            service: *const std::os::raw::c_char,
            port: *mut MachPort,
        ) -> i32;
    }

    let service = std::ffi::CString::new(target)
        .map_err(|error| format!("service name is not a C string: {target}: {error}"))?;
    let mut port: MachPort = 0;
    // SAFETY: `service` is NUL terminated and outlives the call, and `port` is writable.
    let result = unsafe { bootstrap_look_up(bootstrap_port, service.as_ptr(), &mut port) };
    match result {
        0 if port != 0 => {
            eprintln!("bootstrap_look_up({target}) returned port {port}");
            Ok(true)
        }
        BOOTSTRAP_NOT_PRIVILEGED => {
            eprintln!("bootstrap_look_up({target}) refused: BOOTSTRAP_NOT_PRIVILEGED");
            Ok(false)
        }
        BOOTSTRAP_UNKNOWN_SERVICE => Err(format!(
            "bootstrap_look_up({target}) answered BOOTSTRAP_UNKNOWN_SERVICE, so this namespace \
             holds no such name and no rule was measured"
        )),
        other => Err(format!(
            "bootstrap_look_up({target}) returned {other} with port {port}, which is neither a \
             port nor a refusal"
        )),
    }
}

/// Mount a fresh filesystem over `target`.
#[cfg(target_os = "macos")]
fn mount_probe(target: &str) -> Result<bool, String> {
    let kind = std::ffi::CString::new("apfs").expect("no interior NUL");
    let path = std::ffi::CString::new(target)
        .map_err(|error| format!("target is not a C string: {target}: {error}"))?;
    // SAFETY: both strings are NUL terminated and outlive the call; the data argument is null.
    let result = unsafe { libc::mount(kind.as_ptr(), path.as_ptr(), 0, std::ptr::null_mut()) };
    privileged_outcome("mount", target, result)
}

/// Unmount whatever filesystem holds `target`.
#[cfg(target_os = "macos")]
fn unmount_probe(target: &str) -> Result<bool, String> {
    let path = std::ffi::CString::new(target)
        .map_err(|error| format!("target is not a C string: {target}: {error}"))?;
    // SAFETY: `path` is NUL terminated and outlives the call.
    let result = unsafe { libc::unmount(path.as_ptr(), 0) };
    privileged_outcome("unmount", target, result)
}

/// Move this process's filesystem root to `target`.
#[cfg(target_os = "macos")]
fn chroot_probe(target: &str) -> Result<bool, String> {
    let path = std::ffi::CString::new(target)
        .map_err(|error| format!("target is not a C string: {target}: {error}"))?;
    // SAFETY: `path` is NUL terminated and outlives the call.
    let result = unsafe { libc::chroot(path.as_ptr()) };
    privileged_outcome("chroot", target, result)
}

/// Report a view-changing call's outcome, naming the errno so a reader can tell which layer
/// answered.
#[cfg(target_os = "macos")]
fn privileged_outcome(call: &str, target: &str, result: i32) -> Result<bool, String> {
    if result == 0 {
        eprintln!("{call}({target}) succeeded");
        return Ok(true);
    }
    let (errno, error) = last_error();
    if is_refusal(errno) {
        eprintln!("{call}({target}) refused: {error} (errno {errno})");
        Ok(false)
    } else {
        Err(format!(
            "{call}({target}) failed with {error} (errno {errno}), which is neither a grant nor a \
             refusal"
        ))
    }
}

/// Set the mode bit `bit` on `target`, and report whether it stuck.
///
/// The verdict is the stored bit rather than the return code, and every inconclusive outcome is an
/// `Err`. `containment/AGENTS.md` holds the rest.
#[cfg(target_os = "macos")]
fn chmod_bit_probe(target: &str, bit: libc::mode_t) -> Result<bool, String> {
    use std::os::unix::fs::MetadataExt as _;

    require_owned(target, "chmod")?;
    let name = std::ffi::CString::new(target)
        .map_err(|error| format!("target is not a C string: {target}: {error}"))?;
    let mode_now = |what: &str| -> Result<libc::mode_t, String> {
        std::fs::metadata(target)
            .map(|metadata| metadata.mode() as libc::mode_t & 0o7777)
            .map_err(|error| format!("cannot read the mode {what} chmod on {target}: {error}"))
    };
    // SAFETY (every call below): `name` is NUL terminated and outlives the call.
    let set = |value: libc::mode_t| -> std::io::Result<()> {
        match unsafe { libc::chmod(name.as_ptr(), value) } {
            0 => Ok(()),
            _ => Err(std::io::Error::last_os_error()),
        }
    };

    let before = mode_now("before")?;
    if before & bit != 0 {
        return Err(format!(
            "{target} already carries mode bit {bit:#o}, so a refusal cannot be told from a success"
        ));
    }
    let outcome = set(before | bit);
    let after = mode_now("after")?;
    let stored = after & bit != 0;
    if stored {
        // Back to `before`, never to a constant: the target's own permission bits are not this
        // probe's to choose.
        set(before)
            .map_err(|error| format!("cannot restore mode {before:#o} on {target}: {error}"))?;
    }
    match &outcome {
        Err(error) if error.raw_os_error() != Some(libc::EPERM) => Err(format!(
            "chmod on {target} failed with {error}, which is neither a grant nor a refusal"
        )),
        _ => Ok(stored),
    }
}

/// Change `target`'s group to one this process already belongs to, and report whether it stuck.
///
/// The group moves and the owner does not, because that is the one ownership change DAC grants an
/// ordinary caller. Every inconclusive outcome is an `Err`. `containment/AGENTS.md` holds the rest.
#[cfg(target_os = "macos")]
fn chown_probe(target: &str) -> Result<bool, String> {
    use std::os::unix::fs::MetadataExt as _;

    require_owned(target, "chown")?;
    let name = std::ffi::CString::new(target)
        .map_err(|error| format!("target is not a C string: {target}: {error}"))?;
    let group_now = |what: &str| -> Result<libc::gid_t, String> {
        std::fs::metadata(target)
            .map(|metadata| metadata.gid())
            .map_err(|error| format!("cannot read the group {what} chown on {target}: {error}"))
    };
    // SAFETY (every call below): `name` is NUL terminated and outlives the call, and the uid is
    // this process's own so the call changes only the group.
    let set = |group: libc::gid_t| -> std::io::Result<()> {
        match unsafe { libc::chown(name.as_ptr(), libc::getuid(), group) } {
            0 => Ok(()),
            _ => Err(std::io::Error::last_os_error()),
        }
    };

    let before = group_now("before")?;
    let moved_to = groups_held()
        .into_iter()
        .find(|group| *group != before)
        .ok_or_else(|| {
            format!(
                "this process holds no group other than {before}, so a chown on {target} would be \
                 a no-op and a refusal could not be told from a success"
            )
        })?;
    let outcome = set(moved_to);
    let after = group_now("after")?;
    let stored = after == moved_to;
    if stored {
        set(before)
            .map_err(|error| format!("cannot restore group {before} on {target}: {error}"))?;
    }
    match &outcome {
        Err(error) if error.raw_os_error() != Some(libc::EPERM) => Err(format!(
            "chown on {target} failed with {error}, which is neither a grant nor a refusal"
        )),
        _ => Ok(stored),
    }
}

// macOS access-control-list calls, which the `libc` crate does not declare.
#[cfg(target_os = "macos")]
unsafe extern "C" {
    fn acl_init(count: libc::c_int) -> *mut libc::c_void;
    fn acl_from_text(text: *const libc::c_char) -> *mut libc::c_void;
    fn acl_get_file(path: *const libc::c_char, kind: libc::c_int) -> *mut libc::c_void;
    fn acl_set_file(
        path: *const libc::c_char,
        kind: libc::c_int,
        acl: *mut libc::c_void,
    ) -> libc::c_int;
    fn acl_free(acl: *mut libc::c_void) -> libc::c_int;
}

/// `ACL_TYPE_EXTENDED`, the one list type macOS stores.
#[cfg(target_os = "macos")]
const ACL_TYPE_EXTENDED: libc::c_int = 0x0000_0100;

/// An entry denying `everyone` the write right, in the text form `acl_from_text` parses.
#[cfg(target_os = "macos")]
const DENY_WRITE_ACL: &str =
    "!#acl 1\ngroup:ABCDEFAB-CDEF-ABCD-EFAB-CDEF0000000C:everyone:12:deny:write\n\0";

/// Put a deny-write access-control list on `target`, and report whether it stuck.
///
/// The verdict is the stored list, on [`chmod_bit_probe`]'s reasoning, and every inconclusive
/// outcome is an `Err`. `containment/AGENTS.md` holds the rest.
#[cfg(target_os = "macos")]
fn acl_probe(target: &str) -> Result<bool, String> {
    require_owned(target, "acl_set_file")?;
    let name = std::ffi::CString::new(target)
        .map_err(|error| format!("target is not a C string: {target}: {error}"))?;

    // SAFETY (every call below): `name` outlives each call, and every `acl_t` this function
    // obtains is freed on the path that obtained it.
    let carries_a_list = || -> bool {
        let list = unsafe { acl_get_file(name.as_ptr(), ACL_TYPE_EXTENDED) };
        if list.is_null() {
            return false;
        }
        unsafe { acl_free(list) };
        true
    };

    // A target already carrying a list cannot tell a refusal from a success, which is
    // `chflags_probe`'s rule.
    if carries_a_list() {
        return Err(format!(
            "{target} already carries an access-control list, so a refusal cannot be told from a \
             success"
        ));
    }

    let list = unsafe { acl_from_text(DENY_WRITE_ACL.as_ptr().cast()) };
    if list.is_null() {
        return Err(format!(
            "acl_from_text refused the probe's own list text: {}",
            std::io::Error::last_os_error()
        ));
    }
    let outcome = match unsafe { acl_set_file(name.as_ptr(), ACL_TYPE_EXTENDED, list) } {
        0 => Ok(()),
        _ => Err(std::io::Error::last_os_error()),
    };
    unsafe { acl_free(list) };

    let stored = carries_a_list();
    if stored {
        // Restore, or the fixture is left refusing its own owner — the defect this probe measures.
        // An empty list is the only route: `acl_delete_file_np` answers `ENOTSUP` here.
        let empty = unsafe { acl_init(0) };
        if empty.is_null() {
            return Err(format!("cannot build an empty list to restore {target}"));
        }
        let restored = match unsafe { acl_set_file(name.as_ptr(), ACL_TYPE_EXTENDED, empty) } {
            0 => Ok(()),
            // Captured before `acl_free` runs, or the error reported would be that call's.
            _ => Err(std::io::Error::last_os_error()),
        };
        unsafe { acl_free(empty) };
        if let Err(error) = restored {
            return Err(format!(
                "cannot clear the access-control list on {target}: {error}; it may now refuse its \
                 own owner"
            ));
        }
    }
    match &outcome {
        // A call that returned 0 and stored nothing says nothing about authority, which is the
        // false pass `chflags_probe` records for `UF_COMPRESSED`.
        Ok(()) if !stored => Err(format!(
            "acl_set_file on {target} returned 0 and stored nothing, so the call was permitted \
             while the list was not kept"
        )),
        Err(error) if error.raw_os_error() != Some(libc::EPERM) => Err(format!(
            "acl_set_file on {target} failed with {error}, which is neither a grant nor a refusal"
        )),
        _ => Ok(stored),
    }
}

/// Every group this process belongs to, effective group first.
#[cfg(target_os = "macos")]
fn groups_held() -> Vec<libc::gid_t> {
    // SAFETY: a count query with a null buffer, which is how `getgroups(2)` reports the size.
    let count = unsafe { libc::getgroups(0, std::ptr::null_mut()) };
    if count <= 0 {
        // SAFETY: no arguments, and the value is this process's own.
        return vec![unsafe { libc::getgid() }];
    }
    let mut groups = vec![0 as libc::gid_t; count as usize];
    // SAFETY: `groups` holds exactly `count` elements, which is what the query above reported.
    let filled = unsafe { libc::getgroups(count, groups.as_mut_ptr()) };
    if filled < 0 {
        // SAFETY: no arguments, and the value is this process's own.
        return vec![unsafe { libc::getgid() }];
    }
    groups.truncate(filled as usize);
    groups
}

/// Open an existing `target` for writing five ways, and report whether every one wrote.
///
/// This measures what the kernel does with `O_CREAT` on a file that exists, not what this crate
/// renders, so it is a canary rather than a pin. An absent target is an `Err`.
#[cfg(target_os = "macos")]
fn write_open_modes_probe(target: &str) -> Result<bool, String> {
    use std::os::unix::io::FromRawFd as _;

    if std::fs::symlink_metadata(target).is_err() {
        return Err(format!(
            "{target} is absent, so this measures creation rather than writing"
        ));
    }
    let name = std::ffi::CString::new(target)
        .map_err(|error| format!("target is not a C string: {target}: {error}"))?;
    let combinations = [
        ("O_WRONLY", libc::O_WRONLY),
        ("O_WRONLY|O_TRUNC", libc::O_WRONLY | libc::O_TRUNC),
        ("O_WRONLY|O_CREAT", libc::O_WRONLY | libc::O_CREAT),
        (
            "O_WRONLY|O_CREAT|O_TRUNC",
            libc::O_WRONLY | libc::O_CREAT | libc::O_TRUNC,
        ),
        ("O_WRONLY|O_APPEND", libc::O_WRONLY | libc::O_APPEND),
    ];
    for (label, flags) in combinations {
        // SAFETY: `name` is NUL terminated and outlives the call. The mode argument is read only
        // when `O_CREAT` creates, which cannot happen here because the target exists.
        let descriptor = unsafe { libc::open(name.as_ptr(), flags, 0o600) };
        if descriptor < 0 {
            eprintln!(
                "probe: opening {target} with {label} failed: {}",
                std::io::Error::last_os_error()
            );
            return Ok(false);
        }
        // SAFETY: `descriptor` was just opened by this call and is owned here, so `File` may take
        // it and close it on drop.
        let mut file = unsafe { std::fs::File::from_raw_fd(descriptor) };
        if let Err(error) = std::io::Write::write_all(&mut file, b"containment-test-probe") {
            eprintln!("probe: writing {target} opened with {label} failed: {error}");
            return Ok(false);
        }
    }
    Ok(true)
}

/// Rename `target` to a sibling name, then rename it back when the move landed.
///
/// A moved path is renamed back so the caller's later probes still find it. An absent target is
/// an `Err`, because `ENOENT` looks like a refusal whatever any rule says, and so is any failure
/// other than `EPERM`. When the kernel refuses, the target must still be there; a refusal that
/// leaves it gone is an `Err` too, because the rule then answered something other than the move.
#[cfg(target_os = "macos")]
fn rename_away_probe(target: &str) -> Result<bool, String> {
    let path = std::path::Path::new(target);
    if std::fs::symlink_metadata(path).is_err() {
        return Err(format!(
            "{target} is absent, so a refusal cannot be told from a success"
        ));
    }
    let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
        return Err(format!("{target} has no final component to rename"));
    };
    let moved = path.with_file_name(format!("{name}.moved-by-probe"));
    match std::fs::rename(path, &moved) {
        Ok(()) => {
            std::fs::rename(&moved, path).map_err(|error| {
                format!(
                    "{target} moved to {} and could not be moved back: {error}",
                    moved.display()
                )
            })?;
            Ok(true)
        }
        Err(error) if error.raw_os_error() == Some(libc::EPERM) => {
            if std::fs::symlink_metadata(path).is_err() || moved.exists() {
                return Err(format!(
                    "renaming {target} was refused and the path still moved, which no rule explains"
                ));
            }
            Ok(false)
        }
        Err(error) => Err(format!(
            "renaming {target} failed with {error}, which is neither a grant nor a refusal"
        )),
    }
}

/// Remove the file at `target` itself.
///
/// The file cell's counterpart to [`rmdir_probe`], and it reports an `Err` for an absent target
/// rather than a `false`: `ENOENT` looks like a refusal whatever any rule says.
#[cfg(target_os = "macos")]
fn unlink_probe(target: &str) -> Result<bool, String> {
    if std::fs::symlink_metadata(target).is_err() {
        return Err(format!(
            "{target} is absent, so a refusal cannot be told from a success"
        ));
    }
    let outcome = std::fs::remove_file(target);
    let gone = std::fs::symlink_metadata(target).is_err();
    match &outcome {
        Err(error) if error.raw_os_error() != Some(libc::EPERM) => Err(format!(
            "removing {target} failed with {error}, which is neither a grant nor a refusal"
        )),
        _ => Ok(gone),
    }
}

/// HTTP probe: CONNECT to `<host>:<port>` through `$HTTP_PROXY`, then send a
/// tunneled `GET /` carrying `Authorization: Bearer $HTTP_PHANTOM_TOKEN`. Returns
/// true iff the tunneled GET's response status is 200. A missing `HTTP_PROXY`
/// is a probe setup error (Err); everything else — including connect failure,
/// a non-200 CONNECT reply, and a non-200 tunneled reply — is a `false`
/// outcome so the `expect-deny:http:...` variant can assert it.
#[cfg(target_os = "macos")]
fn http_probe(target: &str) -> Result<bool, String> {
    use std::io::Write as _;
    use std::net::{TcpStream, ToSocketAddrs};
    use std::time::Duration;

    let proxy =
        std::env::var("HTTP_PROXY").map_err(|_| "HTTP_PROXY not set for http probe".to_string())?;
    let proxy_hp = proxy
        .trim_start_matches("http://")
        .trim_end_matches('/')
        .to_string();
    let phantom = std::env::var("HTTP_PHANTOM_TOKEN").unwrap_or_default();
    let (host, port) = match target.rsplit_once(':') {
        Some((h, p)) => (h.to_string(), p.parse::<u16>().unwrap_or(80)),
        None => (target.to_string(), 80u16),
    };

    let mut addrs = proxy_hp
        .to_socket_addrs()
        .map_err(|e| format!("resolve proxy {proxy_hp}: {e}"))?;
    let addr = addrs
        .next()
        .ok_or_else(|| format!("no proxy addr for {proxy_hp}"))?;

    let mut sock = match TcpStream::connect_timeout(&addr, Duration::from_secs(2)) {
        Ok(s) => s,
        Err(_) => return Ok(false),
    };
    sock.set_read_timeout(Some(Duration::from_secs(2))).ok();
    sock.set_write_timeout(Some(Duration::from_secs(2))).ok();

    if write!(
        sock,
        "CONNECT {host}:{port} HTTP/1.1\r\nHost: {host}:{port}\r\n\r\n"
    )
    .is_err()
    {
        return Ok(false);
    }
    let head = read_until_double_crlf(&mut sock);
    if parse_status(&head) != 200 {
        return Ok(false);
    }

    if write!(
        sock,
        "GET / HTTP/1.1\r\nHost: {host}\r\nAuthorization: Bearer {phantom}\r\n\
         Connection: close\r\n\r\n"
    )
    .is_err()
    {
        return Ok(false);
    }
    let resp = read_until_double_crlf(&mut sock);
    Ok(parse_status(&resp) == 200)
}

/// Read from a byte stream until the terminating `\r\n\r\n` of an HTTP head (or
/// EOF / a 16 KiB cap that stops a hostile proxy from exhausting memory).
/// Generic over `Read` so the macOS `TcpStream` path and the Linux `UnixStream`
/// path share one implementation.
#[cfg(target_os = "macos")]
fn read_until_double_crlf<R: std::io::Read>(sock: &mut R) -> String {
    let mut buf: Vec<u8> = Vec::with_capacity(512);
    let mut b = [0u8; 1];
    while buf.len() < 16 * 1024 && !buf.ends_with(b"\r\n\r\n") {
        match sock.read(&mut b) {
            Ok(0) => break,
            Ok(_) => buf.push(b[0]),
            Err(_) => break,
        }
    }
    String::from_utf8_lossy(&buf).into_owned()
}

#[cfg(target_os = "macos")]
fn parse_status(head: &str) -> u16 {
    // Status-line shape: "HTTP/1.1 200 Connection Established\r\n..."
    head.lines()
        .next()
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|s| s.parse::<u16>().ok())
        .unwrap_or(0)
}

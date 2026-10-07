//! Production-path proof for I4, no inherited handles, on macOS and Linux.

#![cfg(any(target_os = "linux", target_os = "macos"))]

#[path = "support/fixture.rs"]
mod fixture;

use std::os::fd::{AsRawFd as _, FromRawFd as _, OwnedFd};

use fixture::Request;

/// A second descriptor for the same open file, at or above `minimum`, that every `exec` keeps.
///
/// **This is what makes the test measure a mechanism rather than an outcome.** Nothing the box opens
/// leaks by itself, because Rust marks every descriptor it creates close-on-exec — so with no planted
/// descriptor the census stays empty whether or not the trampoline closes anything. A planted one
/// crosses `strands-box run` and reaches the trampoline, which is the code under test.
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
///
/// **The high number cannot be a constant.** `F_DUPFD` fails with `EINVAL` when the minimum is at or
/// above the soft `RLIMIT_NOFILE`, and macOS ships that limit at 256.
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

fn planted(source: i32, minimum: i32) -> OwnedFd {
    // SAFETY: `source` is open, and `F_DUPFD` returns a new owned descriptor.
    let descriptor = unsafe { libc::fcntl(source, libc::F_DUPFD, minimum) };
    assert!(
        descriptor >= minimum,
        "duplicate descriptor at or above {minimum}"
    );
    // SAFETY: `F_SETFD` only updates the flags of a descriptor this test owns.
    assert_eq!(
        unsafe { libc::fcntl(descriptor, libc::F_SETFD, 0) },
        0,
        "clear FD_CLOEXEC"
    );
    // SAFETY: `F_DUPFD` returned a new descriptor that this value now owns.
    unsafe { OwnedFd::from_raw_fd(descriptor) }
}

#[test]
fn production_launch_passes_only_standard_streams_to_the_workload() {
    if !fixture::namespace_launcher_is_usable() {
        println!("skipping: this host cannot build a namespace mount view");
        return;
    }

    let (ordinary_minimum, high_minimum) = planted_numbers();
    let sentinel = tempfile::tempfile().expect("sentinel file");
    let ordinary = planted(sentinel.as_raw_fd(), ordinary_minimum);
    let high = planted(sentinel.as_raw_fd(), high_minimum);

    let box_ = Request::with_nothing("inherited-handles").expect();
    let output = box_.run(&[env!("CARGO_BIN_EXE_box-inherited-handles-probe"), "initial"]);

    assert!(
        output.status.success(),
        "the production launch leaked a descriptor (planted {} and {}): {}",
        ordinary.as_raw_fd(),
        high.as_raw_fd(),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        String::from_utf8_lossy(&output.stdout)
            .contains("only standard streams survived launch and re-exec"),
        "the probe did not complete its post-reexec census: {output:?}"
    );
}

/// A redirected standard stream is statable through a real box whether or not its directory is named
/// in `[agent.filesystem] metadata`, because the box renders one `file-read-metadata` rule per
/// inherited stream regardless of that list.
#[cfg(target_os = "macos")]
#[test]
fn a_redirected_standard_stream_is_statable_regardless_of_a_log_directory_metadata_grant() {
    use std::process::{Command, Stdio};

    let program = env!("CARGO_BIN_EXE_box-inherited-handles-probe");
    for listed in [false, true] {
        // The broker socket lands under `box_dir`, and macOS caps a pathname socket at about 103
        // bytes, so the box root stands under the short fixture parent rather than `$TMPDIR`.
        let directory = fixture::short_temporary_home();
        let root = directory
            .path()
            .canonicalize()
            .expect("a canonical fixture");
        let logs = root.join("logs");
        let workspace = root.join("work");
        std::fs::create_dir(&logs).expect("a log directory");
        std::fs::create_dir(&workspace).expect("a workspace");
        let config = root.join("box.toml");
        let mut value = toml::toml! {
            name = "stdio-metadata"
            box_dir = ""
            [agent]
            command = []
            workspace = ""
            [agent.filesystem]
            metadata = []
        };
        value["box_dir"] = toml::Value::String(root.join("box").display().to_string());
        value["agent"]["command"] = toml::Value::Array(vec![program.into()]);
        value["agent"]["workspace"] = toml::Value::String(workspace.display().to_string());
        value["agent"]["filesystem"]["metadata"] = if listed {
            toml::Value::Array(vec![logs.display().to_string().into()])
        } else {
            toml::Value::Array(vec![])
        };
        std::fs::write(&config, toml::to_string(&value).expect("serialize config"))
            .expect("write config");
        let boxed_command = || {
            let mut command = Command::new(fixture::box_binary());
            command.args(["run", "--config"]).arg(&config).arg("--");
            command
        };
        let input = logs.join("stdin");
        let output = logs.join("stdout");
        let error = logs.join("stderr");
        std::fs::write(&input, "").expect("the input file");
        let run = |command: &mut Command| {
            command
                .arg("stdio-metadata")
                .stdin(std::fs::File::open(&input).expect("open input"))
                .stdout(std::fs::File::create(&output).expect("open output"))
                .stderr(std::fs::File::create(&error).expect("open error"));
            let status = command.status().expect("run the descriptor probe");
            let stderr = std::fs::read_to_string(&error).expect("read stderr");
            assert!(status.success(), "{status}: {stderr}");
            std::fs::read_to_string(&output).expect("read stdout")
        };
        let permitted = "fstat(0)=0,errno=0\nfstat(1)=0,errno=0\nfstat(2)=0,errno=0\n";
        assert_eq!(run(&mut Command::new(program)), permitted);
        let boxed = run(&mut boxed_command());
        // Statable in either case: the metadata list does not gate `fstat` on an inherited stream.
        assert_eq!(boxed, permitted, "listed={listed}");
        let pipes = boxed_command()
            .arg("stdio-metadata")
            .stdin(Stdio::null())
            .output()
            .expect("run with output pipes");
        assert!(pipes.status.success(), "{pipes:?}");
        assert_eq!(String::from_utf8_lossy(&pipes.stdout), permitted);
    }
}

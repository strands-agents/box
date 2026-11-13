//! On macOS, `[limits.shell] timeout` stops a started tool and every process it left behind, and
//! the box keeps serving (docs/design/decisions.md#python-in-the-shell-is-monty). The Linux counterpart is
//! `command_timeout_stops_tool_descendants_and_box_keeps_serving` in `box_process_cleanup.rs`.

#![cfg(all(target_os = "macos", feature = "test-support"))]

#[path = "support/fixture.rs"]
mod fixture;

use std::time::{Duration, Instant};

/// A `/bin/sh` tool that leaves a `sleep` behind, records both pids, and waits.
const HOLDER: &str = "#!/bin/sh\nsleep 300 &\nprintf %s \"$!\" > \"$1/holder-sleep\"\nprintf %s \"$$\" > \"$1/holder-sh\"\nwait\n";

/// Whether `pid` is gone: `kill(pid, 0)` fails with `ESRCH`.
fn gone(pid: libc::pid_t) -> bool {
    // SAFETY: signal 0 checks for the process and sends nothing.
    let result = unsafe { libc::kill(pid, 0) };
    result == -1 && std::io::Error::last_os_error().raw_os_error() == Some(libc::ESRCH)
}

fn eventually(mut condition: impl FnMut() -> bool) -> bool {
    let deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < deadline {
        if condition() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    condition()
}

#[test]
fn the_shell_timeout_stops_a_tool_and_what_it_started_and_the_box_keeps_serving() {
    // The holder lives at an absolute path in its own folder, outside every write grant, as a
    // configured command must.
    let programs = fixture::short_temporary_home();
    let holder = programs
        .path()
        .canonicalize()
        .expect("the program folder resolves")
        .join("holder");
    std::fs::write(&holder, HOLDER).expect("write the holder tool");
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&holder, std::fs::Permissions::from_mode(0o755))
            .expect("make the holder tool runnable");
    }
    let declaration = format!(
        "[limits.shell]\ntimeout = 2\n\
         [tool.holder]\ncommand = [{:?}]\n\
         [tool.holder.filesystem]\nread = [\"{{box_home}}\"]\nwrite = [\"{{box_home}}\"]\n",
        holder.display().to_string()
    );
    let configured = fixture::Request::with_config(
        "tool-timeout",
        "permit(principal, action, resource);",
        &declaration,
    )
    .expect();
    let output = configured.bash(
        "zsh -lc \"holder $BOX_HOME\"; printf %s \"$?\" > \"$BOX_HOME/status\"; \
         zsh -lc 'printf STILL_SERVING' > \"$BOX_HOME/after\"",
    );
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    let home = configured.box_home();
    let read = |name: &str| std::fs::read_to_string(home.join(name)).unwrap_or_default();
    assert_eq!(
        read("after"),
        "STILL_SERVING",
        "the box serves the next call: {stderr}"
    );
    assert_ne!(read("status"), "0", "the timed-out call fails: {stderr}");
    for name in ["holder-sh", "holder-sleep"] {
        let pid: libc::pid_t = read(name).trim().parse().unwrap_or_else(|_| {
            panic!("{name} records a pid (status {}): {stderr}", read("status"))
        });
        assert!(eventually(|| gone(pid)), "{name} ({pid}) must stop");
    }
}

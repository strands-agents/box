//! `[limits]` `processes` and `memory`: one cgroup caps the box's workload, and the trusted process
//! stays outside it.

#![cfg(feature = "test-support")]

#[path = "support/fixture.rs"]
mod fixture;

#[cfg(target_os = "linux")]
use std::io::{BufRead as _, BufReader};
use std::process::Output;
#[cfg(target_os = "linux")]
use std::process::{Command, Stdio};

const PERMIT: &str = "permit(principal, action, resource);";

#[cfg(target_os = "linux")]
fn probe() -> &'static str {
    env!("CARGO_BIN_EXE_box-resource-probe")
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

/// This test process's cgroup v2 path, or empty.
#[cfg(target_os = "linux")]
fn own_cgroup(pid: &str) -> String {
    std::fs::read_to_string(format!("/proc/{pid}/cgroup"))
        .unwrap_or_default()
        .lines()
        .find_map(|line| line.strip_prefix("0::"))
        .unwrap_or_default()
        .to_string()
}

/// Whether this process already sits in a subtree systemd delegates to its user, with both
/// controllers enabled there.
#[cfg(target_os = "linux")]
fn delegated_here() -> bool {
    // SAFETY: getuid has no failure mode.
    let marker = format!("user@{}.service", unsafe { libc::getuid() });
    let own = own_cgroup("self");
    let Some(index) = own.find(&format!("/{marker}")) else {
        return false;
    };
    let base = format!("/sys/fs/cgroup{}", &own[..index + marker.len() + 1]);
    std::fs::read_to_string(format!("{base}/cgroup.subtree_control")).is_ok_and(|enabled| {
        ["pids", "memory"]
            .iter()
            .all(|controller| enabled.split_whitespace().any(|name| name == *controller))
    })
}

/// The prefix that starts a box inside a delegated cgroup: nothing when this process is already in
/// one, the documented `systemd-run --user --scope` when that works, else `None`.
#[cfg(target_os = "linux")]
fn delegated_launcher() -> Option<Vec<String>> {
    if delegated_here() {
        return Some(Vec::new());
    }
    let scope: Vec<String> = ["systemd-run", "--user", "--scope", "--quiet", "--"]
        .map(String::from)
        .into();
    let check = Command::new(&scope[0])
        .args(&scope[1..])
        .args(["/bin/sh", "-c", "cat /proc/self/cgroup"])
        .envs(user_bus())
        .output()
        .ok()?;
    // SAFETY: getuid has no failure mode.
    let marker = format!("/user@{}.service/", unsafe { libc::getuid() });
    if check.status.success() && String::from_utf8_lossy(&check.stdout).contains(&marker) {
        Some(scope)
    } else {
        None
    }
}

/// The user manager's runtime directory, which a non-login session such as SSM leaves unset.
#[cfg(target_os = "linux")]
fn user_bus() -> Vec<(String, String)> {
    if std::env::var_os("XDG_RUNTIME_DIR").is_some() {
        return Vec::new();
    }
    // SAFETY: getuid has no failure mode.
    let runtime = format!("/run/user/{}", unsafe { libc::getuid() });
    if std::path::Path::new(&runtime).is_dir() {
        vec![("XDG_RUNTIME_DIR".to_string(), runtime)]
    } else {
        Vec::new()
    }
}

/// `inner` started through `launcher`, with the same arguments and environment.
#[cfg(target_os = "linux")]
fn launched(launcher: &[String], inner: &Command) -> Command {
    let mut words = launcher
        .iter()
        .map(std::ffi::OsString::from)
        .chain(std::iter::once(inner.get_program().to_owned()))
        .chain(inner.get_args().map(ToOwned::to_owned));
    let mut command = Command::new(words.next().expect("a program"));
    command.args(words);
    for (name, value) in inner.get_envs() {
        if let Some(value) = value {
            command.env(name, value);
        }
    }
    command.envs(user_bus());
    command
}

/// A run of the resource probe with `arguments`, whose configuration gains `limits`.
///
/// The fixture box is created without limits, so its first run needs no delegated cgroup.
#[cfg(target_os = "linux")]
fn limited_run(configured: &fixture::Configured, limits: &str, arguments: &[&str]) -> Command {
    limited_run_of(configured, probe(), limits, |text| text, arguments)
}

/// A run of `program` whose configuration `edit` changes and then gains `limits`.
#[cfg(target_os = "linux")]
fn limited_run_of(
    configured: &fixture::Configured,
    program: &str,
    limits: &str,
    edit: impl FnOnce(String) -> String,
    arguments: &[&str],
) -> Command {
    let mut command = configured.command_for(program);
    let text = edit(std::fs::read_to_string(configured.config()).unwrap());
    std::fs::write(configured.config(), format!("{text}\n[limits]\n{limits}")).unwrap();
    command.args(arguments);
    command
}

#[cfg(target_os = "linux")]
fn unlimited(name: &str) -> fixture::Configured {
    fixture::Request::with_config(name, PERMIT, "").expect()
}

/// A fork bomb's next start fails at the cap, nothing is killed, and the trusted process stays
/// outside the cap, alive, and reports the limit.
#[cfg(target_os = "linux")]
#[test]
fn a_fork_bomb_stops_at_the_process_limit_and_the_trusted_process_keeps_working() {
    if !fixture::namespace_launcher_is_usable() {
        return;
    }
    let Some(launcher) = delegated_launcher() else {
        println!(
            "skipping: this host has no delegated cgroup v2 subtree and `systemd-run --user \
             --scope` does not give one, so a process limit cannot be enforced here"
        );
        return;
    };
    let configured = unlimited("cap-fork");
    let inner = limited_run(
        &configured,
        "processes = 32\nmemory = \"1G\"\n",
        &["fork", "4096"],
    );
    let mut child = launched(&launcher, &inner)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("start Box");
    let mut report = String::new();
    BufReader::new(child.stdout.take().unwrap())
        .read_line(&mut report)
        .expect("read the probe's report");

    // The workload now sits at its cap, holding every process it could start.
    let field = |key: &str| {
        report
            .split_whitespace()
            .find_map(|word| word.strip_prefix(key))
            .unwrap_or_else(|| panic!("the probe reports {key}: {report:?}"))
            .to_string()
    };
    let workload_cgroup = field("cgroup=");
    let forked: u64 = field("forked=").parse().unwrap();
    let errno: i32 = field("errno=").parse().unwrap();
    assert!(
        workload_cgroup
            .rsplit('/')
            .next()
            .is_some_and(|leaf| leaf.starts_with("strands-box-")),
        "the workload runs in the box's own cgroup: {report:?}"
    );
    assert_eq!(
        errno,
        libc::EAGAIN,
        "the start past the cap fails with EAGAIN, the pids controller's refusal: {report:?}"
    );
    assert!(
        (1..32).contains(&forked),
        "the probe starts some processes and stops below the cap of 32: {report:?}"
    );
    let trusted = own_cgroup(&child.id().to_string());
    assert!(
        !trusted.is_empty() && trusted != workload_cgroup,
        "the trusted process stays outside the workload's cgroup: trusted {trusted:?}, workload \
         {workload_cgroup:?}"
    );
    let knob = |name: &str| {
        std::fs::read_to_string(format!("/sys/fs/cgroup{workload_cgroup}/{name}"))
            .unwrap_or_else(|error| panic!("read {name}: {error}"))
            .trim()
            .to_string()
    };
    for (name, value) in [
        ("pids.max", "32"),
        ("memory.max", "1073741824"),
        ("memory.swap.max", "0"),
        ("memory.oom.group", "1"),
    ] {
        assert_eq!(knob(name), value, "the box cgroup's {name}");
    }
    let leaf = knob("cgroup.procs");
    assert!(
        !leaf.lines().any(|pid| pid == child.id().to_string()),
        "the trusted process is not a member of the box cgroup: {leaf}"
    );

    drop(child.stdin.take());
    let output = child.wait_with_output().expect("Box ends");
    let text = stderr(&output);
    assert!(
        output.status.success(),
        "the trusted process keeps working and returns the workload's own status: {text}"
    );
    assert!(
        text.contains("note[B0215]") && text.contains("processes 32, memory 1G"),
        "startup discloses the process limit: {text}"
    );
    assert!(
        text.contains("warning[B1005]") && text.contains("process limit (32)"),
        "Box says the workload reached its process limit: {text}"
    );
    assert!(
        !std::path::Path::new(&format!("/sys/fs/cgroup{workload_cgroup}")).exists(),
        "the box removes its cgroup when the run ends"
    );
}

/// A tool the agent starts through the box's Shell runs in the same cgroup as the agent.
#[cfg(target_os = "linux")]
#[test]
fn a_tool_joins_the_agents_cgroup() {
    if !fixture::namespace_launcher_is_usable() {
        return;
    }
    let Some(launcher) = delegated_launcher() else {
        println!(
            "skipping: this host has no delegated cgroup v2 subtree and `systemd-run --user \
             --scope` does not give one, so a box cgroup cannot be created here"
        );
        return;
    };
    let request = fixture::Request::with_config(
        "cap-tool",
        PERMIT,
        "[tool.probe]\ncommand = [\"box-resource-probe\"]\n",
    );
    let programs = request.operator_home().join("programs");
    std::fs::create_dir(&programs).unwrap();
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&programs, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    std::fs::copy(probe(), programs.join("box-resource-probe")).unwrap();
    let configured = request
        .env("PATH", &format!("{}:/usr/bin:/bin", programs.display()))
        .expect();
    // The agent reads its own cgroup with a bash builtin, then asks the Shell to run the tool.
    let script = "read -r own < /proc/self/cgroup; echo \"agent=${own#0::}\"; \
                  zsh -c 'box-resource-probe cgroup'";
    let inner = limited_run_of(
        &configured,
        "/bin/bash",
        "processes = 256\n",
        |text| text,
        &["-c", script],
    );
    let output = launched(&launcher, &inner)
        .stdin(Stdio::null())
        .output()
        .expect("run Box");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let value = |key: &str| {
        stdout
            .lines()
            .find_map(|line| line.strip_prefix(key))
            .unwrap_or_else(|| panic!("the run reports {key}: {stdout} {}", stderr(&output)))
            .to_string()
    };
    let agent = value("agent=");
    assert!(
        agent
            .rsplit('/')
            .next()
            .is_some_and(|leaf| leaf.starts_with("strands-box-")),
        "the agent runs in the box cgroup: {stdout}"
    );
    assert_eq!(
        value("cgroup="),
        agent,
        "the tool runs in the agent's cgroup"
    );
}

/// Going over the memory cap ends the workload, and Box says which cap ended it.
#[cfg(target_os = "linux")]
#[test]
fn the_workload_ends_at_its_memory_limit_and_box_says_so() {
    if !fixture::namespace_launcher_is_usable() {
        return;
    }
    let Some(launcher) = delegated_launcher() else {
        println!(
            "skipping: this host has no delegated cgroup v2 subtree and `systemd-run --user \
             --scope` does not give one, so a memory limit cannot be enforced here"
        );
        return;
    };
    let configured = unlimited("cap-memory");
    let inner = limited_run(&configured, "memory = \"64M\"\n", &["memory", "1024"]);
    let output = launched(&launcher, &inner)
        .stdin(Stdio::null())
        .output()
        .expect("run Box");
    let text = stderr(&output);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("cgroup=") && stdout.contains("strands-box-"),
        "the workload ran in the box's own cgroup: {stdout}"
    );
    assert!(
        !stdout.contains("TOOK_ALL"),
        "the workload never holds more than its cap: {stdout}"
    );
    assert!(
        !output.status.success(),
        "a workload the kernel ended does not report success: {text}"
    );
    assert!(
        text.contains("error[B1004]") && text.contains("memory limit (64M)"),
        "Box says the workload reached its memory limit: {text}"
    );
}

/// A limit this host cannot enforce refuses the run before the workload starts.
#[cfg(target_os = "linux")]
#[test]
fn an_unenforceable_limit_refuses_to_start_and_names_the_fix() {
    if !fixture::namespace_launcher_is_usable() {
        return;
    }
    if delegated_here() {
        println!(
            "skipping: this process already sits in a delegated cgroup, so every limit is \
             enforceable here; run this test from an SSH or service session"
        );
        return;
    }
    let configured = unlimited("cap-refuse");
    let output = limited_run(&configured, "processes = 32\n", &["cgroup"])
        .output()
        .expect("run Box");
    let text = stderr(&output);
    assert!(!output.status.success(), "the box must not start: {text}");
    assert!(
        text.contains("error[B0123]")
            && text.contains("this host cannot enforce `limits.processes`"),
        "the refusal names the key it cannot enforce: {text}"
    );
    assert!(
        text.contains("systemd-run --user --scope")
            || text.contains("read-only")
            || text.contains("not a cgroup v2"),
        "the refusal names the reason and its fix: {text}"
    );
    assert!(
        !String::from_utf8_lossy(&output.stdout).contains("cgroup="),
        "the workload never ran: {output:?}"
    );
}

/// A write grant on the cgroup file system would let the workload leave its cgroup, so a box with
/// a limit refuses it.
#[cfg(target_os = "linux")]
#[test]
fn a_write_grant_on_the_cgroup_file_system_is_refused_with_a_limit() {
    if !fixture::namespace_launcher_is_usable() {
        return;
    }
    // The grant is added only to the limited run, which refuses before any launch, so the test also
    // holds where `/sys/fs/cgroup` is read-only and a launch with the grant could not mount it.
    let configured = unlimited("cap-grant");
    let output = limited_run_of(
        &configured,
        probe(),
        "processes = 32\n",
        |text| {
            text.replacen("read = [", "read = [\"/sys/fs/cgroup\", ", 1)
                .replacen("write = [", "write = [\"/sys/fs/cgroup\", ", 1)
        },
        &["cgroup"],
    )
    .output()
    .expect("run Box");
    let text = stderr(&output);
    assert!(!output.status.success(), "the box must not start: {text}");
    assert!(
        text.contains("error[B0102]") && text.contains("could move itself out of the cgroup"),
        "the refusal names the grant and why: {text}"
    );
    assert!(
        !String::from_utf8_lossy(&output.stdout).contains("cgroup="),
        "the workload never ran: {output:?}"
    );
}

/// Without `processes` or `memory`, the box creates no cgroup: the workload stays in the cgroup its
/// caller started it in.
#[cfg(target_os = "linux")]
#[test]
fn without_a_limit_the_box_creates_no_cgroup() {
    if !fixture::namespace_launcher_is_usable() {
        return;
    }
    let configured = unlimited("cap-none");
    let output = limited_run(&configured, "shell.timeout = 30\n", &["cgroup"])
        .output()
        .expect("run Box");
    let text = stderr(&output);
    assert!(output.status.success(), "the box runs: {text}");
    assert_eq!(
        String::from_utf8_lossy(&output.stdout).trim(),
        format!("cgroup={}", own_cgroup("self")),
        "the workload shares its caller's cgroup"
    );
    assert!(!text.contains("B0215"), "nothing to disclose: {text}");
}

/// macOS has no per-tree cap, so either key refuses the box there.
#[cfg(target_os = "macos")]
#[test]
fn the_resource_keys_are_refused_on_macos() {
    for (limits, keys) in [
        ("processes = 32\n", "`limits.processes`"),
        ("memory = \"1G\"\n", "`limits.memory`"),
    ] {
        let (_configured, output) =
            fixture::Request::with_config("cap-mac", PERMIT, &format!("[limits]\n{limits}"))
                .attempt();
        let text = stderr(&output);
        assert!(!output.status.success(), "{limits}: {text}");
        assert!(
            text.contains("error[B0101]") && text.contains(keys) && text.contains("Linux only"),
            "{limits}: {text}"
        );
    }
}

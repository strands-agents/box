//! `[containment] private_proc = false` end to end, on a host that masks `/proc`.
//!
//! These run only where `fixture::masked_proc_host` holds — locally under `~/code/oss-box/bin/masked`,
//! the Kata-pod situation. Everywhere else each test returns at its probe, loudly.
#![cfg(target_os = "linux")]

#[path = "support/fixture.rs"]
mod fixture;

use fixture::Request;

const PERMIT_EVERY_EFFECT: &str = r#"
permit(principal == Box::Agent::"self", action == Box::Action::"shell:exec", resource);
permit(principal == Box::Agent::"self", action == Box::Action::"fs:read", resource);
permit(principal == Box::Agent::"self", action == Box::Action::"fs:write", resource);
permit(principal == Box::Agent::"self", action == Box::Action::"fs:delete", resource);
permit(principal == Box::Agent::"self", action == Box::Action::"fs:move", resource);
permit(principal == Box::Agent::"self", action == Box::Action::"http:request", resource);
"#;

const SHARED: &str = "[containment]\nprivate_proc = false\n";
const SENTINEL: &str = "SENTINEL_26_7f3a";

macro_rules! needs_a_masked_host {
    ($test:literal) => {
        if !fixture::masked_proc_host() {
            eprintln!("SKIPPED: {}: this host does not mask /proc", $test);
            return;
        }
    };
}

fn stdout(output: &std::process::Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

fn stderr(output: &std::process::Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

/// `bash` that finds the trusted box process by its argv (`strands-box run`), prints `SEEN`, then
/// `LEAK:<what>` for every node it can open or enter and `LEAK:signal` if it can signal it.
const REACH_THE_TRUSTED_PROCESS: &str = r#"
for p in /proc/[0-9]*; do
  pid=${p#/proc/}
  mapfile -d '' -t args < $p/cmdline 2>/dev/null || continue
  case "${args[*]}" in *strands-box\ run*) ;; *) continue ;; esac
  echo SEEN:$pid
  for f in environ mem fd/0 maps; do (exec 3< $p/$f) 2>/dev/null && echo LEAK:$f; done
  (cd $p/root) 2>/dev/null && echo LEAK:root
  kill -0 $pid 2>/dev/null && echo LEAK:signal
done
echo DONE
"#;

#[test]
fn box_run_succeeds_on_a_masked_host_with_the_key() {
    needs_a_masked_host!("box_run_succeeds_on_a_masked_host_with_the_key");
    let box_ = Request::with_config("shared-proc", PERMIT_EVERY_EFFECT, SHARED).expect();
    let out = box_.bash("echo READY");
    assert!(
        out.status.success() && stdout(&out).contains("READY"),
        "{out:?}"
    );
}

#[test]
fn box_run_without_the_key_refuses_and_names_it() {
    needs_a_masked_host!("box_run_without_the_key_refuses_and_names_it");
    let (_box, out) = Request::with_policy("private-proc", PERMIT_EVERY_EFFECT).attempt();
    assert!(!out.status.success(), "{out:?}");
    assert!(
        stderr(&out).contains("private_proc = false"),
        "the refusal must name the opt-in: {out:?}"
    );
}

#[test]
fn the_agent_cannot_reach_the_trusted_box_process() {
    needs_a_masked_host!("the_agent_cannot_reach_the_trusted_box_process");
    let box_ = Request::with_config("shared-proc-reach", PERMIT_EVERY_EFFECT, SHARED).expect();
    let out = box_.bash(REACH_THE_TRUSTED_PROCESS);
    let text = stdout(&out);
    assert!(
        text.contains("SEEN:") && text.contains("DONE"),
        "the trusted process must be visible to make this real: {out:?}"
    );
    assert!(!text.contains("LEAK"), "{out:?}");
}

/// **No process's command line carries a declared environment value**, so a shared `/proc` shows no
/// leaf's environment to another. The agent holds the value and searches every `cmdline` for it.
#[test]
fn no_process_cmdline_carries_a_declared_env_value() {
    needs_a_masked_host!("no_process_cmdline_carries_a_declared_env_value");
    let box_ = Request::with_config("shared-proc-env", PERMIT_EVERY_EFFECT, SHARED)
        .agent_env("CANARY", SENTINEL)
        .expect();
    // The script is the agent's own argv, so it must not spell the sentinel whole: it compares in
    // two halves and matches on the variable.
    let (head, tail) = SENTINEL.split_at(8);
    let out = box_.bash(&format!(
        "test \"$CANARY\" = \"{head}\"\"{tail}\" && echo HAVE
         for p in /proc/[0-9]*; do
           mapfile -d '' -t args < $p/cmdline 2>/dev/null || continue
           case \"${{args[*]}}\" in *\"$CANARY\"*) echo ON_ARGV:$p ;; esac
         done
         echo DONE"
    ));
    let text = stdout(&out);
    assert!(text.contains("HAVE") && text.contains("DONE"), "{out:?}");
    assert!(!text.contains("ON_ARGV"), "{out:?}");
}

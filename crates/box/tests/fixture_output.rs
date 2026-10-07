#![cfg(unix)]

use std::time::Duration;

#[path = "support/fixture.rs"]
mod fixture;
#[path = "support/runtime_mcp.rs"]
mod runtime_mcp;

use runtime_mcp::RuntimeMcpBox;

const TIMEOUT: Duration = Duration::from_secs(5);
const OUTPUT_BYTES: usize = 1024 * 1024;

fn output_fixture(name: &str, wait_for_release: bool) -> RuntimeMcpBox {
    let box_ = RuntimeMcpBox::new(name);
    let workload = format!(
        r#"
set -eu
: > "$HOME/started"
chunk=x
i=0
while [ "$i" -lt 12 ]; do
    chunk="$chunk$chunk"
    i=$((i + 1))
done
i=0
while [ "$i" -lt 256 ]; do
    printf '%s' "$chunk"
    printf '%s' "$chunk" >&2
    i=$((i + 1))
done
: > "$HOME/output.complete"
{}
"#,
        if wait_for_release {
            r#"while [ ! -e "$HOME/release" ]; do :; done"#
        } else {
            ""
        },
    );
    box_.write_workspace("", &[], &workload);
    box_
}

fn assert_output(output: std::process::Output) {
    assert!(output.status.success(), "{}", output.status);
    assert_eq!(output.stdout.len(), OUTPUT_BYTES);
    assert!(output.stdout.iter().all(|byte| *byte == b'x'));
    assert!(output.stderr.ends_with(&vec![b'x'; OUTPUT_BYTES]));
}

#[test]
fn waiting_for_exit_drains_both_output_pipes() {
    if !fixture::namespace_launcher_is_usable() {
        return;
    }
    let box_ = output_fixture("output-exit", false);
    let mut run = box_.spawn();
    run.wait_for(box_.workload_path("started"), Duration::from_secs(45));
    assert_output(run.wait(TIMEOUT));
}

#[test]
fn waiting_for_a_marker_drains_output_before_exit() {
    if !fixture::namespace_launcher_is_usable() {
        return;
    }
    let box_ = output_fixture("output-marker", true);
    let mut run = box_.spawn();
    run.wait_for(box_.workload_path("started"), Duration::from_secs(45));
    run.wait_for(box_.workload_path("output.complete"), TIMEOUT);
    assert!(run.is_running());
    box_.release_workload();
    assert_output(run.wait(TIMEOUT));
}

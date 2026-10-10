// Modified by Amazon. Original source: https://github.com/strands-agents/shell
// Local changes are recorded in crates/shell/UPSTREAM.md.

use strands_shell::Shell;

fn run(command: &str, expected: &str, status: i32) {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let local = tokio::task::LocalSet::new();
    runtime.block_on(local.run_until(async {
        let mut shell = Shell::builder().build().unwrap();
        let output = shell.run(command).await;
        assert_eq!(output.status, status, "{}", output.stderr);
        assert_eq!(output.stdout, expected);
    }));
}
#[test]
fn regression_0() {
    run(
        "printf 'a\\na\\nb\\n' > /tmp/input; printf 'obsolete longer contents' > /tmp/output; uniq /tmp/input /tmp/output; printf 'marker\\n'; cat /tmp/output",
        "marker\na\nb\n",
        0,
    );
}

#[test]
fn regression_1() {
    run(
        "printf 'a\\na\\n' > /tmp/input; uniq -c /tmp/input /tmp/output; cat /tmp/output",
        "      2 a\n",
        0,
    );
}

#[test]
fn regression_2() {
    run("printf 'a\\na\\n' | uniq", "a\n", 0);
}

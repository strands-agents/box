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
    run("printf 'a\\nb\\n' | jq -Rsc .", "\"a\\nb\\n\"\n", 0);
}

#[test]
fn regression_1() {
    run("printf '' | jq -sc .", "[]\n", 0);
}

#[test]
fn regression_2() {
    run("printf '' | jq -Rsc .", "\"\"\n", 0);
}

#[test]
fn regression_3() {
    run("printf '1 2' | jq -s length", "2\n", 0);
}

#[test]
fn regression_4() {
    run("printf 'a\\nb\\n' | jq -Rc .", "\"a\"\n\"b\"\n", 0);
}

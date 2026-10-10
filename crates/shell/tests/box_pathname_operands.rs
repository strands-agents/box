// Modified by Amazon. Original source: https://github.com/strands-agents/shell
// Local changes are recorded in crates/shell/UPSTREAM.md.

use strands_shell::Shell;

fn run(command: &str, expected: &str) {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let local = tokio::task::LocalSet::new();
    runtime.block_on(local.run_until(async {
        let mut shell = Shell::builder().build().unwrap();
        let output = shell.run(command).await;
        assert_eq!(output.status, 0, "{}", output.stderr);
        assert_eq!(output.stdout, expected);
    }));
}

#[test]
fn regression_0() {
    run("basename /", "/\n");
}

#[test]
fn regression_1() {
    run("basename /////", "/\n");
}

#[test]
fn regression_2() {
    run("dirname /a/b/", "/a\n");
}

#[test]
fn regression_3() {
    run("dirname a///", ".\n");
}

#[test]
fn regression_4() {
    run("dirname ////", "/\n");
}

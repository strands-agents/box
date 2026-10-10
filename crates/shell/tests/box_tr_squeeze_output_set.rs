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
    run("printf 'xxaabbaa' | tr -s ab AB", "xxABA");
}

#[test]
fn regression_1() {
    run("printf 'xxxx' | tr -s ab AB", "xxxx");
}

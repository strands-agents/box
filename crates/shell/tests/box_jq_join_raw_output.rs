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
    run("jq -nj '\"a\",\"b\"'", "ab", 0);
}

#[test]
fn regression_1() {
    run("jq -n --join-output '\"a\",\"b\"'", "ab", 0);
}

#[test]
fn regression_2() {
    run("jq -nj '1,2'", "12", 0);
}

#[test]
fn regression_3() {
    run("jq -n '\"a\"'", "\"a\"\n", 0);
}

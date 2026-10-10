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
        "printf 'hit\\nhit\\nx\\nhit\\n' | grep -n -m1 -A2 hit",
        "1:hit\n2-hit\n3-x\n",
        0,
    );
}

#[test]
fn regression_1() {
    run("printf 'hit\\n' | grep -m0 hit", "", 1);
}

#[test]
fn regression_2() {
    run("printf 'hit\\n' | grep -c -m0 hit", "0\n", 1);
}

#[test]
fn regression_3() {
    run("printf 'hit\\nx\\nhit\\n' | grep -m1 hit", "hit\n", 0);
}

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
    run("jq -nr '\"\\u0000EXIT_FALSE\"'", "\0EXIT_FALSE\n", 0);
}

#[test]
fn regression_1() {
    run("jq -ner '\"\\u0000EXIT_FALSE\"'", "\0EXIT_FALSE\n", 0);
}

#[test]
fn regression_2() {
    run("printf '' | jq -e .", "", 4);
}

#[test]
fn regression_3() {
    run("jq -ne empty", "", 4);
}

#[test]
fn regression_4() {
    run("jq -ne false", "false\n", 1);
}

#[test]
fn regression_5() {
    run("jq -ne null", "null\n", 1);
}

#[test]
fn regression_6() {
    run("jq -ne 'false,true'", "false\ntrue\n", 0);
}

#[test]
fn regression_7() {
    run("jq -ne 'true,false'", "true\nfalse\n", 1);
}

#[test]
fn regression_8() {
    run("jq -n empty", "", 0);
}

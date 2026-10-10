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
    run("printf 'a\\nb\\nc\\nd\\n' | tail -n +2 -n 2", "c\nd\n");
}

#[test]
fn regression_1() {
    run("printf 'a\\nb\\nc\\nd\\n' | tail -n 2 -n +2", "b\nc\nd\n");
}

#[test]
fn regression_2() {
    run("printf 'a\\nb\\n' > /tmp/-2; tail -- /tmp/-2", "a\nb\n");
}

#[test]
fn regression_3() {
    run("printf 'a\\nb\\n' > -2; tail -- -2", "a\nb\n");
}

#[test]
fn head_dash_number_operand_is_not_a_count() {
    run("printf 'a\\nb\\n' > -2; head -- -2", "a\nb\n");
}

#[test]
fn head_absolute_dash_number_operand_control() {
    run("printf 'a\\nb\\n' > /tmp/-2; head -- /tmp/-2", "a\nb\n");
}

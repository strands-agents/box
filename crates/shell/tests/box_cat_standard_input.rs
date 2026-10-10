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
    run("printf 'input' | cat -", "input");
}

#[test]
fn regression_1() {
    run(
        "printf 'file' > item; printf 'input' | cat item -",
        "fileinput",
    );
}

#[test]
fn regression_2() {
    run(
        "printf 'file\\n' > item; printf 'input\\n' | cat -n item -",
        "     1\tfile\n     2\tinput\n",
    );
}

#[test]
fn repeated_standard_input_operands_share_one_reader() {
    run("printf 'input' | cat - -", "input");
    run(
        "printf 'file' > item; printf 'input' | cat item - -",
        "fileinput",
    );
}

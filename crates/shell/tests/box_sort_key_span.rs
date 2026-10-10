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
    run(
        "printf 'z:1:b\\na:1:a\\n' | sort -t: -k2,3",
        "a:1:a\nz:1:b\n",
    );
}
#[test]
fn regression_1() {
    run(
        "printf 'a:1:z\\nz:1:a\\n' | sort -s -t: -k2",
        "z:1:a\na:1:z\n",
    );
}

#[test]
fn bounded_key_ignores_later_fields() {
    run(
        "printf 'z:1:a\\na:1:z\\n' | sort -s -t: -k2,2",
        "z:1:a\na:1:z\n",
    );
}

#[test]
fn numeric_keys_keep_the_selected_field() {
    run(
        "printf 'z:10:x\\na:2:y\\n' | sort -s -t: -k2n",
        "a:2:y\nz:10:x\n",
    );
    run(
        "printf 'a:2:y\\nz:10:x\\n' | sort -s -t: -k2,3nr",
        "z:10:x\na:2:y\n",
    );
}

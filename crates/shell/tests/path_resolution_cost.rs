//! The time to resolve a path grows linearly with its component count.

#![cfg(unix)]

use std::path::PathBuf;
use std::time::{Duration, Instant};

use strands_shell::Shell;

const SHORT: usize = 2_000;
const LONG: usize = 8 * SHORT;

fn shell(name: &str) -> Shell {
    let base = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(name);
    let _ = std::fs::remove_dir_all(&base);
    let workspace = base.join("ws");
    std::fs::create_dir_all(&workspace).expect("workspace");
    let mut shell = Shell::builder()
        .bind_direct(workspace.to_str().expect("UTF-8 workspace"), "/workspace")
        .disable_network()
        .max_input(1 << 20)
        .build()
        .expect("shell builds");
    shell.proc.cwd = PathBuf::from("/workspace");
    shell
}

async fn elapsed(name: &str, root: &str, components: usize) -> Duration {
    let mut shell = shell(name);
    let path = vec!["a"; components].join("/");
    let start = Instant::now();
    let output = shell.run(&format!("cat -- {root}/{path}")).await;
    let elapsed = start.elapsed();
    assert_ne!(output.status, 0, "a missing path read: {}", output.stdout);
    assert!(!output.stderr.is_empty(), "a missing path gave no error");
    elapsed
}

async fn assert_linear(root: &str) {
    let short = elapsed("path-cost-short", root, SHORT).await;
    let long = elapsed("path-cost-long", root, LONG).await;
    let bound = short * 24 + Duration::from_secs(1);
    assert!(
        long < bound,
        "{LONG} components under {root:?} took {long:?}, and {SHORT} took {short:?}"
    );
}

#[tokio::test]
async fn a_missing_path_of_many_components_resolves_in_linear_time() {
    let local = tokio::task::LocalSet::new();
    local
        .run_until(async {
            assert_linear("/workspace").await;
            assert_linear("").await;
        })
        .await;
}

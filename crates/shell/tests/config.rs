// Modified by Amazon. Original source: https://github.com/strands-agents/shell
// Local changes are recorded in crates/shell/UPSTREAM.md.

//! Integration tests for the read-only config snapshot returned by
//! [`Shell::config`].
//!
//! The snapshot lets an embedder introspect a constructed shell — binds, env,
//! umask, timeout, limits — without having held onto the builder.

use std::sync::Arc;
use std::time::Duration;

use strands_shell::Shell;
use strands_shell::os::Kernel;
use strands_shell::vfs::Vfs;
use strands_shell::vfs_kernel::VfsKernel;

#[test]
fn default_shell_reports_default_config() {
    let shell = Shell::builder().build().unwrap();
    let cfg = shell.config();
    assert!(cfg.binds.is_empty());
    assert!(cfg.network_enabled);
    assert!(cfg.env.is_empty());
    assert_eq!(cfg.umask, 0o022);
    // Builder default is a 30s per-command timeout; the snapshot reports the
    // real effective value.
    assert_eq!(cfg.timeout_secs, Some(30.0));
    assert_eq!(cfg.limits.max_depth, 64);
    assert_eq!(cfg.limits.max_output, 1024 * 1024);
    assert_eq!(cfg.limits.max_fds, 128);
    assert_eq!(cfg.limits.max_bg_jobs, 8);
    assert_eq!(cfg.limits.max_pipeline, 16);
    assert_eq!(cfg.limits.max_input, 1024 * 1024);
    assert_eq!(cfg.limits.max_file_size, 10 * 1024 * 1024);
    assert_eq!(cfg.limits.max_inodes, 10_000);
}

#[test]
fn config_reports_binds() {
    let dir = tempdir();
    let shell = Shell::builder()
        .bind_direct_readonly(&dir, "/work")
        .bind(&dir, "/copy")
        .build()
        .unwrap();
    let cfg = shell.config();
    assert_eq!(cfg.binds.len(), 2);
    assert_eq!(cfg.binds[0].destination, "/work");
    assert_eq!(cfg.binds[0].mode, "direct");
    assert!(cfg.binds[0].readonly);
    assert_eq!(cfg.binds[1].destination, "/copy");
    assert_eq!(cfg.binds[1].mode, "copy");
    assert!(!cfg.binds[1].readonly);
}

#[test]
fn config_reports_env_umask_timeout() {
    let shell = Shell::builder()
        .env("PROJECT", "demo")
        .umask(0o027)
        .timeout(Duration::from_secs_f64(12.5))
        .build()
        .unwrap();
    let cfg = shell.config();
    assert_eq!(cfg.env, vec![("PROJECT".to_string(), "demo".to_string())]);
    assert_eq!(cfg.umask, 0o027);
    assert_eq!(cfg.timeout_secs, Some(12.5));
}

#[test]
fn config_reports_disabled_network() {
    let shell = Shell::builder().disable_network().build().unwrap();
    assert!(!shell.config().network_enabled);
}

#[test]
fn config_reports_overridden_limits() {
    let shell = Shell::builder()
        .max_output(2048)
        .max_inodes(500)
        .build()
        .unwrap();
    let cfg = shell.config();
    assert_eq!(cfg.limits.max_output, 2048);
    assert_eq!(cfg.limits.max_inodes, 500);
}

#[test]
fn a_custom_kernel_inherits_the_default_limits() {
    // A custom kernel is a backend swap, not an opt-out of the limits. Left
    // untouched, every process cap must arrive at its builder default rather
    // than at zero — zero means "no depth, output, fd, job, pipeline, or input
    // bound at all", which is what a Shell constructed around a kernel outside
    // the builder would carry.
    // A bare kernel, as an embedder would supply — not one borrowed back out of a
    // built Shell, which now hands out the *mediated* handle rather than the trait.
    let kernel: Arc<dyn Kernel> = Arc::new(VfsKernel::new(Vfs::new()));
    let shell = Shell::builder().kernel(kernel).build().unwrap();

    let limits = shell.limits();
    assert_eq!(limits.max_depth, 64);
    assert_eq!(limits.max_output, 1024 * 1024);
    assert_eq!(limits.max_fds, 128);
    assert_eq!(limits.max_bg_jobs, 8);
    assert_eq!(limits.max_pipeline, 16);
    assert_eq!(limits.max_input, 1024 * 1024);
    assert_eq!(shell.config().umask, 0o022);
    assert_eq!(shell.config().timeout_secs, Some(30.0));
}

#[test]
fn a_custom_kernel_honors_explicitly_set_limits() {
    // Every value here is deliberately *not* a builder default, so the test
    // cannot pass by a default merely coinciding with the expectation: it
    // fails unless each setting is really carried through to the process.
    let kernel: Arc<dyn Kernel> = Arc::new(VfsKernel::new(Vfs::new()));
    let shell = Shell::builder()
        .kernel(kernel)
        .max_depth(9)
        .max_output(4096)
        .max_fds(11)
        .max_bg_jobs(3)
        .max_pipeline(5)
        .max_input(2048)
        .umask(0o027)
        .timeout(Duration::from_secs(7))
        .build()
        .unwrap();

    let limits = shell.limits();
    assert_eq!(limits.max_depth, 9);
    assert_eq!(limits.max_output, 4096);
    assert_eq!(limits.max_fds, 11);
    assert_eq!(limits.max_bg_jobs, 3);
    assert_eq!(limits.max_pipeline, 5);
    assert_eq!(limits.max_input, 2048);

    let cfg = shell.config();
    assert_eq!(cfg.umask, 0o027);
    assert_eq!(cfg.timeout_secs, Some(7.0));
}

/// Create a throwaway host directory usable as a bind source (bind sources
/// must exist at build time).
fn tempdir() -> String {
    let mut path = std::env::temp_dir();
    let unique = format!(
        "strands-shell-config-rs-{}-{:?}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    );
    path.push(unique);
    std::fs::create_dir_all(&path).unwrap();
    path.to_string_lossy().into_owned()
}

//! The hosted Shell over `box_shell`'s kernel, governed by a real policy.

use std::io;
use std::path::PathBuf;
use std::sync::Arc;

use box_shell::{
    EffectAttempt, EffectInterceptor, EffectOutcome, EffectPermit, Filesystem, HostSpawner,
    ShellKernel,
};
use policy::{GovernedBox, Policy, PolicyEngine, PolicyError, Principal, ShellPolicyInterceptor};
use strands_shell::Shell;

/// Run a future on the current-thread runtime the Shell requires.
pub(crate) fn run<F, T>(body: F) -> T
where
    F: std::future::Future<Output = T>,
{
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime builds");
    let local = tokio::task::LocalSet::new();
    runtime.block_on(local.run_until(body))
}

/// The Shell's own filesystem under the Shell's default caps, serving each host folder.
pub(crate) fn backend(binds: &[(&str, &str)]) -> Arc<Filesystem> {
    let mut vfs = strands_shell::vfs_config::build_vfs(&Default::default()).expect("standard vfs");
    vfs.max_file_size = 10 * 1024 * 1024;
    vfs.max_inodes = 10_000;
    Arc::new(Filesystem::serving(vfs, binds).expect("a filesystem"))
}

/// One policy over `source`.
pub(crate) fn policy(source: &str) -> Arc<PolicyEngine> {
    Arc::new(try_policy(source).expect("policy loads"))
}

/// One policy over `source`, or the refusal to load it.
pub(crate) fn try_policy(source: &str) -> Result<PolicyEngine, PolicyError> {
    super::open_policy(vec![Policy {
        origin: PathBuf::from("shell-e2e.dw"),
        text: source.to_string(),
    }])
}

/// The Shell adapter over `policy`, reporting under `home` when there is one.
pub(crate) fn adapter(policy: Arc<PolicyEngine>, home: Option<&str>) -> Arc<dyn EffectInterceptor> {
    let (principal, governed) = (Principal::agent(), GovernedBox::assigned("test-box"));
    match home {
        Some(home) => {
            ShellPolicyInterceptor::into_handle_reporting_under(policy, principal, governed, home)
        }
        None => ShellPolicyInterceptor::into_handle(policy, principal, governed),
    }
}

/// The Shell's default limits.
fn limited(mut shell: Shell) -> Shell {
    shell.proc.max_depth = 64;
    shell.proc.max_output = 1024 * 1024;
    shell.proc.max_fds = 128;
    shell.proc.max_bg_jobs = 8;
    shell.proc.max_pipeline = 16;
    shell.proc.max_input = 1024 * 1024;
    shell
}

/// A Shell over `filesystem`, each effect decided by `interceptor`.
pub(crate) fn shell_on(
    filesystem: &Arc<Filesystem>,
    interceptor: Arc<dyn EffectInterceptor>,
) -> Shell {
    limited(ShellKernel::over(Arc::clone(filesystem), interceptor).shell())
}

/// A Shell over `filesystem` whose host programs run through `spawner`.
pub(crate) fn shell_with_spawner(
    filesystem: &Arc<Filesystem>,
    interceptor: Arc<dyn EffectInterceptor>,
    spawner: HostSpawner,
) -> Shell {
    limited(
        ShellKernel::over(Arc::clone(filesystem), interceptor)
            .spawner(spawner)
            .shell(),
    )
}

/// A Shell over `filesystem` that every effect passes, for building a fixture.
pub(crate) fn fixture_on(filesystem: &Arc<Filesystem>) -> Shell {
    shell_on(filesystem, Arc::new(PermitAll))
}

/// A Shell over its own filesystem, governed by `source`.
pub(crate) fn governed_by(source: &str) -> Shell {
    shell_on(&backend(&[]), adapter(policy(source), None))
}

/// Permits every attempt and records nothing.
struct PermitAll;

struct Unrecorded;

#[async_trait::async_trait]
impl EffectPermit for Unrecorded {
    async fn record_outcome(self: Box<Self>, _outcome: EffectOutcome) -> io::Result<()> {
        Ok(())
    }

    fn mark_indeterminate(self: Box<Self>) {}
}

#[async_trait::async_trait]
impl EffectInterceptor for PermitAll {
    async fn intercept(&self, _effect: &EffectAttempt<'_>) -> io::Result<Box<dyn EffectPermit>> {
        Ok(Box::new(Unrecorded))
    }
}

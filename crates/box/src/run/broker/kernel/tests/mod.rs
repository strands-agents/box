//! The hosted Shell over `box_shell`'s kernel, as the box composes it.

#[cfg(feature = "test-support")]
mod egress;
mod fallback;
mod limits;
mod streams;

use std::io;
use std::path::PathBuf;
use std::sync::Arc;

use box_shell::{
    EffectAttempt, EffectInterceptor, EffectOutcome, EffectPermit, Filesystem, ShellKernel,
};
use policy::{GovernedBox, Policy, PolicyEngine, Principal, ShellPolicyInterceptor};
use strands_shell::Shell;

/// Run a future on the current-thread runtime the Shell requires.
pub(super) fn run<F, T>(body: F) -> T
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

/// The box's Shell filesystem, serving each `(source, visible)` host folder.
pub(super) fn backend(binds: &[(&str, &str)]) -> Arc<Filesystem> {
    let vfs = crate::run::broker::shell::shell_filesystem().expect("the Shell's filesystem");
    Arc::new(Filesystem::serving(vfs, binds).expect("a filesystem"))
}

/// One policy over `source`.
pub(super) fn policy(source: &str) -> Arc<PolicyEngine> {
    Arc::new(crate::test_support::open_policy(vec![Policy {
        origin: PathBuf::from("kernel-tests.dw"),
        text: source.to_string(),
    }]))
}

/// The Shell adapter over `policy`.
pub(super) fn adapter(policy: Arc<PolicyEngine>) -> Arc<dyn EffectInterceptor> {
    ShellPolicyInterceptor::into_handle(
        policy,
        Principal::agent(),
        GovernedBox::assigned("test-box"),
    )
}

/// The box's limits on a Shell over `kernel`.
pub(super) fn limited(kernel: ShellKernel) -> Shell {
    let mut shell = kernel.shell();
    crate::run::broker::shell::apply_limits(&mut shell.proc);
    shell
}

/// A Shell over `filesystem` that every effect passes.
pub(super) fn fixture_on(filesystem: &Arc<Filesystem>) -> Shell {
    limited(ShellKernel::over(
        Arc::clone(filesystem),
        Arc::new(PermitAll),
    ))
}

/// Permits every attempt and records nothing.
pub(super) struct PermitAll;

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

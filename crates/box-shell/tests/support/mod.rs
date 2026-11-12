//! A Shell over `box_shell`'s kernel, built the way these suites were written against the
//! vendored Shell's builder.

#![allow(dead_code)]

use std::io;
use std::sync::Arc;
use std::time::Duration;

use box_shell::{
    EffectAttempt, EffectInterceptor, EffectOutcome, EffectPermit, Filesystem, HostSpawner,
    ShellKernel,
};
use strands_shell::Shell;

/// The Shell's default limits.
const MAX_FILE_SIZE: usize = 10 * 1024 * 1024;
const MAX_INODES: usize = 10_000;
const TIMEOUT: Duration = Duration::from_secs(30);

/// A Shell to build over host folders and a checkpoint.
#[derive(Default)]
pub struct Builder {
    binds: Vec<(String, String)>,
    interceptor: Option<Arc<dyn EffectInterceptor>>,
    spawner: Option<HostSpawner>,
    env: Vec<(String, String)>,
}

/// A Shell with no host folder, whose every effect passes.
pub fn builder() -> Builder {
    Builder::default()
}

impl Builder {
    /// Serve the host folder `source` at `destination`.
    pub fn bind_direct(
        mut self,
        source: impl Into<String>,
        destination: impl Into<String>,
    ) -> Self {
        self.binds.push((source.into(), destination.into()));
        self
    }

    /// Keep the network off, which a kernel with no `Network` already does.
    pub fn disable_network(self) -> Self {
        self
    }

    /// Decide each effect with `interceptor`.
    pub fn effect_interceptor(mut self, interceptor: Arc<dyn EffectInterceptor>) -> Self {
        self.interceptor = Some(interceptor);
        self
    }

    /// Run each host binary through `spawner`.
    pub fn host_spawner(mut self, spawner: HostSpawner) -> Self {
        self.spawner = Some(spawner);
        self
    }

    /// Set one Shell variable.
    pub fn env(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.env.push((key.into(), value.into()));
        self
    }

    /// The Shell.
    pub fn build(self) -> io::Result<Shell> {
        let mut vfs = strands_shell::vfs_config::build_vfs(&Default::default())?;
        vfs.max_file_size = MAX_FILE_SIZE;
        vfs.max_inodes = MAX_INODES;
        let binds: Vec<(&str, &str)> = self
            .binds
            .iter()
            .map(|(source, destination)| (source.as_str(), destination.as_str()))
            .collect();
        let filesystem = Arc::new(Filesystem::serving(vfs, &binds)?);
        let interceptor = self
            .interceptor
            .unwrap_or_else(|| Arc::new(PermitAll) as Arc<dyn EffectInterceptor>);
        let mut kernel = ShellKernel::over(filesystem, interceptor);
        if let Some(spawner) = self.spawner {
            kernel = kernel.spawner(spawner);
        }
        let mut shell = kernel.shell();
        shell.proc.max_depth = 64;
        shell.proc.max_output = 1024 * 1024;
        shell.proc.max_fds = 128;
        shell.proc.max_bg_jobs = 8;
        shell.proc.max_pipeline = 16;
        shell.proc.max_input = 1024 * 1024;
        shell.proc.deadline = Some(tokio::time::Instant::now() + TIMEOUT);
        for (key, value) in self.env {
            shell.set_env(key, value);
        }
        Ok(shell)
    }
}

/// Permits every attempt and records nothing.
pub struct PermitAll;

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

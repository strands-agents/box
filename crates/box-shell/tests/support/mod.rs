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
        Ok(self.build_with_kernel()?.0)
    }

    /// The Shell, and its kernel.
    pub fn build_with_kernel(self) -> io::Result<(Shell, Arc<ShellKernel>)> {
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
        let kernel = Arc::new(kernel);
        let mut shell =
            Shell::with_kernel(Arc::clone(&kernel) as Arc<dyn strands_shell::os::Kernel>);
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
        Ok((shell, kernel))
    }
}

/// A kernel over the Shell's default filesystem, each effect decided by `interceptor`.
pub fn kernel(interceptor: Arc<dyn EffectInterceptor>) -> ShellKernel {
    let vfs = strands_shell::vfs_config::build_vfs(&Default::default()).expect("vfs");
    let filesystem = Arc::new(Filesystem::serving(vfs, &[]).expect("a filesystem"));
    ShellKernel::over(filesystem, interceptor)
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

/// Run `body` on the current-thread runtime the Shell needs, then drain the tasks it spawned.
pub fn run<F: std::future::Future>(body: F) -> F::Output {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime");
    let local = tokio::task::LocalSet::new();
    let output = local.block_on(&runtime, body);
    runtime.block_on(local);
    output
}

/// Admits every attempt after `hook` sees it.
pub struct Hook<F>(pub F);

#[async_trait::async_trait]
impl<F> EffectInterceptor for Hook<F>
where
    F: Fn(&EffectAttempt<'_>) + Send + Sync,
{
    async fn intercept(&self, effect: &EffectAttempt<'_>) -> io::Result<Box<dyn EffectPermit>> {
        (self.0)(effect);
        Ok(Box::new(Unrecorded))
    }
}

/// A host folder served at `/workspace`, beside a folder outside it.
///
/// | Path under `ws/` | What it is |
/// |---|---|
/// | `secret.txt`, `real.txt`, `mode.txt` | files holding `IN_MOUNT`, `REAL_BYTES`, `MODE` |
/// | `dir/inner.txt` | a file in a directory |
/// | `flink` | a link to `secret.txt`, by its absolute path |
/// | `dlink` | a link to `dir` |
/// | `sub/flink` | a link to `secret.txt` |
/// | `escape` | a link to `outside` |
/// | `gone` | a link to a missing path |
pub struct Folder {
    _base: tempfile::TempDir,
    pub ws: std::path::PathBuf,
    pub outside: std::path::PathBuf,
}

/// What one script did on a [`Folder`].
pub struct Ran {
    pub out: strands_shell::Output,
    /// Each filesystem path the checkpoint saw, in order.
    pub paths: Vec<String>,
}

impl Folder {
    pub fn standard() -> Self {
        let base = tempfile::tempdir().expect("a base folder");
        let ws = base.path().join("ws");
        let outside = base.path().join("outside");
        for directory in [ws.join("dir"), ws.join("sub"), outside.clone()] {
            std::fs::create_dir_all(directory).expect("a directory");
        }
        for (file, text) in [
            (ws.join("secret.txt"), "IN_MOUNT"),
            (ws.join("real.txt"), "REAL_BYTES"),
            (ws.join("mode.txt"), "MODE"),
            (ws.join("dir/inner.txt"), "INNER"),
            (outside.join("host.txt"), "OUTSIDE"),
        ] {
            std::fs::write(file, text).expect("a file");
        }
        for (target, link) in [
            (ws.join("secret.txt"), ws.join("flink")),
            (ws.join("dir"), ws.join("dlink")),
            (ws.join("secret.txt"), ws.join("sub/flink")),
            (outside.clone(), ws.join("escape")),
            (base.path().join("absent"), ws.join("gone")),
        ] {
            std::os::unix::fs::symlink(target, link).expect("a link");
        }
        Self {
            _base: base,
            ws,
            outside,
        }
    }

    /// Run `script` in `/workspace`, with every effect admitted and recorded.
    pub fn run(&self, script: &str) -> Ran {
        let paths = Arc::new(std::sync::Mutex::new(Vec::new()));
        let seen = Arc::clone(&paths);
        let hook = Hook(move |effect: &EffectAttempt<'_>| {
            if let EffectAttempt::Filesystem { path, .. } = effect {
                seen.lock().expect("record").push((*path).to_string());
            }
        });
        let out = self.run_with(Arc::new(hook), script);
        let paths = paths.lock().expect("record").clone();
        Ran { out, paths }
    }

    /// Run `script` in `/workspace`, with `interceptor` deciding each effect.
    pub fn run_with(
        &self,
        interceptor: Arc<dyn EffectInterceptor>,
        script: &str,
    ) -> strands_shell::Output {
        let source = self.ws.to_str().expect("UTF-8").to_string();
        run(async {
            let mut shell = builder()
                .bind_direct(source, "/workspace")
                .effect_interceptor(interceptor)
                .build()
                .expect("shell builds");
            shell.proc.cwd = std::path::PathBuf::from("/workspace");
            shell.run(script).await
        })
    }

    /// Whether `name` under `ws/` is a symlink.
    pub fn is_link(&self, name: &str) -> bool {
        self.ws
            .join(name)
            .symlink_metadata()
            .is_ok_and(|meta| meta.file_type().is_symlink())
    }

    /// Whether anything is bound at `name` under `ws/`.
    pub fn exists(&self, name: &str) -> bool {
        self.ws.join(name).symlink_metadata().is_ok()
    }

    /// The permission bits of `name` under `ws/`.
    pub fn mode(&self, name: &str) -> u32 {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::symlink_metadata(self.ws.join(name))
            .expect("stat")
            .permissions()
            .mode()
            & 0o7777
    }

    /// Set the permission bits of `name` under `ws/`.
    pub fn set_mode(&self, name: &str, mode: u32) {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(self.ws.join(name), std::fs::Permissions::from_mode(mode))
            .expect("chmod");
    }
}

/// One host-folder case: a name, a setup on the folder, a script, and the checks.
#[allow(unused_macros)]
macro_rules! host_case {
    ($name:ident, $script:expr, |$folder:ident, $ran:ident| $check:block) => {
        host_case!($name, |_folder| {}, $script, |$folder, $ran| $check);
    };
    ($name:ident, |$setup:ident| $prepare:block, $script:expr, |$folder:ident, $ran:ident| $check:block) => {
        #[test]
        fn $name() {
            let $folder = support::Folder::standard();
            {
                let $setup = &$folder;
                $prepare
            }
            let $ran = $folder.run($script);
            let _ = &$ran;
            $check
        }
    };
}
#[allow(unused_imports)]
pub(crate) use host_case;

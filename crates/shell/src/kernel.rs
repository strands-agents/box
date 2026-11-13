//! The kernel the hosted Shell runs on: each filesystem effect is resolved, presented at the
//! checkpoint, and performed on the identity the checkpoint judged.

use std::io;
use std::path::PathBuf;
use std::sync::{Arc, Mutex as StdMutex};
use std::time::SystemTime;

use strands_shell::Shell;
use strands_shell::os::{
    CommandFallback, CommandRequest, DirEntry, Fd, FileStat, HttpRequest, HttpResponse, Kernel,
    OpenFlags, Process,
};
use strands_shell::vfs_kernel::VfsKernel;

use crate::effect::{
    EffectAttempt, EffectInterceptor, EffectOutcome, EffectPermit, EffectResult, FsOperation,
    FsPairOperation,
};
use crate::fallback::{self, Commands, ScriptRunner};
use crate::host::{self, Mounts};
use crate::program::{HostPrograms, HostSpawner};
use crate::resolve;
use crate::{Network, memory};

/// Whether an operation acts on a symlink's target or on the link itself.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Follow {
    Yes,
    No,
}

/// One Program's filesystem: the Shell's own, and the host folders it serves.
pub struct Filesystem {
    memory: VfsKernel,
    mounts: Mounts,
    /// Advanced by each effect that changes what a path names.
    generation: tokio::sync::Mutex<u64>,
}

impl Filesystem {
    /// Serve `vfs` with each `(source, visible)` host folder, an empty directory at each name.
    pub fn serving(mut vfs: strands_shell::vfs::Vfs, binds: &[(&str, &str)]) -> io::Result<Self> {
        let mounts = Mounts::new(binds);
        for (_, visible) in mounts.binds() {
            if vfs.resolve(visible, true).is_err() {
                vfs.mkdir_p(
                    visible,
                    0o755,
                    strands_shell::vfs::LASH_UID,
                    strands_shell::vfs::LASH_GID,
                )?;
            }
        }
        Ok(Self {
            memory: VfsKernel::new(vfs, Vec::new()),
            mounts,
            generation: tokio::sync::Mutex::new(0),
        })
    }

    /// Each `(source, visible)` host folder this filesystem serves.
    pub fn binds(&self) -> impl Iterator<Item = (&std::path::Path, &str)> {
        self.mounts.binds()
    }
}

/// A path resolved once, and the identity an effect on it must still find.
struct Resolved {
    path: String,
    follow: Follow,
    generation: u64,
    host: Option<host::HostIdentity>,
}

/// One Call's kernel over a [`Filesystem`], presenting each effect at one checkpoint.
pub struct ShellKernel {
    backend: Arc<Filesystem>,
    pub(crate) interceptor: Arc<dyn EffectInterceptor>,
    network: Option<Arc<dyn Network>>,
    pub(crate) commands: Commands,
    /// Permits of commands Shell runs itself, awaiting their status.
    running: StdMutex<Vec<(CommandKey, Box<dyn EffectPermit>)>>,
    /// Commands for the fallback, decided before their pipeline started.
    decided: StdMutex<Vec<(CommandKey, fallback::Decided)>>,
}

type CommandKey = (String, Vec<String>, PathBuf);

fn command_key(request: &CommandRequest) -> CommandKey {
    (
        request.program().to_string(),
        request.args().to_vec(),
        request.cwd().to_path_buf(),
    )
}

impl ShellKernel {
    /// A kernel over `filesystem` whose every effect `interceptor` decides.
    ///
    /// With no [`Network`] every request is refused, with no program every host binary is refused,
    /// and with no script runner `python` is not found.
    pub fn over(filesystem: Arc<Filesystem>, interceptor: Arc<dyn EffectInterceptor>) -> Self {
        Self {
            backend: filesystem,
            interceptor,
            network: None,
            commands: Commands::default(),
            running: StdMutex::new(Vec::new()),
            decided: StdMutex::new(Vec::new()),
        }
    }

    /// Send each request that passes the SSRF floor through `network`.
    pub fn network(mut self, network: Arc<dyn Network>) -> Self {
        self.network = Some(network);
        self
    }

    /// Run the file `programs` names for a bare name, before the host `PATH`.
    pub fn programs(mut self, programs: HostPrograms) -> Self {
        self.commands.programs = programs;
        self
    }

    /// Run each host binary through `spawner`.
    pub fn spawner(mut self, spawner: HostSpawner) -> Self {
        self.commands.spawner = Some(spawner);
        self
    }

    /// Run `python` and `python3` through `runner`, reading at most `max_script` bytes of a file.
    pub fn python(mut self, max_script: usize, runner: ScriptRunner) -> Self {
        self.commands.script = Some(runner);
        self.commands.max_script = max_script;
        self
    }

    /// A Shell on this kernel.
    pub fn shell(self) -> Shell {
        Shell::with_kernel(Arc::new(self))
    }

    fn route(&self, url: &str) -> io::Result<&dyn Network> {
        let network = self.network.as_deref().ok_or_else(|| {
            io::Error::new(io::ErrorKind::PermissionDenied, "network access disabled")
        })?;
        crate::check_url_safe(url)?;
        Ok(network)
    }

    async fn admit(&self, attempt: &EffectAttempt<'_>) -> io::Result<Permit> {
        self.interceptor.intercept(attempt).await.map(Permit::new)
    }

    /// Resolve `path` per `follow`, keeping the identity an effect must still find.
    async fn resolve(&self, proc: &Process, path: &str, follow: Follow) -> Resolved {
        let generation = self.backend.generation.lock().await;
        let abs = resolve::absolute(&proc.cwd, path);
        let vfs = self.backend.memory.vfs.lock().await;
        let mounts = &self.backend.mounts;
        let resolved = match follow {
            Follow::Yes => resolve::target(&vfs, mounts, &abs),
            Follow::No => match abs.rfind('/') {
                Some(0) | None => abs,
                Some(slash) => {
                    let (parent, leaf) = abs.split_at(slash);
                    let base = resolve::target(&vfs, mounts, parent);
                    format!("{}{leaf}", base.trim_end_matches('/'))
                }
            },
        };
        drop(vfs);
        let resolved = mounts
            .canonical_spelling(&resolved, follow)
            .unwrap_or(resolved);
        let host = mounts.identity(&resolved, follow);
        Resolved {
            path: resolved,
            follow,
            generation: *generation,
            host,
        }
    }

    /// Hold the namespace still while an effect acts, or refuse a path whose object moved.
    async fn guard(&self, path: &Resolved) -> io::Result<tokio::sync::MutexGuard<'_, u64>> {
        let generation = self.backend.generation.lock().await;
        if !self.is_current(path, *generation) {
            return Err(host::stale_resolution());
        }
        Ok(generation)
    }

    fn is_current(&self, path: &Resolved, generation: u64) -> bool {
        path.generation == generation
            && self.backend.mounts.identity(&path.path, path.follow) == path.host
    }

    async fn admit_path(
        &self,
        proc: &Process,
        path: &str,
        follow: Follow,
        operation: FsOperation,
    ) -> io::Result<(Resolved, Permit)> {
        let resolved = self.resolve(proc, path, follow).await;
        let permit = self
            .admit(&EffectAttempt::Filesystem {
                path: &resolved.path,
                operation,
            })
            .await?;
        Ok((resolved, permit))
    }

    /// Admit a probe whose caller cannot report an error.
    async fn admit_probe(
        &self,
        proc: &Process,
        path: &str,
        follow: Follow,
        operation: FsOperation,
    ) -> Option<(Resolved, Permit)> {
        self.admit_path(proc, path, follow, operation).await.ok()
    }

    fn host_for(&self, resolved: &Resolved, follow: Follow) -> Option<(PathBuf, PathBuf)> {
        self.backend.mounts.resolve_host_for(&resolved.path, follow)
    }

    async fn stat_answer(
        &self,
        proc: &Process,
        path: Resolved,
        follow: Follow,
    ) -> io::Result<FileStat> {
        let _generation = self.guard(&path).await?;
        let mounts = &self.backend.mounts;
        let host_follow = if follow == Follow::No && mounts.is_mount_point(&path.path) {
            Follow::Yes
        } else {
            follow
        };
        if mounts.serves(&path.path) {
            return Ok(match mounts.resolve_host_for(&path.path, host_follow) {
                Some((host_path, _)) => host::stat(&host_path, host_follow),
                None => FileStat::default(),
            });
        }
        Ok(match follow {
            Follow::Yes => self.backend.memory.stat(proc, &path.path).await,
            Follow::No => self.backend.memory.lstat(proc, &path.path).await,
        })
    }

    /// One metadata decision for `path`, and its answer, or the refusal.
    async fn stat_decided(
        &self,
        proc: &Process,
        path: &str,
        follow: Follow,
    ) -> io::Result<FileStat> {
        let (resolved, permit) = self
            .admit_path(proc, path, follow, metadata(follow))
            .await?;
        let stat = self.stat_answer(proc, resolved, follow).await;
        permit.report_answer(&stat).await;
        stat
    }

    async fn executable(&self, proc: &Process, path: &Resolved) -> bool {
        let Ok(_generation) = self.guard(path).await else {
            return false;
        };
        if self.backend.mounts.serves(&path.path) {
            return self
                .backend
                .mounts
                .resolve_host(&path.path)
                .is_some_and(|(host_path, _)| host::is_executable(&host_path));
        }
        self.backend.memory.is_executable(proc, &path.path).await
    }

    async fn open_effect(
        &self,
        proc: &mut Process,
        path: &Resolved,
        flags: OpenFlags,
    ) -> io::Result<Fd> {
        let mut generation = self.guard(path).await?;
        let result = if self.backend.mounts.serves(&path.path) {
            match self.backend.mounts.resolve_host(&path.path) {
                Some((host_path, _)) => {
                    host::open(proc, &host_path, &flags, path.host.as_ref()).await
                }
                None => Err(not_found()),
            }
        } else {
            memory::open(&self.backend.memory, proc, &path.path, flags).await
        };
        if result.is_ok() && flags.create {
            *generation = generation.wrapping_add(1);
        }
        result
    }

    async fn rename_effect(
        &self,
        proc: &Process,
        from: &Resolved,
        to: &Resolved,
    ) -> io::Result<()> {
        let mut generation = self.backend.generation.lock().await;
        if !self.is_current(from, *generation) || !self.is_current(to, *generation) {
            return Err(host::stale_resolution());
        }
        let mounts = &self.backend.mounts;
        let host_from = mounts.resolve_host(&from.path);
        let host_to = mounts.resolve_host_for(&to.path, Follow::No);
        if let Some((host_path, _)) = &host_to {
            match host_path.symlink_metadata() {
                Ok(metadata) if metadata.file_type().is_symlink() => {
                    return Err(io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        "cannot rename onto a host symlink",
                    ));
                }
                Ok(_) => {}
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Err(error) => return Err(error),
            }
        }
        let from_served = mounts.serves(&from.path);
        let to_served = mounts.serves(&to.path);
        let result = match (from_served, to_served) {
            (false, false) => self.backend.memory.rename(proc, &from.path, &to.path).await,
            (true, true) => match (host_from, host_to) {
                (Some((from_host, _)), Some((to_host, _))) => {
                    host::rename(&from_host, from.host.as_ref(), &to_host, to.host.as_ref())
                }
                _ => Err(not_found()),
            },
            _ => Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "cannot rename between host and virtual filesystem",
            )),
        };
        if result.is_ok() {
            *generation = generation.wrapping_add(1);
        }
        result
    }

    /// The literal parts of a glob pattern's directory: `.` for a bare relative name.
    fn glob_parent(path: &str) -> String {
        match path.rfind('/') {
            Some(0) => "/".to_string(),
            Some(slash) => path[..slash].to_string(),
            None => ".".to_string(),
        }
    }
}

/// The metadata-read operation matching a symlink disposition.
fn metadata(follow: Follow) -> FsOperation {
    FsOperation::ReadMetadata {
        follow_symlinks: follow == Follow::Yes,
    }
}

fn not_found() -> io::Error {
    io::Error::new(io::ErrorKind::NotFound, "No such file or directory")
}

/// One admitted filesystem effect, marked indeterminate unless its outcome is recorded.
struct Permit(Option<Box<dyn EffectPermit>>);

impl Permit {
    fn new(permit: Box<dyn EffectPermit>) -> Self {
        Self(Some(permit))
    }

    async fn record(mut self, result: EffectResult) -> io::Result<()> {
        match self.0.take() {
            Some(permit) => permit.record_outcome(EffectOutcome::Kernel(result)).await,
            None => Ok(()),
        }
    }

    /// Record an effect whose return value is its whole outcome.
    async fn report<T>(self, outcome: io::Result<T>) -> io::Result<T> {
        let result = match &outcome {
            Ok(_) => EffectResult::Completed,
            Err(error) => EffectResult::Failed(error.kind()),
        };
        self.record(result).await?;
        outcome
    }

    /// Record a metadata answer, yes or no, as completed, and a refusal as failed.
    async fn report_answer<T>(self, answer: &io::Result<T>) {
        let result = match answer {
            Ok(_) => EffectResult::Completed,
            Err(error) => EffectResult::Failed(error.kind()),
        };
        if let Err(error) = self.record(result).await {
            eprintln!("strands-box: recording a metadata outcome failed: {error}");
        }
    }

    /// Record a probe, which cannot surface a recording failure to its caller.
    async fn report_probe(self, found: bool) {
        let result = if found {
            EffectResult::Completed
        } else {
            EffectResult::Failed(io::ErrorKind::NotFound)
        };
        if let Err(error) = self.record(result).await {
            eprintln!("strands-box: recording a metadata outcome failed: {error}");
        }
    }
}

impl Drop for Permit {
    fn drop(&mut self) {
        if let Some(permit) = self.0.take() {
            permit.mark_indeterminate();
        }
    }
}

fn open_outcome(opened: &io::Result<Fd>) -> EffectResult {
    match opened {
        Ok(_) => EffectResult::DescriptorIssued,
        Err(error) => EffectResult::Failed(error.kind()),
    }
}

#[async_trait::async_trait]
impl Kernel for ShellKernel {
    fn new_process(&self) -> Process {
        self.backend.memory.new_process()
    }

    /// A read-write open (`<>`) is admitted as a read and as a write, because it discloses
    /// content.
    async fn open(&self, proc: &mut Process, path: &str, flags: OpenFlags) -> io::Result<Fd> {
        let writes = flags.write || flags.create || flags.truncate;
        let write_operation = FsOperation::WriteContent {
            create: flags.create,
            truncate: flags.truncate,
        };
        if flags.read && writes {
            let (resolved, read_permit) = self
                .admit_path(proc, path, Follow::Yes, FsOperation::ReadContent)
                .await?;
            let write_permit = self
                .admit(&EffectAttempt::Filesystem {
                    path: &resolved.path,
                    operation: write_operation,
                })
                .await?;
            let opened = self.open_effect(proc, &resolved, flags).await;
            let result = open_outcome(&opened);
            read_permit.record(result).await?;
            write_permit.record(result).await?;
            return opened;
        }
        let operation = if writes {
            write_operation
        } else {
            FsOperation::ReadContent
        };
        let (resolved, permit) = self.admit_path(proc, path, Follow::Yes, operation).await?;
        let opened = self.open_effect(proc, &resolved, flags).await;
        permit.record(open_outcome(&opened)).await?;
        opened
    }

    async fn list_dir(&self, proc: &Process, path: &str) -> io::Result<Vec<DirEntry>> {
        let (resolved, permit) = self
            .admit_path(proc, path, Follow::Yes, FsOperation::Enumerate)
            .await?;
        let listed = async {
            let _generation = self.guard(&resolved).await?;
            if self.backend.mounts.serves(&resolved.path) {
                let (host_path, _) = self
                    .backend
                    .mounts
                    .resolve_host(&resolved.path)
                    .ok_or_else(not_found)?;
                return host::list_dir(&host_path);
            }
            self.backend.memory.list_dir(proc, &resolved.path).await
        }
        .await;
        permit.report(listed).await
    }

    async fn change_dir(&self, proc: &mut Process, path: &str) -> io::Result<()> {
        let (resolved, permit) = self
            .admit_path(proc, path, Follow::Yes, FsOperation::ChangeDir)
            .await?;
        let changed = async {
            let _generation = self.guard(&resolved).await?;
            if self.backend.mounts.serves(&resolved.path) {
                let (host_path, _) = self
                    .backend
                    .mounts
                    .resolve_host(&resolved.path)
                    .ok_or_else(not_found)?;
                if !std::fs::metadata(&host_path)?.is_dir() {
                    return Err(io::Error::new(
                        io::ErrorKind::NotADirectory,
                        "Not a directory",
                    ));
                }
                proc.cwd = PathBuf::from(&resolved.path);
                return Ok(());
            }
            self.backend.memory.change_dir(proc, &resolved.path).await
        }
        .await;
        permit.report(changed).await
    }

    async fn stat(&self, proc: &Process, path: &str) -> FileStat {
        self.stat_decided(proc, path, Follow::Yes)
            .await
            .unwrap_or_default()
    }

    async fn lstat(&self, proc: &Process, path: &str) -> FileStat {
        self.stat_decided(proc, path, Follow::No)
            .await
            .unwrap_or_default()
    }

    async fn access(&self, proc: &Process, path: &str, mode: i32) -> bool {
        let Some((resolved, permit)) = self
            .admit_probe(proc, path, Follow::Yes, metadata(Follow::Yes))
            .await
        else {
            return false;
        };
        let allowed = async {
            let _generation = self.guard(&resolved).await?;
            if self.backend.mounts.serves(&resolved.path) {
                return Ok(self
                    .backend
                    .mounts
                    .resolve_host(&resolved.path)
                    .is_some_and(|(host_path, _)| host::access(&host_path, mode)));
            }
            Ok(self.backend.memory.access(proc, &resolved.path, mode).await)
        }
        .await;
        permit.report_answer(&allowed).await;
        allowed.unwrap_or(false)
    }

    async fn try_stat(&self, proc: &Process, path: &str) -> io::Result<FileStat> {
        let stat = self.stat_decided(proc, path, Follow::Yes).await?;
        if stat.exists {
            Ok(stat)
        } else {
            Err(not_found())
        }
    }

    async fn canonicalize(&self, proc: &Process, path: &str) -> io::Result<PathBuf> {
        let (resolved, permit) = self
            .admit_path(proc, path, Follow::Yes, metadata(Follow::Yes))
            .await?;
        let canonical = async {
            let _generation = self.guard(&resolved).await?;
            self.backend.memory.canonicalize(proc, &resolved.path).await
        }
        .await;
        permit.report(canonical).await
    }

    /// A candidate is located with no decision, and only one the backend calls executable is
    /// decided as an `exec` read, so a `PATH` walk records one decision.
    async fn is_executable(&self, proc: &Process, path: &str) -> bool {
        let Some((located, permit)) = self
            .admit_probe(proc, path, Follow::Yes, FsOperation::Locate)
            .await
        else {
            return false;
        };
        let executable = self.executable(proc, &located).await;
        permit.report_probe(executable).await;
        if !executable {
            return false;
        }
        let Some((resolved, permit)) = self
            .admit_probe(proc, path, Follow::Yes, FsOperation::Exec)
            .await
        else {
            return false;
        };
        let executable = self.executable(proc, &resolved).await;
        permit.report_probe(executable).await;
        executable
    }

    /// Every directory the expansion reads is decided, from the literal prefix down to each
    /// match's parent, and then each match; a refused directory drops every match below it.
    async fn glob(&self, proc: &Process, pattern: &str) -> Vec<String> {
        let prefix = Self::glob_parent(
            pattern
                .find(['*', '?', '['])
                .map_or(pattern, |index| &pattern[..=index]),
        );
        let Some((_, permit)) = self
            .admit_probe(proc, &prefix, Follow::Yes, FsOperation::Enumerate)
            .await
        else {
            return Vec::new();
        };
        let mounts = &self.backend.mounts;
        let candidates: Vec<String> = self
            .backend
            .memory
            .glob(proc, pattern)
            .await
            .into_iter()
            .filter(|candidate| {
                let abs = resolve::absolute(&proc.cwd, candidate);
                !mounts.serves(&abs) || mounts.is_mount_point(&abs)
            })
            .collect();
        permit.report_probe(!candidates.is_empty()).await;

        let mut matches = Vec::with_capacity(candidates.len());
        let mut enumerated: Vec<(String, bool)> = vec![(prefix.clone(), true)];
        for candidate in candidates {
            let mut walked = Vec::new();
            let mut directory = Self::glob_parent(&candidate);
            while directory != prefix && directory != "/" && directory != "." {
                let above = Self::glob_parent(&directory);
                walked.push(directory);
                directory = above;
            }
            let mut allowed = true;
            for directory in walked.into_iter().rev() {
                allowed = match enumerated.iter().find(|(seen, _)| *seen == directory) {
                    Some((_, allowed)) => *allowed,
                    None => {
                        let allowed = match self
                            .admit_probe(proc, &directory, Follow::Yes, FsOperation::Enumerate)
                            .await
                        {
                            Some((_, permit)) => {
                                permit.report_probe(true).await;
                                true
                            }
                            None => false,
                        };
                        enumerated.push((directory, allowed));
                        allowed
                    }
                };
                if !allowed {
                    break;
                }
            }
            if !allowed {
                continue;
            }
            if let Some((_, permit)) = self
                .admit_probe(proc, &candidate, Follow::Yes, metadata(Follow::Yes))
                .await
            {
                permit.report_probe(true).await;
                matches.push(candidate);
            }
        }
        matches
    }

    fn isatty(&self, fd: i32) -> bool {
        self.backend.memory.isatty(fd)
    }

    /// Unlinking acts on the name, not on what it points at.
    async fn remove_file(&self, proc: &Process, path: &str) -> io::Result<()> {
        let (resolved, permit) = self
            .admit_path(proc, path, Follow::No, FsOperation::RemoveFile)
            .await?;
        let removed = async {
            let mut generation = self.guard(&resolved).await?;
            let mounts = &self.backend.mounts;
            if mounts.is_mount_point(&resolved.path) {
                return Err(host::mount_point_busy());
            }
            let result = if mounts.serves(&resolved.path) {
                match self.host_for(&resolved, Follow::No) {
                    Some((host_path, _)) => host::unlink(&host_path, resolved.host.as_ref(), false),
                    None => Err(not_found()),
                }
            } else {
                self.backend.memory.remove_file(proc, &resolved.path).await
            };
            if result.is_ok() {
                *generation = generation.wrapping_add(1);
            }
            result
        }
        .await;
        permit.report(removed).await
    }

    async fn remove_dir(&self, proc: &Process, path: &str) -> io::Result<()> {
        let (resolved, permit) = self
            .admit_path(proc, path, Follow::Yes, FsOperation::RemoveDir)
            .await?;
        let removed = async {
            let mut generation = self.guard(&resolved).await?;
            let result = if self.backend.mounts.serves(&resolved.path) {
                match self.host_for(&resolved, Follow::Yes) {
                    Some((host_path, _)) => host::unlink(&host_path, resolved.host.as_ref(), true),
                    None => Err(not_found()),
                }
            } else {
                self.backend.memory.remove_dir(proc, &resolved.path).await
            };
            if result.is_ok() {
                *generation = generation.wrapping_add(1);
            }
            result
        }
        .await;
        permit.report(removed).await
    }

    /// A symlink at the final component is the name that already exists.
    async fn create_dir(&self, proc: &Process, path: &str) -> io::Result<()> {
        let (resolved, permit) = self
            .admit_path(proc, path, Follow::No, FsOperation::CreateDir)
            .await?;
        let created = async {
            let mut generation = self.guard(&resolved).await?;
            let result = if self.backend.mounts.serves(&resolved.path) {
                match self.host_for(&resolved, Follow::No) {
                    Some((host_path, _)) => {
                        host::create_directory(&host_path, resolved.host.as_ref())
                    }
                    None => Err(not_found()),
                }
            } else {
                self.backend.memory.create_dir(proc, &resolved.path).await
            };
            if result.is_ok() {
                *generation = generation.wrapping_add(1);
            }
            result
        }
        .await;
        permit.report(created).await
    }

    /// Both names are admitted together. The source is the link itself, and the destination's
    /// final component is the name replaced, so whether one is bound there is read unfollowed.
    async fn rename(&self, proc: &Process, from: &str, to: &str) -> io::Result<()> {
        let source = self.resolve(proc, from, Follow::No).await;
        let target = self.resolve(proc, to, Follow::No).await;
        let destination = {
            let mounts = &self.backend.mounts;
            if mounts.serves(&target.path) {
                let follow = if mounts.is_mount_point(&target.path) {
                    Follow::Yes
                } else {
                    Follow::No
                };
                mounts
                    .resolve_host_for(&target.path, follow)
                    .map(|(host_path, _)| host::stat(&host_path, follow))
                    .unwrap_or_default()
            } else {
                self.backend.memory.lstat(proc, &target.path).await
            }
        };
        let permit = self
            .admit(&EffectAttempt::FilesystemPair {
                from: &source.path,
                to: &target.path,
                operation: FsPairOperation::Rename {
                    destination_exists: destination.exists,
                    destination_is_dir: destination.is_dir,
                },
            })
            .await?;
        permit
            .report(self.rename_effect(proc, &source, &target).await)
            .await
    }

    /// Only `link` is a resolved identity; `target` is the text the link stores.
    async fn symlink(&self, proc: &Process, target: &str, link: &str) -> io::Result<()> {
        let at = self.resolve(proc, link, Follow::No).await;
        let permit = self
            .admit(&EffectAttempt::FilesystemPair {
                from: target,
                to: &at.path,
                operation: FsPairOperation::Symlink,
            })
            .await?;
        let linked = async {
            let mut generation = self.guard(&at).await?;
            let mounts = &self.backend.mounts;
            if mounts.is_mount_point(&at.path) {
                return Err(host::mount_point_busy());
            }
            let result = if mounts.serves(&at.path) {
                match self.host_for(&at, Follow::No) {
                    Some((host_link, base)) => {
                        host::verify_symlink_target(target, &host_link, &base)
                            .and_then(|()| host::symlink(target, &host_link, at.host.as_ref()))
                    }
                    None => Err(not_found()),
                }
            } else {
                self.backend.memory.symlink(proc, target, &at.path).await
            };
            if result.is_ok() {
                *generation = generation.wrapping_add(1);
            }
            result
        }
        .await;
        permit.report(linked).await
    }

    async fn read_link(&self, proc: &Process, path: &str) -> io::Result<String> {
        let (resolved, permit) = self
            .admit_path(proc, path, Follow::No, FsOperation::ReadLink)
            .await?;
        let read = async {
            let _generation = self.guard(&resolved).await?;
            let (parent, leaf) = host::split_leaf(&resolved.path);
            if !leaf.is_empty() && self.backend.mounts.serves(parent) {
                let (host_parent, _) = self
                    .backend
                    .mounts
                    .resolve_host(parent)
                    .ok_or_else(not_found)?;
                let target = std::fs::read_link(host_parent.join(leaf))?;
                return Ok(target.to_string_lossy().into_owned());
            }
            self.backend.memory.read_link(proc, &resolved.path).await
        }
        .await;
        permit.report(read).await
    }

    /// A host object never takes a setuid, setgid, or sticky bit: it is shared with the operator,
    /// and a process outside the box honours it.
    async fn set_permissions(&self, proc: &Process, path: &str, mode: u32) -> io::Result<()> {
        let (resolved, permit) = self
            .admit_path(
                proc,
                path,
                Follow::Yes,
                FsOperation::SetPermissions { mode },
            )
            .await?;
        let changed = async {
            let _generation = self.guard(&resolved).await?;
            if self.backend.mounts.serves(&resolved.path) {
                let (host_path, _) = self
                    .backend
                    .mounts
                    .resolve_host(&resolved.path)
                    .ok_or_else(not_found)?;
                // A special bit the file already holds is dropped, not refused.
                let held = std::fs::metadata(&host_path).map_or(0, |meta| {
                    std::os::unix::fs::PermissionsExt::mode(&meta.permissions()) & 0o7000
                });
                if mode & 0o7000 & !held != 0 {
                    return Err(io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        "setuid/setgid/sticky bits are not permitted in this box",
                    ));
                }
                return host::set_permissions(&host_path, mode & 0o777, resolved.host.as_ref());
            }
            self.backend
                .memory
                .set_permissions(proc, &resolved.path, mode)
                .await
        }
        .await;
        permit.report(changed).await
    }

    fn now(&self) -> SystemTime {
        SystemTime::now()
    }

    fn check_url(&self, url: &str) -> io::Result<()> {
        self.route(url).map(drop)
    }

    async fn http_request(&self, req: HttpRequest) -> io::Result<HttpResponse> {
        self.route(&req.url)?.send(req).await
    }

    fn command_fallback(&self) -> Option<&dyn CommandFallback> {
        Some(self)
    }

    /// A denial reads `effect denied`, as a denied host program does.
    async fn check_command(&self, request: &CommandRequest) -> io::Result<()> {
        let permit = fallback::admit_run(
            self.interceptor.as_ref(),
            request.program(),
            request.args(),
            &request.cwd().to_string_lossy(),
        )
        .await
        .map_err(denied)?;
        self.running
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push((command_key(request), permit));
        Ok(())
    }

    /// Each stage for the fallback is decided before any stage of its pipeline starts.
    async fn check_fallback(&self, request: &CommandRequest) -> io::Result<()> {
        let decided = self
            .decide(request.program(), request.args(), request.cwd())
            .await
            .map_err(denied)?;
        self.decided
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push((command_key(request), decided));
        Ok(())
    }

    async fn command_finished(&self, request: &CommandRequest, status: i32) -> io::Result<()> {
        match self.take_running(request) {
            Some(permit) => {
                permit
                    .record_outcome(EffectOutcome::ShellCommand {
                        reported_status: status,
                    })
                    .await
            }
            None => Ok(()),
        }
    }

    /// Recorded as indeterminate, status -1, because the command may or may not have run.
    fn command_dropped(&self, request: &CommandRequest) {
        if let Some(permit) = self.take_running(request) {
            permit.mark_indeterminate();
        }
    }
}

impl ShellKernel {
    fn take_running(&self, request: &CommandRequest) -> Option<Box<dyn EffectPermit>> {
        let key = command_key(request);
        let mut running = self
            .running
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let index = running.iter().position(|(held, _)| *held == key)?;
        Some(running.remove(index).1)
    }
}

impl ShellKernel {
    /// Record each fallback stage decided in this Call that never ran as indeterminate.
    pub fn settle(&self) {
        let unrun = std::mem::take(
            &mut *self
                .decided
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner),
        );
        for (_, decided) in unrun {
            decided.drop_unrun();
        }
    }

    /// The latest decision a pre-start check made for this command, when one is held.
    pub(crate) fn take_decided(
        &self,
        program: &str,
        args: &[String],
        cwd: &std::path::Path,
    ) -> Option<fallback::Decided> {
        let key = (program.to_string(), args.to_vec(), cwd.to_path_buf());
        let mut decided = self
            .decided
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let index = decided.iter().rposition(|(held, _)| *held == key)?;
        Some(decided.remove(index).1)
    }
}

/// The refusal a decision gave, as the Shell reports it.
fn denied(error: io::Error) -> io::Error {
    io::Error::new(error.kind(), format!("effect denied: {error}"))
}

impl Drop for ShellKernel {
    fn drop(&mut self) {
        let running = std::mem::take(
            self.running
                .get_mut()
                .unwrap_or_else(std::sync::PoisonError::into_inner),
        );
        for (_, permit) in running {
            permit.mark_indeterminate();
        }
        let decided = std::mem::take(
            self.decided
                .get_mut()
                .unwrap_or_else(std::sync::PoisonError::into_inner),
        );
        for (_, decided) in decided {
            decided.drop_unrun();
        }
    }
}

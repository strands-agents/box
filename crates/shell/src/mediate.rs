//! Effect admission, above the `Kernel` trait.
//!
//! This is the only place a [`Kernel`] is reached from. Every filesystem effect is
//! resolved, presented for admission, executed, and reported here — so mediation is a
//! property of the path callers take rather than of the kernel they happen to be
//! using. A caller-supplied kernel is governed identically to the bundled one.
//!
//! Callers hold a [`Mediated`] and pass path *strings*, exactly as they passed them to
//! the trait before. [`Follow`] is chosen here, once per operation, because it is a
//! property of the operation rather than of the path — leaving that choice to 60-odd
//! call sites is what let `rename` authorize a symlink's name while writing to its
//! target. The [`Resolved`] token exists only between this layer's `resolve` and its
//! trait call; it never appears in caller code.

use std::io;
use std::path::PathBuf;
use std::sync::Arc;

use crate::effect::{
    EffectAttempt, EffectInterceptor, EffectOutcome, EffectPermit, EffectResult, FsOperation,
    FsPairOperation, KernelPermit,
};
use crate::os::{
    DirEntry, Fd, FileStat, Follow, HttpRequest, HttpResponse, Kernel, OpenFlags, Process,
    Resolved, WriteFailure,
};

/// A kernel whose every filesystem effect is admitted before it happens.
pub struct Mediated {
    kernel: Arc<dyn Kernel>,
    interceptor: Option<Arc<dyn EffectInterceptor>>,
}

impl Mediated {
    /// Wrap `kernel`, consulting `interceptor` for each effect.
    ///
    /// `None` leaves every operation unmediated, which is how a shell built without an
    /// interceptor behaves.
    pub(crate) fn new(
        kernel: Arc<dyn Kernel>,
        interceptor: Option<Arc<dyn EffectInterceptor>>,
    ) -> Self {
        Self {
            kernel,
            interceptor,
        }
    }

    /// Present one attempt for admission.
    ///
    /// A denial and an interceptor fault both fail closed, so a caller receiving an
    /// error must propagate it rather than proceed.
    async fn admit(&self, attempt: &EffectAttempt<'_>) -> io::Result<KernelPermit> {
        match &self.interceptor {
            Some(interceptor) => interceptor.intercept(attempt).await.map(KernelPermit::new),
            None => Ok(KernelPermit::absent()),
        }
    }

    /// Resolve one path and admit the operation acting on it.
    ///
    /// Returns the token so the effect runs against the same identity that was
    /// authorized. Resolving again below this point would reintroduce the gap between
    /// the decision and the effect.
    async fn admit_path(
        &self,
        proc: &Process,
        path: &str,
        follow: Follow,
        operation: FsOperation,
    ) -> io::Result<(Resolved, KernelPermit)> {
        let resolved = self.kernel.resolve(proc, path, follow).await;
        let permit = self
            .admit(&EffectAttempt::Filesystem {
                path: resolved.path(),
                operation,
            })
            .await?;
        Ok((resolved, permit))
    }

    /// Admit an operation whose caller cannot report an error.
    ///
    /// `stat`, `lstat`, `access`, `is_executable`, and `glob` return a value rather
    /// than a `Result`. A denial therefore surfaces as the *absent* answer, which is
    /// also the answer that leaks nothing about the target.
    async fn admit_probe(
        &self,
        proc: &Process,
        path: &str,
        follow: Follow,
        operation: FsOperation,
    ) -> Option<(Resolved, KernelPermit)> {
        self.admit_path(proc, path, follow, operation).await.ok()
    }

    /// Present one **resolved** command for admission.
    ///
    /// This is the *exec* counterpart to [`admit_path`](Self::admit_path), and it lives here
    /// for the same reason: mediation is a property of the path callers take, not of the
    /// entry point they happened to use.
    ///
    /// The caller is [`run_pipeline`](crate::exec), the one function every command reaches,
    /// and it calls this **after** resolution so the attempt can name the program rather
    /// than only the text. That placement is what keeps the routes an earlier design missed
    /// covered: `sh <file>`, `.`/`source`, a trap body, `find -exec`, `xargs`, Lua's
    /// `io.popen` and `os.execute`, `eval`, and `$(…)` all resolve each command they run, so
    /// each gets its own decision instead of inheriting one taken over a whole submission.
    ///
    /// Returns a [`CommandPermit`] so the caller reports the command's status, keeping
    /// report-exactly-once. A denial and an interceptor fault both fail closed.
    pub(crate) async fn admit_run(
        &self,
        command: &str,
        program: &str,
        args: &[String],
        literal: &[bool],
        cwd: &str,
    ) -> io::Result<CommandPermit> {
        self.admit_resolved(&EffectAttempt::ShellRun {
            command,
            program,
            args,
            literal,
            cwd,
        })
        .await
    }

    /// Present one resolved command that a **host binary** will execute.
    ///
    /// Raised by [`run_pipeline`](crate::exec) for a program this Shell does not implement, with
    /// the path its own `PATH` walk resolved. A permit here is what `spawn_host_program` acts on,
    /// so the binary that runs is the binary the authority saw.
    pub(crate) async fn admit_spawn(
        &self,
        command: &str,
        program: &str,
        program_path: &str,
        args: &[String],
        literal: &[bool],
        cwd: &str,
    ) -> io::Result<CommandPermit> {
        self.admit_resolved(&EffectAttempt::ShellSpawn {
            command,
            program,
            program_path,
            args,
            literal,
            cwd,
        })
        .await
    }

    /// Raise one resolved-command attempt, shared by both kinds so neither can drift into
    /// a different permit lifecycle.
    async fn admit_resolved(&self, attempt: &EffectAttempt<'_>) -> io::Result<CommandPermit> {
        match &self.interceptor {
            Some(interceptor) => interceptor
                .intercept(attempt)
                .await
                .map(|permit| CommandPermit {
                    permit: Some(permit),
                    spawn_program: None,
                }),
            None => Ok(CommandPermit {
                permit: None,
                spawn_program: None,
            }),
        }
    }

    /// Report an operation whose return value is its complete effect.
    ///
    /// A recording failure cannot undo an effect that already happened, so it is
    /// surfaced rather than converted into a denial.
    async fn report<T>(permit: KernelPermit, outcome: io::Result<T>) -> io::Result<T> {
        let result = match &outcome {
            Ok(_) => EffectResult::Completed,
            Err(error) => EffectResult::Failed(error.kind()),
        };
        permit.record(result).await?;
        outcome
    }

    /// The metadata-read operation matching a symlink disposition.
    ///
    /// The two travel together — a `Follow::No` probe is by definition a no-follow
    /// metadata read — so deriving one from the other keeps five call sites from
    /// restating the pairing, and from being able to get it inconsistent.
    fn metadata(follow: Follow) -> FsOperation {
        FsOperation::ReadMetadata {
            follow_symlinks: matches!(follow, Follow::Yes),
        }
    }

    /// Report an open, whose effect is an issued descriptor rather than a transfer.
    ///
    /// `DescriptorIssued`, never `Completed`: the bytes an open enables move later,
    /// outside any admitted call.
    fn open_outcome(opened: &io::Result<Fd>) -> EffectResult {
        match opened {
            Ok(_) => EffectResult::DescriptorIssued,
            Err(error) => EffectResult::Failed(error.kind()),
        }
    }

    /// Report a probe, which cannot surface a recording failure to its caller.
    async fn report_probe(permit: KernelPermit, found: bool) {
        let result = if found {
            EffectResult::Completed
        } else {
            EffectResult::Failed(io::ErrorKind::NotFound)
        };
        if let Err(error) = permit.record(result).await {
            eprintln!("strands-shell: recording a metadata outcome failed: {error}");
        }
    }

    /// Open a file.
    ///
    /// `create` and `truncate` mutate at open time, so admission precedes the lookup.
    /// The outcome is `DescriptorIssued` rather than `Completed`: an open issues a
    /// descriptor, and the bytes it enables move later, outside any admitted call.
    pub async fn open(&self, proc: &mut Process, path: &str, flags: OpenFlags) -> io::Result<Fd> {
        let writes = flags.write || flags.create || flags.truncate;
        let write_operation = FsOperation::WriteContent {
            create: flags.create,
            truncate: flags.truncate,
        };

        // A read-write open (`<>`) grants BOTH capabilities and the implementation
        // hands back a reader seeded with current content, so it must clear the read
        // authorization too. Admitting it as write-only would disclose content under a
        // write-only permit.
        if flags.read && writes {
            let (resolved, read_permit) = self
                .admit_path(proc, path, Follow::Yes, FsOperation::ReadContent)
                .await?;
            let write_permit = self
                .admit(&EffectAttempt::Filesystem {
                    path: resolved.path(),
                    operation: write_operation,
                })
                .await?;
            let opened = self.kernel.open(proc, resolved, flags).await;
            let result = Self::open_outcome(&opened);
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
        let opened = self.kernel.open(proc, resolved, flags).await;
        permit.record(Self::open_outcome(&opened)).await?;
        opened
    }

    /// List a directory.
    pub async fn list_dir(&self, proc: &Process, path: &str) -> io::Result<Vec<DirEntry>> {
        let (resolved, permit) = self
            .admit_path(proc, path, Follow::Yes, FsOperation::Enumerate)
            .await?;
        Self::report(permit, self.kernel.list_dir(proc, resolved).await).await
    }

    /// Change the process working directory.
    pub async fn change_dir(&self, proc: &mut Process, path: &str) -> io::Result<()> {
        let (resolved, permit) = self
            .admit_path(proc, path, Follow::Yes, FsOperation::ChangeDir)
            .await?;
        Self::report(permit, self.kernel.change_dir(proc, resolved).await).await
    }

    /// Wait until every write whose descriptors are all closed is visible, and report each that failed.
    pub async fn settle_writes(&self) -> Vec<WriteFailure> {
        self.kernel.settle_writes().await
    }

    /// Stat a path, following a final symlink.
    ///
    /// Denial yields the not-found stat, which is also the no-information answer.
    pub async fn stat(&self, proc: &Process, path: &str) -> FileStat {
        self.stat_if_admitted(proc, path).await.unwrap_or_default()
    }

    /// Stat a path, following a final symlink, and report a refused probe as `None`.
    pub(crate) async fn stat_if_admitted(&self, proc: &Process, path: &str) -> Option<FileStat> {
        let operation = Self::metadata(Follow::Yes);
        let (resolved, permit) = self.admit_probe(proc, path, Follow::Yes, operation).await?;
        let stat = self.kernel.stat(proc, resolved).await;
        Self::report_probe(permit, stat.exists).await;
        Some(stat)
    }

    /// Stat a path without following a final symlink.
    ///
    /// Distinct from [`Self::stat`]: a no-follow probe before a delete or a traversal
    /// decision is a symlink-escape defense, so policy sees it apart.
    pub async fn lstat(&self, proc: &Process, path: &str) -> FileStat {
        let operation = Self::metadata(Follow::No);
        let Some((resolved, permit)) = self.admit_probe(proc, path, Follow::No, operation).await
        else {
            return FileStat::default();
        };
        let stat = self.kernel.lstat(proc, resolved).await;
        Self::report_probe(permit, stat.exists).await;
        stat
    }

    /// Test access permissions. Denial yields `false` — the same answer as "no access".
    pub async fn access(&self, proc: &Process, path: &str, mode: i32) -> bool {
        let operation = Self::metadata(Follow::Yes);
        let Some((resolved, permit)) = self.admit_probe(proc, path, Follow::Yes, operation).await
        else {
            return false;
        };
        let allowed = self.kernel.access(proc, resolved, mode).await;
        Self::report_probe(permit, allowed).await;
        allowed
    }

    /// Canonicalize a path.
    pub async fn canonicalize(&self, proc: &Process, path: &str) -> io::Result<PathBuf> {
        let operation = Self::metadata(Follow::Yes);
        let (resolved, permit) = self.admit_path(proc, path, Follow::Yes, operation).await?;
        Self::report(permit, self.kernel.canonicalize(proc, resolved).await).await
    }

    /// Test whether a path is executable. Denial reports it as not executable.
    pub async fn is_executable(&self, proc: &Process, path: &str) -> bool {
        let Some((resolved, permit)) = self
            .admit_probe(proc, path, Follow::Yes, FsOperation::Exec)
            .await
        else {
            return false;
        };
        let executable = self.kernel.is_executable(proc, resolved).await;
        Self::report_probe(permit, executable).await;
        executable
    }

    /// Find `name` on the process `PATH`, presenting each candidate as [`FsOperation::Locate`] and
    /// the first executable one as [`FsOperation::Exec`].
    pub(crate) async fn find_in_path(&self, proc: &Process, name: &str) -> Option<String> {
        let path_var = proc.env.get("PATH")?;
        for dir in path_var.split(':') {
            let full = if dir.is_empty() {
                format!("./{name}")
            } else {
                format!("{dir}/{name}")
            };
            let Some((resolved, permit)) = self
                .admit_probe(proc, &full, Follow::Yes, FsOperation::Locate)
                .await
            else {
                continue;
            };
            let executable = self.kernel.is_executable(proc, resolved).await;
            Self::report_probe(permit, executable).await;
            if executable && self.is_executable(proc, &full).await {
                return Some(full);
            }
        }
        None
    }

    /// Expand a glob pattern. Denial yields no matches.
    ///
    /// A pattern is not a path, and a path rule cannot meaningfully match one — a
    /// `forbid` on `/secrets/` would not fire for `/secr*/*` while the expansion still
    /// disclosed both files. So every *directory actually enumerated* is authorized,
    /// and then every match individually. A denial drops that entry rather than the
    /// whole expansion.
    ///
    /// The enumerated directories are the literal prefix before the first wildcard and
    /// every directory between it and each match, not only the match's parent:
    /// `/tmp/*/*/*` reads `/tmp/private` to reach `/tmp/private/sub/file`. A relative
    /// pattern with no `/` before its first wildcard starts from `.`. The directories
    /// are deduplicated and authorized from the prefix down, and a refused one stops the
    /// walk for every match below it, so the decision count is bounded by the
    /// directories touched rather than by the number of matches.
    pub async fn glob(&self, proc: &Process, pattern: &str) -> Vec<String> {
        let prefix = Self::glob_parent(
            pattern
                .find(['*', '?', '['])
                .map_or(pattern, |index| &pattern[..=index]),
        );
        // The literal prefix is authorized first: it is the directory the expansion
        // starts from, and denying it stops the walk before any name is disclosed.
        let Some((_, permit)) = self
            .admit_probe(proc, &prefix, Follow::Yes, FsOperation::Enumerate)
            .await
        else {
            return Vec::new();
        };
        let candidates = self.kernel.glob(proc, pattern).await;
        Self::report_probe(permit, !candidates.is_empty()).await;

        let operation = Self::metadata(Follow::Yes);
        let mut matches = Vec::with_capacity(candidates.len());
        let mut enumerated: Vec<(String, bool)> = vec![(prefix.clone(), true)];
        for candidate in candidates {
            // Authorize enumeration of every directory the walk read to produce this
            // match, from the prefix down to its parent. A match under
            // `/tmp/private/sub` discloses a name read out of `/tmp/private` too.
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
                                Self::report_probe(permit, true).await;
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
                .admit_probe(proc, &candidate, Follow::Yes, operation)
                .await
            {
                Self::report_probe(permit, true).await;
                matches.push(candidate);
            }
        }
        matches
    }

    /// The directory a glob path names its last component in: `.` for a bare relative name.
    fn glob_parent(path: &str) -> String {
        match path.rfind('/') {
            Some(0) => "/".to_string(),
            Some(slash) => path[..slash].to_string(),
            None => ".".to_string(),
        }
    }

    /// Remove a file. Unlinking acts on the name, not on whatever it points at.
    pub async fn remove_file(&self, proc: &Process, path: &str) -> io::Result<()> {
        let (resolved, permit) = self
            .admit_path(proc, path, Follow::No, FsOperation::RemoveFile)
            .await?;
        Self::report(permit, self.kernel.remove_file(proc, resolved).await).await
    }

    /// Remove an empty directory.
    pub async fn remove_dir(&self, proc: &Process, path: &str) -> io::Result<()> {
        let (resolved, permit) = self
            .admit_path(proc, path, Follow::Yes, FsOperation::RemoveDir)
            .await?;
        Self::report(permit, self.kernel.remove_dir(proc, resolved).await).await
    }

    /// Create a directory. A symlink at the final component is the name that already exists.
    pub async fn create_dir(&self, proc: &Process, path: &str) -> io::Result<()> {
        let (resolved, permit) = self
            .admit_path(proc, path, Follow::No, FsOperation::CreateDir)
            .await?;
        Self::report(permit, self.kernel.create_dir(proc, resolved).await).await
    }

    /// Rename a path.
    ///
    /// **Both** identities are admitted together: permission to read the source does
    /// not imply permission to create the target.
    ///
    /// The two sides take *different* dispositions, and both matter:
    ///
    /// - The **source** is no-follow. `rename` moves the link itself, never its
    ///   target — `mv link link2` must leave `readlink link2` naming the original
    ///   target. Resolving here would move the wrong object.
    /// - The **destination** is no-follow at its final component, as in `rename(2)`, so
    ///   a symlink there is replaced. Its parents are followed: `mv payload
    ///   /alias/key.pem` where `/alias -> /secrets` is judged on `/secrets/key.pem`.
    /// - Whether a name is **bound** at that resolved destination, and whether it is a
    ///   directory, is read there without following it, so a dangling symlink counts.
    pub async fn rename(&self, proc: &Process, from: &str, to: &str) -> io::Result<()> {
        let source = self.kernel.resolve(proc, from, Follow::No).await;
        let target = self.kernel.resolve(proc, to, Follow::No).await;
        let bound = self.kernel.resolve(proc, target.path(), Follow::No).await;
        let destination = self.kernel.lstat(proc, bound).await;
        let permit = self
            .admit(&EffectAttempt::FilesystemPair {
                from: source.path(),
                to: target.path(),
                operation: FsPairOperation::Rename {
                    destination_exists: destination.exists,
                    destination_is_dir: destination.is_dir,
                },
            })
            .await?;
        Self::report(permit, self.kernel.rename(proc, source, target).await).await
    }

    /// Create a symlink at `link` holding the literal text `target`.
    ///
    /// Only `link` is a resolved identity — it is the object created, and it is
    /// resolved no-follow because an existing link at that name is what would be
    /// displaced. `target` stays the caller's exact spelling: it is stored data, and a
    /// relative link must keep its relativity to resolve correctly later. Policy still
    /// sees the target text, so a rule may match on it; it is simply not a path
    /// this call touches.
    pub async fn symlink(&self, proc: &Process, target: &str, link: &str) -> io::Result<()> {
        let at = self.kernel.resolve(proc, link, Follow::No).await;
        let permit = self
            .admit(&EffectAttempt::FilesystemPair {
                from: target,
                to: at.path(),
                operation: FsPairOperation::Symlink,
            })
            .await?;
        Self::report(permit, self.kernel.symlink(proc, target, at).await).await
    }

    /// Read a symlink's target. Acts on the link itself.
    pub async fn read_link(&self, proc: &Process, path: &str) -> io::Result<String> {
        let (resolved, permit) = self
            .admit_path(proc, path, Follow::No, FsOperation::ReadLink)
            .await?;
        Self::report(permit, self.kernel.read_link(proc, resolved).await).await
    }

    /// Replace Unix permission bits.
    pub async fn set_permissions(&self, proc: &Process, path: &str, mode: u32) -> io::Result<()> {
        let (resolved, permit) = self
            .admit_path(
                proc,
                path,
                Follow::Yes,
                FsOperation::SetPermissions { mode },
            )
            .await?;
        Self::report(
            permit,
            self.kernel.set_permissions(proc, resolved, mode).await,
        )
        .await
    }

    /// Mint a process. Carries no path, so nothing to admit.
    pub fn new_process(&self) -> Process {
        self.kernel.new_process()
    }

    /// Whether a descriptor is a terminal. Carries no path.
    pub fn isatty(&self, fd: i32) -> bool {
        self.kernel.isatty(fd)
    }

    /// Wall-clock time. Carries no path.
    pub fn now(&self) -> std::time::SystemTime {
        self.kernel.now()
    }

    /// The SSRF floor — a deny-only control, not an authorization decision.
    pub fn check_url(&self, url: &str) -> io::Result<()> {
        self.kernel.check_url(url)
    }

    /// Dispatch an outbound request.
    ///
    /// Raises no admission: the Shell does not authorize egress. See the note at the
    /// foot of [`crate::EffectAttempt`].
    pub async fn http_request(&self, req: HttpRequest) -> io::Result<HttpResponse> {
        self.kernel.http_request(req).await
    }

    /// Run a script through the embedder's interpreter.
    ///
    /// Raises no admission, for the same reason [`http_request`](Self::http_request)
    /// does not: the command-level `shell:exec` fired when the command resolved, and the
    /// script's own effects are judged by the interpreter the hook drives.
    pub async fn run_script(&self, source: String) -> io::Result<crate::os::ScriptOutcome> {
        self.kernel.run_script(source).await
    }

    /// Run a host binary through the embedder's hook, or the built-in spawn.
    ///
    /// Raises no admission, for the same reason [`run_script`](Self::run_script) does not: the
    /// command-level `shell:spawn` fired when the command resolved.
    pub async fn spawn_host(
        &self,
        spawn: crate::os::HostSpawn,
    ) -> io::Result<crate::os::HostSpawnOutcome> {
        self.kernel.spawn_host(spawn).await
    }
}

/// One admitted command, owing an outcome report.
///
/// Separate from [`KernelPermit`] because a command reports a *status*
/// ([`EffectOutcome::ShellCommand`]) rather than a filesystem [`EffectResult`], and
/// conflating them would let a caller report the wrong shape for the effect it ran.
///
/// Dropping without [`record`](Self::record) marks the effect **indeterminate**, never
/// successful: a command killed by its deadline, or abandoned when a client disconnects,
/// did not complete and history must not claim it did.
pub(crate) struct CommandPermit {
    permit: Option<Box<dyn EffectPermit>>,
    /// The host program a `shell:spawn` decision named, carried to the spawn unchanged.
    spawn_program: Option<crate::exec::HostProgram>,
}

impl CommandPermit {
    /// Carry the host program the `shell:spawn` decision named.
    pub(crate) fn with_spawn_program(mut self, program: crate::exec::HostProgram) -> Self {
        self.spawn_program = Some(program);
        self
    }

    /// The host program the decision named, or `None` for a `shell:run` command.
    pub(crate) fn spawn_program(&self) -> Option<&crate::exec::HostProgram> {
        self.spawn_program.as_ref()
    }

    /// Report the command's exit status, consuming the permit.
    ///
    /// A recording failure is surfaced rather than converted into a denial — the command
    /// already ran, so denying now would misreport it in the other direction. The caller
    /// turns this into a distinguishable status.
    pub(crate) async fn record(mut self, reported_status: i32) -> io::Result<()> {
        match self.permit.take() {
            Some(permit) => {
                permit
                    .record_outcome(EffectOutcome::ShellCommand { reported_status })
                    .await
            }
            None => Ok(()),
        }
    }
}

impl Drop for CommandPermit {
    fn drop(&mut self) {
        if let Some(permit) = self.permit.take() {
            permit.mark_indeterminate();
        }
    }
}

#[cfg(all(test, debug_assertions))]
mod disposition_guard {
    //! Pins the `Follow` disposition each `Mediated` operation wires to the one its
    //! kernel effect expects.
    //!
    //! Each `Kernel` effect asserts `path.follow()` and then re-resolves with its own
    //! hardcoded follow value, so a `Mediated` site that resolves with the wrong `Follow`
    //! would admit one identity and act on another — a symlink-laundering hole. The
    //! `debug_assert_eq!` guarding it is compiled out in release, so the whole module is
    //! gated to `debug_assertions`: in a release build it is absent entirely — the tests never
    //! pass vacuously, and the helpers raise no dead-code warning.
    //! `every_mediated_operation_wires_its_follow_disposition` exercises every operation so
    //! a miswired disposition trips its effect's assertion, and
    //! `a_wrong_follow_token_trips_the_effect_assertion` feeds one effect a wrong-`Follow`
    //! token so a deleted assertion — not just a miswire — also reds the build here.

    use std::sync::Arc;

    use crate::os::{Follow, Kernel, OpenFlags};
    use crate::vfs::{ROOT_GID, ROOT_UID, Vfs};
    use crate::vfs_kernel::VfsKernel;

    use super::Mediated;

    fn fixture_vfs() -> Vfs {
        let mut vfs = Vfs::new();
        vfs.mkdir("/d", 0o755, ROOT_UID, ROOT_GID)
            .expect("mkdir /d");
        vfs.mkdir("/d/sub", 0o755, ROOT_UID, ROOT_GID)
            .expect("mkdir /d/sub");
        vfs.create_file("/d/f", 0o644, ROOT_UID, ROOT_GID)
            .expect("create /d/f");
        vfs.symlink("/d/link", "/d/f", ROOT_UID, ROOT_GID)
            .expect("symlink /d/link");
        vfs
    }

    fn mediated() -> Mediated {
        let kernel: Arc<dyn Kernel> = Arc::new(VfsKernel::new(fixture_vfs()));
        // No interceptor: the operations still resolve and reach their effect, so the
        // per-effect disposition assertion runs. Admission is not what this guard checks.
        Mediated::new(kernel, None)
    }

    /// Every `Mediated` filesystem operation wires the `Follow` its effect asserts.
    ///
    /// A miswired disposition trips the effect's `debug_assert_eq!(path.follow(), …)`,
    /// which is live in this debug test build. The effects themselves may error (the
    /// assertion runs before the effect), so results are deliberately discarded.
    #[tokio::test]
    async fn every_mediated_operation_wires_its_follow_disposition() {
        let m = mediated();
        let mut proc = m.new_process();

        // Follow::Yes operations — act on a symlink's target.
        let _ = m.open(&mut proc, "/d/f", OpenFlags::read()).await;
        let _ = m.open(&mut proc, "/d/w", OpenFlags::write()).await;
        // The read-write open branch carries its own disposition arg, so exercise it too.
        let read_write = OpenFlags {
            read: true,
            write: true,
            create: false,
            append: false,
            truncate: false,
        };
        let _ = m.open(&mut proc, "/d/f", read_write).await;
        let _ = m.list_dir(&proc, "/d").await;
        let _ = m.stat(&proc, "/d/f").await;
        let _ = m.access(&proc, "/d/f", 0).await;
        let _ = m.canonicalize(&proc, "/d/f").await;
        let _ = m.is_executable(&proc, "/d/f").await;
        proc.set_env("PATH", "/d");
        let _ = m.find_in_path(&proc, "f").await;
        let _ = m.glob(&proc, "/d/*").await;
        let _ = m.set_permissions(&proc, "/d/f", 0o600).await;
        let _ = m.remove_dir(&proc, "/d/sub").await;

        // Follow::No operations — act on the final name itself.
        let _ = m.create_dir(&proc, "/d/newdir").await;
        let _ = m.lstat(&proc, "/d/link").await;
        let _ = m.read_link(&proc, "/d/link").await;
        let _ = m.remove_file(&proc, "/d/link").await;
        let _ = m.symlink(&proc, "/d/f", "/d/newlink").await;

        // rename resolves both sides with Follow::No.
        let _ = m.rename(&proc, "/d/f", "/d/f2").await;

        // change_dir mutates the process, so it runs last.
        let _ = m.change_dir(&mut proc, "/d").await;
    }

    /// The disposition guard is live: an effect fed a token minted with the wrong `Follow`
    /// trips its assertion. This pins the assertion's existence, so deleting one reds the
    /// build here — the exhaustive test above only trips a *present* assertion. Debug-only,
    /// because the assertion is compiled out in release.
    #[tokio::test]
    #[should_panic(expected = "removes the name given")]
    async fn a_wrong_follow_token_trips_the_effect_assertion() {
        let kernel = VfsKernel::new(fixture_vfs());
        let proc = kernel.new_process();
        // `remove_file` acts on the link (Follow::No); hand it a Follow::Yes token.
        let wrong = kernel.resolve(&proc, "/d/link", Follow::Yes).await;
        let _ = kernel.remove_file(&proc, wrong).await;
    }
}

#[cfg(test)]
mod spawn_admission {
    use std::sync::Arc;

    use crate::os::Kernel;
    use crate::vfs::Vfs;
    use crate::vfs_kernel::VfsKernel;

    use super::Mediated;

    /// A spawn with no interceptor installed is permitted and carries no permit.
    #[tokio::test]
    async fn a_spawn_without_an_interceptor_is_permitted() {
        let kernel: Arc<dyn Kernel> = Arc::new(VfsKernel::new(Vfs::new()));
        let mediated = Mediated::new(kernel, None);
        let permit = mediated
            .admit_spawn("git status", "git", "/usr/bin/git", &[], &[], "/")
            .await
            .expect("a spawn with no interceptor is permitted");
        assert!(permit.permit.is_none(), "no interceptor issues no permit");
        assert!(
            permit.spawn_program().is_none(),
            "no decision names a program"
        );
        permit
            .record(0)
            .await
            .expect("an absent permit records nothing");
    }
}

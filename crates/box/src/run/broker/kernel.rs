//! Bind backend callbacks and HTTP propagation to one immutable Call context.

use std::io;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::SystemTime;

use strands_shell::os::{
    DirEntry, Fd, FileStat, Follow, HostSpawn, HostSpawnOutcome, HttpRequest, HttpResponse, Kernel,
    OpenFlags, Process, Resolved, ScriptOutcome, WriteFailure,
};

pub(super) struct CallKernel {
    backend: Arc<dyn Kernel>,
    correlation: telemetry::Correlation,
}

impl CallKernel {
    /// Share the backend while retaining this Call's correlation.
    pub(super) fn new(backend: Arc<dyn Kernel>, correlation: telemetry::Correlation) -> Self {
        Self {
            backend,
            correlation,
        }
    }
}

#[async_trait::async_trait]
impl Kernel for CallKernel {
    async fn resolve(&self, proc: &Process, path: &str, follow: Follow) -> Resolved {
        self.backend.resolve(proc, path, follow).await
    }

    fn new_process(&self) -> Process {
        self.backend.new_process()
    }

    async fn open(&self, proc: &mut Process, path: Resolved, flags: OpenFlags) -> io::Result<Fd> {
        self.backend.open(proc, path, flags).await
    }

    async fn list_dir(&self, proc: &Process, path: Resolved) -> io::Result<Vec<DirEntry>> {
        self.backend.list_dir(proc, path).await
    }

    async fn change_dir(&self, proc: &mut Process, path: Resolved) -> io::Result<()> {
        self.backend.change_dir(proc, path).await
    }

    async fn stat(&self, proc: &Process, path: Resolved) -> FileStat {
        self.backend.stat(proc, path).await
    }

    async fn lstat(&self, proc: &Process, path: Resolved) -> FileStat {
        self.backend.lstat(proc, path).await
    }

    async fn access(&self, proc: &Process, path: Resolved, mode: i32) -> bool {
        self.backend.access(proc, path, mode).await
    }

    async fn canonicalize(&self, proc: &Process, path: Resolved) -> io::Result<PathBuf> {
        self.backend.canonicalize(proc, path).await
    }

    async fn is_executable(&self, proc: &Process, path: Resolved) -> bool {
        self.backend.is_executable(proc, path).await
    }

    async fn glob(&self, proc: &Process, pattern: &str) -> Vec<String> {
        self.backend.glob(proc, pattern).await
    }

    fn isatty(&self, fd: i32) -> bool {
        self.backend.isatty(fd)
    }

    async fn remove_file(&self, proc: &Process, path: Resolved) -> io::Result<()> {
        self.backend.remove_file(proc, path).await
    }

    async fn remove_dir(&self, proc: &Process, path: Resolved) -> io::Result<()> {
        self.backend.remove_dir(proc, path).await
    }

    async fn create_dir(&self, proc: &Process, path: Resolved) -> io::Result<()> {
        self.backend.create_dir(proc, path).await
    }

    async fn rename(&self, proc: &Process, from: Resolved, to: Resolved) -> io::Result<()> {
        self.backend.rename(proc, from, to).await
    }

    async fn symlink(&self, proc: &Process, target: &str, link: Resolved) -> io::Result<()> {
        self.backend.symlink(proc, target, link).await
    }

    async fn read_link(&self, proc: &Process, path: Resolved) -> io::Result<String> {
        self.backend.read_link(proc, path).await
    }

    async fn set_permissions(&self, proc: &Process, path: Resolved, mode: u32) -> io::Result<()> {
        self.backend.set_permissions(proc, path, mode).await
    }

    fn now(&self) -> SystemTime {
        self.backend.now()
    }

    async fn settle_writes(&self) -> Vec<WriteFailure> {
        self.backend.settle_writes().await
    }

    fn check_url(&self, url: &str) -> io::Result<()> {
        self.backend.check_url(url)
    }

    async fn http_request(&self, mut req: HttpRequest) -> io::Result<HttpResponse> {
        self.correlation.inject_http(&mut req.headers);
        self.correlation.scope(self.backend.http_request(req)).await
    }

    async fn run_script(&self, source: String) -> io::Result<ScriptOutcome> {
        self.correlation
            .scope(self.backend.run_script(source))
            .await
    }

    async fn spawn_host(&self, spawn: HostSpawn) -> io::Result<HostSpawnOutcome> {
        self.correlation.scope(self.backend.spawn_host(spawn)).await
    }
}

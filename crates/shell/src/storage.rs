//! Descriptor-backed storage paths in an already protected workload view.

use std::collections::VecDeque;
use std::ffi::{CString, OsString};
use std::fs::File;
use std::io;
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::os::unix::fs::MetadataExt;
use std::path::{Component, Path, PathBuf};
use std::sync::{Arc, RwLock};

/// The shared protected storage destinations of one hosted Box.
#[doc(hidden)]
#[derive(Debug)]
pub struct StorageView {
    destinations: Vec<(PathBuf, bool)>,
    state: RwLock<State>,
}

#[derive(Debug, Default)]
struct State {
    root: Option<Arc<File>>,
    closed: bool,
}

/// One logical storage path and its pinned protected parent and object.
#[doc(hidden)]
#[derive(Debug, Clone)]
pub struct StoragePath {
    logical: PathBuf,
    original: PathBuf,
    parent: Arc<File>,
    leaf: CString,
    object: Option<Arc<File>>,
    ancestors: Vec<(u64, u64)>,
}

impl PartialEq for StoragePath {
    fn eq(&self, other: &Self) -> bool {
        self.same_object(other)
    }
}
impl Eq for StoragePath {}

impl StorageView {
    /// Reserve logical destinations before any hosted program can run.
    pub fn new(destinations: Vec<(PathBuf, bool)>) -> io::Result<Self> {
        for (path, _) in &destinations {
            if !path.is_absolute() || path == Path::new("/") || !plain(path) {
                return Err(refused("invalid protected storage destination"));
            }
        }
        Ok(Self {
            destinations,
            state: RwLock::new(State::default()),
        })
    }

    /// Whether the logical name belongs to a reserved storage destination.
    pub fn contains(&self, path: &Path) -> bool {
        self.destinations
            .iter()
            .any(|(root, directory)| path == root || (*directory && path.starts_with(root)))
    }

    /// The logical destinations reserved by this view.
    pub fn destinations(&self) -> impl Iterator<Item = (&Path, bool)> {
        self.destinations
            .iter()
            .map(|(path, directory)| (path.as_path(), *directory))
    }

    /// Install the root received from this Box's trusted agent launcher once.
    pub fn install(&self, root: File) -> io::Result<()> {
        let flags = unsafe { libc::fcntl(root.as_raw_fd(), libc::F_GETFL) };
        let descriptor_flags = unsafe { libc::fcntl(root.as_raw_fd(), libc::F_GETFD) };
        if flags < 0
            || descriptor_flags < 0
            || flags & libc::O_PATH == 0
            || descriptor_flags & libc::FD_CLOEXEC == 0
            || !root.metadata()?.is_dir()
        {
            return Err(refused(
                "the protected storage view is not a retained directory handle",
            ));
        }
        let mut information = std::mem::MaybeUninit::<libc::statvfs>::uninit();
        if unsafe { libc::fstatvfs(root.as_raw_fd(), information.as_mut_ptr()) } != 0 {
            return Err(io::Error::last_os_error());
        }
        let information = unsafe { information.assume_init() };
        let required = libc::ST_RDONLY | libc::ST_NOSUID | libc::ST_NODEV | libc::ST_NOEXEC;
        if information.f_flag & required != required {
            return Err(refused("the protected storage view root is not sealed"));
        }
        let mut state = self
            .state
            .write()
            .map_err(|_| refused("protected storage state was poisoned"))?;
        if state.closed || state.root.is_some() {
            return Err(refused(
                "protected storage view registration is no longer open",
            ));
        }
        state.root = Some(Arc::new(root));
        Ok(())
    }

    /// Refuse new storage operations after owner shutdown or admission failure.
    pub fn close(&self) {
        if let Ok(mut state) = self.state.write() {
            state.closed = true;
            state.root = None;
        }
    }

    /// Resolve a logical name entirely within the retained protected root.
    pub fn resolve(&self, path: &Path, follow: bool) -> io::Result<StoragePath> {
        if !path.is_absolute() || !plain(path) {
            return Err(refused("storage path is not an absolute logical name"));
        }
        let root = {
            let state = self
                .state
                .read()
                .map_err(|_| refused("protected storage state was poisoned"))?;
            if state.closed {
                return Err(refused("protected storage admission is closed"));
            }
            state
                .root
                .clone()
                .ok_or_else(|| io::Error::from_raw_os_error(libc::ENOENT))?
        };
        let mut pending = parts(path);
        let mut names = Vec::<OsString>::new();
        let mut directories = vec![Arc::clone(&root)];
        let mut ancestors = vec![identity(&root.metadata()?)];
        let mut links = 0;
        while let Some(name) = pending.pop_front() {
            if name == "." {
                continue;
            }
            if name == ".." {
                if !names.is_empty() {
                    names.pop();
                    directories.pop();
                    ancestors.pop();
                }
                continue;
            }
            let leaf = CString::new(name.as_bytes())
                .map_err(|_| refused("storage path contains a NUL byte"))?;
            let parent = Arc::clone(directories.last().expect("root retained"));
            let object = open_at(&parent, &leaf, libc::O_PATH | libc::O_NOFOLLOW);
            let object = match object {
                Ok(object) => Arc::new(object),
                Err(error) if error.raw_os_error() == Some(libc::ENOENT) && pending.is_empty() => {
                    names.push(name);
                    return Ok(StoragePath {
                        logical: logical(&names),
                        original: path.to_path_buf(),
                        parent,
                        leaf,
                        object: None,
                        ancestors,
                    });
                }
                Err(error) => return Err(error),
            };
            let metadata = object.metadata()?;
            if metadata.file_type().is_symlink() && (follow || !pending.is_empty()) {
                links += 1;
                if links > 40 {
                    return Err(io::Error::from_raw_os_error(libc::ELOOP));
                }
                let target = read_link_at(&parent, &leaf)?;
                if target.is_absolute() {
                    names.clear();
                    directories.truncate(1);
                    ancestors.truncate(1);
                }
                let mut expanded = parts(&target);
                expanded.append(&mut pending);
                pending = expanded;
                continue;
            }
            names.push(name);
            if pending.is_empty() {
                return Ok(StoragePath {
                    logical: logical(&names),
                    original: path.to_path_buf(),
                    parent,
                    leaf,
                    object: Some(object),
                    ancestors,
                });
            }
            if !metadata.is_dir() {
                return Err(io::Error::from_raw_os_error(libc::ENOTDIR));
            }
            ancestors.push(identity(&metadata));
            directories.push(object);
        }
        Ok(StoragePath {
            logical: PathBuf::from("/"),
            original: path.to_path_buf(),
            parent: Arc::clone(&root),
            leaf: CString::new(".").expect("literal"),
            object: Some(root),
            ancestors,
        })
    }
}

impl StoragePath {
    /// The logical canonical path that policy judges.
    pub fn logical(&self) -> &Path {
        &self.logical
    }
    /// Refuse a changed logical destination after policy admitted an exact name.
    pub fn require_policy_name(&self, admitted: &Path) -> io::Result<()> {
        if self.logical == admitted {
            Ok(())
        } else {
            Err(refused(
                "protected storage destination changed after policy admission",
            ))
        }
    }
    /// The name whose resolution produced this pinned object.
    pub fn original(&self) -> &Path {
        &self.original
    }
    /// The retained parent directory used for effects.
    pub fn parent(&self) -> &File {
        &self.parent
    }
    /// The final component used for effects.
    pub fn leaf(&self) -> &std::ffi::CStr {
        &self.leaf
    }
    /// The original object identity, or none for a new name.
    pub fn identity(&self) -> io::Result<Option<(u64, u64)>> {
        self.object
            .as_ref()
            .map(|file| file.metadata().map(|metadata| identity(&metadata)))
            .transpose()
    }
    /// The identities traversed to reach the parent, in root-to-parent order.
    pub fn ancestors(&self) -> &[(u64, u64)] {
        &self.ancestors
    }
    /// Read the metadata of the retained object without a new path lookup.
    pub fn metadata(&self) -> io::Result<std::fs::Metadata> {
        self.object
            .as_ref()
            .ok_or_else(|| io::Error::from_raw_os_error(libc::ENOENT))?
            .metadata()
    }
    /// Read native metadata for the retained object without a new path lookup.
    pub fn stat(&self) -> io::Result<libc::stat> {
        let object = self
            .object
            .as_ref()
            .ok_or_else(|| io::Error::from_raw_os_error(libc::ENOENT))?;
        let mut metadata = std::mem::MaybeUninit::<libc::stat>::uninit();
        // SAFETY: `object` owns the live descriptor, and `metadata` is writable.
        let result = unsafe { libc::fstat(object.as_raw_fd(), metadata.as_mut_ptr()) };
        if result != 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: successful `fstat` initialized `metadata`.
        Ok(unsafe { metadata.assume_init() })
    }
    /// Check that a new resolution names the same object and parent.
    pub fn same_object(&self, other: &Self) -> bool {
        let (Ok(left), Ok(right), Ok(left_parent), Ok(right_parent)) = (
            self.identity(),
            other.identity(),
            self.parent.metadata(),
            other.parent.metadata(),
        ) else {
            return false;
        };
        self.logical == other.logical
            && left == right
            && identity(&left_parent) == identity(&right_parent)
    }
    /// Open the final name without following a substituted symbolic link.
    pub fn open(&self, flags: libc::c_int, mode: libc::mode_t) -> io::Result<File> {
        let expected = self.identity()?;
        let mut opening = flags & !libc::O_TRUNC;
        if expected.is_none() && flags & libc::O_CREAT != 0 {
            opening |= libc::O_EXCL;
        }
        let fd = unsafe {
            libc::openat(
                self.parent.as_raw_fd(),
                self.leaf.as_ptr(),
                opening | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                mode,
            )
        };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        let file = unsafe { File::from_raw_fd(fd) };
        if let Some(expected) = expected
            && identity(&file.metadata()?) != expected
        {
            return Err(refused(
                "protected storage identity changed during admission",
            ));
        }
        if flags & libc::O_TRUNC != 0 {
            file.set_len(0)?;
        }
        Ok(file)
    }
    /// Enumerate the retained directory without resolving its logical name again.
    pub fn entries(&self) -> io::Result<Vec<(OsString, bool)>> {
        let directory = self.open(libc::O_RDONLY | libc::O_DIRECTORY, 0)?;
        let mut entries = Vec::new();
        for entry in std::fs::read_dir(format!("/proc/self/fd/{}", directory.as_raw_fd()))? {
            let entry = entry?;
            entries.push((entry.file_name(), entry.file_type()?.is_dir()));
        }
        Ok(entries)
    }
    /// Probe access using the serving thread's credentials and the protected mount flags.
    pub fn access(&self, mode: libc::c_int) -> bool {
        // SAFETY: parent and leaf remain alive; faccessat2 does not mutate the object.
        unsafe {
            libc::syscall(
                libc::SYS_faccessat2,
                self.parent.as_raw_fd(),
                self.leaf.as_ptr(),
                mode,
                libc::AT_EACCESS | libc::AT_SYMLINK_NOFOLLOW,
            ) == 0
        }
    }
    /// Read a pinned symbolic link without following its target.
    pub fn read_link(&self) -> io::Result<PathBuf> {
        let object = self
            .object
            .as_ref()
            .ok_or_else(|| io::Error::from_raw_os_error(libc::ENOENT))?;
        read_link_at(object, c"")
    }
}

fn plain(path: &Path) -> bool {
    path.components()
        .all(|part| matches!(part, Component::RootDir | Component::Normal(_)))
}
fn parts(path: &Path) -> VecDeque<OsString> {
    path.components()
        .filter_map(|part| match part {
            Component::Normal(name) => Some(name.to_os_string()),
            Component::ParentDir => Some(OsString::from("..")),
            Component::CurDir => Some(OsString::from(".")),
            _ => None,
        })
        .collect()
}
fn logical(names: &[OsString]) -> PathBuf {
    let mut result = PathBuf::from("/");
    result.extend(names);
    result
}
fn identity(metadata: &std::fs::Metadata) -> (u64, u64) {
    (metadata.dev(), metadata.ino())
}
fn refused(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::PermissionDenied, message)
}
fn open_at(parent: &File, name: &std::ffi::CStr, flags: libc::c_int) -> io::Result<File> {
    let fd = unsafe { libc::openat(parent.as_raw_fd(), name.as_ptr(), flags | libc::O_CLOEXEC) };
    if fd < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(unsafe { File::from_raw_fd(fd) })
    }
}
fn read_link_at(parent: &File, name: &std::ffi::CStr) -> io::Result<PathBuf> {
    let mut bytes = vec![0u8; 4096];
    let length = unsafe {
        libc::readlinkat(
            parent.as_raw_fd(),
            name.as_ptr(),
            bytes.as_mut_ptr().cast(),
            bytes.len(),
        )
    };
    if length < 0 {
        return Err(io::Error::last_os_error());
    }
    if length as usize == bytes.len() {
        return Err(io::Error::from_raw_os_error(libc::ENAMETOOLONG));
    }
    bytes.truncate(length as usize);
    Ok(PathBuf::from(OsString::from_vec(bytes)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;
    use std::os::unix::fs::OpenOptionsExt;

    fn fixture() -> (tempfile::TempDir, StorageView) {
        let directory = tempfile::tempdir().unwrap();
        let root = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_PATH | libc::O_DIRECTORY | libc::O_CLOEXEC)
            .open(directory.path())
            .unwrap();
        let view = StorageView::new(vec![(PathBuf::from("/incoming"), true)]).unwrap();
        view.state.write().unwrap().root = Some(Arc::new(root));
        std::fs::create_dir(directory.path().join("incoming")).unwrap();
        (directory, view)
    }

    #[test]
    fn pending_storage_never_resolves_an_ambient_path() {
        let view = StorageView::new(vec![(PathBuf::from("/tmp"), true)]).unwrap();
        assert!(view.contains(Path::new("/tmp")));
        assert_eq!(
            view.resolve(Path::new("/tmp"), true)
                .unwrap_err()
                .raw_os_error(),
            Some(libc::ENOENT)
        );
    }

    #[test]
    fn absolute_and_parent_symlinks_stay_inside_the_retained_root() {
        let (directory, view) = fixture();
        std::fs::write(directory.path().join("inside"), "captured").unwrap();
        std::os::unix::fs::symlink("/inside", directory.path().join("incoming/absolute")).unwrap();
        std::os::unix::fs::symlink(
            "../../../../inside",
            directory.path().join("incoming/parents"),
        )
        .unwrap();
        std::os::unix::fs::symlink("/etc/passwd", directory.path().join("incoming/outside"))
            .unwrap();
        for name in ["absolute", "parents"] {
            let path = view
                .resolve(&PathBuf::from("/incoming").join(name), true)
                .unwrap();
            assert_eq!(path.logical(), Path::new("/inside"));
            let mut bytes = String::new();
            path.open(libc::O_RDONLY, 0)
                .unwrap()
                .read_to_string(&mut bytes)
                .unwrap();
            assert_eq!(bytes, "captured");
        }
        assert_eq!(
            view.resolve(Path::new("/incoming/outside"), true)
                .unwrap_err()
                .raw_os_error(),
            Some(libc::ENOENT)
        );
    }

    #[test]
    fn a_changed_logical_destination_cannot_reuse_an_exact_path_policy_decision() {
        let (directory, view) = fixture();
        let allowed = directory.path().join("incoming/allowed");
        let denied = directory.path().join("incoming/denied");
        std::fs::write(&allowed, "ALLOWED").unwrap();
        std::fs::write(&denied, "DENIED").unwrap();
        let admitted = view
            .resolve(Path::new("/incoming/allowed"), true)
            .unwrap()
            .logical()
            .to_path_buf();
        std::fs::rename(&allowed, directory.path().join("incoming/original")).unwrap();
        std::os::unix::fs::symlink("denied", &allowed).unwrap();
        let changed = view.resolve(&admitted, true).unwrap();
        assert_eq!(changed.logical(), Path::new("/incoming/denied"));
        let error = changed.require_policy_name(&admitted).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
        assert!(error.to_string().contains("changed after policy admission"));
        assert_eq!(std::fs::read_to_string(denied).unwrap(), "DENIED");
    }

    #[test]
    fn replacement_before_truncation_does_not_modify_the_new_object() {
        let (directory, view) = fixture();
        let file = directory.path().join("incoming/file");
        std::fs::write(&file, "original").unwrap();
        let held = view.resolve(Path::new("/incoming/file"), true).unwrap();
        std::fs::rename(&file, directory.path().join("old")).unwrap();
        std::fs::write(&file, "replacement").unwrap();
        assert!(held.open(libc::O_WRONLY | libc::O_TRUNC, 0).is_err());
        assert_eq!(std::fs::read_to_string(&file).unwrap(), "replacement");
        assert_eq!(
            std::fs::read_to_string(directory.path().join("old")).unwrap(),
            "original"
        );
    }

    #[test]
    fn native_metadata_retains_the_admitted_object_after_name_replacement() {
        let (directory, view) = fixture();
        let file = directory.path().join("incoming/file");
        std::fs::write(&file, "original").unwrap();
        let held = view.resolve(Path::new("/incoming/file"), true).unwrap();
        let original = held.metadata().unwrap();
        std::fs::rename(&file, directory.path().join("old")).unwrap();
        std::fs::write(&file, "replacement with different metadata").unwrap();
        let replacement = std::fs::metadata(&file).unwrap();
        assert_ne!(original.ino(), replacement.ino());
        assert_ne!(original.len(), replacement.len());
        let metadata = held.stat().unwrap();
        assert_eq!(metadata.st_ino, original.ino());
        assert_eq!(metadata.st_size as u64, original.len());

        let missing = view.resolve(Path::new("/incoming/new"), true).unwrap();
        std::fs::write(directory.path().join("incoming/new"), "later").unwrap();
        assert_eq!(
            missing.stat().unwrap_err().raw_os_error(),
            Some(libc::ENOENT)
        );
    }

    #[test]
    fn a_pinned_parent_survives_ambient_directory_replacement() {
        let (directory, view) = fixture();
        std::fs::write(directory.path().join("incoming/file"), "captured").unwrap();
        let held = view.resolve(Path::new("/incoming/file"), true).unwrap();
        std::fs::rename(
            directory.path().join("incoming"),
            directory.path().join("original"),
        )
        .unwrap();
        std::fs::create_dir(directory.path().join("incoming")).unwrap();
        std::fs::write(directory.path().join("incoming/file"), "wrong").unwrap();
        assert!(!held.same_object(&view.resolve(Path::new("/incoming/file"), true).unwrap()));
        let mut bytes = String::new();
        held.open(libc::O_RDONLY, 0)
            .unwrap()
            .read_to_string(&mut bytes)
            .unwrap();
        assert_eq!(bytes, "captured");
    }

    #[test]
    fn shutdown_and_unsealed_handles_cannot_open_registration() {
        let directory = tempfile::tempdir().unwrap();
        let view = StorageView::new(vec![(PathBuf::from("/incoming"), true)]).unwrap();
        assert!(view.install(File::open(directory.path()).unwrap()).is_err());
        let (_directory, view) = fixture();
        view.close();
        assert_eq!(
            view.resolve(Path::new("/incoming"), true)
                .unwrap_err()
                .kind(),
            io::ErrorKind::PermissionDenied
        );
    }

    struct ServingPolicy;
    struct Permit;
    #[async_trait::async_trait]
    impl crate::EffectPermit for Permit {
        async fn record_outcome(self: Box<Self>, _: crate::EffectOutcome) -> io::Result<()> {
            Ok(())
        }
        fn mark_indeterminate(self: Box<Self>) {}
    }
    #[async_trait::async_trait]
    impl crate::EffectInterceptor for ServingPolicy {
        async fn intercept(
            &self,
            effect: &crate::EffectAttempt<'_>,
        ) -> io::Result<Box<dyn crate::EffectPermit>> {
            if matches!(effect, crate::EffectAttempt::Filesystem { path, .. } if path.ends_with("/policy-denied"))
            {
                return Err(refused(
                    "test hosted policy denied this native-readable file",
                ));
            }
            Ok(Box::new(Permit))
        }
    }
    fn serving_kernel(ambient: &Path, view: Arc<StorageView>) -> crate::ShellKernel {
        let vfs = strands_shell::vfs_config::build_vfs(&Default::default()).unwrap();
        let filesystem =
            crate::Filesystem::serving(vfs, &[(ambient.to_str().unwrap(), "/workspace")])
                .unwrap()
                .with_storage(view)
                .unwrap();
        crate::ShellKernel::over(Arc::new(filesystem), Arc::new(ServingPolicy))
    }
    fn run<F: std::future::Future>(body: F) -> F::Output {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let local = tokio::task::LocalSet::new();
        let answer = local.block_on(&runtime, body);
        runtime.block_on(local);
        answer
    }
    fn open_test_root(path: &Path) -> Arc<File> {
        Arc::new(
            std::fs::OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_PATH | libc::O_DIRECTORY | libc::O_CLOEXEC)
                .open(path)
                .unwrap(),
        )
    }

    #[test]
    fn a_held_shell_hides_an_underlay_then_uses_the_protected_view_and_keeps_policy() {
        let ambient = tempfile::tempdir().unwrap();
        std::fs::create_dir(ambient.path().join("incoming")).unwrap();
        std::fs::write(ambient.path().join("incoming/underlay"), "AMBIENT").unwrap();
        let protected = tempfile::tempdir().unwrap();
        let incoming = protected.path().join("workspace/incoming");
        std::fs::create_dir_all(&incoming).unwrap();
        std::fs::write(incoming.join("allowed"), "CAPTURED").unwrap();
        std::fs::write(incoming.join("policy-denied"), "NATIVE-READABLE").unwrap();
        std::os::unix::fs::symlink("allowed", incoming.join("alias")).unwrap();
        std::fs::write(protected.path().join("workspace/outside"), "OUTSIDE").unwrap();
        std::os::unix::fs::symlink("../outside", incoming.join("outside-alias")).unwrap();
        let view =
            Arc::new(StorageView::new(vec![(PathBuf::from("/workspace/incoming"), true)]).unwrap());
        let mut shell = serving_kernel(ambient.path(), Arc::clone(&view)).shell();
        run(async {
            let pending = shell.run("cat /workspace/incoming/underlay").await;
            assert_ne!(pending.status, 0, "{}", pending.stdout);
            assert!(!pending.stdout.contains("AMBIENT"));
            view.state.write().unwrap().root = Some(open_test_root(protected.path()));
            let ready = shell.run("cat /workspace/incoming/alias").await;
            assert_eq!(ready.status, 0, "{}", ready.stderr);
            assert_eq!(ready.stdout, "CAPTURED");
            let hidden = shell.run("cat /workspace/incoming/underlay").await;
            assert_ne!(hidden.status, 0);
            assert_eq!(
                std::fs::read_to_string(incoming.join("policy-denied")).unwrap(),
                "NATIVE-READABLE"
            );
            let denied = shell.run("cat /workspace/incoming/policy-denied").await;
            assert_ne!(denied.status, 0);
            assert!(
                denied.stderr.contains("test hosted policy denied"),
                "{}",
                denied.stderr
            );
            let outside = shell.run("cat /workspace/incoming/outside-alias").await;
            assert_ne!(outside.status, 0);
            assert!(!outside.stdout.contains("OUTSIDE"));
            let sibling = shell.run("printf CREATED > /workspace/incoming/sibling; cat /workspace/incoming/sibling; rm /workspace/incoming/sibling").await;
            assert_eq!(sibling.status, 0, "{}", sibling.stderr);
            assert_eq!(sibling.stdout, "CREATED");
            assert!(!incoming.join("sibling").exists());
        });
    }

    #[test]
    fn protected_file_listing_and_metadata_do_not_reach_ambient_siblings() {
        use strands_shell::os::Kernel as _;
        let ambient = tempfile::tempdir().unwrap();
        std::fs::create_dir(ambient.path().join("incoming")).unwrap();
        std::fs::write(ambient.path().join("incoming/secret"), "AMBIENT").unwrap();
        let protected = tempfile::tempdir().unwrap();
        let incoming = protected.path().join("workspace/incoming");
        std::fs::create_dir_all(&incoming).unwrap();
        std::fs::write(incoming.join("exact"), "CAPTURED").unwrap();
        let view =
            Arc::new(StorageView::new(vec![(PathBuf::from("/workspace/incoming"), true)]).unwrap());
        view.state.write().unwrap().root = Some(open_test_root(protected.path()));
        let kernel = serving_kernel(ambient.path(), view);
        let process = kernel.new_process();
        run(async {
            assert!(
                kernel
                    .stat(&process, "/workspace/incoming/exact")
                    .await
                    .is_file
            );
            assert!(
                !kernel
                    .stat(&process, "/workspace/incoming/secret")
                    .await
                    .exists
            );
            let entries = kernel
                .list_dir(&process, "/workspace/incoming")
                .await
                .unwrap();
            assert_eq!(
                entries
                    .iter()
                    .map(|entry| entry.name.as_str())
                    .collect::<Vec<_>>(),
                ["exact"]
            );
        });
    }

    #[test]
    fn serving_a_protected_view_still_requires_source_read_permission() {
        use std::os::unix::fs::PermissionsExt as _;
        let ambient = tempfile::tempdir().unwrap();
        let protected = tempfile::tempdir().unwrap();
        let incoming = protected.path().join("workspace/incoming");
        std::fs::create_dir_all(&incoming).unwrap();
        std::fs::write(incoming.join("unreadable"), "SOURCE-DENIED").unwrap();
        std::fs::set_permissions(
            incoming.join("unreadable"),
            std::fs::Permissions::from_mode(0o000),
        )
        .unwrap();
        std::fs::write(incoming.join("allowed"), "SOURCE-ALLOWED").unwrap();
        let view =
            Arc::new(StorageView::new(vec![(PathBuf::from("/workspace/incoming"), true)]).unwrap());
        view.state.write().unwrap().root = Some(open_test_root(protected.path()));
        let mut shell = serving_kernel(ambient.path(), view).shell();
        run(async {
            let denied = shell.run("cat /workspace/incoming/unreadable").await;
            assert_ne!(
                denied.status, 0,
                "source-read privilege must not exceed an ordinary workload"
            );
            assert!(
                denied.stderr.contains("Permission denied"),
                "{}",
                denied.stderr
            );
            let allowed = shell.run("cat /workspace/incoming/allowed").await;
            assert_eq!(allowed.status, 0, "{}", allowed.stderr);
            assert_eq!(allowed.stdout, "SOURCE-ALLOWED");
        });
    }
}

use std::io;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, Sender};
use std::time::{Duration, Instant};

use notify::{Event, RecursiveMode, Watcher};

use super::banner::PolicyStatus;
use super::{CompiledRun, Launcher, Loaded, RunSettings, compile_run, process_env};
use crate::compile::Instance;

const DEBOUNCE: Duration = Duration::from_millis(150);
pub(super) const OFF: &str =
    r#"@id("policy_off") @description("policy is off") permit (principal, action, resource);"#;
/// The source name Box Core records for `OFF`, so a run's history shows when policy went off.
pub(super) const OFF_ORIGIN: &str = "policy off";
const RESTART: &str = "profile changes need a restart (configuration changed); policy kept";

#[derive(Debug, Clone)]
pub(super) struct ProfilePolicy {
    launcher: Launcher,
    /// What `box run` was given: a profile name, or the path of a profile file.
    argument: String,
    /// The folder that holds the profile and its policy files.
    folder: PathBuf,
    /// The folder the watcher watches: the profiles folder, or the profile file's own folder.
    root: PathBuf,
    workspace: PathBuf,
    instance: Instance,
    protected: Vec<PathBuf>,
    config: String,
    text: String,
    /// The forbids in `text` that `box` writes, which stay while policy is off.
    generated: String,
}

/// A compiled policy that waits for a reload, and the forbids in it that `box` writes.
#[derive(Debug, Clone, PartialEq)]
struct Pending {
    text: String,
    generated: String,
}

impl ProfilePolicy {
    pub(super) fn new(
        launcher: Launcher,
        argument: String,
        file: Option<&std::path::Path>,
        workspace: PathBuf,
        instance: Instance,
        protected: Vec<PathBuf>,
        run: &CompiledRun,
    ) -> Self {
        let (folder, root) = match file.and_then(std::path::Path::parent) {
            Some(folder) => (folder.to_path_buf(), folder.to_path_buf()),
            None => (
                launcher.profiles().folder(&argument),
                launcher.profiles().root().to_path_buf(),
            ),
        };
        Self {
            launcher,
            argument,
            folder,
            root,
            workspace,
            instance,
            protected,
            config: run.compiled.box_toml.clone(),
            text: run.compiled.policy.clone(),
            generated: run.compiled.generated_forbids.clone(),
        }
    }

    /// The policy that policy off installs: `OFF`, then the forbids that `box` writes.
    pub(super) fn off(&self) -> String {
        match self.generated.trim_end() {
            "" => OFF.to_string(),
            generated => format!("{OFF}\n\n{generated}\n"),
        }
    }

    fn compile(&self) -> Result<Option<Pending>, String> {
        let super::Located {
            name,
            profile,
            policy,
            file,
        } = self
            .launcher
            .locate(&self.argument, &self.workspace, |_| {})
            .map_err(|error| format!("{error}; policy kept"))?;
        let trusted = super::profile_file_protections(file.as_deref(), &profile, &self.workspace)
            .map_err(|error| error.to_string())?;
        let CompiledRun {
            compiled, resolved, ..
        } = compile_run(
            Loaded {
                profile: &profile,
                name: &name,
                policy: policy.as_deref(),
                trusted: &trusted,
                by_path: file.is_some(),
            },
            &self.launcher.host,
            &self.workspace,
            &self.instance,
            &self.protected,
            &process_env,
            RunSettings {
                display: self.launcher.display,
                observations: None,
                resources: self.launcher.resources.as_deref(),
                install: self.launcher.install.as_deref(),
            },
        )
        .map_err(|error| error.to_string())?;
        if compiled.box_toml != self.config {
            return Err(RESTART.into());
        }
        if compiled.policy == self.text {
            return Ok(None);
        }
        self.launcher
            .check_in_scratch(&compiled, &resolved)
            .map_err(|error| error.to_string())?;
        Ok(Some(Pending {
            text: compiled.policy,
            generated: compiled.generated_forbids,
        }))
    }
}

enum Request {
    Refresh,
    WatchRoot,
    Reload,
    Toggle,
    Restore,
    WatchFailed(String),
}

pub(super) struct PolicyControl {
    requests: Arc<Sender<Request>>,
    pub(super) changes: Receiver<(PolicyStatus, Option<String>)>,
}

impl PolicyControl {
    pub(super) fn start(profile: ProfilePolicy) -> io::Result<Self> {
        Self::worker(profile, |policy| {
            strands_box::reload(std::slice::from_ref(policy)).map_err(|error| error.to_string())
        })
    }

    pub(super) fn reload(&self) -> io::Result<()> {
        self.requests
            .send(Request::Reload)
            .map_err(|_| io::Error::other("policy worker stopped"))
    }

    pub(super) fn toggle(&self) -> io::Result<()> {
        self.requests
            .send(Request::Toggle)
            .map_err(|_| io::Error::other("policy worker stopped"))
    }

    /// Turn policy back on if it is off.
    pub(super) fn restore(&self) -> io::Result<()> {
        self.requests
            .send(Request::Restore)
            .map_err(|_| io::Error::other("policy worker stopped"))
    }

    fn worker(
        profile: ProfilePolicy,
        reload: impl FnMut(&strands_box::Policy) -> Result<(), String> + Send + 'static,
    ) -> io::Result<Self> {
        let (requests, receive) = mpsc::channel();
        let requests = Arc::new(requests);
        let (results, changes) = mpsc::channel();
        // The watcher must not keep its worker's request channel open.
        let callback = Arc::downgrade(&requests);
        let folder = profile.folder.clone();
        let root = profile.root.clone();
        let watched_root = root.clone();
        let workspace = profile.workspace.clone();
        let fsevents = notify::RecommendedWatcher::kind() == notify::WatcherKind::Fsevent;
        let watcher = notify::RecommendedWatcher::new(
            move |event: notify::Result<Event>| {
                let Some(callback) = callback.upgrade() else {
                    return;
                };
                match event {
                    Ok(event) if relevant(&event, &folder, &watched_root, &workspace) => {
                        let request = if !fsevents
                            && (event.need_rescan() || event.paths.contains(&watched_root))
                        {
                            Request::WatchRoot
                        } else {
                            Request::Refresh
                        };
                        let _ = callback.send(request);
                    }
                    Err(error) => {
                        let _ = callback.send(Request::WatchFailed(error.to_string()));
                    }
                    _ => {}
                }
            },
            notify::Config::default().with_follow_symlinks(false),
        )
        .and_then(|mut watcher| {
            // FSEvents watches descendants already; reattaching would interrupt its stream.
            if fsevents {
                watcher.watch(root.parent().unwrap(), RecursiveMode::Recursive)?;
            } else {
                watcher.watch(root.parent().unwrap(), RecursiveMode::NonRecursive)?;
                if let Err(error) = watcher.watch(&root, RecursiveMode::Recursive) {
                    let _ = requests.send(Request::WatchFailed(error.to_string()));
                }
            }
            Ok(watcher)
        });
        let watcher = match watcher {
            Ok(watcher) => Some(watcher),
            Err(error) => {
                let _ = requests.send(Request::WatchFailed(error.to_string()));
                None
            }
        };
        std::thread::Builder::new()
            .name("box-policy".into())
            .spawn(move || {
                Worker {
                    status: PolicyStatus::default(),
                    pending: None,
                    profile,
                    results,
                    reload,
                    watcher,
                }
                .run(receive);
            })?;
        Ok(Self { requests, changes })
    }
}

struct Worker<F> {
    status: PolicyStatus,
    pending: Option<Pending>,
    profile: ProfilePolicy,
    results: Sender<(PolicyStatus, Option<String>)>,
    reload: F,
    watcher: Option<notify::RecommendedWatcher>,
}

impl<F> Worker<F>
where
    F: FnMut(&strands_box::Policy) -> Result<(), String>,
{
    fn report(&mut self, error: Option<String>) {
        self.status.failed = error.is_some();
        self.status.pending = self.pending.is_some();
        self.status.changed_at = Some(Instant::now());
        let _ = self.results.send((self.status, error));
    }

    fn refresh(&mut self) {
        self.status.reloaded = false;
        match self.profile.compile() {
            Ok(pending) => {
                if pending != self.pending || self.status.failed {
                    self.pending = pending;
                    self.report(None);
                }
            }
            Err(error) => {
                self.pending = None;
                self.report(Some(error));
            }
        }
    }

    fn run(mut self, requests: Receiver<Request>) {
        let profile_origin = self.profile.instance.directory.join("policy.dw");
        let mut policy = strands_box::Policy {
            origin: profile_origin.clone(),
            text: String::new(),
        };
        self.refresh();
        let mut due: Option<Instant> = None;
        loop {
            let request = match due {
                Some(deadline) => {
                    requests.recv_timeout(deadline.saturating_duration_since(Instant::now()))
                }
                None => requests.recv().map_err(|_| RecvTimeoutError::Disconnected),
            };
            match request {
                Ok(Request::Refresh) => {
                    due = Some(Instant::now() + DEBOUNCE);
                }
                Ok(Request::WatchRoot) => {
                    let root = self.profile.root.clone();
                    let error = self.watcher.as_mut().and_then(|watcher| {
                        let _ = watcher.unwatch(&root);
                        root.is_dir()
                            .then(|| watcher.watch(&root, RecursiveMode::Recursive).err())
                            .flatten()
                    });
                    due = Some(Instant::now() + DEBOUNCE);
                    if let Some(error) = error {
                        self.report(Some(format!(
                            "profile watch failed: {error}; restart after edits"
                        )));
                    }
                }
                Ok(Request::WatchFailed(error)) => {
                    self.report(Some(format!(
                        "profile watch failed: {error}; restart after edits"
                    )));
                }
                Ok(Request::Reload) => {
                    if self.status.enabled && self.pending.is_some() {
                        due = None;
                        self.refresh();
                    }
                    if self.status.enabled
                        && let Some(pending) = &self.pending
                    {
                        policy.origin.clone_from(&profile_origin);
                        policy.text.clone_from(&pending.text);
                        let error = (self.reload)(&policy).err();
                        if error.is_none() {
                            let Pending { text, generated } = self.pending.take().unwrap();
                            self.profile.text = text;
                            self.profile.generated = generated;
                            self.status.reloaded = true;
                        }
                        self.report(error);
                    }
                }
                Ok(Request::Restore) if self.status.enabled => {}
                Ok(Request::Toggle | Request::Restore) => {
                    self.status.reloaded = false;
                    (policy.origin, policy.text) = if self.status.enabled {
                        (OFF_ORIGIN.into(), self.profile.off())
                    } else {
                        (profile_origin.clone(), self.profile.text.clone())
                    };
                    let error = match (self.reload)(&policy) {
                        Ok(()) => {
                            self.status.enabled = !self.status.enabled;
                            None
                        }
                        Err(error) => Some(error),
                    };
                    self.report(error);
                }
                Err(RecvTimeoutError::Timeout) => {
                    self.refresh();
                    due = None;
                }
                Err(RecvTimeoutError::Disconnected) => break,
            }
        }
    }
}

/// Whether `event` can change the profile: a path in its folder, or the folder itself, outside the
/// workspace except its `.box`, because no profile file or policy file is there.
fn relevant(
    event: &Event,
    folder: &std::path::Path,
    root: &std::path::Path,
    workspace: &std::path::Path,
) -> bool {
    let configuration = workspace.join(crate::profile::PROJECT_CONFIGURATION);
    event.need_rescan()
        || (!event.kind.is_access()
            && event.paths.iter().any(|path| {
                (path.starts_with(folder) || path == root)
                    && (!path.starts_with(workspace) || path.starts_with(&configuration))
            }))
}

#[cfg(test)]
pub(super) mod tests {
    use super::*;

    pub(in crate::run) struct Scene {
        _root: tempfile::TempDir,
        folder: PathBuf,
        pub(in crate::run) profile: ProfilePolicy,
    }

    impl Scene {
        pub(in crate::run) fn new() -> Self {
            let root = tempfile::Builder::new()
                .prefix("bx")
                .tempdir_in("/tmp")
                .unwrap();
            let home = root.path().canonicalize().unwrap().join("home");
            let workspace = home.join("project");
            let folder = home.join(".strands/box/profiles/test");
            std::fs::create_dir_all(&workspace).unwrap();
            std::fs::create_dir_all(&folder).unwrap();
            std::fs::write(
                folder.join("profile.toml"),
                "policies = [\"policy.dw\"]\n[agent]\ncommand = [\"/usr/bin/true\"]\n",
            )
            .unwrap();
            std::fs::write(folder.join("policy.dw"), "").unwrap();
            let launcher = Launcher::from_host()
                .home(home)
                .environment(&[])
                .search_path("/usr/bin:/bin");
            let launch = launcher.prepare("test", &workspace, None).unwrap();
            Self {
                _root: root,
                folder,
                profile: launch.policy,
            }
        }

        /// A run of a profile file outside the profile folders, with its policy beside it.
        pub(in crate::run) fn file() -> Self {
            let root = tempfile::tempdir().unwrap();
            let home = root.path().canonicalize().unwrap().join("home");
            let workspace = home.join("my-agent/app");
            let folder = home.join("my-agent/box");
            std::fs::create_dir_all(&workspace).unwrap();
            std::fs::create_dir_all(&folder).unwrap();
            std::fs::write(
                folder.join("profile.toml"),
                "policies = [\"policy.dw\"]\n[agent]\ncommand = [\"/usr/bin/true\"]\n\
                 [profile]\nname = \"filed\"\n",
            )
            .unwrap();
            std::fs::write(folder.join("policy.dw"), "").unwrap();
            let launcher = Launcher::from_host()
                .home(home)
                .environment(&[])
                .search_path("/usr/bin:/bin");
            let file = folder.join("profile.toml").display().to_string();
            let launch = launcher.prepare(&file, &workspace, None).unwrap();
            Self {
                _root: root,
                folder,
                profile: launch.policy,
            }
        }

        fn save(&self, name: &str, text: &str) {
            let path = self.folder.join(name);
            let temporary = path.with_extension("saving");
            std::fs::write(&temporary, text).unwrap();
            std::fs::rename(temporary, path).unwrap();
        }

        pub(in crate::run) fn start(
            &self,
            reload: impl FnMut(&strands_box::Policy) -> Result<(), String> + Send + 'static,
        ) -> PolicyControl {
            PolicyControl::worker(self.profile.clone(), reload).unwrap()
        }
    }

    fn received<T>(channel: &Receiver<T>) -> T {
        channel.recv_timeout(Duration::from_secs(5)).unwrap()
    }

    /// **An edit to a profile file's policy reloads like a named profile's**: the watcher watches the
    /// profile file's own folder, and the reload reads the same file again.
    #[test]
    fn a_profile_files_policy_edit_reloads() {
        let scene = Scene::file();
        let (sent, reloads) = mpsc::channel();
        let policy = scene.start(move |policy| {
            sent.send(policy.text.clone()).unwrap();
            Ok(())
        });
        std::thread::sleep(Duration::from_millis(500));
        while policy.changes.try_recv().is_ok() {}
        scene.save(
            "policy.dw",
            "@id(\"latest\") forbid (principal, action, resource);",
        );
        assert!(
            received(&policy.changes).0.pending,
            "the watcher sees the edit"
        );
        policy.reload().unwrap();
        assert!(
            received(&reloads).contains("latest"),
            "the reload reads the file"
        );
    }

    /// **A profile file's folder that is removed and made again still reloads**, as a `git checkout`
    /// does: the watcher watches that folder again, and not the profiles folder.
    #[test]
    fn a_profile_files_replaced_folder_still_reloads() {
        let scene = Scene::file();
        let policy = scene.start(|_| Ok(()));
        std::thread::sleep(Duration::from_millis(500));
        let profile = std::fs::read(scene.folder.join("profile.toml")).unwrap();
        std::fs::remove_dir_all(&scene.folder).unwrap();
        std::thread::sleep(Duration::from_millis(500));
        std::fs::create_dir_all(&scene.folder).unwrap();
        std::fs::write(scene.folder.join("profile.toml"), profile).unwrap();
        std::fs::write(scene.folder.join("policy.dw"), "").unwrap();
        std::thread::sleep(Duration::from_millis(500));
        while policy.changes.try_recv().is_ok() {}
        scene.save(
            "policy.dw",
            "@id(\"latest\") forbid (principal, action, resource);",
        );
        let deadline = Instant::now() + Duration::from_secs(5);
        while Instant::now() < deadline {
            if let Ok((status, None)) = policy.changes.recv_timeout(Duration::from_millis(200))
                && status.pending
            {
                return;
            }
        }
        panic!("the watcher saw no edit after the folder was made again");
    }

    /// **A write in the workspace does not recompile the profile**, when the profile file's folder
    /// holds the workspace; the profile file, a policy file, and the workspace's `.box` still do.
    #[test]
    fn a_write_in_the_workspace_is_not_a_profile_change() {
        let folder = std::path::Path::new("/repo");
        let workspace = folder.join("app");
        let event = |path: PathBuf| {
            Event::new(notify::EventKind::Modify(notify::event::ModifyKind::Any)).add_path(path)
        };
        for path in [
            workspace.join("src/main.rs"),
            workspace.join("node_modules/x/index.js"),
            workspace.clone(),
        ] {
            assert!(
                !relevant(&event(path.clone()), folder, folder, &workspace),
                "{}",
                path.display()
            );
        }
        for path in [
            folder.join("profile.toml"),
            folder.join("policy.dw"),
            workspace.join(".box/policy.dw"),
            folder.to_path_buf(),
        ] {
            assert!(
                relevant(&event(path.clone()), folder, folder, &workspace),
                "{}",
                path.display()
            );
        }
    }

    #[test]
    fn refused_toggle_keeps_the_confirmed_state() {
        let scene = Scene::new();
        let mut results = [Ok(()), Err("Core refused".into()), Ok(())].into_iter();
        let policy = scene.start(move |_| results.next().unwrap());
        for (enabled, failed) in [(false, false), (false, true), (true, false)] {
            policy.toggle().unwrap();
            let (status, _) = received(&policy.changes);
            assert_eq!(status.enabled, enabled);
            assert_eq!(status.failed, failed);
        }
    }

    #[test]
    fn policy_off_is_one_permit_named_policy_off() {
        assert_eq!(
            OFF,
            "@id(\"policy_off\") @description(\"policy is off\") \
             permit (principal, action, resource);"
        );
    }

    /// **Policy off drops the operator's rules and keeps the forbids `box` writes**, so the box's
    /// shell and Python still cannot change what a later run trusts, and `policy_off` is the one
    /// permit.
    #[test]
    fn policy_off_keeps_the_generated_rules_and_drops_the_operators() {
        let scene = Scene::new();
        scene.save(
            "policy.dw",
            "@id(\"mine\") permit (principal, action, resource);",
        );
        let (sent, reloads) = mpsc::channel();
        let policy = scene.start(move |policy| {
            sent.send(policy.text.clone()).unwrap();
            Ok(())
        });
        assert!(received(&policy.changes).0.pending);
        policy.reload().unwrap();
        let installed = received(&reloads);
        assert!(installed.contains("@id(\"mine\")"));
        assert!(installed.contains("@id(\"box_home_write\")"));
        policy.toggle().unwrap();
        let off = received(&reloads);
        assert!(!off.contains("@id(\"mine\")"), "{off}");
        for id in [
            "box_home_write",
            "project_configuration_write",
            "policy_off",
        ] {
            assert!(off.contains(&format!("@id(\"{id}\")")), "{id}: {off}");
        }
        assert!(off.starts_with(OFF), "{off}");
        assert_eq!(off.matches("permit").count(), 1, "{off}");
        policy.toggle().unwrap();
        assert_eq!(received(&reloads), installed);
    }

    /// **Policy off after a reload keeps the reloaded policy's forbids**: a profile that moves to
    /// another rule file gets the forbid on the new file while policy is off.
    #[test]
    fn policy_off_after_a_reload_keeps_the_reloaded_forbids() {
        let scene = Scene::file();
        let (sent, reloads) = mpsc::channel();
        let policy = scene.start(move |policy| {
            sent.send(policy.text.clone()).unwrap();
            Ok(())
        });
        std::thread::sleep(Duration::from_millis(500));
        while policy.changes.try_recv().is_ok() {}
        scene.save("moved.dw", "");
        scene.save(
            "profile.toml",
            "policies = [\"moved.dw\"]\n[agent]\ncommand = [\"/usr/bin/true\"]\n\
             [profile]\nname = \"filed\"\n",
        );
        let deadline = Instant::now() + Duration::from_secs(5);
        while !received(&policy.changes).0.pending {
            assert!(Instant::now() < deadline, "the watcher saw no edit");
        }
        policy.reload().unwrap();
        assert!(received(&reloads).contains("moved.dw"));
        policy.toggle().unwrap();
        let off = received(&reloads);
        assert!(
            off.lines()
                .any(|line| line.contains("forbid") && line.contains("moved.dw")),
            "{off}"
        );
    }

    /// **A restore turns policy back on only when it is off**, so a banner failure never leaves
    /// policy off without a banner that says so.
    #[test]
    fn restore_turns_policy_back_on_only_when_it_is_off() {
        let scene = Scene::new();
        let (sent, reloads) = mpsc::channel();
        let policy = scene.start(move |policy| {
            sent.send(policy.origin.clone()).unwrap();
            Ok(())
        });
        let profile = scene.profile.instance.directory.join("policy.dw");
        for _ in 0..2 {
            policy.restore().unwrap();
            policy.toggle().unwrap();
            assert!(!received(&policy.changes).0.enabled);
            assert_eq!(received(&reloads), PathBuf::from(OFF_ORIGIN));
            policy.restore().unwrap();
            assert!(received(&policy.changes).0.enabled);
            assert_eq!(received(&reloads), profile);
        }
    }

    #[test]
    fn policy_off_is_installed_under_its_own_name_and_a_refusal_keeps_the_profile_name() {
        let scene = Scene::new();
        let (sent, reloads) = mpsc::channel();
        let mut results = [Err("Core refused".into()), Ok(()), Ok(()), Ok(())].into_iter();
        let policy = scene.start(move |policy| {
            sent.send(policy.origin.clone()).unwrap();
            results.next().unwrap()
        });
        let profile = scene.profile.instance.directory.join("policy.dw");
        policy.toggle().unwrap();
        assert!(received(&policy.changes).0.enabled);
        assert_eq!(received(&reloads), PathBuf::from(OFF_ORIGIN));
        scene.save(
            "policy.dw",
            "@id(\"latest\") forbid (principal, action, resource);",
        );
        assert!(received(&policy.changes).0.pending);
        policy.reload().unwrap();
        assert_eq!(received(&reloads), profile);
        assert!(received(&policy.changes).0.reloaded);
        policy.toggle().unwrap();
        assert!(!received(&policy.changes).0.enabled);
        assert_eq!(received(&reloads), PathBuf::from(OFF_ORIGIN));
        policy.toggle().unwrap();
        assert!(received(&policy.changes).0.enabled);
        assert_eq!(received(&reloads), profile);
    }

    #[test]
    fn edits_wait_for_reload_and_toggles_keep_the_accepted_policy() {
        let scene = Scene::new();
        scene.save(
            "policy.dw",
            "@id(\"ready\") forbid (principal, action, resource);",
        );
        let (sent, reloads) = mpsc::channel();
        let policy = scene.start(move |policy| {
            sent.send(policy.text.clone()).unwrap();
            if policy.text.contains("refused") {
                Err("Core refused".into())
            } else {
                Ok(())
            }
        });
        let (status, error) = received(&policy.changes);
        assert!(error.is_none());
        assert!(status.pending && !status.reloaded);
        assert!(reloads.try_recv().is_err());
        policy.toggle().unwrap();
        assert!(!received(&policy.changes).0.enabled);
        assert_eq!(received(&reloads), scene.profile.off());
        policy.reload().unwrap();
        policy.toggle().unwrap();
        assert!(received(&policy.changes).0.pending);
        assert_eq!(received(&reloads), scene.profile.text);
        assert!(reloads.try_recv().is_err());
        scene.save(
            "policy.dw",
            "@id(\"latest\") forbid (principal, action, resource);",
        );
        policy.reload().unwrap();
        let installed = received(&reloads);
        assert!(installed.contains("latest"));
        let applied = (0..2)
            .map(|_| received(&policy.changes).0)
            .find(|status| status.reloaded)
            .expect("manual reload completes");
        assert!(!applied.pending);
        scene.save(
            "policy.dw",
            "@id(\"refused\") forbid (principal, action, resource);",
        );
        assert!(received(&policy.changes).0.pending);
        policy.reload().unwrap();
        let (status, error) = received(&policy.changes);
        assert!(status.pending && !status.reloaded);
        assert_eq!(error.as_deref(), Some("Core refused"));
        assert!(received(&reloads).contains("refused"));
        for text in [scene.profile.off().as_str(), installed.as_str()] {
            policy.toggle().unwrap();
            assert!(received(&policy.changes).0.pending);
            assert_eq!(received(&reloads), text);
        }
    }

    #[test]
    fn a_banner_edit_during_a_run_keeps_its_display_and_allows_a_policy_update() {
        let root = tempfile::Builder::new()
            .prefix("bx")
            .tempdir_in("/tmp")
            .unwrap();
        let home = root.path().canonicalize().unwrap().join("home");
        let workspace = home.join("project");
        let folder = home.join(".strands/box/profiles/test");
        std::fs::create_dir_all(&workspace).unwrap();
        std::fs::create_dir_all(&folder).unwrap();
        let profile = "policies = [\"policy.dw\"]\n[agent]\ncommand = [\"/usr/bin/true\"]\n";
        std::fs::write(folder.join("profile.toml"), profile).unwrap();
        std::fs::write(folder.join("policy.dw"), "").unwrap();
        let launch = Launcher::from_host()
            .home(home)
            .environment(&[])
            .search_path("/usr/bin:/bin")
            .banner(None)
            .at_terminal()
            .prepare("test", &workspace, None)
            .unwrap();
        std::fs::write(
            folder.join("profile.toml"),
            format!("{profile}[banner]\nenabled = false\n"),
        )
        .unwrap();
        std::fs::write(
            folder.join("policy.dw"),
            "@id(\"edited\") forbid (principal, action, resource);",
        )
        .unwrap();
        let updated = launch
            .policy
            .compile()
            .expect("a policy update, not a restart");
        assert!(updated.is_some_and(|policy| policy.text.contains("edited")));
    }

    #[test]
    fn configuration_changes_clear_pending_policy_and_require_restart() {
        let scene = Scene::new();
        scene.save("policy.dw", "forbid (principal, action, resource);");
        let policy = scene.start(|_| panic!("file edits must not reload"));
        assert!(received(&policy.changes).0.pending);
        scene.save(
            "profile.toml",
            "[agent]\ncommand = [\"/usr/bin/true\"]\nenv.CHANGED = \"yes\"\n",
        );
        let (status, error) = received(&policy.changes);
        assert!(!status.pending);
        assert_eq!(error.as_deref(), Some(RESTART));
    }
}

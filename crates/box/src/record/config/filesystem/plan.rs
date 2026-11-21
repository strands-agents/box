//! Filesystem rules retained while declared mount roots await source admission.

use std::path::{Component, Path, PathBuf};

use serde::{Deserialize, Serialize};

mod generation;
pub(crate) use generation::{
    FilesystemCheckpoint, FilesystemGeneration, FilesystemTargetKind, PendingMask,
    PublicationTarget,
};

use super::{DirectReach, FilesystemContext, direct_grants, expand_home, refuse};
use crate::error::ConfigError;
use crate::record::config::process::{Filesystem, Grant};

/// The original lists and the mount roots whose contents must be judged later.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct FilesystemPlan {
    original: Filesystem,
    roots: Vec<PathBuf>,
    entries: Vec<PlannedEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PlannedEntry {
    #[serde(
        serialize_with = "serialize_kind",
        deserialize_with = "deserialize_kind"
    )]
    kind: Grant,
    authored: PathBuf,
    lexical: PathBuf,
    roots: Vec<PathBuf>,
    alias_root: Option<PathBuf>,
}

fn serialize_kind<S: serde::Serializer>(kind: &Grant, serializer: S) -> Result<S::Ok, S::Error> {
    serializer.serialize_str(kind.key())
}

fn deserialize_kind<'de, D: serde::Deserializer<'de>>(deserializer: D) -> Result<Grant, D::Error> {
    let name = String::deserialize(deserializer)?;
    Grant::ALL
        .into_iter()
        .find(|kind| kind.key() == name)
        .ok_or_else(|| serde::de::Error::custom("unknown retained filesystem rule"))
}

/// A complete judgment or rules that still require protected mount admission.
#[derive(Debug)]
pub(crate) enum FilesystemCompilation {
    Complete(DirectReach),
    Pending(Box<PendingFilesystem>),
}

/// A partial judgment that cannot be passed to the existing sandbox launcher.
#[derive(Debug)]
pub(crate) struct PendingFilesystem {
    plan: FilesystemPlan,
    available: DirectReach,
    roots: Vec<PathBuf>,
}

impl FilesystemPlan {
    /// Retain shape-validated lists and their declared mount dependencies.
    pub(crate) fn new(
        lists: &Filesystem,
        roots: &[PathBuf],
        context: &FilesystemContext<'_>,
    ) -> Result<Self, ConfigError> {
        for (index, root) in roots.iter().enumerate() {
            if !root.is_absolute()
                || root == Path::new("/")
                || root
                    .components()
                    .any(|part| matches!(part, Component::ParentDir | Component::CurDir))
            {
                return Err(refuse(
                    context,
                    &root.display().to_string(),
                    "a declared mount root must be an absolute directory path other than /, without . or ..",
                ));
            }
            if roots[..index]
                .iter()
                .any(|other| root.starts_with(other) || other.starts_with(root))
            {
                return Err(refuse(
                    context,
                    &root.display().to_string(),
                    "declared mount roots must not repeat or overlap",
                ));
            }
        }
        if roots.is_empty() {
            return Ok(Self {
                original: lists.clone(),
                roots: Vec::new(),
                entries: Vec::new(),
            });
        }
        let mut entries = Vec::new();
        for (kind, authored) in lists.entries() {
            let lexical = expand_home(authored, &authored.display().to_string(), context)?;
            let mut dependencies: Vec<_> = roots
                .iter()
                .filter(|root| lexical.starts_with(root))
                .cloned()
                .collect();
            // A positive alias is only a final read link. Denials can use a resolving path too;
            // retain that route without looking inside the unavailable source. `deny_write`
            // still goes through its normal canonical-directory check after admission.
            let alias_root = if dependencies.is_empty() && follows_pending_route(kind, &lexical) {
                let dependency = alias_dependency(&lexical, roots).map_err(|error| {
                    refuse(
                        context,
                        &authored.display().to_string(),
                        &format!("cannot inspect the grant's symbolic-link route: {error}"),
                    )
                })?;
                if let Some(root) = &dependency {
                    dependencies.push(root.clone());
                }
                dependency
            } else {
                None
            };
            entries.push(PlannedEntry {
                kind,
                authored: authored.to_path_buf(),
                lexical,
                roots: dependencies,
                alias_root,
            });
        }
        Ok(Self {
            original: lists.clone(),
            roots: roots.to_vec(),
            entries,
        })
    }

    /// Judge the current view against the complete set of roots the caller has admitted.
    pub(crate) fn judge_current_view(
        mut self,
        admitted: &[PathBuf],
        context: &FilesystemContext<'_>,
    ) -> Result<FilesystemCompilation, ConfigError> {
        for root in admitted {
            if !self.roots.contains(root) {
                return Err(refuse(
                    context,
                    &root.display().to_string(),
                    "the observed mount root was not declared",
                ));
            }
        }
        if self.roots.is_empty() {
            return direct_grants(&self.original, context).map(FilesystemCompilation::Complete);
        }
        let pending: Vec<_> = self
            .roots
            .iter()
            .filter(|root| !admitted.contains(root))
            .cloned()
            .collect();
        let mut available = Filesystem::default();
        for entry in &mut self.entries {
            let mut is_pending = entry.roots.iter().any(|root| pending.contains(root));
            if !is_pending
                && follows_pending_route(entry.kind, &entry.lexical)
                && let Some(root) = alias_dependency(&entry.lexical, &pending).map_err(|error| {
                    refuse(
                        context,
                        &entry.authored.display().to_string(),
                        &format!(
                            "cannot inspect the admitted grant's symbolic-link route: {error}"
                        ),
                    )
                })?
            {
                // An alias observed before admission keeps its original root binding. A newly
                // visible alias may add its first dependency, but must not replace an earlier one.
                if entry
                    .alias_root
                    .as_ref()
                    .is_some_and(|bound| bound != &root)
                {
                    return Err(refuse(
                        context,
                        &entry.authored.display().to_string(),
                        "the grant alias no longer resolves inside the declared mount root",
                    ));
                }
                entry.roots.push(root.clone());
                entry.alias_root.get_or_insert(root);
                is_pending = true;
            }
            if is_pending {
                if cfg!(target_os = "linux") && entry.kind == Grant::List {
                    return Err(refuse(
                        context,
                        &entry.authored.display().to_string(),
                        "the Linux namespace backend cannot enforce list-only access",
                    ));
                }
                continue;
            }
            if let Some(root) = &entry.alias_root {
                let target = entry.lexical.canonicalize().map_err(|error| {
                    refuse(
                        context,
                        &entry.authored.display().to_string(),
                        &format!("cannot resolve the admitted grant alias: {error}"),
                    )
                })?;
                if !target.starts_with(root) {
                    return Err(refuse(
                        context,
                        &entry.authored.display().to_string(),
                        "the grant alias no longer resolves inside the declared mount root",
                    ));
                }
            }
            push(&mut available, entry.kind, entry.authored.clone());
        }
        let reach = direct_grants(&available, context)?;
        if pending.is_empty() {
            Ok(FilesystemCompilation::Complete(reach))
        } else {
            Ok(FilesystemCompilation::Pending(Box::new(
                PendingFilesystem {
                    plan: self,
                    available: reach,
                    roots: pending,
                },
            )))
        }
    }
}

impl PendingFilesystem {
    /// The partial reach for tests that always install every pending-root barrier.
    #[cfg(test)]
    pub(crate) fn available_for_test(&self) -> &DirectReach {
        &self.available
    }

    /// The declared roots that must remain unavailable to sandboxed code.
    pub(crate) fn roots(&self) -> &[PathBuf] {
        &self.roots
    }

    /// The authored rules retained for a later source observation.
    pub(crate) fn original(&self) -> &Filesystem {
        &self.plan.original
    }

    /// Rejudge retained lists against the complete set of roots the caller has admitted.
    #[cfg_attr(
        not(test),
        expect(
            dead_code,
            reason = "Tests rejudge this view directly; production admission compiles retained checkpoints"
        )
    )]
    pub(crate) fn judge_current_view(
        self,
        admitted: &[PathBuf],
        context: &FilesystemContext<'_>,
    ) -> Result<FilesystemCompilation, ConfigError> {
        super::require_judged_identities(&self.available, context.table)?;
        self.plan.judge_current_view(admitted, context)
    }

    /// Reject use by a launcher that has no pending-root barriers.
    pub(crate) fn unavailable(&self, context: &FilesystemContext<'_>) -> ConfigError {
        debug_assert!(self.available.grants.len() <= self.original().entries().count());
        refuse(
            context,
            "filesystem",
            &format!(
                "declared mount roots are pending and require protected admission: {}",
                self.roots()
                    .iter()
                    .map(|root| root.display().to_string())
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
        )
    }
}

fn follows_pending_route(kind: Grant, path: &Path) -> bool {
    matches!(kind, Grant::Deny | Grant::DenyWrite)
        || matches!(kind, Grant::Read | Grant::ReadFile)
            && std::fs::symlink_metadata(path).is_ok_and(|metadata| metadata.is_symlink())
}

/// Find a declared root on a link route without looking inside that root.
fn alias_dependency(path: &Path, roots: &[PathBuf]) -> std::io::Result<Option<PathBuf>> {
    use std::collections::VecDeque;
    use std::ffi::OsString;

    let components = |path: &Path| -> VecDeque<OsString> {
        path.components()
            .filter_map(|component| match component {
                Component::Normal(name) => Some(name.to_os_string()),
                Component::ParentDir => Some("..".into()),
                _ => None,
            })
            .collect()
    };
    let mut remaining = components(path);
    let mut current = PathBuf::from("/");
    let mut links = 0;
    while let Some(component) = remaining.pop_front() {
        if component == ".." {
            current.pop();
            continue;
        }
        current.push(&component);
        if let Some(root) = roots.iter().find(|root| current.starts_with(root)) {
            return Ok(Some(root.clone()));
        }
        let metadata = match std::fs::symlink_metadata(&current) {
            Ok(metadata) => metadata,
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::NotFound | std::io::ErrorKind::NotADirectory
                ) =>
            {
                continue;
            }
            Err(error) => return Err(error),
        };
        if !metadata.is_symlink() {
            continue;
        }
        links += 1;
        if links > 40 {
            return Err(std::io::Error::other(
                "the grant alias passes through too many symbolic links",
            ));
        }
        let target = std::fs::read_link(&current)?;
        if target.is_absolute() {
            current = PathBuf::from("/");
        } else {
            current.pop();
        }
        let mut next = components(&target);
        next.append(&mut remaining);
        remaining = next;
    }
    Ok(None)
}

fn push(lists: &mut Filesystem, kind: Grant, path: PathBuf) {
    match kind {
        Grant::Read => lists.read.push(path),
        Grant::Write => lists.write.push(path),
        Grant::ReadFile => lists.read_file.push(path),
        Grant::WriteFile => lists.write_file.push(path),
        Grant::List => lists.list.push(path),
        Grant::Metadata => lists.metadata.push(path),
        Grant::Exec => lists.exec.push(path),
        Grant::Deny => lists.deny.push(path),
        Grant::DenyWrite => lists.deny_write.push(path),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Fixture {
        _directory: tempfile::TempDir,
        home: PathBuf,
    }

    impl Fixture {
        fn new() -> Self {
            let directory = tempfile::tempdir().unwrap();
            let home = directory.path().canonicalize().unwrap();
            std::fs::create_dir(home.join("project")).unwrap();
            Self {
                _directory: directory,
                home,
            }
        }

        fn context(&self) -> FilesystemContext<'_> {
            FilesystemContext {
                upstream_trust: Vec::new(),
                table: "[agent]",
                operator_home: &self.home,
                policy: None,
                authority_directories: Vec::new(),
                program_search_directories: Vec::new(),
                source_paths: &[],
            }
        }

        fn root(&self, name: &str) -> PathBuf {
            self.home.join("project").join(name)
        }

        fn mount_contents(&self, root: &Path) {
            std::fs::create_dir_all(root.join("private")).unwrap();
            std::fs::create_dir(root.join("readonly")).unwrap();
            std::fs::write(root.join("data"), "mounted data").unwrap();
            std::fs::write(root.join("private/secret"), "secret").unwrap();
        }

        fn plan(&self, lists: &Filesystem, roots: &[PathBuf]) -> FilesystemPlan {
            FilesystemPlan::new(lists, roots, &self.context()).unwrap()
        }
    }

    fn pending(compilation: FilesystemCompilation) -> PendingFilesystem {
        match compilation {
            FilesystemCompilation::Pending(pending) => *pending,
            FilesystemCompilation::Complete(reach) => {
                panic!("unexpected complete reach: {reach:?}")
            }
        }
    }

    fn complete(compilation: FilesystemCompilation) -> DirectReach {
        match compilation {
            FilesystemCompilation::Complete(reach) => reach,
            FilesystemCompilation::Pending(pending) => {
                panic!("unexpected pending roots: {:?}", pending.roots())
            }
        }
    }

    fn assert_same(actual: &DirectReach, expected: &DirectReach) {
        assert_eq!(actual.grants, expected.grants);
        assert_eq!(actual.refusals, expected.refusals);
        assert_eq!(actual.write_protections, expected.write_protections);
        assert_eq!(
            actual.write_protection_identities,
            expected.write_protection_identities
        );
    }

    #[test]
    fn pending_allow_and_deny_rules_are_retained_until_admission() {
        let fixture = Fixture::new();
        let root = fixture.root("storage");
        let lists = Filesystem {
            read: vec![root.clone()],
            write: vec![root.clone()],
            deny: vec![root.join("private")],
            deny_write: vec![root.join("readonly")],
            ..Filesystem::default()
        };
        let result = pending(
            fixture
                .plan(&lists, std::slice::from_ref(&root))
                .judge_current_view(&[], &fixture.context())
                .unwrap(),
        );
        assert_eq!(result.original(), &lists);
        assert_eq!(result.roots(), std::slice::from_ref(&root));
        assert!(result.available.grants.is_empty());
        assert!(direct_grants(&lists, &fixture.context()).is_err());
        fixture.mount_contents(&root);
        let expected = direct_grants(&lists, &fixture.context()).unwrap();
        let actual = complete(
            result
                .judge_current_view(&[root], &fixture.context())
                .unwrap(),
        );
        assert_same(&actual, &expected);
        assert_eq!(actual.refusals.len(), 1);
        assert_eq!(actual.write_protections.len(), 1);
    }

    #[test]
    fn an_existing_placeholder_does_not_admit_storage() {
        let fixture = Fixture::new();
        let root = fixture.root("storage");
        fixture.mount_contents(&root);
        let lists = Filesystem {
            read: vec![root.clone()],
            ..Filesystem::default()
        };
        assert!(direct_grants(&lists, &fixture.context()).is_ok());
        let result = pending(
            fixture
                .plan(&lists, std::slice::from_ref(&root))
                .judge_current_view(&[], &fixture.context())
                .unwrap(),
        );
        assert_eq!(result.roots(), [root]);
    }

    #[test]
    fn an_ordinary_missing_path_still_refuses_startup() {
        let fixture = Fixture::new();
        let root = fixture.root("storage");
        let absent = fixture.root("ordinary-missing");
        let lists = Filesystem {
            read: vec![root.clone(), absent.clone()],
            ..Filesystem::default()
        };
        let error = fixture
            .plan(&lists, &[root])
            .judge_current_view(&[], &fixture.context())
            .unwrap_err();
        assert!(error.to_string().contains(&absent.display().to_string()));
        assert!(error.to_string().contains("not there"));
    }

    #[test]
    fn ancestor_grants_keep_pending_deny_and_write_protection_relationships() {
        let fixture = Fixture::new();
        let root = fixture.root("storage");
        let project = fixture.home.join("project");
        let lists = Filesystem {
            read: vec![project.clone()],
            write: vec![project],
            deny: vec![root.join("private")],
            deny_write: vec![root.join("readonly")],
            ..Filesystem::default()
        };
        let result = pending(
            fixture
                .plan(&lists, std::slice::from_ref(&root))
                .judge_current_view(&[], &fixture.context())
                .unwrap(),
        );
        assert_eq!(result.available.grants.len(), 2);
        assert_eq!(result.original(), &lists);
        assert!(
            result
                .unavailable(&fixture.context())
                .to_string()
                .contains("pending")
        );
        fixture.mount_contents(&root);
        let expected = direct_grants(&lists, &fixture.context()).unwrap();
        let actual = complete(
            result
                .judge_current_view(&[root], &fixture.context())
                .unwrap(),
        );
        assert_same(&actual, &expected);
    }

    #[test]
    fn an_ancestor_deny_is_not_lost_when_a_child_grant_arrives() {
        let fixture = Fixture::new();
        let root = fixture.root("storage");
        let lists = Filesystem {
            read: vec![root.clone()],
            deny: vec![fixture.home.join("project")],
            ..Filesystem::default()
        };
        let result = pending(
            fixture
                .plan(&lists, std::slice::from_ref(&root))
                .judge_current_view(&[], &fixture.context())
                .unwrap(),
        );
        assert_eq!(result.available.refusals.len(), 1);
        fixture.mount_contents(&root);
        let baseline = direct_grants(&lists, &fixture.context())
            .unwrap_err()
            .to_string();
        let admitted = result
            .judge_current_view(&[root], &fixture.context())
            .unwrap_err()
            .to_string();
        assert_eq!(admitted, baseline);
        assert!(admitted.contains("no grant reaches"));
    }

    #[test]
    fn another_declared_root_remains_pending_after_one_arrives() {
        let fixture = Fixture::new();
        let first = fixture.root("first");
        let second = fixture.root("second");
        let lists = Filesystem {
            read: vec![first.clone(), second.clone()],
            deny: vec![first.join("private"), second.join("private")],
            ..Filesystem::default()
        };
        let result = pending(
            fixture
                .plan(&lists, &[first.clone(), second.clone()])
                .judge_current_view(&[], &fixture.context())
                .unwrap(),
        );
        fixture.mount_contents(&first);
        let result = pending(
            result
                .judge_current_view(std::slice::from_ref(&first), &fixture.context())
                .unwrap(),
        );
        assert_eq!(result.roots(), std::slice::from_ref(&second));
        assert_eq!(result.original(), &lists);
        assert_eq!(result.available.grants.len(), 1);
        assert_eq!(result.available.refusals[0].path, first.join("private"));
        fixture.mount_contents(&second);
        let expected = direct_grants(&lists, &fixture.context()).unwrap();
        assert_same(
            &complete(
                result
                    .judge_current_view(&[first, second], &fixture.context())
                    .unwrap(),
            ),
            &expected,
        );
    }

    #[test]
    fn an_admitted_file_rule_keeps_the_normal_kind_check() {
        let fixture = Fixture::new();
        let root = fixture.root("storage");
        let lists = Filesystem {
            read_file: vec![root.clone()],
            ..Filesystem::default()
        };
        let result = pending(
            fixture
                .plan(&lists, std::slice::from_ref(&root))
                .judge_current_view(&[], &fixture.context())
                .unwrap(),
        );
        fixture.mount_contents(&root);
        let baseline = direct_grants(&lists, &fixture.context())
            .unwrap_err()
            .to_string();
        assert_eq!(
            result
                .judge_current_view(&[root], &fixture.context())
                .unwrap_err()
                .to_string(),
            baseline
        );
    }

    #[test]
    fn a_read_alias_into_pending_storage_keeps_its_destination_dependency() {
        let fixture = Fixture::new();
        let root = fixture.root("storage");
        let alias = fixture.home.join("read-data");
        std::os::unix::fs::symlink(root.join("data"), &alias).unwrap();
        let lists = Filesystem {
            read_file: vec![alias],
            ..Filesystem::default()
        };
        let result = pending(
            fixture
                .plan(&lists, std::slice::from_ref(&root))
                .judge_current_view(&[], &fixture.context())
                .unwrap(),
        );
        assert_eq!(result.original(), &lists);
        fixture.mount_contents(&root);
        let expected = direct_grants(&lists, &fixture.context()).unwrap();
        assert_same(
            &complete(
                result
                    .judge_current_view(&[root], &fixture.context())
                    .unwrap(),
            ),
            &expected,
        );
    }

    #[test]
    fn a_newly_visible_alias_keeps_another_declared_root_pending() {
        let fixture = Fixture::new();
        let first = fixture.root("first");
        let second = fixture.root("second");
        let alias = first.join("read-data");
        let lists = Filesystem {
            read_file: vec![alias.clone()],
            ..Filesystem::default()
        };
        let result = pending(
            fixture
                .plan(&lists, &[first.clone(), second.clone()])
                .judge_current_view(&[], &fixture.context())
                .unwrap(),
        );
        fixture.mount_contents(&first);
        std::os::unix::fs::symlink(second.join("data"), alias).unwrap();
        let result = pending(
            result
                .judge_current_view(std::slice::from_ref(&first), &fixture.context())
                .unwrap(),
        );
        assert_eq!(result.roots(), std::slice::from_ref(&second));
        assert_eq!(result.original(), &lists);
        assert!(result.available.grants.is_empty());
        fixture.mount_contents(&second);
        let expected = direct_grants(&lists, &fixture.context()).unwrap();
        assert_same(
            &complete(
                result
                    .judge_current_view(&[first, second], &fixture.context())
                    .unwrap(),
            ),
            &expected,
        );
    }

    #[test]
    fn a_pending_read_alias_cannot_retarget_outside_its_declared_root() {
        let fixture = Fixture::new();
        let root = fixture.root("storage");
        let alias = fixture.home.join("read-data");
        std::os::unix::fs::symlink(root.join("data"), &alias).unwrap();
        let lists = Filesystem {
            read_file: vec![alias.clone()],
            ..Filesystem::default()
        };
        let result = pending(
            fixture
                .plan(&lists, std::slice::from_ref(&root))
                .judge_current_view(&[], &fixture.context())
                .unwrap(),
        );
        fixture.mount_contents(&root);
        let elsewhere = fixture.home.join("other-data");
        std::fs::write(&elsewhere, "other source").unwrap();
        let replacement = fixture.home.join("replacement-link");
        std::os::unix::fs::symlink(&elsewhere, &replacement).unwrap();
        std::fs::rename(replacement, alias).unwrap();
        assert!(
            direct_grants(&lists, &fixture.context()).is_ok(),
            "the negative control grants the new target"
        );
        assert!(
            result
                .judge_current_view(&[root], &fixture.context())
                .unwrap_err()
                .to_string()
                .contains("no longer resolves inside")
        );
    }

    #[test]
    fn a_pending_read_alias_cannot_retarget_to_another_declared_root() {
        let fixture = Fixture::new();
        let first = fixture.root("first");
        let second = fixture.root("second");
        let alias = fixture.home.join("read-data");
        std::os::unix::fs::symlink(first.join("data"), &alias).unwrap();
        let lists = Filesystem {
            read_file: vec![alias.clone()],
            ..Filesystem::default()
        };
        let result = pending(
            fixture
                .plan(&lists, &[first.clone(), second.clone()])
                .judge_current_view(&[], &fixture.context())
                .unwrap(),
        );
        fixture.mount_contents(&first);
        let replacement = fixture.home.join("replacement-link");
        std::os::unix::fs::symlink(second.join("data"), &replacement).unwrap();
        std::fs::rename(replacement, alias).unwrap();
        let error =
            match result.judge_current_view(std::slice::from_ref(&first), &fixture.context()) {
                Err(error) => error,
                Ok(result) => {
                    // Before the fix, admission of the original root rewrote the alias's bound root.
                    // Prove that admitting the replacement then approved the changed destination.
                    let result = pending(result);
                    fixture.mount_contents(&second);
                    let expected = direct_grants(&lists, &fixture.context()).unwrap();
                    let retargeted = complete(
                        result
                            .judge_current_view(&[first, second], &fixture.context())
                            .unwrap(),
                    );
                    assert_same(&retargeted, &expected);
                    panic!("admission accepted an alias retargeted to another declared root");
                }
            };
        assert!(error.to_string().contains("no longer resolves inside"));
    }

    #[test]
    fn pending_storage_does_not_reapprove_a_changed_static_alias() {
        let fixture = Fixture::new();
        let root = fixture.root("storage");
        let first = fixture.home.join("first-file");
        let second = fixture.home.join("second-file");
        std::fs::write(&first, "approved").unwrap();
        std::fs::write(&second, "replacement").unwrap();
        let alias = fixture.home.join("read-file");
        std::os::unix::fs::symlink(&first, &alias).unwrap();
        let lists = Filesystem {
            read: vec![root.clone()],
            read_file: vec![alias.clone()],
            ..Filesystem::default()
        };
        let result = pending(
            fixture
                .plan(&lists, std::slice::from_ref(&root))
                .judge_current_view(&[], &fixture.context())
                .unwrap(),
        );
        let replacement = fixture.home.join("new-link");
        std::os::unix::fs::symlink(&second, &replacement).unwrap();
        std::fs::rename(replacement, alias).unwrap();
        fixture.mount_contents(&root);
        assert!(
            direct_grants(&lists, &fixture.context()).is_ok(),
            "rejudging alone would approve the replacement"
        );
        let error = result
            .judge_current_view(&[root], &fixture.context())
            .unwrap_err()
            .to_string();
        assert!(error.contains("no longer what"), "{error}");
    }

    #[test]
    fn no_mount_declaration_preserves_the_existing_compiler_result() {
        let fixture = Fixture::new();
        let lists = Filesystem {
            read: vec![fixture.home.join("project")],
            ..Filesystem::default()
        };
        let expected = direct_grants(&lists, &fixture.context()).unwrap();
        let actual = complete(
            fixture
                .plan(&lists, &[])
                .judge_current_view(&[], &fixture.context())
                .unwrap(),
        );
        assert_same(&actual, &expected);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn pending_roots_do_not_relax_linux_list_or_write_only_refusals() {
        let fixture = Fixture::new();
        let root = fixture.root("storage");
        for lists in [
            Filesystem {
                list: vec![root.clone()],
                ..Filesystem::default()
            },
            Filesystem {
                write: vec![fixture.home.join("project")],
                ..Filesystem::default()
            },
        ] {
            assert!(
                fixture
                    .plan(&lists, std::slice::from_ref(&root))
                    .judge_current_view(&[], &fixture.context())
                    .is_err()
            );
        }
    }
}

use super::*;
use crate::record::config::process::Filesystem;

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

    fn root(&self, name: &str) -> PathBuf {
        self.home.join("project").join(name)
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

    fn generation(&self, lists: &Filesystem, roots: &[PathBuf]) -> FilesystemGeneration {
        FilesystemPlan::new(lists, roots, &self.context())
            .unwrap()
            .compile_generation(&[], &self.context())
            .unwrap()
    }

    fn contents(&self, root: &Path) {
        std::fs::create_dir_all(root.join("private")).unwrap();
        std::fs::create_dir(root.join("readonly")).unwrap();
        std::fs::write(root.join("data"), "mounted data").unwrap();
        std::fs::write(root.join("private/secret"), "secret").unwrap();
    }
}

#[test]
fn missing_external_file_alias_keeps_its_authored_mask_and_rules() {
    let fixture = Fixture::new();
    let root = fixture.root("storage");
    let aliases = fixture.home.join("aliases");
    std::fs::create_dir(&aliases).unwrap();
    let alias = aliases.join("read-data");
    std::os::unix::fs::symlink(root.join("data"), &alias).unwrap();
    let lists = Filesystem {
        read: vec![fixture.home.join("project"), aliases],
        read_file: vec![alias.clone()],
        deny: vec![root.join("private")],
        ..Filesystem::default()
    };
    let initial = fixture.generation(&lists, std::slice::from_ref(&root));
    initial.with_policy(|reach, masks, targets| {
        assert_eq!(reach.grants.len(), 2);
        assert!(targets.is_empty());
        assert_eq!(
            masks,
            [
                PendingMask {
                    path: root.clone(),
                    kind: FilesystemTargetKind::Directory,
                    roots: vec![root.clone()]
                },
                PendingMask {
                    path: alias.clone(),
                    kind: FilesystemTargetKind::File,
                    roots: vec![root.clone()]
                },
            ]
        );
    });
    assert!(!root.exists());
    assert_eq!(std::fs::read_link(&alias).unwrap(), root.join("data"));
    let encoded = serde_json::to_string(&initial.checkpoint()).unwrap();
    let checkpoint: FilesystemCheckpoint = serde_json::from_str(&encoded).unwrap();
    assert!(checkpoint.matches(&lists, std::slice::from_ref(&root)));
    fixture.contents(&root);
    let admitted = checkpoint
        .compile(std::slice::from_ref(&root), &fixture.context())
        .unwrap();
    admitted.with_policy(|reach, masks, targets| {
        assert!(masks.is_empty());
        assert_eq!(reach.refusals[0].path, root.join("private"));
        assert!(targets.iter().any(|target| target.path == alias && target.kind == FilesystemTargetKind::File));
        assert!(targets.iter().any(|target| target.path == root && target.kind == FilesystemTargetKind::Directory));
        let expected = super::super::super::direct_grants(&lists, &fixture.context()).unwrap();
        assert_eq!(reach.grants, expected.grants);
        assert_eq!(reach.refusals, expected.refusals);
    });
}

#[test]
fn one_available_root_keeps_its_denials_while_the_other_stays_masked() {
    let fixture = Fixture::new();
    let first = fixture.root("first");
    let second = fixture.root("second");
    let project = fixture.home.join("project");
    let lists = Filesystem {
        read: vec![project.clone()],
        write: vec![project],
        deny: vec![first.join("private"), second.join("private")],
        deny_write: vec![first.join("readonly"), second.join("readonly")],
        ..Filesystem::default()
    };
    let initial = fixture.generation(&lists, &[first.clone(), second.clone()]);
    fixture.contents(&first);
    let partial = initial
        .recompile(std::slice::from_ref(&first), &fixture.context())
        .unwrap();
    partial.with_policy(|reach, masks, targets| {
        assert_eq!(masks.len(), 1);
        assert_eq!(masks[0].path, second);
        assert_eq!(targets.len(), 1);
        assert_eq!(targets[0].path, first);
        assert_eq!(reach.refusals[0].path, first.join("private"));
        assert_eq!(reach.write_protections, [first.join("readonly")]);
    });
    fixture.contents(&second);
    let complete = partial
        .recompile(&[first, second], &fixture.context())
        .unwrap();
    complete.with_policy(|reach, masks, targets| {
        assert!(masks.is_empty());
        assert_eq!(targets.len(), 2);
        assert!(
            targets
                .iter()
                .any(|target| target.path == fixture.root("first"))
        );
        assert!(
            targets
                .iter()
                .any(|target| target.path == fixture.root("second"))
        );
        let expected = super::super::super::direct_grants(&lists, &fixture.context()).unwrap();
        assert_eq!(reach.grants, expected.grants);
        assert_eq!(reach.refusals, expected.refusals);
        assert_eq!(reach.write_protections, expected.write_protections);
    });
}

#[test]
fn a_related_root_waits_for_the_other_alias_source() {
    let fixture = Fixture::new();
    let first = fixture.root("first");
    let second = fixture.root("second");
    let alias = first.join("read-data");
    let lists = Filesystem {
        read: vec![first.clone()],
        read_file: vec![alias.clone()],
        ..Filesystem::default()
    };
    let initial = fixture.generation(&lists, &[first.clone(), second.clone()]);
    fixture.contents(&first);
    std::os::unix::fs::symlink(second.join("data"), &alias).unwrap();
    let partial = initial
        .recompile(std::slice::from_ref(&first), &fixture.context())
        .unwrap();
    partial.with_policy(|reach, masks, targets| {
        assert!(reach.grants.is_empty());
        assert_eq!(masks.len(), 2);
        assert!(masks.iter().any(|mask| mask.path == second));
        assert!(masks.iter().any(|mask| mask.path == first));
        assert!(!masks.iter().any(|mask| mask.path == alias));
        assert!(targets.is_empty());
        assert_eq!(
            std::fs::read_to_string(first.join("data")).unwrap(),
            "mounted data"
        );
    });
    fixture.contents(&second);
    let complete = partial
        .recompile(&[first.clone(), second.clone()], &fixture.context())
        .unwrap();
    complete.with_policy(|reach, masks, targets| {
        assert!(masks.is_empty());
        let projected = targets.iter().find(|target| target.path == first).unwrap();
        assert!(projected.roots.contains(&first));
        assert!(projected.roots.contains(&second));
        let expected = super::super::super::direct_grants(&lists, &fixture.context()).unwrap();
        assert_eq!(reach.grants, expected.grants);
    });
}

#[test]
fn a_serialized_checkpoint_rejects_a_replaced_static_file() {
    let fixture = Fixture::new();
    let root = fixture.root("storage");
    let existing = fixture.home.join("existing");
    std::fs::write(&existing, "approved").unwrap();
    let lists = Filesystem {
        read_file: vec![existing.clone(), root.join("data")],
        ..Filesystem::default()
    };
    let initial = fixture.generation(&lists, std::slice::from_ref(&root));
    let checkpoint: FilesystemCheckpoint =
        serde_json::from_str(&serde_json::to_string(&initial.checkpoint()).unwrap()).unwrap();
    std::fs::rename(&existing, fixture.home.join("previous")).unwrap();
    std::fs::write(&existing, "replacement").unwrap();
    fixture.contents(&root);
    let error = checkpoint
        .compile(&[root], &fixture.context())
        .unwrap_err()
        .to_string();
    assert!(
        error.contains("previously judged filesystem object was replaced"),
        "{error}"
    );
}

#[test]
fn a_checkpoint_cannot_move_to_another_process_table_or_forget_an_admitted_root() {
    let fixture = Fixture::new();
    let root = fixture.root("storage");
    let lists = Filesystem {
        read: vec![root.clone()],
        ..Filesystem::default()
    };
    let initial = fixture.generation(&lists, std::slice::from_ref(&root));
    let mut other = fixture.context();
    other.table = "[tool.other]";
    assert!(initial.checkpoint().compile(&[], &other).is_err());
    fixture.contents(&root);
    let admitted = initial.recompile(&[root], &fixture.context()).unwrap();
    assert!(
        admitted
            .checkpoint()
            .compile(&[], &fixture.context())
            .is_err()
    );
}

#[test]
fn a_directory_alias_keeps_the_normal_compiler_refusal() {
    let fixture = Fixture::new();
    let root = fixture.root("storage");
    let alias = fixture.home.join("directory-link");
    std::os::unix::fs::symlink(root.join("readonly"), &alias).unwrap();
    let lists = Filesystem {
        read: vec![alias],
        ..Filesystem::default()
    };
    let initial = fixture.generation(&lists, std::slice::from_ref(&root));
    fixture.contents(&root);
    let expected = super::super::super::direct_grants(&lists, &fixture.context())
        .unwrap_err()
        .to_string();
    let actual = initial
        .recompile(&[root], &fixture.context())
        .unwrap_err()
        .to_string();
    assert_eq!(actual, expected);
}

#[test]
fn a_generation_does_not_retarget_a_bound_alias_to_another_declared_root() {
    let fixture = Fixture::new();
    let first = fixture.root("first");
    let second = fixture.root("second");
    let alias = fixture.home.join("read-data");
    std::os::unix::fs::symlink(first.join("data"), &alias).unwrap();
    let lists = Filesystem {
        read_file: vec![alias.clone()],
        ..Filesystem::default()
    };
    let initial = fixture.generation(&lists, &[first.clone(), second.clone()]);
    let replacement = fixture.home.join("replacement");
    std::os::unix::fs::symlink(second.join("data"), &replacement).unwrap();
    std::fs::rename(replacement, alias).unwrap();
    fixture.contents(&first);
    let error = initial
        .recompile(&[first], &fixture.context())
        .unwrap_err()
        .to_string();
    assert!(
        error.contains("previously judged filesystem object was replaced"),
        "{error}"
    );
}

#[test]
fn nonempty_placeholders_and_aliases_are_masked_before_any_source_is_admitted() {
    let fixture = Fixture::new();
    let root = fixture.root("storage");
    fixture.contents(&root);
    let aliases = fixture.home.join("aliases");
    std::fs::create_dir(&aliases).unwrap();
    let alias = aliases.join("read-data");
    std::os::unix::fs::symlink(root.join("data"), &alias).unwrap();
    let lists = Filesystem {
        read: vec![fixture.home.join("project"), aliases],
        read_file: vec![alias.clone()],
        ..Filesystem::default()
    };
    let pending = fixture.generation(&lists, std::slice::from_ref(&root));
    pending.with_policy(|reach, masks, targets| {
        assert_eq!(reach.grants.len(), 2);
        assert!(targets.is_empty());
        assert!(masks.iter().any(|mask| mask.path == root));
        assert!(masks.iter().any(|mask| mask.path == alias));
        assert!(!reach.grants.iter().any(|grant| grant.lexical == alias));
    });
}

#[test]
fn missing_static_rules_and_admitted_denials_still_fail() {
    let fixture = Fixture::new();
    let root = fixture.root("storage");
    let missing = Filesystem {
        read_file: vec![fixture.home.join("missing")],
        ..Filesystem::default()
    };
    assert!(
        FilesystemPlan::new(&missing, std::slice::from_ref(&root), &fixture.context())
            .unwrap()
            .compile_generation(&[], &fixture.context())
            .is_err()
    );
    let lists = Filesystem {
        read: vec![root.clone()],
        deny_write: vec![root.join("readonly")],
        ..Filesystem::default()
    };
    let pending = fixture.generation(&lists, std::slice::from_ref(&root));
    fixture.contents(&root);
    let error = pending
        .recompile(&[root], &fixture.context())
        .unwrap_err()
        .to_string();
    assert!(
        error.contains("lies inside no `write` directory"),
        "{error}"
    );
}

#[test]
fn a_pending_alias_link_is_pinned_without_resolving_its_absent_target() {
    let fixture = Fixture::new();
    let root = fixture.root("storage");
    let alias = fixture.home.join("read-data");
    std::os::unix::fs::symlink(root.join("data"), &alias).unwrap();
    let lists = Filesystem {
        read_file: vec![alias.clone()],
        ..Filesystem::default()
    };
    let pending = fixture.generation(&lists, std::slice::from_ref(&root));
    assert!(!root.exists());
    std::fs::rename(&alias, fixture.home.join("old-link")).unwrap();
    std::os::unix::fs::symlink(root.join("private/secret"), alias).unwrap();
    fixture.contents(&root);
    let error = pending
        .recompile(&[root], &fixture.context())
        .unwrap_err()
        .to_string();
    assert!(
        error.contains("previously judged filesystem object was replaced"),
        "{error}"
    );
}

#[test]
fn a_denial_through_an_external_directory_link_keeps_its_source_dependency() {
    let fixture = Fixture::new();
    let root = fixture.root("storage");
    let link = fixture.home.join("storage-link");
    std::os::unix::fs::symlink(&root, &link).unwrap();
    let lists = Filesystem {
        read: vec![root.clone()],
        deny: vec![link.join("private")],
        ..Filesystem::default()
    };
    let pending = fixture.generation(&lists, std::slice::from_ref(&root));
    pending.with_policy(|reach, masks, _| {
        assert!(reach.refusals.is_empty());
        assert_eq!(masks.len(), 1);
        assert_eq!(masks[0].path, root);
    });
    fixture.contents(&root);
    let admitted = pending.recompile(&[root], &fixture.context()).unwrap();
    admitted.with_policy(|reach, masks, _| {
        assert!(masks.is_empty());
        let expected = super::super::super::direct_grants(&lists, &fixture.context()).unwrap();
        assert_eq!(reach.grants, expected.grants);
        assert_eq!(reach.refusals, expected.refusals);
    });
}

#[test]
fn a_denial_discovered_under_a_keeps_that_related_root_pending() {
    let fixture = Fixture::new();
    let first = fixture.root("first");
    let second = fixture.root("second");
    let link = first.join("other");
    let lists = Filesystem {
        read: vec![first.clone(), second.clone()],
        deny: vec![link.join("private")],
        ..Filesystem::default()
    };
    let pending = fixture.generation(&lists, &[first.clone(), second.clone()]);
    fixture.contents(&first);
    std::os::unix::fs::symlink(&second, &link).unwrap();
    let partial = pending
        .recompile(std::slice::from_ref(&first), &fixture.context())
        .unwrap();
    partial.with_policy(|reach, masks, targets| {
        assert!(reach.grants.is_empty());
        assert_eq!(masks.len(), 2);
        assert!(masks.iter().any(|mask| mask.path == first));
        assert!(masks.iter().any(|mask| mask.path == second));
        assert!(targets.is_empty());
    });
    fixture.contents(&second);
    let admitted = partial
        .recompile(&[first, second], &fixture.context())
        .unwrap();
    admitted.with_policy(|reach, masks, _| {
        assert!(masks.is_empty());
        let expected = super::super::super::direct_grants(&lists, &fixture.context()).unwrap();
        assert_eq!(reach.grants, expected.grants);
        assert_eq!(reach.refusals, expected.refusals);
    });
}

#[test]
fn a_write_denial_through_a_link_retains_its_normal_canonical_path_refusal() {
    let fixture = Fixture::new();
    let root = fixture.root("storage");
    let link = fixture.home.join("storage-link");
    std::os::unix::fs::symlink(&root, &link).unwrap();
    let lists = Filesystem {
        read: vec![root.clone()],
        write: vec![root.clone()],
        deny_write: vec![link.join("readonly")],
        ..Filesystem::default()
    };
    let pending = fixture.generation(&lists, std::slice::from_ref(&root));
    fixture.contents(&root);
    let expected = super::super::super::direct_grants(&lists, &fixture.context())
        .unwrap_err()
        .to_string();
    let actual = pending
        .recompile(&[root], &fixture.context())
        .unwrap_err()
        .to_string();
    assert_eq!(actual, expected);
}

#[test]
fn unrelated_roots_publish_independently_and_compiled_targets_remain_declarative() {
    let fixture = Fixture::new();
    let first = fixture.root("first");
    let second = fixture.root("second");
    let unrelated = fixture.root("unrelated");
    let alias = first.join("other");
    let lists = Filesystem {
        read: vec![first.clone(), unrelated.clone()],
        read_file: vec![alias.clone()],
        ..Filesystem::default()
    };
    let pending = fixture.generation(&lists, &[first.clone(), second.clone(), unrelated.clone()]);
    fixture.contents(&first);
    fixture.contents(&unrelated);
    std::os::unix::fs::symlink(second.join("data"), alias).unwrap();
    let partial = pending
        .recompile(&[first.clone(), unrelated.clone()], &fixture.context())
        .unwrap();
    partial.with_policy(|reach, masks, targets| {
        assert_eq!(reach.grants.len(), 1);
        assert_eq!(reach.grants[0].resolved, unrelated);
        assert_eq!(targets.len(), 1);
        assert_eq!(targets[0].path, unrelated);
        assert!(masks.iter().any(|mask| mask.path == first));
        assert!(masks.iter().any(|mask| mask.path == second));
        assert!(!masks.iter().any(|mask| mask.path == unrelated));
    });
    // Compiler checkpoints carry no receiver publication acknowledgment.
    fixture.contents(&second);
    let captured = [first.clone(), second.clone(), unrelated.clone()];
    let complete = partial.recompile(&captured, &fixture.context()).unwrap();
    complete.with_policy(|reach, masks, targets| {
        assert!(masks.is_empty());
        assert_eq!(targets.len(), 3);
        assert!(targets.iter().any(|target| target.path == first));
        assert!(targets.iter().any(|target| target.path == second));
        assert!(targets.iter().any(|target| target.path == unrelated));
        let expected = super::super::super::direct_grants(&lists, &fixture.context()).unwrap();
        assert_eq!(reach.grants, expected.grants);
    });
    let checkpoint: FilesystemCheckpoint =
        serde_json::from_str(&serde_json::to_string(&complete.checkpoint()).unwrap()).unwrap();
    let repeated = checkpoint.compile(&captured, &fixture.context()).unwrap();
    repeated.with_policy(|_, masks, targets| {
        assert!(masks.is_empty());
        assert_eq!(targets.len(), 3);
        assert!(targets.iter().any(|target| target.path == first));
        assert!(targets.iter().any(|target| target.path == second));
        assert!(targets.iter().any(|target| target.path == unrelated));
    });
}

#[test]
fn denial_and_alias_dependencies_are_transitive_in_both_startup_orders() {
    for captured_before_first_generation in [false, true] {
        let fixture = Fixture::new();
        let first = fixture.root("first");
        let second = fixture.root("second");
        let third = fixture.root("third");
        let unrelated = fixture.root("unrelated");
        let roots = [
            first.clone(),
            second.clone(),
            third.clone(),
            unrelated.clone(),
        ];
        let lists = Filesystem {
            read: vec![first.clone(), second.clone(), unrelated.clone()],
            write: vec![second.clone()],
            read_file: vec![second.join("next-data")],
            deny: vec![first.join("other/private")],
            deny_write: vec![second.join("readonly")],
            ..Filesystem::default()
        };
        for root in [&first, &second, &unrelated] {
            fixture.contents(root);
        }
        std::os::unix::fs::symlink(&second, first.join("other")).unwrap();
        std::os::unix::fs::symlink(third.join("data"), second.join("next-data")).unwrap();
        let complete = if captured_before_first_generation {
            fixture.contents(&third);
            FilesystemPlan::new(&lists, &roots, &fixture.context())
                .unwrap()
                .compile_generation(&roots, &fixture.context())
                .unwrap()
        } else {
            let pending = fixture.generation(&lists, &roots);
            let partial = pending
                .recompile(
                    &[first.clone(), second.clone(), unrelated.clone()],
                    &fixture.context(),
                )
                .unwrap();
            partial.with_policy(|reach, masks, targets| {
                assert_eq!(reach.grants.len(), 1);
                assert_eq!(reach.grants[0].resolved, unrelated);
                assert_eq!(targets.len(), 1);
                assert_eq!(targets[0].path, unrelated);
                for root in [&first, &second, &third] {
                    let mask = masks.iter().find(|mask| &mask.path == root).unwrap();
                    assert_eq!(mask.roots.len(), 3);
                    assert!(mask.roots.contains(&first));
                    assert!(mask.roots.contains(&second));
                    assert!(mask.roots.contains(&third));
                }
            });
            fixture.contents(&third);
            partial.recompile(&roots, &fixture.context()).unwrap()
        };
        complete.with_policy(|reach, masks, targets| {
            assert!(masks.is_empty());
            assert_eq!(targets.len(), 4);
            for root in [&first, &second, &third] {
                let target = targets.iter().find(|target| &target.path == root).unwrap();
                assert_eq!(target.roots.len(), 3);
                assert!(target.roots.contains(&first));
                assert!(target.roots.contains(&second));
                assert!(target.roots.contains(&third));
                assert!(!target.roots.contains(&unrelated));
            }
            let independent = targets
                .iter()
                .find(|target| target.path == unrelated)
                .unwrap();
            assert_eq!(
                independent.roots.as_slice(),
                std::slice::from_ref(&unrelated)
            );
            let expected = super::super::super::direct_grants(&lists, &fixture.context()).unwrap();
            assert_eq!(reach.grants, expected.grants);
            assert_eq!(reach.refusals, expected.refusals);
            assert_eq!(reach.write_protections, expected.write_protections);
            assert_eq!(reach.write_protections, [second.join("readonly")]);
        });
    }
}

#[test]
fn a_late_denial_cannot_newly_restrict_a_previously_available_root() {
    let fixture = Fixture::new();
    let first = fixture.root("first");
    let second = fixture.root("second");
    let roots = [first.clone(), second.clone()];
    let lists = Filesystem {
        read: vec![first.clone()],
        deny: vec![second.join("other/private")],
        ..Filesystem::default()
    };
    let pending = fixture.generation(&lists, &roots);
    let both_masked = pending.checkpoint();
    fixture.contents(&first);
    let first_ready = pending
        .recompile(std::slice::from_ref(&first), &fixture.context())
        .unwrap();
    first_ready.with_policy(|reach, masks, targets| {
        assert!(reach.refusals.is_empty());
        assert_eq!(masks.len(), 1);
        assert_eq!(masks[0].path, second);
        assert_eq!(targets.len(), 1);
        assert_eq!(targets[0].path, first);
    });
    let checkpoint: FilesystemCheckpoint =
        serde_json::from_str(&serde_json::to_string(&first_ready.checkpoint()).unwrap()).unwrap();
    fixture.contents(&second);
    std::os::unix::fs::symlink(&first, second.join("other")).unwrap();
    let expected = super::super::super::direct_grants(&lists, &fixture.context()).unwrap();
    assert_eq!(expected.refusals[0].path, second.join("other/private"));
    assert_eq!(
        resolved_to_its_deepest_existing_ancestor(&expected.refusals[0].path),
        first.join("private"),
    );
    let error = checkpoint
        .compile(&roots, &fixture.context())
        .unwrap_err()
        .to_string();
    assert!(
        error
            .contains("newly resolved filesystem restriction would change an already exposed path"),
        "{error}"
    );
    assert!(
        error.contains(&first.join("private").display().to_string()),
        "{error}"
    );
    // The same authored policy is admissible while both affected destinations remain masked.
    let together = both_masked.compile(&roots, &fixture.context()).unwrap();
    together.with_policy(|reach, masks, _| {
        assert!(masks.is_empty());
        assert_eq!(reach.refusals, expected.refusals);
    });
}

#[test]
fn a_late_denial_cannot_newly_restrict_an_ordinary_visible_path() {
    let fixture = Fixture::new();
    let root = fixture.root("storage");
    let ordinary = fixture.home.join("ordinary");
    fixture.contents(&ordinary);
    let lists = Filesystem {
        read: vec![ordinary.clone()],
        deny: vec![root.join("other/private")],
        ..Filesystem::default()
    };
    let pending = fixture.generation(&lists, std::slice::from_ref(&root));
    pending.with_policy(|reach, masks, targets| {
        assert_eq!(reach.grants[0].resolved, ordinary);
        assert!(reach.refusals.is_empty());
        assert_eq!(masks.len(), 1);
        assert_eq!(masks[0].path, root);
        assert!(targets.is_empty());
    });
    fixture.contents(&root);
    std::os::unix::fs::symlink(&ordinary, root.join("other")).unwrap();
    let expected = super::super::super::direct_grants(&lists, &fixture.context()).unwrap();
    let error = pending
        .recompile(std::slice::from_ref(&root), &fixture.context())
        .unwrap_err()
        .to_string();
    assert!(
        error
            .contains("newly resolved filesystem restriction would change an already exposed path"),
        "{error}"
    );
    assert!(
        error.contains(&ordinary.join("private").display().to_string()),
        "{error}"
    );
    // With the source captured before first exposure, normal denial semantics remain accepted.
    let before_launch =
        FilesystemPlan::new(&lists, std::slice::from_ref(&root), &fixture.context())
            .unwrap()
            .compile_generation(std::slice::from_ref(&root), &fixture.context())
            .unwrap();
    before_launch.with_policy(|reach, masks, _| {
        assert!(masks.is_empty());
        assert_eq!(reach.refusals, expected.refusals);
    });
}

#[test]
fn compiled_restriction_coverage_preserves_scope_and_write_protection() {
    let root = PathBuf::from("/captured/data");
    let deny_tree = CompiledRestriction {
        path: root.clone(),
        resolved: root.clone(),
        kind: RestrictionKind::Deny,
        scope: Scope::Root,
    };
    let deny_file = CompiledRestriction {
        path: root.join("file"),
        resolved: root.join("file"),
        kind: RestrictionKind::Deny,
        scope: Scope::File,
    };
    let write_tree = CompiledRestriction {
        path: root.clone(),
        resolved: root.clone(),
        kind: RestrictionKind::DenyWrite,
        scope: Scope::Root,
    };
    let nested_write = CompiledRestriction {
        path: root.join("readonly"),
        resolved: root.join("readonly"),
        kind: RestrictionKind::DenyWrite,
        scope: Scope::Root,
    };
    assert!(deny_tree.covers(&deny_file));
    assert!(deny_tree.covers(&write_tree));
    assert!(!deny_file.covers(&deny_tree));
    assert!(!write_tree.covers(&deny_tree));
    assert!(write_tree.covers(&nested_write));
    assert!(!nested_write.covers(&write_tree));
}

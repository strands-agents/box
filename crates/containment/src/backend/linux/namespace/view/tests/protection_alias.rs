use super::*;
use std::cell::Cell;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};

#[derive(Clone, Copy)]
enum AliasKind {
    Directory,
    File,
}

struct Fixture {
    _directory: tempfile::TempDir,
    original: PathBuf,
    alias: PathBuf,
    outer_alias: PathBuf,
    protected: PathBuf,
    sibling: PathBuf,
    requested: PathBuf,
    root: PathBuf,
    opened: std::fs::File,
    view: MountView,
}

impl Fixture {
    fn new(kind: AliasKind, alias_name: &str, linked_tree: bool) -> Self {
        let directory = tempfile::tempdir().unwrap();
        let original = directory.path().join("original");
        let child = original.join("child");
        std::fs::create_dir_all(&child).unwrap();
        let protected = child.join("policy");
        let sibling = child.join("ordinary");
        std::fs::write(&protected, b"protected policy").unwrap();
        std::fs::write(&sibling, b"ordinary bytes").unwrap();
        std::fs::write(original.join("outside-write-grant"), b"read only").unwrap();
        let alias = original.join(alias_name);
        let relative = match kind {
            AliasKind::Directory => "child",
            AliasKind::File => "child/policy",
        };
        std::os::unix::fs::symlink(relative, &alias).unwrap();
        let outer_alias = directory.path().join("outer-alias");
        std::os::unix::fs::symlink("original", &outer_alias).unwrap();
        let tree = if linked_tree { &outer_alias } else { &original };
        let grant = tree.join(alias_name);
        let scope = match kind {
            AliasKind::Directory => Scope::Root,
            AliasKind::File => Scope::File,
        };
        let mut config = ContainmentConfig::new()
            .allow(tree, Operation::Read, Scope::Root)
            .unwrap()
            .allow(&grant, Operation::Write, scope)
            .unwrap();
        if matches!(kind, AliasKind::File) {
            config = config
                .allow(&sibling, Operation::Write, Scope::File)
                .unwrap();
        }
        let opened = std::fs::File::open(&protected).unwrap();
        config = config.protect_write(&protected, &opened).unwrap();
        crate::floors::require_all(&config).unwrap();
        config.require_live_path_identities().unwrap();
        let view = MountView::plan(&config).unwrap();
        let requested = match kind {
            AliasKind::Directory => grant.join("policy"),
            AliasKind::File => grant,
        };
        let root = directory.path().join("view");
        std::fs::create_dir(&root).unwrap();
        Self {
            _directory: directory,
            original,
            alias,
            outer_alias,
            protected,
            sibling,
            requested,
            root,
            opened,
            view,
        }
    }

    fn staged(&self, path: &Path) -> PathBuf {
        self.root.join(path.strip_prefix("/").unwrap())
    }

    fn alias_protection(&self) -> &MountEntry {
        self.view
            .entries()
            .iter()
            .find(|entry| {
                matches!(entry.origin, MountOrigin::Protection { .. })
                    && entry.target == self.requested
            })
            .unwrap()
    }
}

fn in_private_namespace(action: impl FnOnce()) {
    assert!(super::forked(|| {
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            assert!(enter_private_namespace());
            action();
        }))
        .is_ok()
    }));
}

fn protected_alias_stays_usable(kind: AliasKind, alias_name: &str, linked_tree: bool) {
    if !super::super::super::failure_tests::namespace_test_is_permitted() {
        return;
    }
    let fixture = Fixture::new(kind, alias_name, linked_tree);
    let protections: Vec<_> = fixture
        .view
        .entries()
        .iter()
        .filter(|entry| matches!(entry.origin, MountOrigin::Protection { .. }))
        .collect();
    assert_eq!(protections.len(), 2);
    assert!(
        protections
            .iter()
            .any(|entry| entry.target == fixture.protected)
    );
    assert!(
        protections
            .iter()
            .any(|entry| entry.target == fixture.requested)
    );
    let identity = fixture.opened.metadata().unwrap();
    let alias_contents = std::fs::read_link(&fixture.alias).unwrap();
    in_private_namespace(|| {
        assert!(establish_every_entry(&fixture.view, &fixture.root));
        fixture.view.protect_parents(&fixture.root).unwrap();
        for path in [&fixture.protected, &fixture.requested] {
            let staged = fixture.staged(path);
            let metadata = std::fs::metadata(&staged).unwrap();
            assert_eq!(
                (metadata.dev(), metadata.ino()),
                (identity.dev(), identity.ino())
            );
            assert_eq!(std::fs::read(&staged).unwrap(), b"protected policy");
            assert!(std::fs::write(&staged, b"not permitted").is_err());
        }
        let ordinary = fixture.staged(&fixture.sibling);
        std::fs::write(&ordinary, b"permitted sibling write").unwrap();
        assert_eq!(
            std::fs::read(&ordinary).unwrap(),
            b"permitted sibling write"
        );
        let read_only = fixture.staged(&fixture.original.join("outside-write-grant"));
        assert!(std::fs::write(&read_only, b"not permitted").is_err());
        assert_eq!(std::fs::read(&read_only).unwrap(), b"read only");
    });
    assert_eq!(
        std::fs::read(&fixture.protected).unwrap(),
        b"protected policy"
    );
    assert_eq!(
        std::fs::read(&fixture.sibling).unwrap(),
        b"permitted sibling write"
    );
    assert_eq!(std::fs::read_link(&fixture.alias).unwrap(), alias_contents);
    assert_eq!(
        std::fs::read_link(&fixture.outer_alias).unwrap(),
        Path::new("original")
    );
}

#[test]
fn a_protected_file_under_an_earlier_writable_directory_alias_remains_read_only() {
    protected_alias_stays_usable(AliasKind::Directory, "alias", false);
}

#[test]
fn a_protected_file_under_a_later_writable_directory_alias_remains_read_only() {
    protected_alias_stays_usable(AliasKind::Directory, "link", false);
}

#[test]
fn a_protected_file_under_a_writable_alias_in_a_linked_read_tree_remains_read_only() {
    protected_alias_stays_usable(AliasKind::Directory, "link", true);
}

#[test]
fn a_protected_file_named_by_a_writable_file_alias_remains_read_only() {
    protected_alias_stays_usable(AliasKind::File, "alias", false);
}

#[test]
fn a_missing_protected_alias_target_refuses_without_creating_it() {
    let fixture = Fixture::new(AliasKind::Directory, "alias", false);
    let staged_child = fixture.staged(fixture.protected.parent().unwrap());
    std::fs::create_dir_all(&staged_child).unwrap();
    std::os::unix::fs::symlink("child", fixture.staged(&fixture.alias)).unwrap();
    let error = targets::MountTarget::prepare_bind(
        &fixture.view,
        fixture.alias_protection(),
        &fixture.root,
        false,
    )
    .err()
    .expect("an absent protection target must refuse");
    assert!(error.to_string().contains("child/policy"), "{error}");
    assert!(!staged_child.join("policy").exists());
    assert_eq!(std::fs::read_dir(&staged_child).unwrap().count(), 0);
    assert_eq!(
        std::fs::read(&fixture.protected).unwrap(),
        b"protected policy"
    );
}

#[test]
fn a_protected_alias_loop_refuses_without_creating_a_target() {
    let fixture = Fixture::new(AliasKind::Directory, "alias", false);
    let staged_original = fixture.staged(&fixture.original);
    std::fs::create_dir_all(&staged_original).unwrap();
    std::os::unix::fs::symlink("alias", staged_original.join("alias")).unwrap();
    let error = targets::MountTarget::prepare_bind(
        &fixture.view,
        fixture.alias_protection(),
        &fixture.root,
        false,
    )
    .err()
    .expect("a protection alias loop must refuse");
    assert!(
        error.to_string().contains("too many symbolic links"),
        "{error}"
    );
    assert_eq!(std::fs::read_dir(&staged_original).unwrap().count(), 1);
    assert_eq!(
        std::fs::read(&fixture.protected).unwrap(),
        b"protected policy"
    );
}

#[test]
fn a_replaced_protected_file_under_a_writable_alias_refuses_the_view() {
    if !super::super::super::failure_tests::namespace_test_is_permitted() {
        return;
    }
    let fixture = Fixture::new(AliasKind::Directory, "alias", false);
    let saved = fixture.protected.with_extension("saved");
    in_private_namespace(|| {
        for entry in fixture.view.entries().iter().filter(|entry| {
            entry.target != Path::new("/proc")
                && !matches!(entry.origin, MountOrigin::Protection { .. })
        }) {
            fixture.view.establish(entry, &fixture.root).unwrap();
        }
        std::fs::rename(&fixture.protected, &saved).unwrap();
        std::fs::write(&fixture.protected, b"replacement policy").unwrap();
        let result: Result<(), _> = fixture
            .view
            .entries()
            .iter()
            .filter(|entry| matches!(entry.origin, MountOrigin::Protection { .. }))
            .try_for_each(|entry| fixture.view.establish(entry, &fixture.root));
        let error = result.unwrap_err();
        assert!(error.to_string().contains("different identity"), "{error}");
    });
    assert_eq!(std::fs::read(&saved).unwrap(), b"protected policy");
    assert_eq!(
        std::fs::read(&fixture.protected).unwrap(),
        b"replacement policy"
    );
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum AliasDescendant {
    Unchanged,
    RelativeDecoy,
    AbsoluteDecoy,
}

fn independent_alias_protection(descendant: AliasDescendant) {
    if !super::super::super::failure_tests::namespace_test_is_permitted() {
        return;
    }
    let fixture = tempfile::tempdir().unwrap();
    let original = fixture.path().join("a-project");
    let middle = original.join("sub");
    let held = original.join("sub-real");
    let decoy = original.join("decoy");
    let protected = middle.join("policy");
    let ordinary = original.join("ordinary");
    let alias = fixture.path().join("z-project-link");
    let alias_protected = alias.join("sub/policy");
    let root = fixture.path().join("view");
    std::fs::create_dir_all(&middle).unwrap();
    std::fs::create_dir(&decoy).unwrap();
    std::fs::create_dir(&root).unwrap();
    std::fs::write(&protected, b"protected policy").unwrap();
    std::fs::write(&ordinary, b"ordinary bytes").unwrap();
    std::fs::write(decoy.join("policy"), b"decoy policy").unwrap();
    std::os::unix::fs::symlink("a-project", &alias).unwrap();
    let opened = std::fs::File::open(&protected).unwrap();
    let identity = opened.metadata().unwrap();
    let config = ContainmentConfig::new()
        .allow(&alias, Operation::Write, Scope::Root)
        .unwrap()
        .protect_write(&protected, &opened)
        .unwrap();
    crate::floors::require_all(&config).unwrap();
    config.require_live_path_identities().unwrap();
    let view = MountView::plan(&config).unwrap();
    let protections: Vec<_> = view
        .entries()
        .iter()
        .filter(|entry| matches!(entry.origin, MountOrigin::Protection { .. }))
        .map(|entry| entry.target.as_path())
        .collect();
    assert_eq!(
        protections,
        [protected.as_path(), alias_protected.as_path()]
    );
    let staged = |path: &Path| root.join(path.strip_prefix("/").unwrap());
    in_private_namespace(|| {
        let retained = Rc::new(RefCell::new(None::<std::fs::File>));
        let canonical_fired = Rc::new(Cell::new(false));
        let alias_bound = Rc::new(Cell::new(false));
        let mut alias_reached = false;
        for entry in view
            .entries()
            .iter()
            .filter(|entry| entry.target != Path::new("/proc"))
        {
            let protection = matches!(entry.origin, MountOrigin::Protection { .. });
            let canonical_protection = protection && entry.target == protected;
            let alias_protection = protection && entry.target == alias_protected;
            if canonical_protection {
                let retained = retained.clone();
                let fired = canonical_fired.clone();
                let target = staged(&protected);
                targets::AFTER_BIND_VERIFICATION.with(|hook| {
                    *hook.borrow_mut() = Some(Box::new(move || {
                        *retained.borrow_mut() = Some(
                            std::fs::OpenOptions::new()
                                .read(true)
                                .custom_flags(libc::O_PATH | libc::O_CLOEXEC)
                                .open(target)
                                .unwrap(),
                        );
                        fired.set(true);
                    }));
                });
            } else if entry.origin == MountOrigin::Grant && entry.target == alias {
                let fired = alias_bound.clone();
                targets::AFTER_BIND_VERIFICATION.with(|hook| {
                    *hook.borrow_mut() = Some(Box::new(move || fired.set(true)));
                });
            }
            if alias_protection {
                assert!(
                    canonical_fired.get(),
                    "canonical protection was not established"
                );
                alias_reached = true;
            }
            let outcome = view.establish(entry, &root);
            if canonical_protection {
                outcome.unwrap();
                assert!(
                    canonical_fired.get(),
                    "the canonical verification hook did not run"
                );
                if descendant != AliasDescendant::Unchanged {
                    std::fs::rename(&middle, &held).unwrap();
                    let destination = if descendant == AliasDescendant::RelativeDecoy {
                        Path::new("decoy")
                    } else {
                        decoy.as_path()
                    };
                    std::os::unix::fs::symlink(destination, &middle).unwrap();
                }
            } else if alias_protection && descendant != AliasDescendant::Unchanged {
                let error = outcome.expect_err("a redirected protection must refuse the view");
                assert!(error.to_string().contains("unexpected location"), "{error}");
                break;
            } else {
                outcome.unwrap();
            }
        }
        assert!(
            alias_bound.get(),
            "the alias did not establish a separate bind"
        );
        assert!(alias_reached, "the alias protection was not attempted");
        let borrowed = retained.borrow();
        let canonical = targets::descriptor_path(borrowed.as_ref().unwrap());
        let metadata = std::fs::metadata(&canonical).unwrap();
        assert_eq!(
            (metadata.dev(), metadata.ino()),
            (identity.dev(), identity.ino())
        );
        assert_eq!(std::fs::read(&canonical).unwrap(), b"protected policy");
        assert_eq!(
            std::fs::OpenOptions::new()
                .write(true)
                .open(&canonical)
                .unwrap_err()
                .raw_os_error(),
            Some(libc::EROFS)
        );
        if descendant == AliasDescendant::Unchanged {
            view.protect_parents(&root).unwrap();
            for target in [&protected, &alias_protected] {
                let target = staged(target);
                assert_eq!(std::fs::read(&target).unwrap(), b"protected policy");
                assert_eq!(
                    std::fs::OpenOptions::new()
                        .write(true)
                        .open(target)
                        .unwrap_err()
                        .raw_os_error(),
                    Some(libc::EROFS)
                );
            }
        }
        for target in [staged(&ordinary), staged(&alias.join("ordinary"))] {
            std::fs::write(&target, b"permitted sibling write").unwrap();
            assert_eq!(std::fs::read(&target).unwrap(), b"permitted sibling write");
        }
        for target in [
            staged(&decoy.join("policy")),
            staged(&alias.join("decoy/policy")),
        ] {
            assert_eq!(std::fs::read(target).unwrap(), b"decoy policy");
        }
    });
    let retained_original = if descendant == AliasDescendant::Unchanged {
        protected
    } else {
        held.join("policy")
    };
    assert_eq!(
        std::fs::read(retained_original).unwrap(),
        b"protected policy"
    );
    assert_eq!(
        std::fs::read(decoy.join("policy")).unwrap(),
        b"decoy policy"
    );
    assert_eq!(std::fs::read(ordinary).unwrap(), b"permitted sibling write");
    assert_eq!(std::fs::read_link(alias).unwrap(), Path::new("a-project"));
}

#[test]
fn an_independent_writable_directory_alias_keeps_its_protection_and_sibling_write() {
    independent_alias_protection(AliasDescendant::Unchanged);
}

#[test]
fn an_independent_protection_alias_refuses_a_relative_descendant_redirect() {
    independent_alias_protection(AliasDescendant::RelativeDecoy);
}

#[test]
fn an_independent_protection_alias_refuses_an_absolute_descendant_redirect() {
    independent_alias_protection(AliasDescendant::AbsoluteDecoy);
}

use super::*;
use std::cell::Cell;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;

type Contents = Vec<(PathBuf, u32, Vec<u8>)>;

fn contents(root: &Path) -> Contents {
    fn visit(root: &Path, path: &Path, out: &mut Contents) {
        let metadata = std::fs::symlink_metadata(path).unwrap();
        let value = if metadata.is_file() {
            std::fs::read(path).unwrap()
        } else if metadata.is_symlink() {
            std::fs::read_link(path)
                .unwrap()
                .as_os_str()
                .as_bytes()
                .to_vec()
        } else {
            Vec::new()
        };
        out.push((
            path.strip_prefix(root).unwrap().to_path_buf(),
            metadata.mode(),
            value,
        ));
        if metadata.is_dir() {
            for entry in std::fs::read_dir(path).unwrap() {
                visit(root, &entry.unwrap().path(), out);
            }
        }
    }
    let mut out = Vec::new();
    visit(root, root, &mut out);
    out.sort();
    out
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Object {
    Directory,
    File,
}

impl Object {
    fn create(self, path: &Path, value: &[u8]) {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        match self {
            Self::Directory => {
                std::fs::create_dir(path).unwrap();
                std::fs::write(path.join("value"), value).unwrap();
            }
            Self::File => std::fs::write(path, value).unwrap(),
        }
    }

    fn scope(self) -> Scope {
        match self {
            Self::Directory => Scope::Root,
            Self::File => Scope::File,
        }
    }

    fn value(self, path: &Path) -> PathBuf {
        match self {
            Self::Directory => path.join("value"),
            Self::File => path.to_path_buf(),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Stage {
    BeforeSourcePin,
    SourcePinned,
    TargetOpened,
    Mounted,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Replacement {
    None,
    LinkToMissingTarget,
    LinkToExistingTarget,
    LeafLinkToOutside,
    EmptyDirectory,
    PopulatedDirectory,
    MissingLeaf,
    DifferentSource,
}

pub(super) fn with_private_namespace(action: impl FnOnce()) {
    // SAFETY: the child uses private mounts and never returns to the test harness.
    let pid = unsafe { libc::fork() };
    assert!(pid >= 0);
    if pid == 0 {
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            assert!(enter_private_namespace());
            action();
        }));
        // SAFETY: terminate the child without running the parent test harness.
        unsafe { libc::_exit(i32::from(result.is_err())) };
    }
    let mut status = 0;
    // SAFETY: reap only this test's child.
    assert_eq!(unsafe { libc::waitpid(pid, &raw mut status, 0) }, pid);
    assert!(
        libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0,
        "child failed: {status}"
    );
}

fn mounted_path(root: &Path, source: &Path) -> PathBuf {
    root.join(source.strip_prefix("/").unwrap())
}

fn descriptor_count() -> usize {
    std::fs::read_dir("/proc/self/fd").unwrap().count()
}

fn nested_case(object: Object, stage: Stage, replacement: Replacement) {
    if !super::super::super::failure_tests::namespace_test_is_permitted() {
        return;
    }
    let fixture = tempfile::tempdir().unwrap();
    let tree = fixture.path().join("tree");
    let middle = tree.join("middle");
    let source = middle.join("inner/leaf");
    let held = tree.join("held");
    let outside = fixture.path().join("outside");
    let replacement_tree = fixture.path().join("replacement");
    let root = fixture.path().join("view");
    let report = fixture.path().join("report");
    object.create(&source, b"validated");
    let identity = std::fs::metadata(&source).unwrap();
    std::fs::write(tree.join("sibling"), b"sibling").unwrap();
    std::fs::create_dir(&outside).unwrap();
    std::fs::write(outside.join("sentinel"), b"unchanged").unwrap();
    if matches!(
        replacement,
        Replacement::LinkToExistingTarget | Replacement::LeafLinkToOutside
    ) {
        object.create(&outside.join("inner/leaf"), b"outside");
    }
    std::fs::create_dir(&replacement_tree).unwrap();
    if replacement == Replacement::PopulatedDirectory {
        object.create(&replacement_tree.join("inner/leaf"), b"replacement");
    }
    let replacement_before = contents(&replacement_tree);
    std::fs::create_dir(&root).unwrap();
    let outside_before = contents(&outside);
    let config = ContainmentConfig::new()
        .allow(&tree, Operation::Read, Scope::Root)
        .unwrap()
        .allow(&source, Operation::Write, object.scope())
        .unwrap();
    crate::floors::require_all(&config).unwrap();
    config.require_live_path_identities().unwrap();
    let view = MountView::plan(&config).unwrap();
    let success_expected = replacement == Replacement::None
        || (replacement == Replacement::PopulatedDirectory && stage == Stage::SourcePinned);

    with_private_namespace(|| {
        let fired = Rc::new(Cell::new(false));
        let mut outcome = Ok(());
        for entry in view
            .entries()
            .iter()
            .filter(|entry| entry.target != Path::new("/proc"))
        {
            if entry.target == source && replacement != Replacement::None {
                let middle = middle.clone();
                let source = source.clone();
                let held = held.clone();
                let outside = outside.clone();
                let replacement_tree = replacement_tree.clone();
                let fired = fired.clone();
                let replace: Box<dyn FnOnce()> = Box::new(move || {
                    match replacement {
                        Replacement::MissingLeaf
                        | Replacement::DifferentSource
                        | Replacement::LeafLinkToOutside => {
                            std::fs::rename(&source, &held).unwrap();
                            if replacement == Replacement::DifferentSource {
                                object.create(&source, b"replacement");
                            } else if replacement == Replacement::LeafLinkToOutside {
                                std::os::unix::fs::symlink(outside.join("inner/leaf"), &source)
                                    .unwrap();
                            }
                        }
                        Replacement::None => unreachable!(),
                        _ => {
                            std::fs::rename(&middle, &held).unwrap();
                            match replacement {
                                Replacement::LinkToMissingTarget
                                | Replacement::LinkToExistingTarget => {
                                    std::os::unix::fs::symlink(&outside, &middle).unwrap();
                                }
                                Replacement::EmptyDirectory | Replacement::PopulatedDirectory => {
                                    std::fs::rename(&replacement_tree, &middle).unwrap();
                                }
                                _ => unreachable!(),
                            }
                        }
                    }
                    fired.set(true);
                });
                match stage {
                    Stage::BeforeSourcePin => replace(),
                    Stage::SourcePinned => targets::AFTER_BIND_SOURCE_PIN
                        .with(|hook| *hook.borrow_mut() = Some(replace)),
                    Stage::TargetOpened => targets::AFTER_BIND_TARGET_OPEN
                        .with(|hook| *hook.borrow_mut() = Some(replace)),
                    Stage::Mounted => {
                        targets::AFTER_BIND_MOUNT.with(|hook| *hook.borrow_mut() = Some(replace))
                    }
                }
            }
            let before = descriptor_count();
            outcome = view.establish(entry, &root);
            assert_eq!(
                descriptor_count(),
                before,
                "mount preparation leaked a descriptor: {entry:?}"
            );
            if outcome.is_err() {
                break;
            }
        }
        if replacement != Replacement::None {
            assert!(
                fired.get(),
                "the requested replacement interval was not reached"
            );
        }
        let table = std::fs::read_to_string("/proc/self/mountinfo").unwrap();
        let outside_mounts = table
            .lines()
            .filter(|line| {
                line.split_whitespace().nth(4).is_some_and(|point| {
                    Path::new(&unescape_mount_field(point)).starts_with(&outside)
                })
            })
            .count();
        std::fs::write(
            &report,
            format!("result={outcome:?}\noutside_mounts={outside_mounts}\n"),
        )
        .unwrap();
        assert_eq!(
            outside_mounts, 0,
            "a mount escaped into the outside fixture"
        );
        assert_eq!(
            outcome.is_ok(),
            success_expected,
            "{object:?} {stage:?} {replacement:?}: {outcome:?}"
        );
        assert_eq!(
            std::fs::read(mounted_path(&root, &tree).join("sibling")).unwrap(),
            b"sibling"
        );
        if success_expected {
            let mounted = mounted_path(&root, &source);
            let actual = std::fs::metadata(&mounted).unwrap();
            assert_eq!(
                (actual.dev(), actual.ino()),
                (identity.dev(), identity.ino())
            );
            let value = object.value(&mounted);
            assert_eq!(std::fs::read(&value).unwrap(), b"validated");
            std::fs::write(&value, b"permitted").unwrap();
            if object == Object::Directory {
                std::fs::write(mounted.join("created"), b"new file").unwrap();
            }
        }
    });
    let report = std::fs::read_to_string(report).unwrap();
    println!("{object:?} {stage:?} {replacement:?}: {report}");
    assert_eq!(
        contents(&outside),
        outside_before,
        "outside contents changed: {report}"
    );
    if matches!(
        replacement,
        Replacement::EmptyDirectory | Replacement::PopulatedDirectory
    ) {
        assert_eq!(
            contents(&middle),
            replacement_before,
            "mount preparation modified the replacement directory"
        );
    }
    if replacement == Replacement::MissingLeaf {
        assert!(
            !source.exists(),
            "mount preparation recreated a missing nested target"
        );
    }
    if success_expected {
        let original = if replacement == Replacement::PopulatedDirectory {
            held.join("inner/leaf")
        } else {
            source
        };
        assert_eq!(
            std::fs::read(object.value(&original)).unwrap(),
            b"permitted"
        );
    }
}

#[test]
fn nested_directory_targets_do_not_create_outside_after_source_pinning() {
    nested_case(
        Object::Directory,
        Stage::SourcePinned,
        Replacement::LinkToMissingTarget,
    );
}

#[test]
fn nested_file_targets_do_not_mount_outside_after_source_pinning() {
    nested_case(
        Object::File,
        Stage::SourcePinned,
        Replacement::LinkToExistingTarget,
    );
}

#[test]
fn missing_nested_file_parents_do_not_create_outside_after_source_pinning() {
    nested_case(
        Object::File,
        Stage::SourcePinned,
        Replacement::LinkToMissingTarget,
    );
}

#[test]
fn legitimate_nested_directory_and_file_grants_remain_usable() {
    for object in [Object::Directory, Object::File] {
        nested_case(object, Stage::SourcePinned, Replacement::None);
    }
}

#[test]
fn missing_nested_targets_are_not_recreated() {
    for object in [Object::Directory, Object::File] {
        nested_case(object, Stage::SourcePinned, Replacement::MissingLeaf);
    }
}

#[test]
fn empty_replacement_directories_do_not_gain_mountpoint_descendants() {
    for object in [Object::Directory, Object::File] {
        nested_case(object, Stage::SourcePinned, Replacement::EmptyDirectory);
    }
}

#[test]
fn replacement_directories_with_targets_expose_the_validated_source() {
    for object in [Object::Directory, Object::File] {
        nested_case(object, Stage::SourcePinned, Replacement::PopulatedDirectory);
    }
}

#[test]
fn symlink_replacement_after_target_open_refuses_without_outside_changes() {
    for object in [Object::Directory, Object::File] {
        nested_case(
            object,
            Stage::TargetOpened,
            Replacement::LinkToExistingTarget,
        );
    }
}

#[test]
fn directory_replacement_after_target_open_refuses_without_creation() {
    for object in [Object::Directory, Object::File] {
        nested_case(object, Stage::TargetOpened, Replacement::PopulatedDirectory);
    }
}

#[test]
fn symlink_replacement_after_mount_refuses_without_outside_changes() {
    for object in [Object::Directory, Object::File] {
        nested_case(object, Stage::Mounted, Replacement::LinkToExistingTarget);
    }
}

#[test]
fn directory_replacement_after_mount_refuses_without_creation() {
    for object in [Object::Directory, Object::File] {
        nested_case(object, Stage::Mounted, Replacement::PopulatedDirectory);
    }
}

#[test]
fn source_replacement_before_pinning_preserves_identity_refusal() {
    for object in [Object::Directory, Object::File] {
        nested_case(object, Stage::BeforeSourcePin, Replacement::DifferentSource);
    }
}

fn permitted_alias(object: Object) {
    if !super::super::super::failure_tests::namespace_test_is_permitted() {
        return;
    }
    let fixture = tempfile::tempdir().unwrap();
    let tree = fixture.path().join("tree");
    let source = tree.join("real");
    let alias = tree.join("alias");
    let root = fixture.path().join("view");
    object.create(&source, b"validated");
    std::fs::write(tree.join("sibling"), b"sibling").unwrap();
    std::os::unix::fs::symlink("real", &alias).unwrap();
    std::fs::create_dir(&root).unwrap();
    let config = ContainmentConfig::new()
        .allow(&tree, Operation::Read, Scope::Root)
        .unwrap()
        .allow(&alias, Operation::Write, object.scope())
        .unwrap();
    crate::floors::require_all(&config).unwrap();
    config.require_live_path_identities().unwrap();
    let view = MountView::plan(&config).unwrap();
    with_private_namespace(|| {
        for entry in view
            .entries()
            .iter()
            .filter(|entry| entry.target != Path::new("/proc"))
        {
            view.establish(entry, &root).unwrap();
        }
        let alias_value = object.value(&mounted_path(&root, &alias));
        let real_value = object.value(&mounted_path(&root, &source));
        assert_eq!(std::fs::read(&alias_value).unwrap(), b"validated");
        std::fs::write(&alias_value, b"permitted").unwrap();
        assert_eq!(std::fs::read(real_value).unwrap(), b"permitted");
        assert_eq!(
            std::fs::read(mounted_path(&root, &tree).join("sibling")).unwrap(),
            b"sibling"
        );
    });
    assert_eq!(std::fs::read(object.value(&source)).unwrap(), b"permitted");
    assert_eq!(std::fs::read_link(&alias).unwrap(), Path::new("real"));
}

#[test]
fn nested_directory_alias_remains_usable() {
    permitted_alias(Object::Directory);
}

#[test]
fn nested_file_alias_remains_usable() {
    permitted_alias(Object::File);
}

#[test]
fn exact_file_grants_create_only_staging_parents_and_preserve_siblings() {
    if !super::super::super::failure_tests::namespace_test_is_permitted() {
        return;
    }
    let fixture = tempfile::tempdir().unwrap();
    let source = fixture.path().join("tree/inner/file");
    Object::File.create(&source, b"validated");
    let sibling = source.with_file_name("sibling");
    std::fs::write(&sibling, b"outside the exact grant").unwrap();
    let root = fixture.path().join("view");
    std::fs::create_dir(&root).unwrap();
    let config = ContainmentConfig::new()
        .allow(&source, Operation::Read, Scope::File)
        .unwrap()
        .allow(&source, Operation::Write, Scope::File)
        .unwrap();
    crate::floors::require_all(&config).unwrap();
    let view = MountView::plan(&config).unwrap();
    with_private_namespace(|| {
        for entry in view
            .entries()
            .iter()
            .filter(|entry| entry.target != Path::new("/proc"))
        {
            view.establish(entry, &root).unwrap();
        }
        let mounted = mounted_path(&root, &source);
        assert_eq!(std::fs::read(&mounted).unwrap(), b"validated");
        std::fs::write(&mounted, b"permitted").unwrap();
        assert!(!mounted_path(&root, &sibling).exists());
    });
    assert_eq!(std::fs::read(&source).unwrap(), b"permitted");
    assert_eq!(std::fs::read(&sibling).unwrap(), b"outside the exact grant");
}

#[derive(Clone, Copy)]
enum TreeSpelling {
    Canonical,
    Alias,
}

fn permitted_intermediate_alias(object: Object, spelling: TreeSpelling) {
    if !super::super::super::failure_tests::namespace_test_is_permitted() {
        return;
    }
    let fixture = tempfile::tempdir().unwrap();
    let original = fixture.path().join("original");
    let outer_alias = fixture.path().join("outer-alias");
    let child = original.join("child");
    let source = match object {
        Object::Directory => child.clone(),
        Object::File => child.join("file"),
    };
    object.create(&source, b"validated");
    std::fs::write(original.join("sibling"), b"sibling").unwrap();
    std::os::unix::fs::symlink("child", original.join("link")).unwrap();
    std::os::unix::fs::symlink("original", &outer_alias).unwrap();
    let tree = match spelling {
        TreeSpelling::Canonical => &original,
        TreeSpelling::Alias => &outer_alias,
    };
    let grant = match object {
        Object::Directory => tree.join("link"),
        Object::File => tree.join("link/file"),
    };
    let root = fixture.path().join("view");
    std::fs::create_dir(&root).unwrap();
    let config = ContainmentConfig::new()
        .allow(tree, Operation::Read, Scope::Root)
        .unwrap()
        .allow(&grant, Operation::Write, object.scope())
        .unwrap();
    crate::floors::require_all(&config).unwrap();
    config.require_live_path_identities().unwrap();
    let view = MountView::plan(&config).unwrap();
    with_private_namespace(|| {
        for entry in view
            .entries()
            .iter()
            .filter(|entry| entry.target != Path::new("/proc"))
        {
            view.establish(entry, &root).unwrap();
        }
        let requested = object.value(&mounted_path(&root, &grant));
        assert_eq!(std::fs::read(&requested).unwrap(), b"validated");
        std::fs::write(&requested, b"permitted").unwrap();
        let canonical = object.value(&mounted_path(&root, &source));
        assert_eq!(std::fs::read(canonical).unwrap(), b"permitted");
        let sibling = mounted_path(&root, tree).join("sibling");
        assert_eq!(std::fs::read(&sibling).unwrap(), b"sibling");
        assert!(std::fs::write(&sibling, b"not granted").is_err());
    });
    assert_eq!(std::fs::read(object.value(&source)).unwrap(), b"permitted");
    assert_eq!(std::fs::read(original.join("sibling")).unwrap(), b"sibling");
    assert_eq!(
        std::fs::read_link(original.join("link")).unwrap(),
        Path::new("child")
    );
    assert_eq!(
        std::fs::read_link(&outer_alias).unwrap(),
        Path::new("original")
    );
}

#[test]
fn nested_directory_alias_in_a_linked_read_tree_remains_writable() {
    permitted_intermediate_alias(Object::Directory, TreeSpelling::Alias);
}

#[test]
fn nested_file_under_a_directory_alias_remains_writable() {
    permitted_intermediate_alias(Object::File, TreeSpelling::Canonical);
}

#[test]
fn nested_file_under_a_directory_alias_in_a_linked_read_tree_remains_writable() {
    permitted_intermediate_alias(Object::File, TreeSpelling::Alias);
}

#[test]
fn canonical_file_leaf_replacement_with_a_link_refuses_startup() {
    nested_case(
        Object::File,
        Stage::SourcePinned,
        Replacement::LeafLinkToOutside,
    );
}

fn enter_staged_root(root: &Path) {
    let root = path_to_c(root).unwrap();
    // SAFETY: this child owns the private view, and root is a live C string.
    assert_eq!(unsafe { libc::chroot(root.as_ptr()) }, 0);
    std::env::set_current_dir("/").unwrap();
}

#[derive(Clone, Copy)]
enum AliasRoute {
    Absolute,
    LinkBeforeParent,
}

fn permitted_rebased_alias(object: Object, route: AliasRoute) {
    if !super::super::super::failure_tests::namespace_test_is_permitted() {
        return;
    }
    let fixture = tempfile::tempdir().unwrap();
    let tree = fixture.path().join("tree");
    let source = tree.join("deep/target");
    let decoy = tree.join("target");
    let alias = tree.join("alias");
    let root = fixture.path().join("view");
    object.create(&source, b"validated");
    object.create(&decoy, b"decoy");
    std::fs::create_dir(tree.join("deep/directory")).unwrap();
    std::os::unix::fs::symlink("deep/directory", tree.join("hop")).unwrap();
    match route {
        AliasRoute::Absolute => std::os::unix::fs::symlink(&source, &alias).unwrap(),
        AliasRoute::LinkBeforeParent => {
            std::os::unix::fs::symlink("hop/../target", &alias).unwrap()
        }
    }
    std::fs::write(tree.join("sibling"), b"sibling").unwrap();
    std::fs::create_dir(&root).unwrap();
    let config = ContainmentConfig::new()
        .allow(&tree, Operation::Read, Scope::Root)
        .unwrap()
        .allow(&alias, Operation::Write, object.scope())
        .unwrap();
    crate::floors::require_all(&config).unwrap();
    config.require_live_path_identities().unwrap();
    let view = MountView::plan(&config).unwrap();
    with_private_namespace(|| {
        for entry in view
            .entries()
            .iter()
            .filter(|entry| entry.target != Path::new("/proc"))
        {
            view.establish(entry, &root).unwrap();
        }
        enter_staged_root(&root);
        let requested = object.value(&alias);
        assert_eq!(std::fs::read(&requested).unwrap(), b"validated");
        std::fs::write(&requested, b"permitted").unwrap();
        assert_eq!(std::fs::read(object.value(&source)).unwrap(), b"permitted");
        let decoy_value = object.value(&decoy);
        assert_eq!(std::fs::read(&decoy_value).unwrap(), b"decoy");
        assert!(std::fs::write(&decoy_value, b"not granted").is_err());
        let sibling = tree.join("sibling");
        assert_eq!(std::fs::read(&sibling).unwrap(), b"sibling");
        assert!(std::fs::write(&sibling, b"not granted").is_err());
    });
    assert_eq!(std::fs::read(object.value(&source)).unwrap(), b"permitted");
    assert_eq!(std::fs::read(object.value(&decoy)).unwrap(), b"decoy");
    assert_eq!(std::fs::read(tree.join("sibling")).unwrap(), b"sibling");
}

#[test]
fn absolute_directory_alias_remains_writable_inside_the_view() {
    permitted_rebased_alias(Object::Directory, AliasRoute::Absolute);
}

#[test]
fn absolute_file_alias_remains_writable_inside_the_view() {
    permitted_rebased_alias(Object::File, AliasRoute::Absolute);
}

#[test]
fn directory_alias_resolves_a_link_before_its_parent_component() {
    permitted_rebased_alias(Object::Directory, AliasRoute::LinkBeforeParent);
}

#[test]
fn file_alias_resolves_a_link_before_its_parent_component() {
    permitted_rebased_alias(Object::File, AliasRoute::LinkBeforeParent);
}

#[test]
fn an_authored_alias_replaced_with_a_loop_refuses_startup() {
    if !super::super::super::failure_tests::namespace_test_is_permitted() {
        return;
    }
    let fixture = tempfile::tempdir().unwrap();
    let tree = fixture.path().join("tree");
    let source = tree.join("real");
    let alias = tree.join("alias");
    let root = fixture.path().join("view");
    let outside = fixture.path().join("outside");
    Object::Directory.create(&source, b"validated");
    std::os::unix::fs::symlink("real", &alias).unwrap();
    std::fs::create_dir(&root).unwrap();
    std::fs::create_dir(&outside).unwrap();
    std::fs::write(outside.join("sentinel"), b"unchanged").unwrap();
    let outside_before = contents(&outside);
    let config = ContainmentConfig::new()
        .allow(&tree, Operation::Read, Scope::Root)
        .unwrap()
        .allow(&alias, Operation::Write, Scope::Root)
        .unwrap();
    crate::floors::require_all(&config).unwrap();
    config.require_live_path_identities().unwrap();
    let view = MountView::plan(&config).unwrap();
    with_private_namespace(|| {
        let fired = Rc::new(Cell::new(false));
        let mut outcome = Ok(());
        // SAFETY: the alarm bounds only this disposable child.
        unsafe { libc::alarm(5) };
        for entry in view
            .entries()
            .iter()
            .filter(|entry| entry.target != Path::new("/proc"))
        {
            if entry.target == alias {
                let alias = alias.clone();
                let fired = fired.clone();
                targets::AFTER_BIND_SOURCE_PIN.with(|hook| {
                    *hook.borrow_mut() = Some(Box::new(move || {
                        std::fs::rename(&alias, alias.with_file_name("original-alias")).unwrap();
                        std::os::unix::fs::symlink("alias", &alias).unwrap();
                        fired.set(true);
                    }));
                });
            }
            outcome = view.establish(entry, &root);
            if outcome.is_err() {
                break;
            }
        }
        // SAFETY: cancel this child's alarm after mount preparation returns.
        unsafe { libc::alarm(0) };
        assert!(fired.get(), "the alias source-pin interval was not reached");
        assert!(
            outcome.is_err(),
            "a replacement symlink loop must refuse startup"
        );
        assert_eq!(std::fs::read(source.join("value")).unwrap(), b"validated");
    });
    assert_eq!(contents(&outside), outside_before);
}

fn permitted_shallow_absolute_alias(object: Object) {
    if !super::super::super::failure_tests::namespace_test_is_permitted() {
        return;
    }
    let fixture = tempfile::tempdir().unwrap();
    let tree = fixture.path().join("allowed");
    let source = fixture
        .path()
        .join("external-source/canonical/deeper/object");
    let alias = tree.join("alias");
    let root = fixture.path().join("view");
    object.create(&source, b"validated");
    std::fs::create_dir(&tree).unwrap();
    std::fs::write(tree.join("sibling"), b"sibling").unwrap();
    let external_sibling = fixture.path().join("external-source/sibling");
    std::fs::write(&external_sibling, b"outside the grant").unwrap();
    std::os::unix::fs::symlink(&source, &alias).unwrap();
    std::fs::create_dir(&root).unwrap();
    assert!(alias.components().count() < source.components().count());
    let identity = std::fs::metadata(&source).unwrap();
    let config = ContainmentConfig::new()
        .allow(&tree, Operation::Read, Scope::Root)
        .unwrap()
        .allow(&alias, Operation::Read, object.scope())
        .unwrap()
        .allow(&alias, Operation::Write, object.scope())
        .unwrap();
    crate::floors::require_all(&config).unwrap();
    config.require_live_path_identities().unwrap();
    let view = MountView::plan(&config).unwrap();
    with_private_namespace(|| {
        for entry in view
            .entries()
            .iter()
            .filter(|entry| entry.target != Path::new("/proc"))
        {
            view.establish(entry, &root).unwrap();
        }
        enter_staged_root(&root);
        let actual = std::fs::metadata(&alias).unwrap();
        assert_eq!(
            (actual.dev(), actual.ino()),
            (identity.dev(), identity.ino())
        );
        let requested = object.value(&alias);
        assert_eq!(std::fs::read(&requested).unwrap(), b"validated");
        std::fs::write(&requested, b"permitted").unwrap();
        assert_eq!(std::fs::read(object.value(&source)).unwrap(), b"permitted");
        let sibling = tree.join("sibling");
        assert_eq!(std::fs::read(&sibling).unwrap(), b"sibling");
        assert!(std::fs::write(&sibling, b"not granted").is_err());
        assert!(!external_sibling.exists());
    });
    assert_eq!(std::fs::read(object.value(&source)).unwrap(), b"permitted");
    assert_eq!(
        std::fs::read(&external_sibling).unwrap(),
        b"outside the grant"
    );
}

#[test]
fn a_shallow_absolute_directory_alias_reaches_its_deeper_source() {
    permitted_shallow_absolute_alias(Object::Directory);
}

#[test]
fn a_shallow_absolute_file_alias_reaches_its_deeper_source() {
    permitted_shallow_absolute_alias(Object::File);
}

#[test]
fn a_read_granted_file_alias_to_dev_null_preserves_the_device() {
    if !super::super::super::failure_tests::namespace_test_is_permitted() {
        return;
    }
    let fixture = tempfile::tempdir().unwrap();
    let tree = fixture.path().join("tree");
    let alias = tree.join("null");
    let root = fixture.path().join("view");
    std::fs::create_dir(&tree).unwrap();
    std::fs::write(tree.join("sibling"), b"sibling").unwrap();
    std::os::unix::fs::symlink("/dev/null", &alias).unwrap();
    std::fs::create_dir(&root).unwrap();
    let config = ContainmentConfig::new()
        .allow(&tree, Operation::Read, Scope::Root)
        .unwrap()
        .allow(&alias, Operation::Read, Scope::File)
        .unwrap();
    crate::floors::require_all(&config).unwrap();
    config.require_live_path_identities().unwrap();
    let view = MountView::plan(&config).unwrap();
    with_private_namespace(|| {
        for entry in view
            .entries()
            .iter()
            .filter(|entry| entry.target != Path::new("/proc"))
        {
            view.establish(entry, &root).unwrap();
        }
        enter_staged_root(&root);
        let kind = std::fs::metadata(&alias).unwrap().file_type();
        assert!(std::os::unix::fs::FileTypeExt::is_char_device(&kind));
        assert!(std::fs::read(&alias).unwrap().is_empty());
        std::fs::write("/dev/null", b"discarded").unwrap();
        std::fs::write(&alias, b"discarded").unwrap();
        assert_eq!(std::fs::read(tree.join("sibling")).unwrap(), b"sibling");
    });
    assert_eq!(std::fs::read_link(&alias).unwrap(), Path::new("/dev/null"));
}

fn read_alias_preserves_canonical_write(object: Object) {
    if !super::super::super::failure_tests::namespace_test_is_permitted() {
        return;
    }
    let fixture = tempfile::tempdir().unwrap();
    let tree = fixture.path().join("tree");
    let source = tree.join("real");
    let alias = tree.join("alias");
    let root = fixture.path().join("view");
    object.create(&source, b"validated");
    std::fs::write(tree.join("sibling"), b"sibling").unwrap();
    std::os::unix::fs::symlink("real", &alias).unwrap();
    std::fs::create_dir(&root).unwrap();
    let config = ContainmentConfig::new()
        .allow(&tree, Operation::Read, Scope::Root)
        .unwrap()
        .allow(&source, Operation::Read, object.scope())
        .unwrap()
        .allow(&source, Operation::Write, object.scope())
        .unwrap()
        .allow(&alias, Operation::Read, object.scope())
        .unwrap();
    crate::floors::require_all(&config).unwrap();
    config.require_live_path_identities().unwrap();
    let view = MountView::plan(&config).unwrap();
    with_private_namespace(|| {
        for entry in view
            .entries()
            .iter()
            .filter(|entry| entry.target != Path::new("/proc"))
        {
            view.establish(entry, &root).unwrap();
        }
        enter_staged_root(&root);
        assert_eq!(std::fs::read(object.value(&alias)).unwrap(), b"validated");
        std::fs::write(object.value(&source), b"permitted").unwrap();
        assert_eq!(std::fs::read(object.value(&alias)).unwrap(), b"permitted");
        let sibling = tree.join("sibling");
        assert_eq!(std::fs::read(&sibling).unwrap(), b"sibling");
        assert!(std::fs::write(&sibling, b"not granted").is_err());
    });
    assert_eq!(std::fs::read(object.value(&source)).unwrap(), b"permitted");
    assert_eq!(std::fs::read(tree.join("sibling")).unwrap(), b"sibling");
}

#[test]
fn a_read_only_directory_alias_preserves_the_canonical_write_grant() {
    read_alias_preserves_canonical_write(Object::Directory);
}

#[test]
fn a_read_only_file_alias_preserves_the_canonical_write_grant() {
    read_alias_preserves_canonical_write(Object::File);
}

#[test]
fn an_alias_bind_does_not_replace_nested_metadata_mounts() {
    if !super::super::super::failure_tests::namespace_test_is_permitted() {
        return;
    }
    let fixture = tempfile::tempdir().unwrap();
    let original = fixture.path().join("original");
    let outer_alias = fixture.path().join("outer-alias");
    let child = original.join("child");
    let alias_child = outer_alias.join("child");
    let root = fixture.path().join("view");
    std::fs::create_dir_all(&child).unwrap();
    std::fs::write(child.join("value"), b"hidden contents").unwrap();
    std::fs::write(original.join("sibling"), b"permitted sibling").unwrap();
    std::os::unix::fs::symlink("original", &outer_alias).unwrap();
    std::fs::create_dir(&root).unwrap();
    let config = ContainmentConfig::new()
        .allow(&outer_alias, Operation::Read, Scope::Root)
        .unwrap()
        .allow(&alias_child, Operation::Metadata, Scope::Dir)
        .unwrap();
    crate::floors::require_all(&config).unwrap();
    config.require_live_path_identities().unwrap();
    let view = MountView::plan(&config).unwrap();
    for target in [&child, &alias_child] {
        assert!(
            view.entries().iter().any(|entry| {
                entry.target == *target
                    && entry.kind == MountKind::Fresh { fstype: "tmpfs" }
                    && !entry.writable
            }),
            "metadata grant must plan an empty directory at {target:?}"
        );
    }
    with_private_namespace(|| {
        for entry in view
            .entries()
            .iter()
            .filter(|entry| entry.target != Path::new("/proc"))
        {
            view.establish(entry, &root).unwrap();
        }
        enter_staged_root(&root);
        for target in [&child, &alias_child] {
            assert!(std::fs::metadata(target).unwrap().is_dir());
            assert_eq!(
                std::fs::read_dir(target).unwrap().count(),
                0,
                "metadata directory exposes host contents at {target:?}"
            );
            assert!(std::fs::write(target.join("created"), b"not granted").is_err());
        }
        for tree in [&original, &outer_alias] {
            let sibling = tree.join("sibling");
            assert_eq!(std::fs::read(&sibling).unwrap(), b"permitted sibling");
            assert!(std::fs::write(&sibling, b"not granted").is_err());
        }
    });
    assert_eq!(
        std::fs::read(child.join("value")).unwrap(),
        b"hidden contents"
    );
    assert_eq!(
        std::fs::read(original.join("sibling")).unwrap(),
        b"permitted sibling"
    );
}

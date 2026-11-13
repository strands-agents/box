//! `strands_box::check_read_grant` judges a read grant as a box judges a `read` entry.

use std::path::Path;

use strands_box::{ForbiddenClass, GrantRefusal};

fn kind(path: &Path) -> Option<GrantRefusal> {
    strands_box::check_read_grant(path)
        .err()
        .map(|refused| refused.kind())
}

fn ordinary_directory() -> (tempfile::TempDir, std::path::PathBuf) {
    let directory = tempfile::tempdir().expect("a directory");
    let canonical = directory.path().canonicalize().expect("a canonical path");
    (directory, canonical)
}

#[test]
fn a_read_grant_on_a_system_tree_or_the_whole_filesystem_is_refused() {
    for path in ["/", "/usr"] {
        assert!(
            strands_box::check_read_grant(Path::new(path)).is_err(),
            "{path}"
        );
    }
}

#[test]
fn a_system_tree_is_refused_as_a_floor_row_of_that_class() {
    for path in ["/usr", "/usr/bin"] {
        assert_eq!(
            kind(Path::new(path)),
            Some(GrantRefusal::Forbidden(ForbiddenClass::SystemTree)),
            "{path}"
        );
    }
}

#[cfg(target_os = "macos")]
#[test]
fn a_machine_store_is_refused_as_a_floor_row_of_its_own_class() {
    for (path, class) in [
        (
            "/private/etc/sudoers",
            ForbiddenClass::PrivilegeConfiguration,
        ),
        ("/private/var/db/dslocal", ForbiddenClass::PasswordDatabase),
        ("/Library/Keychains", ForbiddenClass::MachineCredential),
    ] {
        assert_eq!(
            kind(Path::new(path)),
            Some(GrantRefusal::Forbidden(class)),
            "{path}"
        );
    }
}

#[cfg(target_os = "linux")]
#[test]
fn the_password_database_is_refused_as_a_floor_row_of_its_own_class() {
    let shadow = Path::new("/etc/shadow");
    if shadow.exists() {
        assert_eq!(
            kind(shadow),
            Some(GrantRefusal::Forbidden(ForbiddenClass::PasswordDatabase))
        );
    }
}

#[test]
fn the_whole_filesystem_encloses_a_credential_store_and_is_refused_as_other() {
    assert_eq!(kind(Path::new("/")), Some(GrantRefusal::Other));
}

#[test]
fn a_relative_path_is_refused_as_not_absolute() {
    assert_eq!(kind(Path::new("relative")), Some(GrantRefusal::NotAbsolute));
}

#[test]
fn a_read_grant_on_an_ordinary_directory_passes_and_names_no_credential_store() {
    let (_directory, path) = ordinary_directory();
    assert_eq!(strands_box::check_read_grant(&path).ok(), Some(false));
}

#[test]
fn a_read_grant_on_a_path_that_is_not_there_is_refused() {
    let (_directory, path) = ordinary_directory();
    let refused = strands_box::check_read_grant(&path.join("absent")).expect_err("absent");
    assert!(refused.to_string().contains("is not there"), "{refused}");
    assert_eq!(refused.kind(), GrantRefusal::Absent);
}

#[test]
fn a_read_grant_through_a_file_is_refused_as_absent() {
    let (_directory, path) = ordinary_directory();
    std::fs::write(path.join("file"), "").expect("a file");
    let refused =
        strands_box::check_read_grant(&path.join("file/child")).expect_err("through a file");
    assert_eq!(refused.kind(), GrantRefusal::Absent);
}

#[cfg(unix)]
#[test]
fn a_read_grant_under_an_unreadable_directory_is_not_refused_as_absent() {
    use std::os::unix::fs::PermissionsExt;
    if unsafe { libc::geteuid() } == 0 {
        eprintln!("skipping: root reads a directory with no permissions");
        return;
    }
    let (_directory, path) = ordinary_directory();
    let locked = path.join("locked");
    std::fs::create_dir(&locked).expect("a directory");
    std::fs::write(locked.join("file"), "").expect("a file");
    std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o000)).expect("lock");
    let refused = strands_box::check_read_grant(&locked.join("file"));
    std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o755)).expect("unlock");
    let refused = refused.expect_err("unreadable");
    assert_eq!(refused.kind(), GrantRefusal::Other, "{refused}");
    assert!(!refused.to_string().contains("is not there"), "{refused}");
}

#[test]
fn a_read_grant_through_a_link_or_a_spelling_that_is_not_canonical_is_refused() {
    let (_directory, path) = ordinary_directory();
    let target = path.join("target");
    std::fs::create_dir(&target).expect("a target");
    let link = path.join("link");
    std::os::unix::fs::symlink(&target, &link).expect("a link");
    let refused = strands_box::check_read_grant(&link).expect_err("a link");
    assert!(refused.to_string().contains("symbolic link"), "{refused}");
    assert_eq!(refused.kind(), GrantRefusal::Link);
    let dotted = path.join("target/../target");
    let refused = strands_box::check_read_grant(&dotted).expect_err("a dotted spelling");
    assert!(
        refused
            .to_string()
            .contains("not the path the kernel checks"),
        "{refused}"
    );
    assert_eq!(refused.kind(), GrantRefusal::NotCanonical);
}

#[test]
fn a_read_grant_naming_a_link_to_a_file_is_accepted() {
    let (_directory, path) = ordinary_directory();
    let file = path.join("file");
    std::fs::write(&file, "").expect("a file");
    let link = path.join("link");
    std::os::unix::fs::symlink(&file, &link).expect("a link");
    assert!(strands_box::check_read_grant(&link).is_ok());
}

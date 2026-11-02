//! `strands_box::check_read_grant` judges a read grant as a box judges a `read` entry.

use std::path::Path;

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
fn a_read_grant_on_an_ordinary_directory_passes_and_names_no_credential_store() {
    let (_directory, path) = ordinary_directory();
    assert_eq!(strands_box::check_read_grant(&path).ok(), Some(false));
}

#[test]
fn a_read_grant_on_a_path_that_is_not_there_is_refused() {
    let (_directory, path) = ordinary_directory();
    let refused = strands_box::check_read_grant(&path.join("absent")).expect_err("absent");
    assert!(refused.to_string().contains("is not there"), "{refused}");
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
    let dotted = path.join("target/../target");
    let refused = strands_box::check_read_grant(&dotted).expect_err("a dotted spelling");
    assert!(
        refused
            .to_string()
            .contains("not the path the kernel checks"),
        "{refused}"
    );
}

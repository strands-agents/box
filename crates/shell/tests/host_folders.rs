//! A host folder is served as the host holds it: a link is a link, a link out of the folder is
//! refused, and an effect through a link is judged on what it names.

mod support;

use support::host_case;

fn line(ran: &support::Ran) -> &str {
    ran.out.stdout.trim()
}

// A metadata read that does not follow answers for the link.

host_case!(
    test_minus_l_sees_a_host_symlink,
    "if test -L flink; then echo LINK; fi; readlink flink",
    |folder, ran| {
        let target = folder.ws.join("secret.txt");
        assert_eq!(
            line(&ran),
            format!("LINK\n{}", target.display()),
            "{}",
            ran.out.stderr
        );
    }
);

host_case!(
    test_minus_l_sees_a_dangling_host_symlink,
    "if test -L gone; then echo LINK; fi",
    |_folder, ran| {
        assert_eq!(line(&ran), "LINK", "{}", ran.out.stderr);
    }
);

host_case!(
    find_type_l_lists_a_host_symlink,
    "find /workspace -maxdepth 1 -type l -name flink",
    |_folder, ran| {
        assert_eq!(line(&ran), "/workspace/flink", "{}", ran.out.stderr);
    }
);

host_case!(
    ls_l_shows_a_host_symlink_as_a_link,
    "ls -l flink",
    |_folder, ran| {
        assert!(ran.out.stdout.starts_with('l'), "{:?}", ran.out.stdout);
    }
);

host_case!(
    stat_still_follows_a_host_symlink,
    "if test -d dlink; then echo DIR; fi",
    |_folder, ran| {
        assert_eq!(line(&ran), "DIR", "{}", ran.out.stderr);
    }
);

host_case!(
    rm_on_a_host_symlink_to_a_directory_removes_the_link,
    "rm dlink",
    |folder, ran| {
        assert_eq!(ran.out.status, 0, "{}", ran.out.stderr);
        assert!(!folder.exists("dlink"));
        assert!(folder.exists("dir/inner.txt"), "the target is kept");
    }
);

host_case!(
    rm_r_on_a_host_symlink_to_a_directory_removes_only_the_link,
    "rm -r dlink",
    |folder, ran| {
        assert_eq!(ran.out.status, 0, "{}", ran.out.stderr);
        assert!(!folder.exists("dlink"));
        assert!(folder.exists("dir/inner.txt"), "the target is kept");
    }
);

host_case!(
    rm_r_on_a_host_symlink_out_of_the_mount_removes_only_the_link,
    "if test -L escape; then echo LINK; fi; rm -r escape",
    |folder, ran| {
        assert_eq!(line(&ran), "LINK");
        assert_eq!(ran.out.status, 0, "{}", ran.out.stderr);
        assert!(!folder.exists("escape"));
        assert!(
            folder.outside.join("host.txt").exists(),
            "nothing outside is reached"
        );
    }
);

#[test]
fn a_file_bind_whose_source_is_a_symlink_is_not_a_link() {
    let folder = support::Folder::standard();
    let source = folder.ws.join("flink").display().to_string();
    let out = support::run(async {
        let mut shell = support::builder()
            .bind_direct(source, "/home/lash/cfg.txt")
            .build()
            .expect("shell builds");
        shell
            .run("if test -L /home/lash/cfg.txt; then echo LINK; else echo NOTLINK; fi")
            .await
    });
    assert_eq!(out.stdout.trim(), "NOTLINK", "{}", out.stderr);
}

// Links the Shell makes, and the target floor.

host_case!(
    ln_s_creates_a_real_symlink_on_the_host,
    "ln -s real.txt link && cat link && readlink link",
    |folder, ran| {
        assert_eq!(line(&ran), "REAL_BYTESreal.txt", "{}", ran.out.stderr);
        assert!(folder.is_link("link"));
    }
);

host_case!(
    ln_s_to_an_in_bind_target_with_missing_dirs_is_allowed,
    "ln -s newsub/file link",
    |folder, ran| {
        assert_eq!(ran.out.status, 0, "{}", ran.out.stderr);
        assert_eq!(
            std::fs::read_link(folder.ws.join("link")).expect("a link"),
            std::path::Path::new("newsub/file")
        );
    }
);

/// Each target the floor refuses, by the case that pins it.
const REFUSED_TARGETS: &[(&str, &str)] = &[
    ("ln_s_to_an_absolute_target_is_refused", "/etc/passwd"),
    (
        "ln_s_to_a_target_that_climbs_out_of_the_bind_is_refused",
        "../../../../etc/passwd",
    ),
    (
        "ln_s_through_a_non_directory_component_is_refused",
        "real.txt/sub",
    ),
    (
        "ln_s_through_a_dangling_symlink_prefix_is_refused",
        "gone/file",
    ),
];

#[test]
fn ln_s_to_a_target_out_of_the_folder_is_refused() {
    for (case, target) in REFUSED_TARGETS {
        let folder = support::Folder::standard();
        let ran = folder.run(&format!("ln -s {target} link"));
        assert_ne!(ran.out.status, 0, "{case}: {}", ran.out.stderr);
        assert!(!folder.exists("link"), "{case}: no link is planted");
    }
}

// `chmod` on a host file, and the setuid, setgid, and sticky refusal.

host_case!(
    chmod_changes_the_host_file_mode,
    "chmod 700 mode.txt",
    |folder, ran| {
        assert_eq!(ran.out.status, 0, "{}", ran.out.stderr);
        assert_eq!(folder.mode("mode.txt"), 0o700);
    }
);

host_case!(
    chmod_restores_a_host_file_with_no_permissions,
    |folder| { folder.set_mode("mode.txt", 0) },
    "chmod 644 mode.txt",
    |folder, ran| {
        assert_eq!(ran.out.status, 0, "{}", ran.out.stderr);
        assert_eq!(folder.mode("mode.txt"), 0o644);
    }
);

#[test]
fn chmod_refuses_setuid_and_leaves_the_host_mode_unchanged() {
    let folder = support::Folder::standard();
    let before = folder.mode("mode.txt");
    let ran = folder.run("chmod 4755 mode.txt");
    assert_ne!(ran.out.status, 0, "{}", ran.out.stderr);
    assert_eq!(
        folder.mode("mode.txt"),
        before,
        "the host mode is unchanged"
    );
}

host_case!(
    symbolic_chmod_on_a_setgid_host_file_succeeds,
    |folder| { folder.set_mode("mode.txt", 0o2644) },
    "chmod +x mode.txt",
    |folder, ran| {
        assert_eq!(ran.out.status, 0, "{}", ran.out.stderr);
        assert_eq!(folder.mode("mode.txt"), 0o755, "the special bit is dropped");
    }
);

// An effect through a link inside the folder is judged on its target.

host_case!(
    an_in_mount_symlink_read_is_judged_on_the_target,
    "cat sub/flink",
    |_folder, ran| {
        assert_eq!(line(&ran), "IN_MOUNT", "{}", ran.out.stderr);
        assert!(
            ran.paths.iter().any(|path| path == "/workspace/secret.txt"),
            "{:?}",
            ran.paths
        );
        assert!(
            !ran.paths.iter().any(|path| path == "/workspace/sub/flink"),
            "{:?}",
            ran.paths
        );
    }
);

host_case!(
    an_in_mount_symlink_write_is_judged_on_the_target,
    "printf PWNED > sub/flink",
    |folder, ran| {
        assert_eq!(ran.out.status, 0, "{}", ran.out.stderr);
        assert_eq!(
            std::fs::read_to_string(folder.ws.join("secret.txt")).expect("read"),
            "PWNED"
        );
        assert!(
            ran.paths.iter().any(|path| path == "/workspace/secret.txt"),
            "{:?}",
            ran.paths
        );
        assert!(
            !ran.paths.iter().any(|path| path == "/workspace/sub/flink"),
            "{:?}",
            ran.paths
        );
    }
);

host_case!(
    a_symlink_escaping_the_mount_is_refused,
    "cat escape/host.txt",
    |_folder, ran| {
        assert_ne!(ran.out.status, 0);
        assert!(!ran.out.stdout.contains("OUTSIDE"), "{}", ran.out.stdout);
    }
);

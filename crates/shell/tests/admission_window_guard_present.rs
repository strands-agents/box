//! Every mutating filesystem effect must keep its admission-window guards.

const SRC: &str = include_str!("../src/vfs_kernel.rs");

const MUTATING_METHODS: &[&str] = &[
    "open",
    "create_dir",
    "remove_file",
    "remove_dir",
    "rename",
    "symlink",
    "set_permissions",
];

const GENERATION_CHANGES: &[&str] = &[
    "open",
    "create_dir",
    "remove_file",
    "remove_dir",
    "rename",
    "symlink",
];

const HOST_DELEGATIONS: &[(&str, &str)] = &[
    ("open_effect", "open_host"),
    ("create_dir_effect", "create_host_directory"),
    ("remove_file_effect", "unlink_host"),
    ("remove_dir_effect", "unlink_host"),
    ("rename_effect", "rename_host"),
    ("symlink_effect", "create_host_symlink"),
    ("set_permissions_effect", "set_host_permissions"),
];

fn method_body<'a>(src: &'a str, section: &str, name: &str) -> &'a str {
    let section = src
        .find(section)
        .map(|start| &src[start..])
        .unwrap_or_else(|| panic!("section `{section}` is absent"));
    let marker = format!("\n    async fn {name}(");
    let start = section
        .find(&marker)
        .unwrap_or_else(|| panic!("method `{name}` is absent"));
    let rest = &section[start + marker.len()..];
    let end = rest.find("\n    async fn ").unwrap_or(rest.len());
    &rest[..end]
}

#[test]
fn every_mutating_effect_keeps_its_admission_window_guards() {
    for name in MUTATING_METHODS {
        let body = method_body(SRC, "impl Kernel for VfsKernel", name);
        assert!(
            body.contains("guard_resolution") || body.contains("resolution_is_current"),
            "{name} no longer validates the admitted generation and host identity"
        );
        assert!(
            body.contains("host_identity()"),
            "{name} no longer passes the admitted host identity to its effect"
        );
    }

    for name in GENERATION_CHANGES {
        let body = method_body(SRC, "impl Kernel for VfsKernel", name);
        assert!(
            body.contains("changed_resolution"),
            "{name} no longer invalidates older resolved tokens after a namespace change"
        );
    }

    for (effect, helper) in HOST_DELEGATIONS {
        let body = method_body(SRC, "impl VfsKernel {", effect);
        assert!(
            body.contains(helper) && body.contains("expected"),
            "{effect} no longer delegates its admitted identity to `{helper}`"
        );
    }
}

#[test]
fn host_chmod_is_defined_for_supported_and_other_unix_targets() {
    assert!(SRC.contains(
        "#[cfg(any(target_os = \"linux\", target_os = \"macos\"))]\n    fn set_host_permissions("
    ));
    assert!(SRC.contains(
        "#[cfg(all(unix, not(any(target_os = \"linux\", target_os = \"macos\"))))]\n    fn \
         set_host_permissions("
    ));
}

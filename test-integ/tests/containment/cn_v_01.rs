use strands_det_harness::{NOT_IDENTITY_REFUSAL, det_case, user_home};

// Containment CN-V (a symlink cannot lend its grant to its target)
//
// What this case proves, from the mediated path-admission contract in the box source
// (`run/broker/reach.rs`, pinned there by
// `a_symlink_whose_spelling_is_not_its_identity_is_refused`): the resolver beneath policy admits a
// path only as its own canonical identity. A spelling that resolves elsewhere — every symlink,
// "however reachable both ends are" — is refused with "resolves to a different path, so it is not
// the identity policy judged", before any bytes are read and after policy permitted the spelling.
// So a link the agent can place inside its writable workspace cannot lend the workspace's grant
// to the file it points at: the escape is refused at the resolver, and the journal records that
// refusal as the reach floor on the link's own path.
//
// Evidence, all test-owned and portable (no /etc/hostname):
//   - a canonical direct read of the workspace's `readable.txt` — the positive control that the
//     mediated reader works on this route (it says nothing about symlink support);
//   - a secret file under the operator home, outside every grant, with unique bytes, and a
//     host-prepared link to it inside the workspace, proven on the host to be a symlink that
//     resolves and reads those bytes — so the refusal that follows is of a real, readable escape;
//   - the refusal's own words at the resolver, the journaled `fs:read` deny on the link spelling
//     from the reach floor, and the secret bytes absent from everything the workload printed.
// An in-workspace link to `readable.txt` is probed too and is expected to be refused with the
// same words: that is the resolver as written, not a claim about symlink support, and a change there
// would be a contract change worth seeing. The second native run showed both links
// refused exactly so; the earlier form wrongly required the in-workspace link to read.
det_case! {
    name: cn_v_01,
    id:   "CN-V-01",
    desc: "Symlink escape: a workspace symlink to a secret outside every grant is refused by the resolver as not its own identity; the secret never leaks; a canonical direct read works",
    run: |b| {
        b.reset_policy();
        let home = user_home().canonicalize().expect("DET_ERROR: resolve operator home");
        let pid = std::process::id();
        let secret_path = home.join(format!(".det-cnv01-secret-{pid}"));
        let secret = format!("DET_SECRET_CNV01_{pid}_{:x}", std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH).map(|d| d.as_nanos()).unwrap_or(0));
        std::fs::write(&secret_path, format!("{secret}\n")).expect("DET_ERROR: plant the secret under the operator home");
        let escape = b.workspace().join("escape-link");
        let inside = b.workspace().join("inlink");
        let direct = b.workspace().join("readable.txt");
        #[cfg(unix)]
        {
            std::os::unix::fs::symlink(&secret_path, &escape).expect("DET_ERROR: host-prepare the escape link");
            std::os::unix::fs::symlink("readable.txt", &inside).expect("DET_ERROR: host-prepare the in-workspace link");
        }
        // The escape is real: on the host it is a symlink that resolves to the secret and reads it.
        let is_link = std::fs::symlink_metadata(&escape).map(|m| m.file_type().is_symlink()).unwrap_or(false);
        let through_link = std::fs::read_to_string(&escape).unwrap_or_default();
        let resolved = std::fs::canonicalize(&escape).unwrap_or_default();

        let r = b.run_mediated(&format!(
            "cat {d} && echo DIRECT_OK; cat {i} && echo INSIDE_OK; cat {e} && echo ESCAPE_OK; echo done",
            d = direct.display(),
            i = inside.display(),
            e = escape.display()
        ));
        let _ = std::fs::remove_file(&secret_path);

        assert!(is_link, "DET_ERROR: the host-prepared escape link is not a symlink");
        assert_eq!(resolved, secret_path, "DET_ERROR: the escape link does not resolve to the secret on the host");
        assert!(through_link.contains(&secret), "DET_ERROR: the host cannot read the secret through the escape link; the probe would prove nothing");

        // Positive control: the mediated reader reads a canonical workspace path.
        r.assert_contains("LISTED_CONTENT");
        r.assert_contains("DIRECT_OK");
        // The boundary: the escape spelling is refused as not its identity, journaled as the reach
        // floor on the link's own path, and the secret bytes never appear.
        r.assert_contains(&format!("{}: {NOT_IDENTITY_REFUSAL}", escape.display()));
        let rule = r.assert_mediated_denied("fs:read", "escape-link");
        assert!(rule.contains("reach-floor"), "the escape must be refused beneath policy, at the reach floor: {rule}");
        r.assert_absent("ESCAPE_OK");
        r.assert_absent_secret(&secret, "CN-V-01 home secret marker");
        // The resolver as written: a link inside the workspace is not its identity either.
        r.assert_contains(&format!("{}: {NOT_IDENTITY_REFUSAL}", inside.display()));
        r.assert_absent("INSIDE_OK");
        r.assert_contains("done");
        if strands_det_harness::Platform::current() == strands_det_harness::Platform::Macos {
            // Preserve the mainline native macOS alternate-view cells as a separate route.
            // HOME is this probe's granted workspace, not the operator home.
            assert!(std::path::Path::new("/etc/hosts").is_file(), "DET_ERROR: /etc/hosts fixture absent");
            let denied = std::path::Path::new("/etc/hosts").canonicalize()
                .expect("DET_ERROR: resolve the existing denied file");
            let relative = relative_via_root(b.workspace(), &denied);
            assert_eq!(
                b.workspace().join(&relative).canonicalize()
                    .expect("DET_ERROR: the relative escape does not resolve on the host"),
                denied,
                "DET_ERROR: the relative probe names a different host object"
            );
            let operator = home.to_string_lossy().into_owned();
            let native = b.probe_py(&format!(r#"
BH = os.environ["HOME"]
L = BH + "/cn-v-01-native-link"
L2 = BH + "/cn-v-01-native-home"
os.symlink("/etc", L)
print("link_created", os.path.islink(L))
t("read_through_link", lambda: len(open(L + "/hosts").read()))
t("read_direct", lambda: len(open("/etc/hosts").read()))
t("read_private_spelling", lambda: len(open("/private/etc/hosts").read()))
os.symlink({operator:?}, L2)
t("read_home_through_link", lambda: os.listdir(L2))
print("relative_target_control", os.path.abspath({relative:?}) == {denied_path:?})
t("openat_escape", lambda: os.open({relative:?}, os.O_RDONLY))
os.unlink(L); os.unlink(L2)
"#, denied_path = denied.to_string_lossy().into_owned()));
            native.assert_contains("link_created True");
            native.assert_contains("relative_target_control True");
            for label in ["read_through_link", "read_direct", "read_private_spelling", "read_home_through_link", "openat_escape"] {
                native.assert_errno(label, 1);
            }
            native.assert_absent("broadcasthost");
        }
    }
}

/// Reach the actual absolute target from this fixture's canonical cwd, regardless of its depth.
fn relative_via_root(workspace: &std::path::Path, target: &std::path::Path) -> String {
    let parents = workspace.ancestors().skip(1).count();
    format!("{}{}", "../".repeat(parents), target.strip_prefix("/").unwrap().display())
}

#[test]
fn the_relative_escape_names_the_existing_target_at_different_fixture_depths() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().canonicalize().unwrap();
    let target = root.join("denied.txt");
    std::fs::write(&target, "DENIED_TARGET").unwrap();
    for suffix in ["workspace", "a/b/c/d/e/f/workspace"] {
        let workspace = root.join(suffix);
        std::fs::create_dir_all(&workspace).unwrap();
        let relative = relative_via_root(&workspace, &target);
        assert_eq!(workspace.join(&relative).canonicalize().unwrap(), target);
        assert_eq!(std::fs::read_to_string(workspace.join(relative)).unwrap(), "DENIED_TARGET");
    }
}

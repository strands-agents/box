use strands_det_harness::{PROTECTED_CONFIG_MARKER, Platform, det_case};

// The box's own loaded authority — `<workspace>/.strands-box/box.toml` and `policy.dw` — is
// defended two ways at once: its directory is subtracted from the project grant as a refusal
// (docs/design/decisions.md#direct-filesystem-reach-is-declared-and-disclosed,
// `record/config/filesystem.rs::direct_grants`), and each loaded source is a write protection
// (docs/design/decisions.md#an-opened-file-can-require-identity-or-write-protection,
// `run/contain/boundary.rs::protect_authorities`). This case moves the directory ABOVE
// the two sources with the agent's own `rename(2)`, which the write grant on the project would
// otherwise permit, and asks that the sources stay where the box loaded them.
//
// What the source says each platform answers: on Linux the `.strands-box` directory is a refusal
// mountpoint (a fresh read-only tmpfs, `view.rs`), and `rename(2)` of a mount point answers EBUSY —
// the errno `box_shell.rs::a_contained_host_binary_cannot_move_an_authority_sources_parent` asserts
// for a rename that reaches a protected mountpoint. On macOS the refusal renders
// `deny file-write-unlink` and `deny file-write-create` over the `.strands-box` subpath
// (`seatbelt.rs`), which covers the directory itself, and a Seatbelt refusal surfaces as EPERM. The
// mediated half of this property is `a_host_binary_cannot_use_the_broker_to_move_an_authority_sources_parent`;
// this is the native half at the agent's own boundary, which no det case exercised.
//
// Two more moves are attempted and each refused inside its own errno family: the policy file out
// of its directory, and a permitted file over it. On Linux both are cross-mount renames — the
// tmpfs on one side, the workspace bind on the other — and `rename(2)` compares the two parents'
// mounts before it looks up either final component, so both answer EXDEV, the empty tmpfs
// notwithstanding. The first native Linux run measured exactly that; an earlier expectation of
// ENOENT for the move-out had the syscall's checks in the wrong order, and
// `the_native_linux_run_answers_its_own_families` below pins the measured lines. The control is an
// ordinary directory rename inside the same write grant.
//
// If the directory move is NOT refused, the script moves it straight back before anything else, so
// a box that let it through is recorded as a FAIL on the `RENAME_OK` line rather than as an ERROR
// when the fixture cannot restore the configuration it keeps in that directory (measured under
// the fault-injection tool's permissive fake box). A real box refuses the move and the branch is
// never taken.
const PROBE: &str = include_str!("../probes/fs_probe.rs");
include!("../probes/probe_lines.rs");

/// The refusal families this case admits, per operation and platform, each from the mechanism's
/// source. Nothing else a syscall can fail with is a denial here.
///
/// | operation | Linux (`view.rs`: `.strands-box` is a fresh read-only tmpfs mountpoint) | macOS (`seatbelt.rs`: denies over the `.strands-box` subpath) |
/// |---|---|---|
/// | `rename(2)` of the directory | EBUSY: a mount point (rename(2); `a_contained_host_binary_cannot_move_an_authority_sources_parent`) | EPERM |
/// | `rename(2)` of `policy.dw` out of it | EXDEV: the source parent is the tmpfs and the destination parent the workspace bind; `do_renameat2` compares the two parents' mounts before it looks up either final component, so the absent source is never reached (rename(2); measured on a native Linux run) | EPERM |
/// | `rename(2)` of a permitted file over `policy.dw` | EXDEV: the destination parent is on another mount (rename(2); measured, same run) | EPERM |
/// | `read(2)` of `policy.dw` | ENOENT: not in the view (measured, same run) | EPERM |
fn directory_move_denials() -> &'static [i32] {
    match Platform::current() {
        Platform::Linux => &[EBUSY],
        Platform::Macos => &[EPERM],
    }
}
fn masked_denials() -> &'static [i32] {
    match Platform::current() {
        Platform::Linux => &[ENOENT],
        Platform::Macos => &[EPERM],
    }
}
fn cross_mount_denials() -> &'static [i32] {
    match Platform::current() {
        Platform::Linux => &[EXDEV],
        Platform::Macos => &[EPERM],
    }
}

/// The refusal lines the first native Linux run answered, verbatim: every operation passes inside the
/// family this case names for Linux, the move-out is EXDEV and not ENOENT, and none of the lines
/// passes inside another operation's family.
#[test]
fn the_native_linux_run_answers_its_own_families() {
    let ws = std::path::Path::new("/root/.det-harness-boxes/det-box-zO3OVK/workspace");
    let own = ws.join(".strands-box");
    let policy = own.join("policy.dw");
    let out = "DET_ENTERED\n\
               RENAME_OK \"/root/.det-harness-boxes/det-box-zO3OVK/workspace/plain\" -> \"/root/.det-harness-boxes/det-box-zO3OVK/workspace/plain2\"\n\
               RENAME_REFUSED \"/root/.det-harness-boxes/det-box-zO3OVK/workspace/.strands-box\" -> \"/root/.det-harness-boxes/det-box-zO3OVK/workspace/.strands-box-moved\" errno=16 (Device or resource busy (os error 16))\n\
               RENAME_REFUSED \"/root/.det-harness-boxes/det-box-zO3OVK/workspace/.strands-box/policy.dw\" -> \"/root/.det-harness-boxes/det-box-zO3OVK/workspace/stolen.dw\" errno=18 (Invalid cross-device link (os error 18))\n\
               RENAME_REFUSED \"/root/.det-harness-boxes/det-box-zO3OVK/workspace/readable.txt\" -> \"/root/.det-harness-boxes/det-box-zO3OVK/workspace/.strands-box/policy.dw\" errno=18 (Invalid cross-device link (os error 18))\n\
               READ_REFUSED \"/root/.det-harness-boxes/det-box-zO3OVK/workspace/.strands-box/policy.dw\" errno=2 (No such file or directory (os error 2))\n\
               READ_REFUSED \"/root/.det-harness-boxes/det-box-zO3OVK/workspace/.strands-box/box.toml\" errno=2 (No such file or directory (os error 2))\n\
               done";
    // The Linux families, spelled out rather than read from the platform, so this holds on any host.
    let directory_move: &[i32] = &[EBUSY];
    let cross_mount: &[i32] = &[EXDEV];
    let masked: &[i32] = &[ENOENT];
    assert!(
        probe_line(
            out,
            "RENAME_OK",
            &pair(&ws.join("plain"), &ws.join("plain2"))
        )
        .is_some()
    );
    assert!(
        refused_as(
            out,
            "RENAME",
            &pair(&own, &ws.join(".strands-box-moved")),
            directory_move
        )
        .is_ok()
    );
    // The move-out: EXDEV, as measured, and the earlier ENOENT expectation is what the oracle rejects.
    let stolen = pair(&policy, &ws.join("stolen.dw"));
    assert!(refused_as(out, "RENAME", &stolen, cross_mount).is_ok());
    let why = refused_as(out, "RENAME", &stolen, masked)
        .expect_err("ENOENT is not what the kernel answers here");
    assert!(
        why.contains("errno 18") && why.contains("accepted [2]"),
        "{why}"
    );
    assert!(
        refused_as(
            out,
            "RENAME",
            &pair(&ws.join("readable.txt"), &policy),
            cross_mount
        )
        .is_ok()
    );
    assert!(refused_as(out, "READ", &subject(&policy), masked).is_ok());
    assert!(refused_as(out, "READ", &subject(&own.join("box.toml")), masked).is_ok());
    // No line passes in a family that is not its operation's.
    assert!(
        refused_as(
            out,
            "RENAME",
            &pair(&own, &ws.join(".strands-box-moved")),
            cross_mount
        )
        .is_err()
    );
    assert!(refused_as(out, "READ", &subject(&policy), cross_mount).is_err());
    assert!(refused_as(out, "RENAME", &stolen, directory_move).is_err());
}

det_case! {
    name: cn_fs_01,
    id:   "CN-FS-01",
    desc: "Own authority: the agent's own rename(2) cannot move the workspace's .strands-box (Linux EBUSY, macOS EPERM), move its policy.dw out, or move a permitted file over it; an ordinary directory rename works; the loaded sources are unchanged on the host",
    run: |b| {
        b.reset_policy();
        let probe = b.compile_probe("fsprobe", PROBE);
        let own = b.workspace().join(".strands-box");
        let moved = b.workspace().join(".strands-box-moved");
        let config = own.join("box.toml");
        let policy = own.join("policy.dw");
        let stolen = b.workspace().join("stolen.dw");
        let readable = b.workspace().join("readable.txt");
        let plain = b.workspace().join("plain");
        let plain2 = b.workspace().join("plain2");
        std::fs::create_dir(&plain).expect("DET_ERROR: plant the control directory");
        std::fs::write(plain.join("p.txt"), "PLAIN\n").expect("DET_ERROR: plant the control file");
        let policy_before = std::fs::read_to_string(&policy).expect("DET_ERROR: read the box's own policy on the host");

        let r = b.run_sh_with_config(
            b.with_exec_tree(),
            &format!(
                "P='{p}'; \
                 \"$P\" rename '{plain}' '{plain2}'; \
                 out=$(\"$P\" rename '{own}' '{moved}'); printf '%s\\n' \"$out\"; \
                 case \"$out\" in RENAME_OK*) \"$P\" rename '{moved}' '{own}'; printf 'RESTORED_AFTER_UNREFUSED_MOVE\\n';; esac; \
                 \"$P\" rename '{policy}' '{stolen}'; \
                 \"$P\" rename '{readable}' '{policy}'; \
                 \"$P\" read '{policy}'; \
                 \"$P\" read '{config}'; \
                 printf done",
                p = probe.display(),
                plain = plain.display(),
                plain2 = plain2.display(),
                own = own.display(),
                moved = moved.display(),
                policy = policy.display(),
                stolen = stolen.display(),
                readable = readable.display(),
                config = config.display(),
            ),
        );
        // Host observations first. The config the box loaded is the edited copy, so its bytes are
        // compared through the marker only this file carries; the policy is compared whole.
        let moved_exists = moved.exists();
        let stolen_exists = stolen.exists();
        let config_after = std::fs::read_to_string(&config).unwrap_or_default();
        let policy_after = std::fs::read_to_string(&policy).unwrap_or_default();
        let readable_after = std::fs::read_to_string(&readable).unwrap_or_default();
        let plain2_text = std::fs::read_to_string(plain2.join("p.txt")).unwrap_or_default();

        // The probe ran, and the control rename inside the write grant landed on the host.
        r.assert_contains(&format!("RENAME_OK {}", pair(&plain, &plain2)));
        r.assert_contains("done");
        assert_eq!(plain2_text, "PLAIN\n", "the control rename did not land on the host");

        // The boundary: the directory above the loaded sources cannot be moved, with the errno its
        // mechanism answers.
        let parent_move = pair(&own, &moved);
        r.assert_absent(&format!("RENAME_OK {parent_move}"));
        r.assert_absent("RESTORED_AFTER_UNREFUSED_MOVE");
        refused_as(&r.out, "RENAME", &parent_move, directory_move_denials())
            .unwrap_or_else(|why| panic!("the box's own .strands-box was not refused a rename: {why}; out=[{}]", r.snippet()));
        // The two file moves are refused with the errno each mechanism answers.
        let stolen_move = pair(&policy, &stolen);
        refused_as(&r.out, "RENAME", &stolen_move, cross_mount_denials())
            .unwrap_or_else(|why| panic!("the box's own policy.dw was not refused a move out of its directory: {why}; out=[{}]", r.snippet()));
        let replace_move = pair(&readable, &policy);
        refused_as(&r.out, "RENAME", &replace_move, cross_mount_denials())
            .unwrap_or_else(|why| panic!("a permitted file was not refused a move over the box's own policy.dw: {why}; out=[{}]", r.snippet()));
        r.assert_absent(&format!("RENAME_OK {stolen_move}"));
        r.assert_absent(&format!("RENAME_OK {replace_move}"));
        // Neither loaded source reads through the agent's own syscall (CN-W-07 pins the builtin form).
        r.assert_absent(PROTECTED_CONFIG_MARKER);
        r.assert_absent("permit (principal, action == Box::Action::\"shell:exec\"");
        refused_as(&r.out, "READ", &subject(&policy), masked_denials())
            .unwrap_or_else(|why| panic!("the box's own policy.dw was not refused a read: {why}; out=[{}]", r.snippet()));

        // The host: both sources where the box loaded them, unchanged; no moved copy anywhere.
        assert!(!moved_exists, "the box's own .strands-box was moved on the host");
        assert!(!stolen_exists, "the box's own policy.dw was moved on the host");
        assert!(config_after.contains(PROTECTED_CONFIG_MARKER), "the box's own box.toml changed or vanished on the host");
        assert_eq!(policy_after, policy_before, "the box's own policy.dw changed on the host");
        assert_eq!(readable_after, "LISTED_CONTENT\n", "the permitted file was moved or changed on the host");
    }
}

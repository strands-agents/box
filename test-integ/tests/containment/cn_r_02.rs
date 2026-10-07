use std::os::unix::fs::MetadataExt as _;

use strands_det_harness::{Platform, det_case};

// The guarantee under test is docs/design/decisions.md#a-denial-is-an-operation-not-a-second-list
// as the box lowers an EXISTING file `deny` inside a write grant
// (`record/config/filesystem.rs::denial` gives an existing file `Scope::File`): the refused object
// cannot be moved to a permitted name, and no permitted file can be moved over it. On Linux the
// namespace view binds an empty read-only file over the leaf
// (`view.rs::MountKind::EmptyFile`, pinned by `mod.rs::a_refused_file_reads_empty_and_refuses_a_write`),
// so the leaf is a mountpoint and `rename(2)` of it, or onto it, answers EBUSY — the errno
// `box_shell.rs::a_contained_host_binary_cannot_move_an_authority_sources_parent` asserts for a
// rename that reaches a protected mountpoint, and the one rename(2) documents for a mount point.
// On macOS `seatbelt.rs` renders the refusal as `deny file-write*` plus one deny per write leaf
// (`file-write-unlink`, `file-write-create`, …) on the literal, and a Seatbelt refusal surfaces as
// EPERM. Upstream, SRT's `macos-seatbelt` suite pins the same two moves against a `denyOnly` file
// (`read-mv-denied-file`) and a `denyWithinAllow` directory (`write-mv-denied-dir`).
//
// The probe is native: a binary the case compiles into the exec tree and runs from the contained
// bash under the agent's own `exec` entry, so each `rename(2)` is the agent's own syscall. A
// mediated `mv` would measure the Shell's resolver instead. The controls: an ordinary rename inside
// the same write grant succeeds and the host sees it, and the probe's own lines prove each syscall
// was attempted. The host proves the outcome: the denied file keeps its bytes and its (dev, inode),
// and the permitted name it was to take never appears.
const PROBE: &str = include_str!("../probes/fs_probe.rs");
include!("../probes/probe_lines.rs");

/// The refusal families this case admits, per operation and platform, each from the mechanism's
/// source. Nothing else a syscall can fail with is a denial here.
///
/// | operation on the denied leaf | Linux (`view.rs` empty-file bind, `remount_protected` read-only) | macOS (`seatbelt.rs` leaf denies on the literal) |
/// |---|---|---|
/// | `rename(2)` of it, or onto it | EBUSY: it is a mount point (rename(2); `a_contained_host_binary_cannot_move_an_authority_sources_parent` pins EBUSY on a protected mountpoint) | EPERM |
/// | `read(2)` of it | not a refusal: reads EMPTY (`a_refused_file_reads_empty_and_refuses_a_write`, code 22 makes an absent file a failure) | EPERM |
/// | `open(2)` for append on it | EROFS: the bind is remounted read-only (open(2)) | EPERM |
/// | `read(2)` of the permitted name it was to take | ENOENT: nothing was ever created there | ENOENT: nothing there, and the workspace's read root answers existence for its entries |
fn rename_denials() -> &'static [i32] {
    match Platform::current() {
        Platform::Linux => &[EBUSY],
        Platform::Macos => &[EPERM],
    }
}
fn append_denials() -> &'static [i32] {
    match Platform::current() {
        Platform::Linux => &[EROFS],
        Platform::Macos => &[EPERM],
    }
}

/// The one shape a read of the denied leaf may take on `platform`: on Linux a successful EMPTY read
/// (`READ_OK … len=0`), because the box binds an empty file over the leaf and its own test treats an
/// absent or non-empty leaf as a failure; on macOS a refusal with EPERM. Every other outcome — bytes,
/// a refusal on Linux, any other errno on macOS — is `Err` with what was seen.
fn denied_leaf_read<'a>(out: &'a str, leaf: &str, platform: Platform) -> Result<&'a str, String> {
    match platform {
        Platform::Linux => match probe_line(out, "READ_", leaf) {
            Some(line) if line.starts_with(&format!("READ_OK {leaf} len=0 ::")) => Ok(line),
            Some(line) if line.starts_with("READ_OK") => Err(format!(
                "the denied leaf read bytes on Linux, where the empty-file bind must read empty: {line}"
            )),
            Some(line) => Err(format!(
                "the denied leaf was refused on Linux, where the empty-file bind must read empty (the box's own test counts an absent leaf as a failure): {line}"
            )),
            None => Err("the probe never read the denied leaf".to_string()),
        },
        Platform::Macos => refused_as(out, "READ", leaf, &[EPERM]),
    }
}

/// A configuration edit that adds `entry` to the agent's `deny` list, joining the fixture's own
/// list on macOS (which already denies `later.env`) and creating the key on Linux.
fn with_deny(entry: String) -> impl Fn(String) -> String {
    move |text: String| {
        if text.contains("deny = [") {
            text.replacen("deny = [", &format!("deny = [{entry}, "), 1)
        } else {
            text.replacen(
                "read_file = [",
                &format!("deny = [{entry}]\nread_file = ["),
                1,
            )
        }
    }
}

/// The parser regression (parent review of 903a91dc): the first form of `probe_line` matched the
/// subject by suffix, so a valid empty read, `READ_OK len=0 <path> :: `, ended in `::` and never
/// matched, and the case then reported "the probe never read the denied leaf" against correct
/// box output. The parser now reads the quoted subject after the tag, so a valid empty read and a
/// non-empty read both match, and neither a longer path, a shorter path, a read whose content
/// quotes the path, nor another operation on the same path can satisfy a read assertion.
#[test]
fn the_probe_line_parser_matches_the_subject_and_nothing_else() {
    let secret = std::path::Path::new("/tmp/det/secret.env");
    let quoted = subject(secret);
    assert_eq!(quoted, "\"/tmp/det/secret.env\"");
    let out = "DET_ENTERED\n\
               READ_OK \"/tmp/det/secret.env\" len=0 :: \n\
               READ_OK \"/tmp/det/other.txt\" len=6 :: OTHER\n\
               READ_OK \"/tmp/det/secret.env/deeper\" len=0 :: \n\
               READ_OK \"/x/tmp/det/secret.env\" len=0 :: \n\
               READ_OK \"/tmp/det/quoting.txt\" len=21 :: \"/tmp/det/secret.env\"\n\
               APPEND_REFUSED \"/tmp/det/secret.env\" errno=30 (Read-only file system (os error 30))\n\
               READ_REFUSED \"/tmp/det/copy.env\" errno=2 (No such file or directory (os error 2))\n\
               RENAME_REFUSED \"/tmp/det/secret.env\" -> \"/tmp/det/copy.env\" errno=16 (Device or resource busy (os error 16))\n\
               done\n";
    // A valid empty read is recognized, as the successful read it is.
    let empty = probe_line(out, "READ_", &quoted).expect("a valid empty read matches");
    assert!(
        empty.starts_with("READ_OK \"/tmp/det/secret.env\" len=0 ::"),
        "{empty}"
    );
    assert_eq!(probe_line(out, "READ_OK", &quoted), Some(empty));
    // A non-empty read of another path is recognized under its own subject only.
    let other = probe_line(
        out,
        "READ_",
        &subject(std::path::Path::new("/tmp/det/other.txt")),
    );
    assert_eq!(other, Some("READ_OK \"/tmp/det/other.txt\" len=6 :: OTHER"));
    // A refusal is recognized, and the tag distinguishes it from a success.
    assert!(
        probe_line(out, "READ_REFUSED", &quoted).is_none(),
        "the secret was read, not refused"
    );
    let copy = subject(std::path::Path::new("/tmp/det/copy.env"));
    assert!(
        probe_line(out, "READ_REFUSED", &copy)
            .unwrap()
            .contains("errno=2 (")
    );
    assert!(probe_line(out, "READ_OK", &copy).is_none());
    // Wrong paths: a longer path, a shorter path, a path that is a suffix, a path quoted in content.
    assert!(probe_line(out, "READ_", &subject(std::path::Path::new("/tmp/det"))).is_none());
    assert!(
        probe_line(
            out,
            "READ_",
            &subject(std::path::Path::new("det/secret.env"))
        )
        .is_none()
    );
    let deeper = subject(std::path::Path::new("/tmp/det/secret.env/deeper"));
    assert_ne!(probe_line(out, "READ_", &deeper), Some(empty));
    // Another operation on the same path cannot satisfy a read assertion, and vice versa.
    assert!(
        probe_line(out, "READ_", &quoted)
            .unwrap()
            .starts_with("READ_")
    );
    assert!(
        probe_line(out, "APPEND_REFUSED", &quoted)
            .unwrap()
            .starts_with("APPEND_REFUSED")
    );
    assert!(probe_line(out, "APPEND_OK", &quoted).is_none());
    // A two-path subject matches whole, and neither half alone.
    let moved = pair(secret, std::path::Path::new("/tmp/det/copy.env"));
    assert!(
        probe_line(out, "RENAME_REFUSED", &moved)
            .unwrap()
            .contains("errno=16 (")
    );
    assert!(probe_line(out, "RENAME_", &quoted).is_none());
    assert!(probe_line(out, "RENAME_", &copy).is_none());
    // The parent's reproduction, in the old grammar, is no longer a line this parser accepts at all.
    assert!(
        probe_line(
            "READ_OK len=0 /tmp/secret.env :: \n",
            "READ_",
            &subject(std::path::Path::new("/tmp/secret.env"))
        )
        .is_none()
    );
}

/// The refusal oracle (parent review item 3): a `*_REFUSED` line is a failed syscall until its errno
/// is one the case names for that operation on that platform. EIO, EMFILE, ENOMEM and ENOSPC are
/// what a broken disk, an exhausted descriptor table or an exhausted heap answer, and none is a
/// denial; a legitimate denial passes only inside its own family, and a Linux empty read passes only
/// on Linux, where the mechanism produces it.
#[test]
fn the_refusal_oracle_admits_only_the_named_denials() {
    let leaf = subject(std::path::Path::new("/ws/secret.env"));
    let line = |errno: i32, text: &str| {
        format!("READ_REFUSED {leaf} errno={errno} ({text} (os error {errno}))\n")
    };
    // Failures that are not denials, each rejected with its value in the reason.
    for (errno, text) in [
        (5, "Input/output error"),
        (24, "Too many open files"),
        (12, "Cannot allocate memory"),
        (28, "No space left on device"),
        (13, "Permission denied"),
    ] {
        let out = line(errno, text);
        let why = refused_as(&out, "READ", &leaf, &[EPERM, ENOENT]).expect_err(text);
        assert!(why.contains(&format!("errno {errno}")), "{why}");
        assert!(why.contains("not a denial"), "{why}");
        // The same failure is not a Linux empty read and not a macOS EPERM either.
        assert!(
            denied_leaf_read(&out, &leaf, Platform::Linux).is_err(),
            "{text} passed as a Linux empty read"
        );
        assert!(
            denied_leaf_read(&out, &leaf, Platform::Macos).is_err(),
            "{text} passed as a macOS denial"
        );
    }
    // Legitimate denials pass only inside their own family.
    let eperm = line(1, "Operation not permitted");
    assert!(refused_as(&eperm, "READ", &leaf, &[EPERM]).is_ok());
    assert!(
        refused_as(&eperm, "READ", &leaf, &[ENOENT]).is_err(),
        "EPERM passed where only ENOENT is the mechanism's answer"
    );
    let enoent = line(2, "No such file or directory");
    assert!(refused_as(&enoent, "READ", &leaf, &[ENOENT]).is_ok());
    assert!(
        refused_as(&enoent, "READ", &leaf, &[EPERM]).is_err(),
        "ENOENT passed where only EPERM is the mechanism's answer"
    );
    let ebusy = format!(
        "RENAME_REFUSED {leaf} -> \"/ws/copy.env\" errno=16 (Device or resource busy (os error 16))\n"
    );
    assert!(
        refused_as(
            &ebusy,
            "RENAME",
            &format!("{leaf} -> \"/ws/copy.env\""),
            &[EBUSY]
        )
        .is_ok()
    );
    assert!(
        refused_as(
            &ebusy,
            "RENAME",
            &format!("{leaf} -> \"/ws/copy.env\""),
            &[EPERM]
        )
        .is_err()
    );
    // A refusal with no errno, a success, and no attempt are each named, never accepted.
    assert!(
        refused_as(
            &format!("READ_REFUSED {leaf} (no errno here)\n"),
            "READ",
            &leaf,
            &[EPERM]
        )
        .unwrap_err()
        .contains("no errno")
    );
    assert!(
        refused_as(
            &format!("READ_OK {leaf} len=3 :: abc\n"),
            "READ",
            &leaf,
            &[EPERM]
        )
        .unwrap_err()
        .contains("succeeded")
    );
    assert!(
        refused_as("DET_ENTERED\n", "READ", &leaf, &[EPERM])
            .unwrap_err()
            .contains("never attempted")
    );
    // The denied leaf's read: a valid Linux empty read passes on Linux and nowhere else; bytes never do.
    let empty = format!("READ_OK {leaf} len=0 :: \n");
    assert!(denied_leaf_read(&empty, &leaf, Platform::Linux).is_ok());
    assert!(
        denied_leaf_read(&empty, &leaf, Platform::Macos).is_err(),
        "an empty read passed on macOS, where the leaf must be refused"
    );
    assert!(denied_leaf_read(&eperm, &leaf, Platform::Macos).is_ok());
    assert!(
        denied_leaf_read(&eperm, &leaf, Platform::Linux)
            .unwrap_err()
            .contains("must read empty")
    );
    assert!(
        denied_leaf_read(&enoent, &leaf, Platform::Linux).is_err(),
        "an absent leaf passed on Linux, where the box's own test counts it as a failure"
    );
    let bytes = format!("READ_OK {leaf} len=7 :: SECRET!\n");
    assert!(
        denied_leaf_read(&bytes, &leaf, Platform::Linux)
            .unwrap_err()
            .contains("read bytes")
    );
    assert!(
        denied_leaf_read(&bytes, &leaf, Platform::Macos)
            .unwrap_err()
            .contains("succeeded")
    );
    assert!(denied_leaf_read("DET_ENTERED\n", &leaf, Platform::Linux).is_err());
}

det_case! {
    name: cn_r_02,
    id:   "CN-R-02",
    desc: "Deny leaf: the agent's own rename(2) cannot move an existing denied file to a permitted name nor move a permitted file over it (Linux EBUSY, macOS EPERM); an ordinary rename works; the host sees the denied bytes and inode unchanged",
    run: |b| {
        b.reset_policy();
        let probe = b.compile_probe("fsprobe", PROBE);
        let pid = std::process::id();
        let secret_text = format!("DET_SECRET_CNR02_{pid}_{:x}\n", std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH).map(|d| d.as_nanos()).unwrap_or(0));
        let secret = b.workspace().join("secret.env");
        let copy = b.workspace().join("copy.env");
        let other = b.workspace().join("other.txt");
        let other2 = b.workspace().join("other2.txt");
        std::fs::write(&secret, &secret_text).expect("DET_ERROR: plant the file the deny names");
        std::fs::write(&other, "OTHER\n").expect("DET_ERROR: plant the permitted file");
        let before = std::fs::metadata(&secret).expect("DET_ERROR: stat the denied file on the host");

        let deny_entry = serde_json::to_string(&secret.to_string_lossy()).unwrap();
        let exec_tree = b.with_exec_tree();
        let deny = with_deny(deny_entry);
        let r = b.run_sh_with_config(
            move |text| deny(exec_tree(text)),
            &format!(
                "P='{p}'; \
                 \"$P\" rename '{other}' '{other2}'; \
                 \"$P\" rename '{secret}' '{copy}'; \
                 \"$P\" rename '{other2}' '{secret}'; \
                 \"$P\" read '{secret}'; \
                 \"$P\" read '{copy}'; \
                 \"$P\" append '{secret}' DET_TAMPERED_CNR02; \
                 \"$P\" stat '{secret}'; \
                 printf done",
                p = probe.display(),
                other = other.display(),
                other2 = other2.display(),
                secret = secret.display(),
                copy = copy.display(),
            ),
        );
        // Host observations, taken before any assertion so a panic cannot skip them.
        let after = std::fs::metadata(&secret).ok();
        let secret_after = std::fs::read_to_string(&secret).unwrap_or_default();
        let copy_exists = copy.exists();
        let other_exists = other.exists();
        let other2_text = std::fs::read_to_string(&other2).unwrap_or_default();

        // The probe ran, and the control rename inside the write grant succeeded.
        r.assert_contains(&format!("RENAME_OK {}", pair(&other, &other2)));
        r.assert_contains("done");

        // The boundary, twice: the denied leaf cannot be moved to a permitted name, and a permitted
        // file cannot be moved over it. Each is refused with the errno its mechanism answers. These
        // come before the host checks so an unconfined box is named for what it let through, not
        // for the control file its second rename then consumed.
        let moved_out = pair(&secret, &copy);
        refused_as(&r.out, "RENAME", &moved_out, rename_denials())
            .unwrap_or_else(|why| panic!("the denied file was not refused a rename to a permitted name: {why}; out=[{}]", r.snippet()));
        let moved_over = pair(&other2, &secret);
        refused_as(&r.out, "RENAME", &moved_over, rename_denials())
            .unwrap_or_else(|why| panic!("a permitted file was not refused a rename over the denied leaf: {why}; out=[{}]", r.snippet()));
        r.assert_absent(&format!("RENAME_OK {moved_out}"));
        r.assert_absent(&format!("RENAME_OK {moved_over}"));

        // The leaf reads as the refusal lowers it — empty on Linux, EPERM on macOS — and never as
        // its bytes; the permitted name it was to take does not exist; a write is refused with the
        // errno the mechanism answers.
        let leaf = subject(&secret);
        r.assert_contains_any(&[&format!("READ_OK {leaf} len=0 ::"), &format!("READ_REFUSED {leaf} errno=")]);
        denied_leaf_read(&r.out, &leaf, Platform::current())
            .unwrap_or_else(|why| panic!("{why}; out=[{}]", r.snippet()));
        r.assert_absent_secret(secret_text.trim_end(), "secret.env marker");
        r.assert_absent(&format!("READ_OK {}", subject(&copy)));
        refused_as(&r.out, "READ", &subject(&copy), &[ENOENT])
            .unwrap_or_else(|why| panic!("the permitted name the denied file was to take did not answer absent: {why}; out=[{}]", r.snippet()));
        refused_as(&r.out, "APPEND", &leaf, append_denials())
            .unwrap_or_else(|why| panic!("the denied leaf was not refused a write: {why}; out=[{}]", r.snippet()));
        r.assert_absent("APPEND_OK");

        // The host is the trustworthy channel: the control landed, and the denied file is the same
        // object with the same bytes and no copy.
        assert_eq!(other2_text, "OTHER\n", "the control rename did not land on the host");
        assert!(!other_exists, "the control rename left its source on the host");
        let after = after.expect("the denied file vanished from the host");
        assert_eq!((after.dev(), after.ino()), (before.dev(), before.ino()), "the denied file's identity changed on the host");
        assert_eq!(secret_after, secret_text, "the denied file's bytes changed on the host");
        assert!(!copy_exists, "the denied file's bytes appeared under a permitted name on the host");
    }
}

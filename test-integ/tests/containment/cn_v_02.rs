use std::os::unix::fs::MetadataExt as _;

use strands_det_harness::{det_case, user_home};

// CN-V-01 measures the MEDIATED resolver: the hosted Shell refuses every symlink spelling as not its
// own identity (reach.rs). This case measures the other route — the agent's own syscalls
// following a real symbolic link inside its writable workspace — where no resolver stands between
// the workload and the kernel, so the property is the kernel view's: on Linux the workspace is a
// bind and an absolute link target outside every grant is simply not in the view
// (`view.rs`; the read answers ENOENT), and on macOS Seatbelt judges the object the link resolves
// to, whose path no rule allows and whose home the existence deny covers
// (`contains_operator_home.rs::no_respelling_of_a_refused_path_answers`; EPERM). Upstream SRT pins
// the same shape in `symlink-boundary` (`block-write-via-symlink-traversal`) and
// `linux-ancestor-pin` (`planted-symlink-cannot-reopen-denied-dir`); Box's own native pin is
// `box_filesystem.rs::a_symlinked_agent_read_entry_cannot_read_private_state`, which is about a
// GRANT that is a link, not a link the workload holds.
//
// Two ways the link gets there, both native: the host prepares one before the run (proven on the
// host to be a symlink that resolves to the secret and reads it), and the workload makes one itself
// with `symlink(2)` from a compiled probe under its own `exec` entry, which its write grant permits.
// Reads use bash's own redirection and the probe's `read`; the write attempts are a redirection and
// the probe's `append`. The controls: a host-prepared link to a sibling inside the grant reads, and
// a write through an in-grant link lands on the host, so the refusals that follow are of the escape
// and not of symlinks. The host proves the secret's bytes and identity unchanged afterwards.
const PROBE: &str = include_str!("../probes/fs_probe.rs");
include!("../probes/probe_lines.rs");

/// The refusals a read or an append through the escape link answers, from the mechanism's source:
/// on Linux ENOENT, because the link's target is outside every bind and so absent from the view
/// (`view.rs`; the append opens without create, so it is the same failed lookup); on macOS EPERM,
/// because Seatbelt judges the object the link resolves to, which no rule allows and the home's
/// existence deny covers (`seatbelt.rs`, `no_respelling_of_a_refused_path_answers`). Any other
/// errno is a failed syscall, not a refusal.
fn escape_denials() -> &'static [i32] {
    match strands_det_harness::Platform::current() {
        strands_det_harness::Platform::Linux => &[ENOENT],
        strands_det_harness::Platform::Macos => &[EPERM],
    }
}

det_case! {
    name: cn_v_02,
    id:   "CN-V-02",
    desc: "Native symlink escape: a workspace link to a secret outside every grant, host-prepared or made by the workload's own symlink(2), yields no bytes and takes no write through the agent's own syscalls; an in-grant link reads and writes through; the secret is unchanged on the host",
    run: |b| {
        b.reset_policy();
        let probe = b.compile_probe("fsprobe", PROBE);
        let home = user_home().canonicalize().expect("DET_ERROR: resolve operator home");
        let pid = std::process::id();
        let secret_path = home.join(format!(".det-cnv02-secret-{pid}"));
        let secret = format!("DET_SECRET_CNV02_{pid}_{:x}", std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH).map(|d| d.as_nanos()).unwrap_or(0));
        std::fs::write(&secret_path, format!("{secret}\n")).expect("DET_ERROR: plant the secret under the operator home");
        let before = std::fs::metadata(&secret_path).expect("DET_ERROR: stat the secret on the host");
        let escape = b.workspace().join("escape-link");
        let inside = b.workspace().join("inlink");
        let inside_write = b.workspace().join("inlink-w");
        let target = b.workspace().join("target.txt");
        let made = b.workspace().join("made-link");
        std::fs::write(&target, "").expect("DET_ERROR: plant the in-grant write target");
        std::os::unix::fs::symlink(&secret_path, &escape).expect("DET_ERROR: host-prepare the escape link");
        std::os::unix::fs::symlink("readable.txt", &inside).expect("DET_ERROR: host-prepare the in-grant read link");
        std::os::unix::fs::symlink(&target, &inside_write).expect("DET_ERROR: host-prepare the in-grant write link");
        // The escape is real: on the host the link resolves to the secret and reads its bytes.
        let is_link = std::fs::symlink_metadata(&escape).map(|m| m.file_type().is_symlink()).unwrap_or(false);
        let resolved = std::fs::canonicalize(&escape).unwrap_or_default();
        let through_link = std::fs::read_to_string(&escape).unwrap_or_default();

        let r = b.run_sh_with_config(
            b.with_exec_tree(),
            &format!(
                "P='{p}'; \
                 read -r v < '{inside}' && printf 'INSIDE=%s\\n' \"$v\"; \
                 printf 'WROTE_IN\\n' > '{inside_write}' && printf 'INSIDE_WRITE_OK\\n'; \
                 read -r v < '{escape}' && printf 'ESCAPE=%s\\n' \"$v\"; \
                 printf 'DET_ESCAPED_WRITE_CNV02\\n' > '{escape}' && printf 'ESCAPE_WRITE_OK\\n'; \
                 \"$P\" read '{escape}'; \
                 \"$P\" symlink '{secret_path}' '{made}'; \
                 \"$P\" read '{made}'; \
                 \"$P\" append '{made}' DET_ESCAPED_WRITE_CNV02; \
                 printf done",
                p = probe.display(),
                inside = inside.display(),
                inside_write = inside_write.display(),
                escape = escape.display(),
                secret_path = secret_path.display(),
                made = made.display(),
            ),
        );
        // Host observations, then the secret is removed whatever the assertions say.
        let after = std::fs::metadata(&secret_path).ok();
        let secret_after = std::fs::read_to_string(&secret_path).unwrap_or_default();
        let target_after = std::fs::read_to_string(&target).unwrap_or_default();
        let made_points_at_secret = std::fs::read_link(&made).map(|t| t == secret_path).unwrap_or(false);
        let _ = std::fs::remove_file(&secret_path);

        assert!(is_link, "DET_ERROR: the host-prepared escape link is not a symlink");
        assert_eq!(resolved, secret_path, "DET_ERROR: the escape link does not resolve to the secret on the host");
        assert!(through_link.contains(&secret), "DET_ERROR: the host cannot read the secret through the escape link; the probe would prove nothing");

        // Positive controls: an in-grant link reads through, and a write through one lands.
        r.assert_contains("INSIDE=LISTED_CONTENT");
        r.assert_contains("INSIDE_WRITE_OK");
        r.assert_contains("done");
        assert_eq!(target_after, "WROTE_IN\n", "the write through the in-grant link did not land on the host");
        // The workload made its own link inside its write grant, and the host sees it aimed at the secret.
        r.assert_contains(&format!("SYMLINK_OK {}", pair(&made, &secret_path)));
        assert!(made_points_at_secret, "the workload-made link is not a symlink to the secret on the host");

        // The boundary: neither link yields the secret's bytes or takes a write, and the kernel
        // said so for the redirection. The leak checks come first, so an unconfined box is named
        // for the bytes it let out rather than for the marker it did not print.
        r.assert_absent("ESCAPE=");
        r.assert_absent_secret(&secret, "CN-V-02 home secret marker");
        r.assert_absent("ESCAPE_WRITE_OK");
        r.assert_kernel_marker();
        for link in [&escape, &made] {
            let spelled = subject(link);
            refused_as(&r.out, "READ", &spelled, escape_denials())
                .unwrap_or_else(|why| panic!("the read through {spelled} was not refused as the view refuses it: {why}; out=[{}]", r.snippet()));
        }
        refused_as(&r.out, "APPEND", &subject(&made), escape_denials())
            .unwrap_or_else(|why| panic!("the write through the workload-made link was not refused as the view refuses it: {why}; out=[{}]", r.snippet()));
        r.assert_absent("READ_OK ");
        r.assert_absent("APPEND_OK");

        // The host: the secret is the same object with the same bytes, and nothing was written to it.
        let after = after.expect("the secret vanished from the host");
        assert_eq!((after.dev(), after.ino()), (before.dev(), before.ino()), "the secret's identity changed on the host");
        assert_eq!(secret_after, format!("{secret}\n"), "the secret's bytes changed on the host");
    }
}

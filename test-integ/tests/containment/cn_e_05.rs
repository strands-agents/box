// The existence deny is scoped to the operator home.
//
// macOS only. A TRIPWIRE, not a recorded gap. An absent path outside the operator home must
// answer ENOENT, so a workload can tell "there is nothing there" from "you may not look". A
// harness that cannot tell them apart aborts on an optional configuration file it merely
// probed for.
//
// Measured 2026-09-28 on the `sbpl-version-3-prototype` branch, which closes
// `file-test-existence` by default: codex 0.158.0 then reports `Failed to read requirements
// file /etc/codex/requirements.toml: Operation not permitted (os error 1)` and exits, on a host
// where `/etc/codex/` does not exist at all. Flipping only the `(version 3)` line back to
// `(version 1)` gets codex past that read. No `[agent.filesystem]` grant repairs it: an absent
// path grants nothing, `/etc` is a symbolic link, and `/private/etc` is a system root.
//
// IF THIS CASE GOES RED, an absent path has become indistinguishable from a refused one. That
// is a deliberate decision to take, not a test to update: re-decide the scoped existence deny
// first, and record which harnesses the new errno aborts.
//
// Two things this case is written around:
//   * CN-E-04 owns the `os.access` shape, whose boolean collapses EPERM and ENOENT into False.
//     That is exactly why it stayed green through the version-3 measurement, and why this case
//     reads the errno instead. Neither case replaces the other.
//   * EVERY arm reads an errno, controls included. `os.path.lexists` was the first spelling of
//     the controls here and it was wrong for the same reason `os.access` is: it answers False on
//     any OSError, EPERM as well as ENOENT, so it held under both regimes and controlled
//     nothing. `os.lstat` inside `t()` reports the errno, so the control is itself an ENOENT
//     assertion. The arms are reads, not existence tests: a read is what a harness does to a
//     configuration file, and it is the errno codex acted on.
use strands_det_harness::det_case;

det_case! {
    name: cn_e_05,
    id:   "CN-E-05",
    platforms: [Macos],
    desc: "Tripwire: reading an absent path outside the operator home answers ENOENT, not EPERM",
    run: |b| {
        b.reset_policy();
        let r = b.probe_py(
            r#"
absent_etc = "/etc/cn-e-05-absent-%d/requirements.toml" % os.getpid()
absent_bin = "/bin/cn-e-05-absent-%d" % os.getpid()

# Controls, and they read the errno too: `lstat` reports ENOENT for a path that is not there
# and EPERM for one that is refused, so each control asserts the same thing its read arm does.
t("lstat_absent_under_etc", lambda: os.lstat(absent_etc))
t("lstat_absent_under_bin", lambda: os.lstat(absent_bin))

# The shape a harness uses on an optional configuration file. ENOENT lets it continue;
# EPERM makes it fail.
t("read_absent_under_etc", lambda: open(absent_etc, "rb").read())
t("read_absent_under_bin", lambda: open(absent_bin, "rb").read())
"#,
        );
        // ENOENT (2), not EPERM (1), on every arm. `assert_errno` compares the whole integer
        // token, so a 1 cannot satisfy any of these.
        r.assert_errno("lstat_absent_under_etc", 2);
        r.assert_errno("lstat_absent_under_bin", 2);
        r.assert_errno("read_absent_under_etc", 2);
        r.assert_errno("read_absent_under_bin", 2);
    }
}

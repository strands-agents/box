use strands_det_harness::det_case;

// The write-cell allowlist, residual N4.
//
// A recorded GAP, kept visible on purpose. A write cell must grant `file-write-create` and
// `file-write-unlink` for ordinary work — an atomic save is write-temp-then-rename, and cleanup
// needs unlink — and those two leaves together reach the MODE of any path the cell covers.
// Remove a file and create it again, and the new file carries whatever mode the caller asked
// for. `mkdir` carries its mode argument the same way. No rule closes either: the mode rides
// the create, and the only rule that refuses it is `(deny file-write* ...)`, which removes
// writing.
//
// Why it is worth recording even though `file-write-mode` is granted on a write root today:
// this route does not need that leaf. It survives dropping it, so a future cell that refuses
// `mode` would still leak the mode through create, and a reader who assumed otherwise would be
// wrong. The blast radius is whatever `write = [...]` names — for a pre-existing operator file
// under that root, this launders its mode.
//
// `refusals()` renders `(deny file-write* (subpath ...))`, the one shape that refuses everything,
// so an operator `deny` entry is airtight against this. That is the mitigation, and it is the
// reason this is accepted rather than open-ended.
//
// This case asserts the gap is still exactly this wide. It must NEVER be rewritten to claim a
// denial: a suite that says the mode is protected here is how a tracked residual stops being
// tracked.
//
// The trap this case is written around: `umask` masks the mode argument of both `open` and
// `mkdir`, so a case that does not clear it measures the umask and not the profile. `os.umask(0)`
// comes first, and the stored mode is what every arm judges — never the return code.
det_case! {
    name: cn_f_04,
    id: "CN-F-04",
    platforms: [Macos],
    desc: "Recorded gap: unlink-then-create and mkdir carry a mode no rule refuses, so a file's mode launders inside a write root",
    run: |b| {
        b.reset_policy();
        let r = b.probe_py(
            r#"
# Clear the umask first, or every stored mode below is the umask's answer, not the profile's.
os.umask(0)

BH = os.environ["HOME"]
F = BH + "/cn-f-04.txt"
D = BH + "/cn-f-04-dir"

# A pre-existing file, private to its owner, standing in for an operator file under the root.
fd = os.open(F, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
os.write(fd, b"x")
os.close(fd)
t("planted_mode", lambda: oct(os.stat(F).st_mode & 0o777))

# The laundering route: remove it, create it again with a wider mode. Neither leaf can be
# withdrawn, because an atomic save and cleanup both need them.
os.unlink(F)
fd = os.open(F, os.O_WRONLY | os.O_CREAT, 0o777)
os.close(fd)
t("relaunder_mode", lambda: oct(os.stat(F).st_mode & 0o777))

# The same authority through mkdir, which carries its own mode argument.
os.mkdir(D, 0o777)
t("mkdir_mode", lambda: oct(os.stat(D).st_mode & 0o777))

os.unlink(F)
os.rmdir(D)
"#,
        );
        // Positive control: the file really started private to its owner.
        r.assert_ok("planted_mode", "0o600");
        // The residual: the recreated file carries the mode the caller asked for, so the
        // original mode is gone.
        r.assert_ok("relaunder_mode", "0o777");
        // And a new directory carries its own mode argument the same way.
        r.assert_ok("mkdir_mode", "0o777");
    }
}

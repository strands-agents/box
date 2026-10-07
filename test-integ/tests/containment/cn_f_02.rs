// macOS only. A writable path carries no authority over itself. The write family is wider
// than writing, so the profile takes back the members that confer authority: the BSD file
// flags, the owner, and the granted root's own identity. Ordinary writes stay granted.
//
// Two traps this case is written around, both of which produced a false result before:
//   * chmod judges the STORED bit, never the return code. Setting 04755 returns 0 and stores
//     0755, so a case that reads the return code records a pass that is not one.
//   * `Write`+`Root` deliberately keeps mode authority (git sets +x); only `Write`+`File`
//     denies it. Asserting a mode denial here would assert a defect.
use strands_det_harness::det_case;

det_case! {
    name: cn_f_02,
    id:   "CN-F-02",
    platforms: [Macos],
    desc: "No self-authority: owner, file flags, and root identity are refused in a write cell; the set-user-ID bit is not stored",
    run: |b| {
        b.reset_policy();
        let r = b.probe_py(
            r#"
BH = os.environ["HOME"]
F = BH + "/cn-f-02.txt"
t("ordinary_write", lambda: open(F, "w").write("x"))
t("chown_self", lambda: os.chown(F, os.getuid(), os.getgid()))
print("chflags_uf_immutable", raw("chflags", F.encode(), 2))
os.chmod(F, 0o4755)
print("stored_mode_after_setuid", oct(os.stat(F).st_mode & 0o7777))
t("rmdir_write_root", lambda: os.rmdir(BH))
t("symlink_over_write_root", lambda: os.symlink("/tmp", BH))
os.unlink(F)
"#,
        );
        // Positive control: an ordinary write inside the write root succeeds.
        r.assert_ok("ordinary_write", "1");
        // Changing owner and setting UF_IMMUTABLE inside the write root are refused (errno 1).
        r.assert_errno("chown_self", 1);
        r.assert_contains("chflags_uf_immutable ('rc', -1, 'errno', 1)");
        // chmod 04755 returns success, yet the set-user-ID bit is NOT stored (judge the mode).
        r.assert_contains("stored_mode_after_setuid 0o755");
        // Root identity: the workload cannot remove or relink its own write root.
        r.assert_errno("rmdir_write_root", 1);
        r.assert_errno("symlink_over_write_root", 1);
    }
}

// Do not directly execute writable files.
//
// macOS only. Bytes the workload writes cannot become a new executable: the write root
// carries `(deny file-map-executable (subpath ...))`, so no file the workload can rewrite
// loads as code. The strong arm copies the workload's OWN signed interpreter — bytes known
// to be runnable and correctly signed — and the copy still cannot exec, which distinguishes
// the profile from code signing.
//
// Two things this case is written around:
//   * os.access(path, X_OK) answers False here, because the query itself consults the
//     profile's exec permission. The STORED mode is the control for "the write worked".
//   * No fork. execv is refused, so it returns and the process survives to run the next arm;
//     if it ever succeeded the marker would print, which the last arm catches.
use strands_det_harness::det_case;

det_case! {
    name: cn_x_01,
    id:   "CN-X-01",
    platforms: [Macos],
    desc: "Write-xor-exec: a written script and a copy of the signed interpreter both refuse to exec; the marker never prints",
    run: |b| {
        b.reset_policy();
        let r = b.probe_py(
            r##"
import shutil
BH = os.environ["HOME"]
S = BH + "/cn-x-01.sh"
open(S, "w").write("#!/bin/sh\necho ESCAPED_MARKER\n")
os.chmod(S, 0o755)
print("script_stored_mode", oct(os.stat(S).st_mode & 0o777))
t("exec_written_script", lambda: os.execv(S, [S]))
D = BH + "/cn-x-01.bin"
shutil.copyfile(sys.executable, D)
os.chmod(D, 0o700)
print("copy_stored_mode", oct(os.stat(D).st_mode & 0o777))
print("copy_same_size", os.path.getsize(D) == os.path.getsize(sys.executable))
t("exec_written_binary", lambda: os.execv(D, [D, "-c", 'print("ESCAPED_MARKER")']))
os.unlink(S); os.unlink(D)
"##,
        );
        // Positive control: the written script stored mode 0755, so the write half worked.
        r.assert_contains("script_stored_mode 0o755");
        // Executing a script the workload wrote is refused with errno 1.
        r.assert_errno("exec_written_script", 1);
        // Positive control: the interpreter copy is byte-complete inside the write root.
        r.assert_contains("copy_same_size True");
        // A copy of the interpreter's own signed bytes still cannot exec — the profile
        // refuses it, not code signing.
        r.assert_errno("exec_written_binary", 1);
        // The escape marker never reaches stdout by either route.
        r.assert_absent("ESCAPED_MARKER");
    }
}

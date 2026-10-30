use strands_det_harness::{Platform, det_case};

det_case! {
    name: when_agent_writes_script_or_copies_interpreter_then_execution_is_refused,
    id:   "CN-X-01",
    platforms: [Macos, Linux],
    desc: "Write-xor-exec: a written script and a copy of the running interpreter both refuse to exec; the marker never prints",
    run: |b| {
        b.reset_policy();
        let denied = match Platform::current() {
            Platform::Macos => 1,
            Platform::Linux => 13,
        };
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
        // The written script cannot execute.
        r.assert_errno("exec_written_script", denied);
        // Positive control: the interpreter copy is byte-complete inside the write root.
        r.assert_contains("copy_same_size True");
        // The copied interpreter cannot execute from the write root.
        r.assert_errno("exec_written_binary", denied);
        // The escape marker never reaches stdout by either route.
        r.assert_absent("ESCAPED_MARKER");
    }
}

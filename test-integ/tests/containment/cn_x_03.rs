// Do not directly execute writable files.
//
// macOS only. The LIBRARY-LOAD half of write-xor-exec. `process-exec` and a file-backed
// executable mapping are two separate authorities, and a profile can leave one open while it
// closes the other: the 2026-08-31 invariant measurements found exactly that — a contained
// workload wrote a dynamic library into its own home and loaded it, because write-xor-exec held
// for `process-exec` and not for a library load. Each write cell renders
// `(deny file-map-executable (subpath ...))` for that reason.
//
// CN-X-01 owns the `process-exec` half — a written script and a copy of the signed interpreter,
// both refused `execv`. Neither of its arms reaches `file-map-executable`, so a regression that
// dropped only the mapping deny would leave CN-X-01 green. This case is that arm.
//
// SCOPE. This measures the agent box with no `exec` grant, which is what `probe_py` declares.
// `seatbelt.rs::executable_carve_outs` renders `(allow file-map-executable ...)` in the AGENT box
// when an `exec` grant overlaps a `write` grant, and over the write grant's own subpath when a
// write root sits inside a Root-scope `exec` grant. That configuration re-opens the mapping by
// operator authorship and has no case here; do not read this one as covering it.
//
// Four things this case is written around:
//   * The control must load bytes DYLD HAS NOT SEEN. Loading the library the probe already
//     imported proves nothing: `dlopen` returns the cached handle for a path it has mapped, so
//     the call never re-reads the file. Measured — `DYLD_PRINT_LIBRARIES=1` prints the mapping
//     during the import and prints nothing for a later `CDLL` of the same path, and a library
//     overwritten with garbage after its first load still "loads" by that path. So the control
//     picks an extension this process has not imported.
//   * Loading the original first does not poison the refusal arm. dyld caches by path, and the
//     copy has a different path, so the copy is mapped fresh.
//   * ONLY `file system sandbox blocked mmap()` is accepted. dyld's
//     `SyscallDelegate::sandboxBlockedMmap` emits that text when `sandbox_check` reports the
//     sandbox blocked the mapping, and `code signing blocked mmap()` when it reports the sandbox
//     did NOT. Accepting the second string would let an AMFI or code-signing refusal satisfy this
//     case with the mapping deny deleted, which is the one alternative explanation the case
//     exists to exclude. If a future profile version changes which text appears, this case must
//     fail and the change must be re-decided — never widen the needle.
//   * Every `/usr/lib` system dylib is in the dyld shared cache and absent from disk, so none can
//     serve as the source. A Python extension module is the available on-disk library.
use strands_det_harness::det_case;

det_case! {
    name: cn_x_03,
    id:   "CN-X-03",
    platforms: [Macos],
    desc: "Write-xor-exec: a loadable library copied into the write root cannot be mapped executable, although the same bytes load from a read root",
    run: |b| {
        b.reset_policy();
        let r = b.probe_py(
            r#"
import ctypes, glob, shutil

def load(label, path):
    """Report the dyld MESSAGE, which `t` cannot: ctypes raises OSError with a bare string, so
    both `errno` and `strerror` are None and the layer that refused would be lost."""
    try:
        ctypes.CDLL(path)
        print(label, "OK", "loaded")
    except Exception as e:
        print(label, "REFUSED", " ".join(str(e).split()))

# An extension module directory this interpreter really has. `_ctypes` is imported by now, so its
# own image is cached and unusable as a control; its directory is where the unloaded siblings are.
import _ctypes
seed = getattr(_ctypes, "__file__", None)
t("found_extension_directory", lambda: bool(seed) and os.path.isdir(os.path.dirname(seed)))
if not seed:
    raise SystemExit("this CPython links _ctypes statically, so it offers no on-disk extension")

loaded = {getattr(m, "__file__", None) for m in sys.modules.values()}
SRC = next(
    p for p in sorted(glob.glob(os.path.join(os.path.dirname(seed), "*.so")))
    if p not in loaded
)
# Control on the control: the source is not an image this process already mapped.
t("source_is_unloaded", lambda: SRC not in loaded)

BH = os.environ["HOME"]
DST = BH + "/cn-x-03.dylib"

# Positive control: these bytes map from the read root, on a path dyld has not seen. So the
# refusal below cannot mean the library was never loadable here.
load("load_unseen_original", SRC)

shutil.copyfile(SRC, DST)
# Positive control: the write half worked and the copy is byte-complete.
t("copy_same_size", lambda: os.path.getsize(DST) == os.path.getsize(SRC))

# The mapping the write cell refuses. A different path, so dyld maps it fresh.
load("load_written_copy", DST)
os.unlink(DST)
"#,
        );
        // Controls first: a real extension directory, a source this process has not mapped, the
        // same bytes loading from the read root, and a byte-complete copy.
        r.assert_ok("found_extension_directory", "True");
        r.assert_ok("source_is_unloaded", "True");
        r.assert_ok("load_unseen_original", "loaded");
        r.assert_ok("copy_same_size", "True");
        // The copy cannot be mapped executable, and the message names the SANDBOX. A
        // code-signing refusal is not an acceptable pass here — see the header.
        r.assert_absent("load_written_copy OK");
        r.assert_contains("file system sandbox blocked mmap()");
    }
}

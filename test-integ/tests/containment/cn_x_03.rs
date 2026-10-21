use strands_det_harness::{Platform, det_case};

det_case! {
    name: cn_x_03,
    id:   "CN-X-03",
    platforms: [Macos, Linux],
    desc: "Write-xor-exec: a loadable library copied into the write root cannot be mapped executable, although the same bytes load from the approved runtime directory",
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
        match Platform::current() {
            Platform::Macos => r.assert_contains("file system sandbox blocked mmap()"),
            Platform::Linux => r.assert_contains("failed to map segment from shared object"),
        }
    }
}

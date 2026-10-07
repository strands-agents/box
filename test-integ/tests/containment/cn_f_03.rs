// The write-cell allowlist.
//
// macOS only. `setattrlist(2)` is a SECOND route to the attributes a write cell governs, and
// it is the reason the cell is an allowlist rather than a denylist. Seatbelt dispatches that
// call per requested attribute, and only `ATTR_CMN_FLAGS` maps to a `file-write-*` leaf a rule
// can name. Under the five leaf denies the cell used to render, `ATTR_CMN_ACCESSMASK`,
// `ATTR_CMN_GRPID` and `ATTR_CMN_OWNERID` all stored their value; bisection over all eleven
// leaves found no deny that reached them. An allowlist never has to name the operation, so the
// cell now names the leaves it needs — `data`, `create`, `unlink`, `xattr`, `mode`, `times` —
// and everything else is refused by `(deny default)`.
//
// The profile is the layer that refuses, not DAC and not the kernel. Uncontained control, macOS
// 26.6 arm64 at euid 503 on the caller's own file: all four arms below return 0, `ACCESSMASK`
// stores 0777 and `FLAGS` stores 2. Every arm asks for a change DAC already permits its caller,
// so a refusal inside the box can only be the cell.
//
// CN-F-02 covers the same attributes through their LEGACY calls (`chown`, `chflags`, `chmod`).
// This case covers the `setattrlist` route, and the divergence between the two is the
// assertion: `os.chmod` succeeds because `file-write-mode` is granted, and
// `setattrlist ATTR_CMN_ACCESSMASK` is refused on the same file because it never dispatches to
// that leaf. A revert to the denylist shape leaves CN-F-02 green and turns these three arms
// reachable, which is what this case exists to catch.
//
// Three things this case is written around:
//   * Every constant and the `struct attrlist` layout come from `sys/attr.h` on the build host,
//     not from memory: `ATTR_BIT_MAP_COUNT` 5, `ATTR_CMN_OWNERID` 0x00008000, `ATTR_CMN_GRPID`
//     0x00010000, `ATTR_CMN_ACCESSMASK` 0x00020000, `ATTR_CMN_FLAGS` 0x00040000. The struct is
//     `u_short, u_int16_t, attrgroup_t x 5` with `attrgroup_t = u_int32_t`.
//   * `ATTR_CMN_EXTENDED_SECURITY` is deliberately absent. It takes an `attrreference_t`
//     pointing at a `kauth_filesec`, and a malformed buffer answers EINVAL before the profile is
//     consulted — such an arm would measure the probe rather than the cell. The access-control
//     list is covered through `acl_set_file` by
//     `contains_exec_target.rs::the_agent_cannot_set_an_access_control_list_in_its_own_home`.
//   * `chmod` must judge the STORED mode, never the return code — the trap CN-F-02 records.
use strands_det_harness::det_case;

det_case! {
    name: cn_f_03,
    id:   "CN-F-03",
    platforms: [Macos],
    desc: "The setattrlist route to a write cell's attributes is refused, although chmod to the granted mode leaf succeeds",
    run: |b| {
        b.reset_policy();
        let r = b.probe_py(
            r#"
import ctypes

# struct attrlist: u_short bitmapcount, u_int16_t reserved, attrgroup_t commonattr,
# volattr, dirattr, fileattr, forkattr — attrgroup_t is u_int32_t (sys/attr.h).
class Attrlist(ctypes.Structure):
    _fields_ = [
        ("bitmapcount", ctypes.c_ushort),
        ("reserved", ctypes.c_uint16),
        ("commonattr", ctypes.c_uint32),
        ("volattr", ctypes.c_uint32),
        ("dirattr", ctypes.c_uint32),
        ("fileattr", ctypes.c_uint32),
        ("forkattr", ctypes.c_uint32),
    ]

ATTR_BIT_MAP_COUNT = 5
ATTR_CMN_OWNERID = 0x00008000
ATTR_CMN_GRPID = 0x00010000
ATTR_CMN_ACCESSMASK = 0x00020000
ATTR_CMN_FLAGS = 0x00040000

def setattr_one(label, path, common, value):
    """Set exactly one ATTR_CMN_* attribute, and report what the kernel answered."""
    attrs = Attrlist(ATTR_BIT_MAP_COUNT, 0, common, 0, 0, 0, 0)
    buf = ctypes.c_uint32(value)
    # A zero-attribute call passes a zero-length buffer, which is what "ask for nothing" means.
    size = 0 if common == 0 else ctypes.sizeof(buf)
    ctypes.set_errno(0)
    rc = libc().setattrlist(
        path.encode(), ctypes.byref(attrs), ctypes.byref(buf),
        size, ctypes.c_ulong(0),
    )
    errno = ctypes.get_errno()
    if rc == 0:
        print(label, "OK", "stored")
    else:
        print(label, "ERR", errno, "rc", rc)

BH = os.environ["HOME"]
F = BH + "/cn-f-03.txt"
open(F, "w").write("x")

# Positive control: the legacy call to the GRANTED leaf works, so the file and the cell are
# both real and an ordinary mode change is not what this case refuses.
os.chmod(F, 0o644)
print("chmod_stored_mode", oct(os.stat(F).st_mode & 0o777))

# Positive control on the SYSCALL, not on a different one. A zero-attribute setattrlist asks for
# no authority, so it must succeed. Without it, all four arms below read the same whether the
# profile refuses per attribute or the call is dead in the probe, the kernel, or the sandbox.
setattr_one("setattrlist_no_attributes", F, 0, 0)

# The setattrlist route to the same three authorities the write cell does not name.
setattr_one("setattrlist_accessmask", F, ATTR_CMN_ACCESSMASK, 0o777)
setattr_one("setattrlist_grpid", F, ATTR_CMN_GRPID, os.getgid())
setattr_one("setattrlist_ownerid", F, ATTR_CMN_OWNERID, os.getuid())
setattr_one("setattrlist_flags", F, ATTR_CMN_FLAGS, 2)

# The mode after every refusal: still what chmod stored, so nothing landed by another route.
print("final_stored_mode", oct(os.stat(F).st_mode & 0o777))

# Clear the file flags before unlinking. Inside the box the FLAGS arm is refused and this
# changes nothing, but under a permissive box it SUCCEEDS and stores UF_IMMUTABLE, and an
# immutable file cannot be removed — which leaves the fixture undeletable for the rest of the
# run. Cleanup must not depend on the profile refusing.
libc().chflags(F.encode(), 0)
os.unlink(F)
"#,
        );
        // Positive control: `chmod` reaches the granted `file-write-mode` leaf.
        r.assert_contains("chmod_stored_mode 0o644");
        // Positive control on the syscall itself: asking for no attribute succeeds, so
        // `setattrlist` does reach the profile and the four refusals below are per-attribute.
        r.assert_ok("setattrlist_no_attributes", "stored");
        // The same attribute through `setattrlist` is refused, because it never dispatches to
        // that leaf. This pair is the case.
        r.assert_errno("setattrlist_accessmask", 1);
        // Owner and group are absent from the allowlist, so `(deny default)` refuses both.
        r.assert_errno("setattrlist_grpid", 1);
        r.assert_errno("setattrlist_ownerid", 1);
        // The one attribute a leaf deny ever reached is refused under the allowlist too.
        r.assert_errno("setattrlist_flags", 1);
        // No refused arm stored its value by a side route.
        r.assert_contains("final_stored_mode 0o644");
    }
}

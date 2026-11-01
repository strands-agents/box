
use strands_det_harness::det_case;

// New macOS operations do not receive access automatically.
//
// The macOS profile reads exactly the named sysctls. A new operation must stay denied until
// the profile names it, so this case bounds the grant from ABOVE: it requires that a name the
// profile does not carry is refused (rc -1, errno 1), not merely that the granted names work.
//
// macOS-only: there is no Linux counterpart in the shared tree.
det_case! {
    name: cn_p_02,
    id:   "CN-P-02",
    platforms: [Macos],
    desc: "sysctl census: granted names answer; unnamed sysctls stay refused with errno 1",
    run: |b| {
        b.reset_policy();
        let r = b.probe_py(
            r#"
def probe(name):
    import ctypes
    ctypes.set_errno(0)
    size = ctypes.c_size_t(0)
    rc = libc().sysctlbyname(name.encode(), None, ctypes.byref(size), None, ctypes.c_size_t(0))
    errno = ctypes.get_errno()
    label = "sysctl_" + name.replace(".", "_")
    if rc == 0:
        print(label, "OK", "rc=0 errno=0")
    else:
        print(label, "ERR", errno, "rc", rc)
for n in ["kern.hostname", "kern.osrelease", "kern.ostype", "hw.ncpu", "hw.machine"]:
    probe(n)
for n in ["kern.boottime", "kern.argmax", "hw.memsize", "kern.procname"]:
    probe(n)
"#,
        );
        // Granted names answer.
        r.assert_ok("sysctl_kern_hostname", "rc=0 errno=0");
        r.assert_ok("sysctl_kern_osrelease", "rc=0 errno=0");
        r.assert_ok("sysctl_hw_ncpu", "rc=0 errno=0");
        r.assert_ok("sysctl_hw_machine", "rc=0 errno=0");
        // Names the profile does not carry stay refused, so a new operation gets no access.
        r.assert_errno("sysctl_kern_boottime", 1);
        r.assert_errno("sysctl_kern_argmax", 1);
        r.assert_errno("sysctl_hw_memsize", 1);
    }
}

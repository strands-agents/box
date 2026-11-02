use std::process::Command;
use strands_det_harness::{det_case, native_python};

const PROBE: &str = r#"
import ctypes, os
lib = ctypes.CDLL(None, use_errno=True)
class Utsname(ctypes.Structure):
    _fields_ = [(name, ctypes.c_char * 65) for name in
                ("sysname", "nodename", "release", "version", "machine", "domainname")]
class Sysinfo(ctypes.Structure):
    _fields_ = [
        ("uptime", ctypes.c_long), ("loads", ctypes.c_ulong * 3),
        *[(name, ctypes.c_ulong) for name in
          ("totalram", "freeram", "sharedram", "bufferram", "totalswap", "freeswap")],
        ("procs", ctypes.c_ushort), ("pad", ctypes.c_ushort),
        ("totalhigh", ctypes.c_ulong), ("freehigh", ctypes.c_ulong),
        ("mem_unit", ctypes.c_uint),
        ("reserved", ctypes.c_char * (20 - 2 * ctypes.sizeof(ctypes.c_long) - ctypes.sizeof(ctypes.c_int))),
    ]
def check_rc(rc):
    if rc != 0:
        error = ctypes.get_errno()
        raise OSError(error, os.strerror(error))
def identity():
    value = Utsname()
    check_rc(lib.uname(ctypes.byref(value)))
    assert value.sysname == b"Linux"
    assert all(getattr(value, name) for name in ("nodename", "release", "version", "machine"))
    assert isinstance(value.domainname, bytes)
    return True
def statistics():
    value = Sysinfo()
    check_rc(lib.sysinfo(ctypes.byref(value)))
    assert value.uptime >= 0 and value.mem_unit > 0 and value.totalram > 0
    assert len(value.loads) == 3 and value.procs > 0
    for name in ("freeram", "sharedram", "bufferram", "totalswap", "freeswap", "totalhigh", "freehigh"):
        assert getattr(value, name) >= 0
    return True
def set_name():
    name = b"box-system-info-control"
    lib.sethostname.argtypes = [ctypes.c_char_p, ctypes.c_size_t]
    check_rc(lib.sethostname(name, len(name)))
    return os.uname().nodename == name.decode()
"#;

det_case! {
    name: cn_linux_system_information,
    id: "CN-LINUX-SYSTEM-INFORMATION",
    platforms: [Linux],
    desc: "Linux exposes identity and aggregate statistics but refuses workload hostname changes",
    run: |b| {
        let python = native_python();
        let before = std::fs::read_to_string("/proc/sys/kernel/hostname").unwrap();
        let parent_namespace = std::fs::read_link("/proc/self/ns/uts").unwrap();
        let namespace = serde_json::to_string(&parent_namespace.to_string_lossy()).unwrap();
        let control = Command::new("unshare")
            .args(["--user", "--map-root-user", "--uts"])
            .arg(&python.executable)
            .args(["-c", &format!(
                "{PROBE}\n\
                 assert os.readlink('/proc/self/ns/uts') != {namespace}\n\
                 assert identity() and statistics()\n\
                 assert set_name()\n\
                 print('SYSTEM_INFORMATION_CONTROL_OK')"
            )])
            .output()
            .expect("DET_ERROR: run the isolated hostname control");
        assert!(control.status.success(), "DET_ERROR: isolated control failed: {control:?}");
        assert!(String::from_utf8_lossy(&control.stdout).contains("SYSTEM_INFORMATION_CONTROL_OK"));
        assert_eq!(std::fs::read_to_string("/proc/sys/kernel/hostname").unwrap(), before);

        let result = b.probe_py(&format!(
            "{PROBE}\n\
             before = os.uname().nodename\n\
             t('uname_fields', identity)\n\
             t('sysinfo_fields', statistics)\n\
             t('hostname_change', set_name)\n\
             t('hostname_unchanged', lambda: os.uname().nodename == before)"
        ));
        assert_eq!(result.rc, 0, "the complete probe must exit successfully");
        result.assert_ok("uname_fields", "True");
        result.assert_ok("sysinfo_fields", "True");
        result.assert_errno("hostname_change", 1);
        result.assert_ok("hostname_unchanged", "True");
        assert_eq!(std::fs::read_to_string("/proc/sys/kernel/hostname").unwrap(), before);
    }
}


use crate::phase3 as support;
use std::process::Command;
use strands_det_harness::{BoxFixture, Platform, det_case, native_python};

det_case! {
    name: cn_i_04,
    id:   "CN-I-04",
    platforms: [Macos, Linux],
    desc: "Process queries: macOS retains foreign-process visibility; Linux refuses queries against a live host process",
    run: |b| {
        b.reset_policy();
        if Platform::current() == Platform::Linux {
            linux_queries(b);
            return;
        }
        let r = b.probe_py(
            r#"
def oracle(label, name, *args):
    result = raw(name, *args)
    if result[3] == 0:
        print(label, "OK", "answered")
    else:
        print(label, "ERR", result[3], "rc", result[1])
oracle("getpgid_pid1", "getpgid", 1)
oracle("getsid_pid1", "getsid", 1)
oracle("getpriority_pid1", "getpriority", 0, 1)
"#,
        );
        // The exact pgid, sid, and priority are host state. The residual is
        // that all three foreign-pid queries answer with errno 0.
        r.assert_ok("getpgid_pid1", "answered");
        r.assert_ok("getsid_pid1", "answered");
        r.assert_ok("getpriority_pid1", "answered");
    }
}

fn linux_queries(b: &BoxFixture) {
    let probe = support::compile(b);
    let mut marker =
        support::Marker::start(&probe, &b.workspace().with_file_name("query-marker"), false);
    let pid = marker.pid();
    let control = Command::new(&native_python().executable)
        .args(["-c", &format!(
            "import os\n\
             os.getpgid({pid})\n\
             os.getsid({pid})\n\
             os.getpriority(os.PRIO_PROCESS, {pid})\n\
             print('HOST_QUERIES_SUCCEEDED')"
        )])
        .output()
        .expect("DET_ERROR: run the host process-query control");
    assert!(support::text(control).contains("HOST_QUERIES_SUCCEEDED"));
    let result = b.probe_py(&format!(
        "t('self_process_group', lambda: os.getpgid(0) == os.getpgrp())\n\
         t('getsid_self', lambda: os.getsid(0))\n\
         t('getpriority_self', lambda: os.getpriority(os.PRIO_PROCESS, 0))\n\
         t('getpgid_host', lambda: os.getpgid({pid}))\n\
         t('getsid_host', lambda: os.getsid({pid}))\n\
         t('getpriority_host', lambda: os.getpriority(os.PRIO_PROCESS, {pid}))"
    ));
    result.assert_ok("self_process_group", "True");
    result.assert_errno("getpgid_host", 3);
    // The syscall filter refuses getsid and getpriority regardless of the target process.
    result.assert_errno("getsid_self", 1);
    result.assert_errno("getpriority_self", 1);
    result.assert_errno("getsid_host", 1);
    result.assert_errno("getpriority_host", 1);
    marker.advance();
}

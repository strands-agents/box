// Referenced only inside this case's `#[cfg(target_os = "linux")]` body.
#[cfg(target_os = "linux")]
use crate::phase3 as support;
use strands_det_harness::det_case;

det_case! {
    name: cn_i_10,
    id: "CN-I-10",
    platforms: [Linux],
    desc: "A native Unix socket pair works while a live host abstract listener remains unreachable",
    run: |b| {
        #[cfg(target_os = "linux")]
        {
            use std::io::Read;
            use std::os::linux::net::SocketAddrExt;
            use std::os::unix::net::{SocketAddr, UnixListener};
            use std::time::Duration;
            let probe = support::compile(b);
            let name = format!("p3-{}", b.workspace().parent().unwrap().file_name().unwrap().to_string_lossy());
            let addr = SocketAddr::from_abstract_name(name.as_bytes()).expect("DET_ERROR: abstract name");
            let listener = UnixListener::bind_addr(&addr).expect("DET_ERROR: bind owned abstract listener");
            listener.set_nonblocking(true).expect("DET_ERROR: listener nonblocking");
            let receive = || {
                let (mut stream, _) = listener.accept().expect("DET_ERROR: host control connection missing");
                stream.set_read_timeout(Some(Duration::from_secs(2))).expect("DET_ERROR: socket timeout");
                let mut text = String::new();
                stream.read_to_string(&mut text).expect("DET_ERROR: listener read");
                text
            };
            let control = support::host(&probe, &["abstract", &name, "before"]);
            assert!(control.contains("ABSTRACT_REACHED"), "DET_ERROR: abstract control: {control}");
            assert_eq!(receive(), "before", "DET_ERROR: abstract observer control");
            let r = b.run_sh_with_config(b.with_exec_tree(),
                &format!("{} abstract {name} contained", support::q(&probe)));
            support::native_ok(&r, "ABSTRACT_ENTERED");
            r.assert_contains("SOCKETPAIR_OK");
            support::require_refusal(&r.out, "ABSTRACT", &[1, 111]);
            match listener.accept() {
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => (),
                other => panic!("host abstract listener was reached or failed: {other:?}"),
            }
            let after = support::host(&probe, &["abstract", &name, "after"]);
            assert!(after.contains("ABSTRACT_REACHED"), "DET_ERROR: abstract observer after: {after}");
            assert_eq!(receive(), "after", "DET_ERROR: abstract observer after");
        }
    }
}

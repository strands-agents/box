#[cfg(target_os = "linux")]
use std::io::{Read, Write};
use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

unsafe extern "C" {
    fn kill(pid: i32, signal: i32) -> i32;
    fn signal(signal: i32, handler: usize) -> usize;
    fn getpid() -> i32;
    #[cfg(target_os = "linux")]
    fn prctl(option: i32, ...) -> i32;
    #[cfg(target_os = "linux")]
    fn ptrace(request: u32, ...) -> i64;
    #[cfg(target_os = "linux")]
    fn waitpid(pid: i32, status: *mut i32, options: i32) -> i32;
    #[cfg(target_os = "linux")]
    fn shmat(id: i32, address: *const u8, flags: i32) -> *mut u8;
    #[cfg(target_os = "linux")]
    fn shmdt(address: *const u8) -> i32;
    #[cfg(target_os = "linux")]
    fn isatty(fd: i32) -> i32;
    #[cfg(target_os = "linux")]
    fn ioctl(fd: i32, request: usize, ...) -> i32;
}

const USR1: i32 = if cfg!(target_os = "macos") { 30 } else { 10 };
static SIGNALS: AtomicUsize = AtomicUsize::new(0);

extern "C" fn received(_: i32) {
    SIGNALS.fetch_add(1, Ordering::Relaxed);
}

fn atomic_number(dir: &Path, name: &str, value: usize) {
    let stage = dir.join(format!("{name}.stage"));
    std::fs::write(&stage, value.to_string()).expect("DET_ERROR: marker state");
    std::fs::rename(stage, dir.join(name)).expect("DET_ERROR: marker publish");
}

fn marker(args: &[String]) {
    #[cfg(target_os = "linux")]
    {
        let name = std::ffi::CString::new(args[2].as_str()).unwrap();
        assert_eq!(
            unsafe { prctl(15, name.as_ptr(), 0, 0, 0) },
            0,
            "DET_ERROR: marker name"
        );
        if args[4] == "trace" {
            assert_eq!(
                unsafe { prctl(0x59616d61, usize::MAX, 0, 0, 0) },
                0,
                "DET_ERROR: allow tracing this synthetic marker"
            );
        }
    }
    assert_ne!(
        unsafe { signal(USR1, received as *const () as usize) },
        usize::MAX,
        "DET_ERROR: marker signal handler"
    );
    let dir = Path::new(&args[3]);
    atomic_number(dir, "heartbeat", 0);
    atomic_number(dir, "signals", 0);
    std::fs::write(dir.join("ready"), "ready").expect("DET_ERROR: marker ready");
    for tick in 1..6000 {
        atomic_number(dir, "signals", SIGNALS.load(Ordering::Relaxed));
        atomic_number(dir, "heartbeat", tick);
        std::thread::sleep(Duration::from_millis(20));
    }
}

fn result(label: &str, rc: i64) {
    if rc == 0 {
        println!("{label}_REACHED");
    } else {
        println!(
            "{label}_REFUSED {}",
            std::io::Error::last_os_error().raw_os_error().unwrap()
        );
    }
}

fn files(args: &[String]) {
    println!("FILES_ENTERED");
    let own = std::fs::read_to_string(&args[2]).expect("DET_ERROR: own granted file");
    println!("OWN_CONTENT {own}");
    let seen = match std::fs::read_to_string(&args[3]) {
        Ok(text) => format!("OTHER_REACHED {text}"),
        Err(e) => format!(
            "OTHER_REFUSED {}",
            e.raw_os_error().expect("DET_ERROR: file errno")
        ),
    };
    println!("{seen}");
    if let Some(path) = args.get(4) {
        std::fs::write(path, format!("TOOL_WITNESS\nOWN_CONTENT {own}\n{seen}\n"))
            .expect("DET_ERROR: tool witness write");
    }
}

#[cfg(target_os = "linux")]
fn process_view(token: &str) {
    println!("VIEW_ENTERED");
    let pid = unsafe { getpid() };
    let status = std::fs::read_to_string("/proc/self/status").expect("DET_ERROR: own proc status");
    assert!(
        status.lines().any(|l| l == format!("Pid:\t{pid}")),
        "DET_ERROR: self PID"
    );
    println!("SELF_VISIBLE {pid}");
    println!(
        "PID_NAMESPACE {}",
        std::fs::read_link("/proc/self/ns/pid")
            .expect("DET_ERROR: own PID namespace")
            .display()
    );
    let mut count = 0;
    let mut found = false;
    for entry in std::fs::read_dir("/proc").expect("DET_ERROR: enumerate proc") {
        let entry = entry.expect("DET_ERROR: proc entry");
        if entry.file_name().to_string_lossy().parse::<u32>().is_err() {
            continue;
        }
        match std::fs::read_to_string(entry.path().join("comm")) {
            Ok(name) => {
                count += 1;
                found |= name.trim() == token;
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => (),
            Err(e) => panic!("DET_ERROR: read proc comm: {e}"),
        }
    }
    assert!(count > 0, "DET_ERROR: empty process view");
    println!("PROC_ENTRIES {count}");
    println!("HOST_MARKER_{}", if found { "VISIBLE" } else { "ABSENT" });
}

#[cfg(target_os = "linux")]
fn trace(target: i32) {
    println!("TRACE_ENTERED");
    println!("SELF_PID {}", unsafe { getpid() });
    let rc = unsafe { ptrace(16, target, 0usize, 0usize) };
    result("TRACE", rc);
    if rc == 0 {
        let mut status = 0;
        assert_eq!(
            unsafe { waitpid(target, &mut status, 0) },
            target,
            "DET_ERROR: trace stop"
        );
        assert_eq!(status & 0xff, 0x7f, "DET_ERROR: target not stopped");
        assert_eq!(
            unsafe { ptrace(17, target, 0usize, 0usize) },
            0,
            "DET_ERROR: trace detach"
        );
        println!("TRACE_DETACHED");
    }
}

#[cfg(target_os = "linux")]
fn abstract_socket(args: &[String]) {
    use std::os::linux::net::SocketAddrExt;
    use std::os::unix::net::{SocketAddr, UnixStream};
    println!("ABSTRACT_ENTERED");
    let (mut a, mut b) = UnixStream::pair().expect("DET_ERROR: allowed socketpair");
    a.write_all(b"pair").expect("DET_ERROR: socketpair write");
    let mut buf = [0; 4];
    b.read_exact(&mut buf).expect("DET_ERROR: socketpair read");
    assert_eq!(&buf, b"pair", "DET_ERROR: socketpair bytes");
    println!("SOCKETPAIR_OK");
    let address =
        SocketAddr::from_abstract_name(args[2].as_bytes()).expect("DET_ERROR: abstract address");
    match UnixStream::connect_addr(&address) {
        Ok(mut stream) => {
            stream
                .write_all(args[3].as_bytes())
                .expect("DET_ERROR: abstract write");
            println!("ABSTRACT_REACHED");
        }
        Err(e) => println!("ABSTRACT_REFUSED {}", e.raw_os_error().unwrap()),
    }
}

fn descendant(args: &[String]) {
    println!("DESCENDANT_ENTERED");
    let dir = Path::new(&args[2]);
    let end = Instant::now() + Duration::from_secs(120);
    for tick in 1.. {
        if Instant::now() >= end || dir.join("stop").exists() {
            break;
        }
        atomic_number(dir, "heartbeat", tick);
        std::thread::sleep(Duration::from_millis(20));
    }
}

fn workload(args: &[String]) {
    use std::process::{Command, Stdio};
    let dir = Path::new(&args[2]);
    let mut child = Command::new(&args[5])
        .arg("descendant")
        .arg(dir)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("DET_ERROR: workload descendant spawn");
    let end = Instant::now() + Duration::from_secs(15);
    while !dir.join("heartbeat").exists() {
        assert!(
            child.try_wait().expect("DET_ERROR: child state").is_none(),
            "DET_ERROR: descendant exited before readiness"
        );
        assert!(
            Instant::now() < end,
            "DET_ERROR: descendant readiness timeout"
        );
        std::thread::sleep(Duration::from_millis(20));
    }
    println!("DESCENDANT_STARTED {}", child.id());
    std::fs::write(&args[3], "ready").expect("DET_ERROR: workload readiness");
    while !Path::new(&args[4]).exists() {
        assert!(Instant::now() < end, "DET_ERROR: host release timeout");
        std::thread::sleep(Duration::from_millis(20));
    }
    println!("ORDINARY_EXIT");
}

#[cfg(target_os = "linux")]
fn shared_memory(id: i32) {
    println!("SHM_ENTERED");
    let local = vec![0x5au8; 4096];
    assert_eq!(local.iter().map(|&b| b as u64).sum::<u64>(), 4096 * 0x5a);
    println!("LOCAL_MEMORY_OK");
    let address = unsafe { shmat(id, std::ptr::null(), 0o10000) };
    if address as isize == -1 {
        println!(
            "SHM_REFUSED {}",
            std::io::Error::last_os_error().raw_os_error().unwrap()
        );
    } else {
        let bytes = unsafe { std::slice::from_raw_parts(address, 16) };
        println!("SHM_REACHED {}", String::from_utf8_lossy(bytes));
        assert_eq!(
            unsafe { shmdt(address) },
            0,
            "DET_ERROR: detach shared memory"
        );
    }
}

#[cfg(target_os = "linux")]
fn terminal() {
    println!("TTY_ENTERED");
    assert_eq!(
        unsafe { isatty(0) },
        1,
        "DET_ERROR: stdin is not a terminal"
    );
    println!("TTY_STDIN_OK");
    let byte = b'\n';
    result("TIOCSTI", unsafe { ioctl(0, 0x5412, &byte as *const u8) }
        as i64);
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("marker") => marker(&args),
        Some("files") => files(&args),
        Some("signal") => {
            println!("SIGNAL_ENTERED");
            println!("SELF_PID {}", unsafe { getpid() });
            result("SIGNAL", unsafe { kill(args[2].parse().unwrap(), USR1) }
                as i64);
        }
        #[cfg(target_os = "linux")]
        Some("view") => process_view(&args[2]),
        #[cfg(target_os = "linux")]
        Some("trace") => trace(args[2].parse().unwrap()),
        #[cfg(target_os = "linux")]
        Some("abstract") => abstract_socket(&args),
        #[cfg(target_os = "linux")]
        Some("shm") => shared_memory(args[2].parse().unwrap()),
        #[cfg(target_os = "linux")]
        Some("tty") => terminal(),
        Some("descendant") => descendant(&args),
        Some("workload") => workload(&args),
        _ => panic!("DET_ERROR: unknown phase3 probe"),
    }
}

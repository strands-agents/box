use super::*;

#[test]
fn copied_path_ends_at_the_first_nul_and_rejects_unterminated_input() {
    let mut bytes = [b'x'; 4096];
    let mut request = notify::Request {
        pid: std::process::id(),
        ..Default::default()
    };
    request.data.args[0] = bytes.as_ptr() as u64;
    assert_eq!(
        notify::read_path(&request, 0).unwrap_err().kind(),
        std::io::ErrorKind::InvalidInput
    );
    bytes[3] = 0;
    request.data.args[0] = bytes.as_ptr() as u64;
    assert_eq!(notify::read_path(&request, 0).unwrap(), b"xxx");
}

#[test]
fn disabled_guard_removes_loader_capabilities_without_loading_hooks() {
    fn capabilities() -> Vec<u64> {
        std::fs::read_to_string("/proc/self/status")
            .unwrap()
            .lines()
            .filter(|line| {
                ["CapInh:", "CapPrm:", "CapEff:", "CapAmb:"]
                    .iter()
                    .any(|name| line.starts_with(name))
            })
            .map(|line| u64::from_str_radix(line.split_whitespace().nth(1).unwrap(), 16).unwrap())
            .collect()
    }
    let before = capabilities();
    assert_eq!(before.len(), 4);
    // SAFETY: fork takes no pointers; the child operates on its copied address space and exits with _exit.
    let child = unsafe { libc::fork() };
    assert!(child >= 0);
    if child == 0 {
        let result = guard::Guard::prepare(false);
        let loader = (1_u64 << 38) | (1_u64 << 39);
        let expected: Vec<_> = before.iter().map(|bits| bits & !loader).collect();
        let success = matches!(result, Ok(None)) && capabilities() == expected;
        // SAFETY: This is the child branch; _exit terminates it without running inherited Rust destructors.
        unsafe { libc::_exit(if success { 0 } else { 1 }) };
    }
    let mut status = 0;
    // SAFETY: status is writable, and child names the unreaped process created above.
    assert_eq!(unsafe { libc::waitpid(child, &mut status, 0) }, child);
    assert!(libc::WIFEXITED(status));
    assert_eq!(libc::WEXITSTATUS(status), 0);
}

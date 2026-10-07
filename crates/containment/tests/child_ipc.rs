//! Native children and pathname sockets use the declared filesystem boundary.

use std::os::unix::net::UnixListener;
use std::path::Path;
use std::process::{Command, Output};

use containment::{ContainmentConfig, Network, Operation, Scope};
use sha2::{Digest as _, Sha256};

fn config() -> ContainmentConfig {
    let config = ContainmentConfig::new()
        .allow(
            Path::new(env!("CARGO_BIN_EXE_containment-test-probe")),
            Operation::Exec,
            Scope::File,
        )
        .unwrap()
        .allow(Path::new("/"), Operation::Read, Scope::Dir)
        .unwrap()
        .allow(Path::new("/etc"), Operation::Metadata, Scope::Dir)
        .unwrap();
    if cfg!(target_os = "macos") {
        config
            .set_network(Network::localhost().connect(43123))
            .unwrap()
    } else {
        config
    }
}

fn launch(root: &Path, config: &ContainmentConfig, args: &[&str]) -> Output {
    let json = config.to_json().unwrap();
    let digest = Sha256::digest(json.as_bytes())
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    let path = root.join("containment.json");
    std::fs::write(&path, json).unwrap();
    Command::new(env!("CARGO_BIN_EXE_strands-box-contain-trampoline"))
        .args([
            "--config",
            path.to_str().unwrap(),
            "--config-sha256",
            &digest,
        ])
        .args(["--target-env-json", "{}", "--"])
        .arg(env!("CARGO_BIN_EXE_containment-test-probe"))
        .args(args)
        .current_dir("/")
        .output()
        .unwrap()
}

fn supported() -> bool {
    if cfg!(all(target_os = "linux", not(target_arch = "aarch64"))) {
        eprintln!("skipping: Linux containment requires ARM64");
        return false;
    }
    #[cfg(target_os = "linux")]
    if !the_host_can_build_a_view() {
        eprintln!("skipping: this host cannot build a namespace mount view");
        return false;
    }
    true
}

/// Whether this host grants the namespaces and the `proc` mount the view needs.
///
/// A build fleet container holds neither, so a case that launches the trampoline reports the host's
/// own refusal rather than a defect. The probe is a third copy of the one in
/// `contains_exec_target_linux.rs` and `inherited_handles_linux.rs`, forced by the module boundary
/// between integration tests.
#[cfg(target_os = "linux")]
fn the_host_can_build_a_view() -> bool {
    // SAFETY: the child makes syscalls and `_exit`s only. It allocates nothing, formats nothing,
    // and never returns into test-harness code.
    let child = unsafe { libc::fork() };
    if child < 0 {
        // Unmeasurable rather than refused. Let the case run and report its own failure instead of
        // skipping on a probe that never happened.
        return true;
    }
    if child == 0 {
        // SAFETY: syscall-only child.
        unsafe {
            let namespaces = libc::CLONE_NEWUSER | libc::CLONE_NEWNS | libc::CLONE_NEWPID;
            if libc::unshare(namespaces) != 0 {
                libc::_exit(10);
            }
            let inner = libc::fork();
            if inner < 0 {
                libc::_exit(12);
            }
            if inner == 0 {
                let fstype = c"proc".as_ptr();
                let target = c"/proc".as_ptr();
                if libc::mount(fstype, target, fstype, 0, std::ptr::null()) != 0 {
                    libc::_exit(11);
                }
                libc::_exit(0);
            }
            let mut inner_status = 0;
            libc::waitpid(inner, &mut inner_status, 0);
            let mounted = libc::WIFEXITED(inner_status) && libc::WEXITSTATUS(inner_status) == 0;
            libc::_exit(if mounted { 0 } else { 11 });
        }
    }
    let mut status = 0;
    // SAFETY: waiting on this process's own child.
    unsafe { libc::waitpid(child, &mut status, 0) };
    libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0
}

#[test]
fn a_write_root_permits_a_unix_listener_and_roundtrip() {
    if !supported() {
        return;
    }
    let directory = tempfile::Builder::new()
        .prefix("ipc")
        .tempdir_in("/var/tmp")
        .unwrap();
    let root = directory.path().canonicalize().unwrap();
    let writable = root.join("write");
    std::fs::create_dir(&writable).unwrap();
    let config = config()
        .allow(&writable, Operation::Write, Scope::Root)
        .unwrap();
    let socket = writable.join("peer.sock");
    let output = launch(
        &root,
        &config,
        &["--unix-ipc", "roundtrip", socket.to_str().unwrap()],
    );
    assert!(output.status.success(), "{output:?}");
    assert!(
        String::from_utf8_lossy(&output.stdout).contains("IPC_OK"),
        "{output:?}"
    );
}

#[test]
fn unix_sockets_outside_grants_and_under_deny_stay_unreachable() {
    if !supported() {
        return;
    }
    let directory = tempfile::Builder::new()
        .prefix("ipc")
        .tempdir_in("/var/tmp")
        .unwrap();
    let root = directory.path().canonicalize().unwrap();
    let writable = root.join("write");
    let denied = writable.join("denied");
    std::fs::create_dir_all(&denied).unwrap();
    let outside = root.join("outside.sock");
    let outside_alias = writable.join("outside.sock");
    let denied_socket = denied.join("peer.sock");
    let _outside_listener = UnixListener::bind(&outside).unwrap();
    let _denied_listener = UnixListener::bind(&denied_socket).unwrap();
    std::os::unix::fs::symlink(&outside, &outside_alias).unwrap();
    let config = config()
        .allow(&writable, Operation::Write, Scope::Root)
        .unwrap()
        .refuse(&denied, Scope::Root)
        .unwrap();
    for socket in [&outside, &outside_alias, &denied_socket] {
        assert!(std::os::unix::net::UnixStream::connect(socket).is_ok());
        let output = launch(
            &root,
            &config,
            &["--unix-ipc", "connect", socket.to_str().unwrap()],
        );
        assert!(
            String::from_utf8_lossy(&output.stdout).contains("IPC_READY"),
            "{output:?}"
        );
        assert_eq!(output.status.code(), Some(1), "{output:?}");
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            [libc::EPERM, libc::EACCES, libc::ENOENT]
                .iter()
                .any(|errno| stderr.contains(&format!("errno=Some({errno})"))),
            "{output:?}"
        );
    }
    for socket in [root.join("new.sock"), denied.join("new.sock")] {
        let output = launch(
            &root,
            &config,
            &["--unix-ipc", "roundtrip", socket.to_str().unwrap()],
        );
        assert!(
            String::from_utf8_lossy(&output.stdout).contains("IPC_READY"),
            "{output:?}"
        );
        assert_eq!(output.status.code(), Some(1), "{output:?}");
        assert!(!socket.exists());
    }
}

#[test]
fn native_shell_children_need_exec_grants_and_keep_the_parent_boundary() {
    if !supported() {
        return;
    }
    let directory = tempfile::Builder::new()
        .prefix("ipc")
        .tempdir_in("/var/tmp")
        .unwrap();
    let root = directory.path().canonicalize().unwrap();
    let writable = root.join("write");
    std::fs::create_dir(&writable).unwrap();
    let output_file = writable.join("hooks.log");
    let secret = root.join("secret");
    std::fs::write(&secret, "outside\n").unwrap();
    let config = config()
        .allow(&writable, Operation::Write, Scope::Root)
        .unwrap();
    let args = [
        "--shell-child",
        output_file.to_str().unwrap(),
        secret.to_str().unwrap(),
    ];
    let refused = launch(&root, &config, &args);
    assert!(
        String::from_utf8_lossy(&refused.stdout).contains("CHILD_READY"),
        "{refused:?}"
    );
    assert!(!refused.status.success(), "{refused:?}");
    assert!(!output_file.exists());
    let config = config
        .allow(Path::new("/bin/sh"), Operation::Exec, Scope::File)
        .unwrap()
        .allow(Path::new("/bin/bash"), Operation::Exec, Scope::File)
        .unwrap();
    let allowed = launch(&root, &config, &args);
    assert!(allowed.status.success(), "{allowed:?}");
    assert_eq!(std::fs::read_to_string(output_file).unwrap(), "hooked");
    assert_eq!(std::fs::read_to_string(secret).unwrap(), "outside\n");
}

//! Linux end-to-end proof that a `#!/bin/sh` script runs when only `/usr/bin/sh` is granted, on a
//! host where `/bin` is a link to `usr/bin`, and that the link reaches no ungranted or refused file.

#![cfg(all(
    target_os = "linux",
    any(target_arch = "aarch64", target_arch = "x86_64")
))]

use std::path::Path;
use std::process::Command;

use containment::{ContainmentConfig, Operation, Scope};
use sha2::{Digest as _, Sha256};

/// pnpm's `node_modules/.bin` commands and uvx's cached tool commands are `#!/bin/sh` scripts. The
/// view binds the granted `/usr/bin/sh`, and the host's `/bin -> usr/bin` link in the view is what
/// lets the kernel find the interpreter under the name the script uses.
#[test]
fn a_bin_sh_script_runs_through_the_hosts_bin_link() {
    let bin = Path::new("/bin");
    let sh = Path::new("/usr/bin/sh");
    if std::fs::read_link(bin).ok().as_deref() != Some(Path::new("usr/bin")) || !sh.exists() {
        println!("skipping: this host's /bin is not a link to usr/bin, or it has no /usr/bin/sh");
        return;
    }
    if !the_host_can_build_a_view() {
        println!("skipping: this host cannot build a namespace mount view");
        return;
    }

    let scripts = tempfile::tempdir().expect("script directory");
    let script = scripts.path().join("run");
    // `/usr/bin/cat` is granted and refused through the link as `/bin/cat`, so the script checks
    // that the link reaches the empty overmount: a real `cat` would echo its input. `/bin/ls` is
    // never granted, so the link must not reach it.
    std::fs::write(
        &script,
        "#!/bin/sh\n\
         echo ROOT_LINK_SCRIPT_RAN\n\
         [ -e /bin/ls ] || echo UNGRANTED_ABSENT\n\
         [ -s /bin/cat ] || echo REFUSED_EMPTY\n\
         out=$(printf CAT_RAN | /bin/cat 2>/dev/null)\n\
         [ \"$out\" = CAT_RAN ] && echo REFUSED_CAT_RAN\n\
         exit 0\n",
    )
    .expect("write the script");
    let mut permissions = std::fs::metadata(&script)
        .expect("script metadata")
        .permissions();
    std::os::unix::fs::PermissionsExt::set_mode(&mut permissions, 0o755);
    std::fs::set_permissions(&script, permissions).expect("make the script executable");

    let cat = Path::new("/usr/bin/cat");
    let mut config = ContainmentConfig::new()
        .allow(scripts.path(), Operation::Read, Scope::Root)
        .expect("read the script directory")
        .allow(&script, Operation::Exec, Scope::File)
        .expect("execute the script")
        .allow(sh, Operation::Read, Scope::File)
        .expect("read /usr/bin/sh")
        .allow(sh, Operation::Exec, Scope::File)
        .expect("execute /usr/bin/sh");
    if cat.exists() {
        config = config
            .allow(cat, Operation::Read, Scope::File)
            .expect("read /usr/bin/cat")
            .allow(cat, Operation::Exec, Scope::File)
            .expect("execute /usr/bin/cat")
            .refuse("/bin/cat", Scope::File)
            .expect("refuse /bin/cat");
    }
    let config_json = config.to_json().expect("config json");
    let config_sha256 = Sha256::digest(config_json.as_bytes())
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    let config_file = tempfile::NamedTempFile::new().expect("config file");
    std::fs::write(config_file.path(), config_json).expect("write config");

    let output = Command::new(env!("CARGO_BIN_EXE_strands-box-contain-trampoline"))
        .current_dir(scripts.path())
        .arg("--config")
        .arg(config_file.path())
        .arg("--config-sha256")
        .arg(config_sha256)
        .arg("--target-env-json")
        .arg("{}")
        .arg("--")
        .arg(&script)
        .output()
        .expect("launch the real containment trampoline");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(
        output.status.code(),
        Some(0),
        "a #!/bin/sh script must start when /usr/bin/sh is granted; ENOENT here means the view \
         has no /bin link:\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
    assert!(
        stdout.contains("ROOT_LINK_SCRIPT_RAN"),
        "stdout:\n{stdout}\nstderr:\n{stderr}"
    );
    if Path::new("/usr/bin/ls").exists() {
        assert!(
            stdout.contains("UNGRANTED_ABSENT"),
            "the /bin link must reach only what the view binds, and /usr/bin/ls is not granted:\n\
             stdout:\n{stdout}\nstderr:\n{stderr}"
        );
    }
    if cat.exists() {
        assert!(
            stdout.contains("REFUSED_EMPTY") && !stdout.contains("REFUSED_CAT_RAN"),
            "a refusal written as /bin/cat must overmount the granted /usr/bin/cat, so the link \
             reaches an empty file that does not run cat:\nstdout:\n{stdout}\nstderr:\n{stderr}"
        );
    }
}

fn the_host_can_build_a_view() -> bool {
    // SAFETY: the child uses syscalls only and calls `_exit`.
    let child = unsafe { libc::fork() };
    if child < 0 {
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
                if libc::mount(
                    c"proc".as_ptr(),
                    c"/proc".as_ptr(),
                    c"proc".as_ptr(),
                    0,
                    std::ptr::null(),
                ) != 0
                {
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
    // SAFETY: wait for this process's child.
    unsafe { libc::waitpid(child, &mut status, 0) };
    libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0
}

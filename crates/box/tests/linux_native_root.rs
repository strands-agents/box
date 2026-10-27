//! Root startup and mixed-capability cleanup through the public entry points.
#[cfg(not(all(target_os = "linux", box_native_kernel_tests)))]
fn main() {}

#[cfg(all(target_os = "linux", box_native_kernel_tests))]
fn main() {
    root::run();
}

#[cfg(all(target_os = "linux", box_native_kernel_tests))]
mod root {
    use std::path::{Path, PathBuf};
    use std::process::{Command, ExitCode};

    const LOADER: u64 = (1 << 38) | (1 << 39);
    const SETFCAP: u64 = 1 << 31;

    fn capabilities(status: &str, field: &str) -> u64 {
        u64::from_str_radix(
            status
                .lines()
                .find_map(|line| line.strip_prefix(field))
                .unwrap()
                .trim(),
            16,
        )
        .unwrap()
    }

    fn config(root: &Path, global: bool) -> String {
        let quote = |path: &Path| toml::Value::String(path.display().to_string()).to_string();
        format!(
            "name = \"root-capabilities\"\nbox_dir = {}\npolicy = \"policy.dw\"\n\
             [experimental-features]\nnative-filesystem-policy = {global}\n\
             [agent]\ncommand = [\"/usr/bin/true\"]\nworkspace = {}\nnative-filesystem-policy = false\n",
            quote(&root.join("state")),
            quote(&root.join("workspace"))
        )
    }

    fn fixture() -> tempfile::TempDir {
        let root = tempfile::tempdir_in("/var/tmp").unwrap();
        std::fs::create_dir(root.path().join("workspace")).unwrap();
        std::fs::write(
            root.path().join("policy.dw"),
            "permit(principal, action, resource);\n",
        )
        .unwrap();
        root
    }

    fn binary() -> PathBuf {
        std::env::var_os("BOX_NATIVE_ROOT_TEST_BINARY")
            .map(PathBuf::from)
            .unwrap_or_else(|| env!("CARGO_BIN_EXE_strands-box").into())
    }

    fn install_bundle(root: &Path, executable: &Path, companions: &Path) -> PathBuf {
        let directory = root.join("bin");
        std::fs::create_dir(&directory).unwrap();
        let installed = directory.join(executable.file_name().unwrap());
        std::fs::copy(executable, &installed).unwrap();
        for name in ["strands-box-contain-trampoline", "strands-box-sock-alias"] {
            std::fs::copy(companions.join(name), directory.join(name)).unwrap();
        }
        installed
    }

    pub(super) fn run() {
        assert_eq!(
            unsafe { libc::getuid() },
            0,
            "run this suite through the root test runner"
        );
        let status = std::fs::read_to_string("/proc/self/status").unwrap();
        assert_eq!(
            capabilities(&status, "CapEff:") & (LOADER | SETFCAP),
            LOADER | SETFCAP
        );
        if let Some(argument) = std::env::args().find(|arg| arg.starts_with("--callback-")) {
            callback(argument == "--callback-permitted-only");
            return;
        }
        for global in [false, true] {
            let root = fixture();
            let path = root.path().join("box.toml");
            std::fs::write(&path, config(root.path(), global)).unwrap();
            let binary = binary();
            let installed = install_bundle(root.path(), &binary, binary.parent().unwrap());
            let output = Command::new(installed)
                .args(["run", "--config"])
                .arg(&path)
                .env("EXPERIMENTAL_LINUX_SUPPORT", "TRUE")
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "global={global}: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }
        let root = fixture();
        let executable = std::env::current_exe().unwrap();
        let binary = binary();
        let companions = binary.parent().unwrap();
        let installed = install_bundle(root.path(), &executable, companions);
        for argument in ["--callback-full", "--callback-permitted-only"] {
            let output = Command::new(&installed)
                .arg(argument)
                .env("EXPERIMENTAL_LINUX_SUPPORT", "TRUE")
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "{argument}: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }
        println!(
            "root native regression: global-off, workload-off, full-capability callback, and permitted-only callback passed"
        );
    }

    fn callback(permitted_only: bool) {
        #[repr(C)]
        struct Header {
            version: u32,
            pid: i32,
        }
        #[repr(C)]
        #[derive(Clone, Copy, Default)]
        struct Data {
            effective: u32,
            permitted: u32,
            inheritable: u32,
        }
        let header = Header {
            version: 0x2008_0522,
            pid: 0,
        };
        let mut data = [Data::default(); 2];
        assert_eq!(
            unsafe { libc::syscall(libc::SYS_capget, &header, data.as_mut_ptr()) },
            0
        );
        let mask = (LOADER >> 32) as u32;
        if permitted_only {
            data[1].effective &= !mask;
        }
        data[1].inheritable |= mask;
        data[0].inheritable |= SETFCAP as u32;
        assert_eq!(
            unsafe { libc::syscall(libc::SYS_capset, &header, data.as_ptr()) },
            0
        );
        for capability in [31, 38, 39] {
            assert_eq!(
                unsafe {
                    libc::prctl(
                        libc::PR_CAP_AMBIENT,
                        libc::PR_CAP_AMBIENT_RAISE,
                        capability,
                        0,
                        0,
                    )
                },
                0
            );
        }
        let root = fixture();
        let path = root.path().join("created-by-callback.toml");
        let body = config(root.path(), false);
        let code = strands_box::run(
            path.clone(),
            Vec::new(),
            strands_box::RunOptions {
                on_ready: Some(Box::new(|| {
                    for entry in std::fs::read_dir("/proc/self/task")? {
                        let status = std::fs::read_to_string(entry?.path().join("status"))?;
                        for field in ["CapEff:", "CapPrm:", "CapInh:", "CapAmb:"] {
                            assert_eq!(
                                capabilities(&status, field) & LOADER,
                                0,
                                "{field}: {status}"
                            );
                        }
                        assert_eq!(capabilities(&status, "CapEff:") & SETFCAP, SETFCAP);
                        assert_eq!(capabilities(&status, "CapAmb:") & SETFCAP, SETFCAP);
                    }
                    std::fs::write(&path, &body)
                })),
                ..Default::default()
            },
        );
        assert_eq!(code, ExitCode::SUCCESS);
        assert!(path.exists());
    }
}

//! Root startup and mixed-capability cleanup through the public entry points.
#[cfg(not(all(target_os = "linux", box_native_kernel_tests)))]
fn main() {}

#[cfg(all(target_os = "linux", box_native_kernel_tests))]
fn main() {
    root::run();
}

#[cfg(all(target_os = "linux", box_native_kernel_tests))]
#[path = "support/bounded_output.rs"]
mod bounded_output;

#[cfg(all(target_os = "linux", box_native_kernel_tests))]
mod root {
    use super::bounded_output::bounded_output;
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
            callback(&argument);
            return;
        }
        for global in [false, true] {
            let root = fixture();
            let path = root.path().join("box.toml");
            std::fs::write(&path, config(root.path(), global)).unwrap();
            let binary = binary();
            let installed = install_bundle(root.path(), &binary, binary.parent().unwrap());
            let mut command = Command::new(installed);
            command
                .args(["run", "--config"])
                .arg(&path)
                .env("EXPERIMENTAL_LINUX_SUPPORT", "TRUE");
            command.stdin(std::process::Stdio::null());
            let output = bounded_output(command);
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
        for argument in [
            "--callback-full",
            "--callback-permitted-only",
            "--callback-existing-off",
            "--callback-existing-absent",
            "--callback-enables-native",
            "--callback-creates-native",
        ] {
            let mut command = Command::new(&installed);
            command
                .arg(argument)
                .env("EXPERIMENTAL_LINUX_SUPPORT", "TRUE");
            command.stdin(std::process::Stdio::null());
            let output = bounded_output(command);
            assert!(
                output.status.success(),
                "{argument}: {}",
                String::from_utf8_lossy(&output.stderr)
            );
            if argument == "--callback-enables-native" {
                assert!(
                    String::from_utf8_lossy(&output.stderr).contains(
                        "native filesystem selection changed after capability preparation; restart with native filesystem policy already enabled"
                    ),
                    "{}",
                    String::from_utf8_lossy(&output.stderr)
                );
            }
        }
        println!(
            "root native regression: ordinary startup, callback capability cleanup, opted-out callbacks, and callback native selection passed"
        );
    }

    fn callback(argument: &str) {
        let permitted_only = argument == "--callback-permitted-only";
        let existing = matches!(
            argument,
            "--callback-existing-off" | "--callback-existing-absent" | "--callback-enables-native"
        );
        let enables_native = argument == "--callback-enables-native";
        let native = enables_native || argument == "--callback-creates-native";
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
        let without_native_flags = |body: String| {
            body.replace(
                "[experimental-features]\nnative-filesystem-policy = false\n",
                "",
            )
            .replace("native-filesystem-policy = false\n", "")
        };
        if existing {
            let body = config(root.path(), false);
            let body = if argument == "--callback-existing-absent" {
                without_native_flags(body)
            } else {
                body
            };
            std::fs::write(&path, body).unwrap();
        }
        let marker = root.path().join("workspace/workload-ran");
        let command = toml::Value::Array(
            ["/usr/bin/touch".into(), marker.display().to_string()]
                .into_iter()
                .map(toml::Value::String)
                .collect(),
        );
        let mut body =
            config(root.path(), native).replace("[\"/usr/bin/true\"]", &command.to_string());
        if native {
            body = body.replace("native-filesystem-policy = false\n", "");
        } else if argument == "--callback-existing-absent" {
            body = without_native_flags(body);
        }
        body.push_str(&format!(
            "[agent.filesystem]\nread = [{0}]\nwrite = [{0}]\n",
            toml::Value::String(root.path().join("workspace").display().to_string())
        ));
        let code = strands_box::run(
            path.clone(),
            Vec::new(),
            strands_box::RunOptions {
                on_ready: Some(Box::new(|| {
                    assert!(
                        !root.path().join("state").exists(),
                        "native selection must not create box_dir before the callback"
                    );
                    let guard_descriptors: Vec<_> = std::fs::read_dir("/proc/self/fd")?
                        .filter_map(|entry| std::fs::read_link(entry.ok()?.path()).ok())
                        .filter(|target| target.to_string_lossy().contains("bpf"))
                        .collect();
                    assert_eq!(
                        !guard_descriptors.is_empty(),
                        !existing && !permitted_only,
                        "{argument}: native guard descriptors: {guard_descriptors:?}"
                    );
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
        if enables_native {
            assert_ne!(code, ExitCode::SUCCESS);
            assert!(
                !marker.exists(),
                "refused native selection ran the workload"
            );
        } else {
            assert_eq!(code, ExitCode::SUCCESS);
            assert!(
                marker.exists(),
                "the callback's final configuration was ignored"
            );
        }
        assert!(path.exists());
    }
}

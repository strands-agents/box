//! Process protections and repeat-run refusal through the public library entry point.

#[cfg(target_os = "macos")]
#[path = "support/bounded_output.rs"]
mod bounded_output;

#[cfg(unix)]
fn main() {
    #[cfg(target_os = "macos")]
    if let Some(home) = std::env::var_os("BOX_TEST_INSTALLATION") {
        let home = std::path::PathBuf::from(home);
        let code = strands_box::run(
            home.join("box.toml"),
            Vec::new(),
            strands_box::RunOptions {
                on_ready: Some(Box::new(|| {
                    std::os::unix::fs::symlink("new", home.join("packages/next"))?;
                    std::fs::rename(home.join("packages/next"), home.join("packages/current"))
                })),
                ..Default::default()
            },
        );
        std::process::exit(if code == std::process::ExitCode::SUCCESS {
            0
        } else {
            1
        });
    }
    #[cfg(target_os = "linux")]
    if std::env::args().any(|argument| argument == "--linux-refusal") {
        let mut called = false;
        assert_eq!(
            strands_box::run(
                "/missing-linux-library.toml".into(),
                Vec::new(),
                strands_box::RunOptions {
                    on_ready: Some(Box::new(|| {
                        called = true;
                        Ok(())
                    })),
                    ..Default::default()
                },
            ),
            std::process::ExitCode::FAILURE
        );
        assert!(!called, "opt-in refusal must precede the callback");
        assert_eq!(
            strands_box::generate_policy_schema(
                "/missing-linux-schema.toml".into(),
                "/missing-linux-schema-output".into(),
            ),
            std::process::ExitCode::FAILURE
        );
        return;
    }
    if std::env::args().any(|argument| argument == "--probe") {
        hardening_and_repeat_run();
        return;
    }
    if std::env::args().any(|argument| argument == "--callback-config") {
        let directory = tempfile::tempdir().unwrap();
        let config = directory.path().join("created-by-callback.toml");
        let code = strands_box::run(
            config.clone(),
            Vec::new(),
            strands_box::RunOptions {
                on_ready: Some(Box::new(|| std::fs::write(&config, "["))),
                ..Default::default()
            },
        );
        assert_eq!(code, std::process::ExitCode::FAILURE);
        assert!(config.exists());
        return;
    }
    if std::env::args().any(|argument| argument == "--callback-error") {
        let code = strands_box::run(
            "/missing-callback-config.toml".into(),
            Vec::new(),
            strands_box::RunOptions {
                on_ready: Some(Box::new(|| Err(std::io::Error::other("callback refused")))),
                ..Default::default()
            },
        );
        assert_eq!(code, std::process::ExitCode::FAILURE);
        return;
    }

    #[cfg(target_os = "macos")]
    symlinked_library_keeps_helpers_after_upgrade();

    let output = std::process::Command::new(std::env::current_exe().expect("test executable"))
        .arg("--probe")
        .env("EXPERIMENTAL_LINUX_SUPPORT", "TRUE")
        .output()
        .expect("run the library probe");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(output.status.success(), "{stderr}");
    assert!(stderr.contains("missing.toml"), "{stderr}");
    assert!(
        stderr.lines().any(|line| {
            line == "strands-box: refusing to run: this process already attempted to run a box"
        }),
        "{stderr}"
    );
    let output = std::process::Command::new(std::env::current_exe().unwrap())
        .arg("--callback-error")
        .env("EXPERIMENTAL_LINUX_SUPPORT", "TRUE")
        .output()
        .unwrap();
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(output.status.success(), "{stderr}");
    assert!(
        stderr.contains("on_ready callback failed: callback refused"),
        "{stderr}"
    );
    assert!(!stderr.contains("missing-callback-config.toml"), "{stderr}");

    let output = std::process::Command::new(std::env::current_exe().unwrap())
        .arg("--callback-config")
        .env("EXPERIMENTAL_LINUX_SUPPORT", "TRUE")
        .output()
        .unwrap();
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(output.status.success(), "{stderr}");
    assert!(stderr.contains("cannot parse config file"), "{stderr}");
    assert!(
        !stderr.contains("cannot read configuration source"),
        "{stderr}"
    );

    #[cfg(target_os = "linux")]
    for value in [None, Some("true"), Some("1")] {
        let mut command = std::process::Command::new(std::env::current_exe().unwrap());
        command
            .arg("--linux-refusal")
            .env_remove("EXPERIMENTAL_LINUX_SUPPORT");
        if let Some(value) = value {
            command.env("EXPERIMENTAL_LINUX_SUPPORT", value);
        }
        let output = command.output().expect("run the Linux refusal probe");
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(output.status.success(), "{stderr}");
        assert_eq!(
            stderr.matches("Linux support is experimental.").count(),
            2,
            "{stderr}"
        );
        assert!(!stderr.contains("missing-linux-"), "{stderr}");
    }
}

#[cfg(target_os = "macos")]
fn symlinked_library_keeps_helpers_after_upgrade() {
    use std::fs;
    use std::os::unix::fs::symlink;
    use std::path::Path;
    use std::process::Command;

    let directory = tempfile::Builder::new()
        .prefix("bi")
        .tempdir_in("/var/tmp")
        .unwrap();
    let home = directory.path().canonicalize().unwrap();
    let release = home.join("packages/old");
    fs::create_dir_all(&release).unwrap();
    fs::create_dir_all(home.join("packages/new")).unwrap();
    fs::create_dir(home.join("bin")).unwrap();
    fs::create_dir(home.join("project")).unwrap();
    fs::copy(std::env::current_exe().unwrap(), release.join("boxy")).unwrap();
    let built = Path::new(env!("CARGO_BIN_EXE_strands-box"))
        .parent()
        .unwrap();
    let helpers = ["strands-box-sock-alias", "strands-box-contain-trampoline"];
    for helper in helpers {
        fs::copy(built.join(helper), release.join(helper)).unwrap();
    }
    symlink("../packages/current/boxy", home.join("bin/boxy")).unwrap();
    fs::write(
        home.join("policy.dw"),
        r#"
permit(principal, action == Box::Action::"shell:exec", resource)
when { context.input.command == "printf helper-ok" };
"#,
    )
    .unwrap();
    fs::write(
        home.join("box.toml"),
        format!(
            r#"
name = "installation"
box_dir = "{home}/state"
policy = "{home}/policy.dw"
[agent]
command = ["/bin/bash", "--noprofile", "--norc", "-c", "bash -c 'printf helper-ok'"]
workspace = "{home}/project"
"#,
            home = home.display()
        ),
    )
    .unwrap();
    for missing in [None, Some(helpers[0]), Some(helpers[1])] {
        if home.join("state").exists() {
            fs::remove_dir_all(home.join("state")).unwrap();
        }
        let current = home.join("packages/current");
        if current.exists() {
            fs::remove_file(&current).unwrap();
        }
        symlink("old", &current).unwrap();
        if let Some(helper) = missing {
            fs::rename(
                release.join(helper),
                release.join(format!("{helper}.saved")),
            )
            .unwrap();
        }
        let mut command = Command::new(home.join("bin/boxy"));
        command
            .env("BOX_TEST_INSTALLATION", &home)
            .env("HOME", &home);
        let output = bounded_output::bounded_output(command);
        if let Some(helper) = missing {
            fs::rename(
                release.join(format!("{helper}.saved")),
                release.join(helper),
            )
            .unwrap();
            assert!(!output.status.success(), "missing {helper} must fail");
            assert!(String::from_utf8_lossy(&output.stderr).contains(helper));
        } else {
            assert!(
                output.status.success(),
                "{}",
                String::from_utf8_lossy(&output.stderr)
            );
            assert_eq!(output.stdout, b"helper-ok");
        }
        assert_eq!(fs::read_link(&current).unwrap(), Path::new("new"));
    }
}

#[cfg(unix)]
fn hardening_and_repeat_run() {
    let mut limits = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: getrlimit writes to the initialized limits value.
    assert_eq!(
        unsafe { libc::getrlimit(libc::RLIMIT_CORE, &mut limits) },
        0
    );
    if limits.rlim_max > 0 {
        limits.rlim_cur = 1;
        // SAFETY: the new soft limit does not exceed the existing hard limit.
        assert_eq!(unsafe { libc::setrlimit(libc::RLIMIT_CORE, &limits) }, 0);
    } else {
        eprintln!("core dumps already disabled; checking the final state only");
    }

    #[cfg(target_os = "linux")]
    {
        // SAFETY: this test process holds no Box credentials or workload.
        assert_eq!(unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 1, 0, 0, 0) }, 0);
        // SAFETY: PR_GET_DUMPABLE reads the current process setting.
        assert_eq!(unsafe { libc::prctl(libc::PR_GET_DUMPABLE, 0, 0, 0, 0) }, 1);
    }

    let directory = tempfile::tempdir().expect("create test directory");
    let config = directory.path().join("missing.toml");
    let mut called = false;
    let exit_code = strands_box::run(
        config.clone(),
        Vec::new(),
        strands_box::RunOptions {
            on_ready: Some(Box::new(|| {
                called = true;
                // SAFETY: getrlimit writes to initialized storage in this isolated probe.
                assert_eq!(
                    unsafe { libc::getrlimit(libc::RLIMIT_CORE, &mut limits) },
                    0
                );
                assert_eq!((limits.rlim_cur, limits.rlim_max), (0, 0));
                for signal in [libc::SIGINT, libc::SIGTERM] {
                    // SAFETY: initialized sigaction storage and a null action only read the disposition.
                    let mut action: libc::sigaction = unsafe { std::mem::zeroed() };
                    assert_eq!(
                        unsafe { libc::sigaction(signal, std::ptr::null(), &mut action) },
                        0
                    );
                    assert_ne!(action.sa_sigaction, libc::SIG_DFL);
                    assert_ne!(action.sa_sigaction, libc::SIG_IGN);
                }
                Ok(())
            })),
            ..Default::default()
        },
    );
    assert!(
        called,
        "callback runs before the missing configuration is rejected"
    );
    assert_eq!(exit_code, std::process::ExitCode::FAILURE);

    // SAFETY: getrlimit writes to the initialized limits value.
    assert_eq!(
        unsafe { libc::getrlimit(libc::RLIMIT_CORE, &mut limits) },
        0
    );
    assert_eq!(limits.rlim_cur, 0);
    assert_eq!(limits.rlim_max, 0);
    #[cfg(target_os = "linux")]
    {
        // SAFETY: PR_GET_DUMPABLE reads the current process setting.
        assert_eq!(unsafe { libc::prctl(libc::PR_GET_DUMPABLE, 0, 0, 0, 0) }, 0);
    }

    assert_eq!(
        strands_box::run(config, Vec::new(), Default::default()),
        std::process::ExitCode::FAILURE
    );
}

#[cfg(not(unix))]
fn main() {
    eprintln!("skipping: process-protection test requires Unix");
}

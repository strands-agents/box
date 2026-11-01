use strands_det_harness::{det_case, user_home};

// Containment CN-C (a credential store is beneath the kernel floor)
//
// The operator's `~/.aws` is beneath the kernel floor: the mount view (Linux) or the Seatbelt
// profile (macOS) refuses it whatever policy says. So the probe is NATIVE — a bash redirection
// in the contained bash, the agent's own syscall — with no broker involved. A fresh instance has
// no credential file there, so the host plants a credential-shaped file first (something that
// would leak), proves it is there during the run, and asserts the planted content never appears
// while the kernel's refusal spelling does. The probe reads every line, so the marker on the
// second line is reachable: under an unconfined run it is printed and the case fails on it
// (a review found the earlier single-line read could never print it).
det_case! {
    name: cn_c_01,
    id:   "CN-C-01",
    desc: "Operator-home floor: a credential file the host plants under ~/.aws is unreadable by the agent's own syscall and its content never leaks",
    run: |b| {
        b.reset_policy();
        let home = user_home().canonicalize().expect("DET_ERROR: resolve operator home");
        let aws = home.join(".aws");
        let created_dir = !aws.exists();
        std::fs::create_dir_all(&aws).expect("DET_ERROR: create ~/.aws");
        let name = format!(".det-credentials-{}", std::process::id());
        let planted = aws.join(&name);
        let secret = format!("DET_SECRET_{}", std::process::id());
        // Credential-shaped in placement only: the content is a sentinel, not a key.
        std::fs::write(&planted, format!("[default]\ndet_planted_marker = {secret}\n"))
            .expect("DET_ERROR: plant the credential file");
        // Every line, with bash builtins only (no external program, so no wrong-exec route): a
        // permitted read prints CRED= for each line including the marker's; a refused one prints
        // the kernel's spelling and no CRED= at all.
        let r = b.run_sh(&format!(
            "while IFS= read -r v || [ -n \"$v\" ]; do printf 'CRED=%s\\n' \"$v\"; done < '{}'; printf done",
            planted.display()
        ));
        if strands_det_harness::Platform::current() == strands_det_harness::Platform::Macos {
            // Retain the mainline macOS syscall and mediated cells against our planted file.
            let path = planted.to_string_lossy().into_owned();
            let native = b.probe_py(&format!(
                "t(\"native_read\", lambda: len(open({path:?}).read()))\n\
                 t(\"native_control\", lambda: os.access(os.environ[\"HOME\"], os.F_OK))\n"
            ));
            native.assert_errno("native_read", 1);
            native.assert_ok("native_control", "True");
            native.assert_absent_secret(&secret, "CN-C-01 credential marker");
            let shell = b.run_shell(&format!("cat {}", strands_det_harness::sh_quote(&path)));
            shell.assert_mediated_denied("fs:read", &name);
            shell.assert_absent_secret(&secret, "CN-C-01 credential marker");
            b.run_shell("echo SHELL_CONTROL_OK").assert_contains("SHELL_CONTROL_OK");
        }
        let still_there = std::fs::read_to_string(&planted).unwrap_or_default();
        let _ = std::fs::remove_file(&planted);
        if created_dir {
            let _ = std::fs::remove_dir(&aws);
        }
        assert!(still_there.contains(&secret), "DET_ERROR: the planted file was not on the host during the run");
        r.assert_kernel_marker();
        r.assert_absent("CRED=");
        r.assert_absent_secret(&secret, "CN-C-01 credential marker");
        r.assert_contains("done");
    }
}

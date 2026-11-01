use strands_det_harness::{det_case, user_home};

// Containment CN-C (a credential store is beneath the kernel floor)
//
// `~/.ssh` is beneath the kernel floor, so the probe is NATIVE: a bash glob (the agent's own
// getdents) and a redirection of a planted entry, with no broker involved. The host plants the
// entry first so the tree has something a permitted listing would show; the planted name and
// key text never appear, and the kernel's refusal spelling does.
det_case! {
    name: cn_c_03,
    id:   "CN-C-03",
    desc: "Operator-home floor: the agent's own syscalls cannot enumerate ~/.ssh or read a planted entry there",
    run: |b| {
        b.reset_policy();
        let home = user_home().canonicalize().expect("DET_ERROR: resolve operator home");
        let ssh = home.join(".ssh");
        let created_dir = !ssh.exists();
        std::fs::create_dir_all(&ssh).expect("DET_ERROR: create ~/.ssh");
        let name = format!("det-marker-{}.pub", std::process::id());
        let planted = ssh.join(&name);
        std::fs::write(&planted, "ssh-ed25519 AAAA det\n").expect("DET_ERROR: plant the marker");
        let r = b.run_sh(&format!(
            "for e in '{d}'/*; do printf 'ENTRY=%s\\n' \"$e\"; done; read -r v < '{d}/{n}' && printf 'KEY=%s\\n' \"$v\"; printf done",
            d = ssh.display(),
            n = name
        ));
        let still_there = planted.exists();
        if strands_det_harness::Platform::current() == strands_det_harness::Platform::Macos {
            let dir = ssh.to_string_lossy().into_owned();
            let path = planted.to_string_lossy().into_owned();
            let native = b.probe_py(&format!(
                "t(\"native_listdir\", lambda: os.listdir({dir:?}))\n\
                 t(\"native_read_key\", lambda: len(open({path:?}).read()))\n\
                 t(\"native_control\", lambda: len(os.listdir(os.environ[\"HOME\"])) >= 0)\n"
            ));
            native.assert_errno("native_listdir", 1);
            native.assert_errno("native_read_key", 1);
            native.assert_ok("native_control", "True");
            let shell_read = b.run_shell(&format!("cat {}", strands_det_harness::sh_quote(&path)));
            shell_read.assert_mediated_denied("fs:read", &name);
            shell_read.assert_absent("ssh-ed25519");
            let shell_list = b.run_shell(&format!("ls -la {}", strands_det_harness::sh_quote(&dir)));
            shell_list.assert_contains("No such file or directory");
            shell_list.assert_absent(&name);
        }
        let _ = std::fs::remove_file(&planted);
        if created_dir {
            let _ = std::fs::remove_dir(&ssh);
        }
        assert!(still_there, "DET_ERROR: the planted marker was not on the host during the run");
        r.assert_kernel_marker();
        // A refused glob echoes its pattern; a permitted one would name the planted entry.
        r.assert_absent(&format!("ENTRY={}/{name}", ssh.display()));
        r.assert_absent("KEY=");
        r.assert_absent("ssh-ed25519");
        r.assert_contains("done");
    }
}

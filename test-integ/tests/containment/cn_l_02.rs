use crate::phase3::{git_identity, with_git};
use strands_det_harness::{Platform, det_case, git_only_spawn_policy, sh_quote};

det_case! {
    name: cn_l_02,
    id:   "CN-L-02",
    platforms: [Macos, Linux],
    desc: "No shell:spawn permit refuses git with no output; a permit for exactly the declared git identity allows it; a sibling program and another git identity stay denied under that same narrow permit",
    run: |b| {
        let git = git_identity();
        let git_word = sh_quote(&git.to_string_lossy());

        // No spawn permit: git is a host binary, so it is refused and nothing runs.
        b.reset_policy();
        let unpermitted = b.run_mediated_with_config(|text| with_git(b, text), &format!("{git_word} --version"));
        unpermitted.assert_shell_denied();
        unpermitted.assert_spawn_denied(&git.to_string_lossy());
        unpermitted.assert_absent("git version");

        // Exact-identity permit: git now runs and its output returns. Control evidence that the
        // spelled program, the declared `[tool.git]` command and the permitted subject are one
        // file: the journaled spawn permit's resource is exactly the verified identity, and the
        // box did not report a missing tool declaration for it.
        b.apply_policy(&git_only_spawn_policy(&git));
        let permitted = b.run_mediated_with_config(|text| with_git(b, text), &format!("{git_word} --version"));
        permitted.assert_allow();
        permitted.assert_contains("git version");
        permitted.assert_spawn_permitted_exactly(&git);
        permitted.assert_absent("no tool runs");

        let (sibling, resource, output) = if Platform::current() == Platform::Macos {
            ("ssh -V".to_owned(), "ssh".to_owned(), "OpenSSH")
        } else {
            let program = std::path::Path::new("/bin/ls").canonicalize()
                .expect("DET_ERROR: resolve the sibling program");
            let resource = program.to_string_lossy().into_owned();
            (format!("{} --version", sh_quote(&resource)), resource, "GNU coreutils")
        };
        let denied = b.run_mediated_with_config(|text| with_git(b, text), &sibling);
        denied.assert_shell_denied();
        denied.assert_spawn_denied(&resource);
        denied.assert_absent(output);

        let other_git = if Platform::current() == Platform::Macos {
            std::path::PathBuf::from("/usr/bin/git")
        } else {
            let path = b.exec_tree().join("git");
            std::fs::copy(&git, &path).expect("DET_ERROR: copy the second Git identity");
            let control = std::process::Command::new(&path).arg("--version").output()
                .expect("DET_ERROR: run the second Git identity on the host");
            assert!(crate::phase3::text(control).contains("git version"));
            path
        };
        let other = b.run_mediated_with_config(|text| with_git(b, text),
            &format!("{} --version", sh_quote(&other_git.to_string_lossy())));
        other.assert_shell_denied();
        let resource = if Platform::current() == Platform::Linux {
            let home = strands_det_harness::user_home().canonicalize()
                .expect("DET_ERROR: resolve the operator home");
            format!("~/{}", other_git.strip_prefix(home).unwrap().display())
        } else {
            other_git.to_string_lossy().into_owned()
        };
        other.assert_spawn_denied(&resource);
        other.assert_absent("git version");
    }
}

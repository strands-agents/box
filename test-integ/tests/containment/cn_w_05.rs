use std::collections::BTreeSet;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::Command;

use strands_det_harness::{det_case, sh_quote};

fn with_git(text: String, shell: &Path, helpers: &Path, read_only: &Path) -> String {
    let ws = text
        .lines()
        .find_map(|line| line.strip_prefix("workspace = "))
        .expect("the template names the workspace")
        .to_string();
    let libraries: BTreeSet<_> = ["/lib", "/lib64", "/usr/lib", "/usr/lib64"]
        .into_iter()
        .filter_map(|path| std::fs::canonicalize(path).ok())
        .chain([helpers.to_path_buf(), read_only.to_path_buf()])
        .collect();
    let libraries = libraries
        .iter()
        .filter(|path| {
            !libraries
                .iter()
                .any(|other| other != *path && path.starts_with(other))
        })
        .map(|path| serde_json::to_string(&path.to_string_lossy()).unwrap())
        .collect::<Vec<_>>()
        .join(", ");
    let shell = serde_json::to_string(&shell.to_string_lossy()).unwrap();
    text + &format!(
        "\n[tool.git]\ncommand = [\"git\"]\nworkspace = {ws}\n\n\
         [tool.git.env]\nGIT_CONFIG_NOSYSTEM = \"1\"\nGIT_TEMPLATE_DIR = \"\"\n\n\
         [tool.git.filesystem]\nread = [{ws}, {libraries}]\nwrite = [{ws}]\n\
         read_file = [{shell}]\n"
    )
}

det_case! {
    name: cn_w_05,
    id:   "CN-W-05",
    platforms: [Linux],
    desc: "Git commits through a declared tool and executes its commit hook; removing the tool or executing its hook as the agent is refused",
    run: |b| {
        let shell = std::fs::canonicalize("/bin/sh").expect("DET_ERROR: resolve the hook interpreter");
        let git = std::env::split_paths(&std::env::var_os("PATH").expect("DET_ERROR: PATH is set"))
            .map(|directory| directory.join("git"))
            .find(|path| path.is_file())
            .expect("DET_ERROR: Git is installed")
            .canonicalize()
            .expect("DET_ERROR: resolve Git");
        let found = Command::new(&git)
            .arg("--exec-path")
            .env_remove("GIT_EXEC_PATH")
            .output()
            .expect("DET_ERROR: Git is installed");
        assert!(found.status.success(), "DET_ERROR: Git must report its helper directory");
        let helpers = std::fs::canonicalize(String::from_utf8(found.stdout).unwrap().trim())
            .expect("DET_ERROR: resolve Git's helper directory");
        let hooks = b.workspace().join("hooks");
        std::fs::create_dir(&hooks).expect("DET_ERROR: create the hook directory");
        let hook = hooks.join("pre-commit");
        std::fs::write(&hook, format!("#!{}\nprintf 'GIT_HOOK_RAN\\n'\n", shell.display()))
            .expect("DET_ERROR: write the commit hook");
        std::fs::set_permissions(&hook, std::fs::Permissions::from_mode(0o755))
            .expect("DET_ERROR: make the hook executable");
        let host = Command::new(&hook).output().expect("DET_ERROR: run the hook outside Box");
        assert!(host.status.success(), "DET_ERROR: the host hook must succeed");

        let read_only = b.workspace().with_file_name("git-read-only");
        std::fs::create_dir(&read_only).expect("DET_ERROR: create the read-only grant");
        let protected_write = read_only.join("unchanged.txt");
        std::fs::write(&protected_write, "HOST_CONTENT\n").expect("DET_ERROR: the host can write the file");
        let outside = b.workspace().with_file_name("git-ungranted");
        std::fs::create_dir(&outside).expect("DET_ERROR: create the ungranted directory");
        let ungranted = outside.join("program");
        std::fs::copy(b.built_tool(), &ungranted).expect("DET_ERROR: copy the ungranted program");
        let host = Command::new(&ungranted).arg("host-control").output()
            .expect("DET_ERROR: run the ungranted program outside Box");
        assert!(host.status.success(), "DET_ERROR: the host program must succeed");
        let protected_config = b.workspace().join(".strands-box/box.toml");
        let config_bytes = std::fs::read(&protected_config)
            .expect("DET_ERROR: read the protected configuration on the host");
        assert!(!config_bytes.is_empty(), "DET_ERROR: the protected configuration must not be empty");
        let quoted = |path: &Path| sh_quote(&path.to_string_lossy());
        std::fs::write(&hook, format!(
            "#!{}\n\
             IFS= read -r value < {} || exit 60\n\
             [ \"$value\" = HOST_CONTENT ] || exit 60\n\
             printf 'READ_ONLY_CONTENT_READ\\n'\n\
             if (printf changed > {}) 2>/dev/null; then exit 61; fi\n\
             printf 'READ_ONLY_WRITE_REFUSED\\n'\n\
             if ({} ungranted) >/dev/null 2>&1; then exit 62; fi\n\
             printf 'UNGRANTED_PROGRAM_REFUSED\\n'\n\
             if (read -r line < {}) 2>/dev/null; then exit 63; fi\n\
             printf 'PROTECTED_CONFIG_REFUSED\\n'\n\
             printf 'GIT_HOOK_RAN\\n'\n",
            shell.display(), quoted(&protected_write), quoted(&protected_write),
            quoted(&ungranted), quoted(&protected_config),
        )).expect("DET_ERROR: write the hook's denial checks");

        b.apply_policy(
            r#"@id("spawn_git") permit (principal, action == Box::Action::"shell:spawn", resource);"#,
        );
        let edit = |text| with_git(text, &shell, &helpers, &read_only);
        let ws = sh_quote(&b.workspace().to_string_lossy());
        let hooks = sh_quote(&hooks.to_string_lossy());
        let script = format!(
            "cd {ws} && git init -q . && git add readable.txt && \
             git -c core.hooksPath={hooks} -c user.name=det -c user.email=det@example.com \
             commit -q -m act5-commit && git log --oneline -1"
        );
        let r = b.run_mediated_with_config(edit, &script);
        assert_eq!(r.rc, 0, "Git must complete: {}", r.out);
        r.assert_contains("GIT_HOOK_RAN");
        r.assert_contains("READ_ONLY_CONTENT_READ");
        r.assert_contains("READ_ONLY_WRITE_REFUSED");
        r.assert_contains("UNGRANTED_PROGRAM_REFUSED");
        r.assert_contains("PROTECTED_CONFIG_REFUSED");
        r.assert_contains("act5-commit");
        r.assert_spawn_permitted_exactly(&git);
        assert_eq!(std::fs::read_to_string(&protected_write).unwrap(), "HOST_CONTENT\n");
        let committed = Command::new(&git).args(["log", "-1", "--format=%s"])
            .current_dir(b.workspace()).output().expect("DET_ERROR: inspect the committed repository");
        assert!(committed.status.success(), "Host Git must read the committed repository: {committed:?}");
        assert_eq!(String::from_utf8(committed.stdout).unwrap().trim(), "act5-commit");

        let hook = sh_quote(&hook.to_string_lossy());
        let agent = b.run_sh_with_config(edit, &format!("{hook}; printf 'HOOK_RC=%s\\n' \"$?\""));
        agent.assert_absent("GIT_HOOK_RAN");
        agent.assert_contains("HOOK_RC=126");

        let r = b.run_mediated_with_config(|text| text, &format!("cd {ws} && git status"));
        r.assert_contains("no `[tool.<name>] command` matches");
    }
}

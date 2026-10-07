use strands_det_harness::det_case;

// Containment CN-W (Linux workload, act 5)
//
// A `[tool.git]` with its own filesystem runs `git init`, `add`, and `commit` through the hosted
// Shell after a `shell:spawn` permit whose journal row names the canonical program; without a
// `[tool.git]` table the same invocation is refused, because no table names the program.
fn with_git(text: String) -> String {
    let ws = text
        .lines()
        .find_map(|line| line.strip_prefix("workspace = "))
        .expect("the template names the workspace")
        .to_string();
    text + &format!(
        "\n[tool.git]\ncommand = [\"git\"]\nworkspace = {ws}\n\n[tool.git.filesystem]\nread = [{ws}]\nwrite = [{ws}]\nexec = [\"/usr/libexec/git-core\"]\n"
    )
}

// TEMPORARY QUARANTINE (linux): this fixture authors `[tool.git.filesystem] exec`, which a box
// refuses at load
// (docs/design/decisions.md#a-leaf-runs-its-whole-toolchain-and-loads-what-it-builds). Broad exec
// ships on macOS only; broad exec for a Linux tool leaf is a currently-missing feature. The case
// runs only on linux, so it records an authorized SKIP there (see test-integ/src/quarantine.rs
// and QUARANTINE.md) until that Linux broad-exec feature lands. The body and its assertions are
// unchanged.
det_case! {
    name: cn_w_05,
    id:   "CN-W-05",
    platforms: [Linux],
    desc: "Workload act 5: [tool.git] commits through the hosted Shell after a shell:spawn permit; dropping the table refuses it",
    run: |b| {
        b.apply_policy(
            r#"@id("spawn_git") permit (principal, action == Box::Action::"shell:spawn", resource);"#,
        );
        let ws = b.workspace().display().to_string();
        let r = b.run_sh_with_config(
            with_git,
            &format!(
                "zsh -c 'cd {ws} && git init -q . && git add readable.txt && git -c user.name=det -c user.email=det@example.com commit -q -m act5-commit && git log --oneline -1'"
            ),
        );
        r.assert_contains("act5-commit");
        let journal = b.journal();
        assert!(
            journal.contains("shell:spawn") && journal.contains("/usr/bin/git"),
            "the journal must carry the shell:spawn decision naming the canonical program: {}",
            &journal[journal.len().saturating_sub(1500)..]
        );
        let r = b.run_sh_with_config(
            |text| text,
            &format!("zsh -c 'cd {ws} && git status'"),
        );
        r.assert_contains("no `[tool.<name>] command` matches");
    }
}

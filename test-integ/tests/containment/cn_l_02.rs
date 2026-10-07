// Containment CN-L (git as a leaf)
//
// macOS-only. Absent policy is default-deny for host binaries: a `shell:exec`
// grant is not a `shell:spawn` grant. This case walks the narrow-permit family in
// one file — no permit refuses git with no output, a git-only permit lets git run,
// and that same permit does NOT over-authorize a sibling host binary (ssh) or the
// same-named launcher shim.
//
// How the hosted Shell names a host program (`crates/shell/src/exec.rs`): a bare name is
// looked up on the BROKER PROCESS's own `PATH` (`host_program_path`: `std::env::var_os("PATH")`,
// falling back to `/usr/bin:/bin`) — never on the agent's declared `[agent.env] PATH`, which the
// native run of 2026-09-22 confirmed (the agent's PATH began with the CLT directory and `git`
// still resolved to `/usr/bin/git`). A spelling with a `/` is that path, canonicalized. The policy
// then reads `context.input.program` (the spelling) and `context.input.program_path` (the
// canonical identity); the journal's `shell:spawn` resource is the identity; and the process that
// runs is the `[tool.<name>]` whose `command` matches it (`hosted.rs::select_tool`). So the case
// spells the verified developer-directory git by its canonical path, declares `[tool.git]` as
// that same path, and permits exactly that identity — one path, three places, checked to agree by
// the journaled resource. No Core resolver change, no PATH claim, no global exec.
mod macos {
    use strands_det_harness::{det_case, git_only_spawn_policy, macos_git_identity, sh_quote};

    det_case! {
        name: cn_l_02,
        id:   "CN-L-02",
        platforms: [Macos],
        desc: "No shell:spawn permit refuses git with no output; a permit for exactly the declared git identity allows it; ssh and the /usr/bin/git shim stay denied under that same narrow permit",
        run: |b| {
            let git = macos_git_identity();
            let git_word = sh_quote(&git.to_string_lossy());

            // No spawn permit: git is a host binary, so it is refused and nothing runs.
            b.reset_policy();
            let unpermitted = b.run_mediated_with_config(b.with_macos_git_tool(), &format!("{git_word} --version"));
            unpermitted.assert_shell_denied();
            unpermitted.assert_spawn_denied(&git.to_string_lossy());
            unpermitted.assert_absent("git version");

            // Exact-identity permit: git now runs and its output returns. Control evidence that the
            // spelled program, the declared `[tool.git]` command and the permitted subject are one
            // file: the journaled spawn permit's resource is exactly the verified identity, and the
            // box did not report a missing tool declaration for it.
            b.apply_policy(&git_only_spawn_policy(&git));
            let permitted = b.run_mediated_with_config(b.with_macos_git_tool(), &format!("{git_word} --version"));
            permitted.assert_allow();
            permitted.assert_contains("git version");
            permitted.assert_spawn_permitted_exactly(&git);
            permitted.assert_absent("no tool runs");

            // The same narrow permit must not authorize a different host binary…
            let ssh = b.run_mediated_with_config(b.with_macos_git_tool(), "ssh -V");
            ssh.assert_shell_denied();
            ssh.assert_spawn_denied("ssh");
            ssh.assert_absent("OpenSSH");

            // …nor the same-named Apple launcher shim, whose identity is not the declared one.
            let shim = b.run_mediated_with_config(b.with_macos_git_tool(), "/usr/bin/git --version");
            shim.assert_shell_denied();
            shim.assert_spawn_denied("/usr/bin/git");
            shim.assert_absent("git version");
        }
    }
}

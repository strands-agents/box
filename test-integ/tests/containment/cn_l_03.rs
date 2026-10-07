// Containment CN-L (git as a leaf)
//
// macOS-only. Broad exec
// (docs/design/decisions.md#a-leaf-runs-its-whole-toolchain-and-loads-what-it-builds): a tool
// leaf renders `process-exec*`, so a permitted `git` runs its whole toolchain — including the
// `git-remote-https` transport helper it forks for a remote. The helper is NOT refused at exec;
// egress is what bounds the fetch. The policy permits the git spawn but no `net:*`/`http:request`
// to the remote, so the box's egress gateway refuses the request with 403 and git aborts with
// "returned error: 403" — no refs enumerated, and no `Operation not permitted` exec refusal. The
// family in one file: the helper runs (no EPERM), the gateway's 403 bounds it, no refs, and a
// git-runs control.
//
// The git that runs is the developer directory's real git, invoked by its canonical path and
// declared as `[tool.git]` with its developer directory and the workspace as its filesystem and no
// exec grant; the permit names
// exactly that identity (see CN-L-02 for why a bare name and an agent PATH cannot do this). The
// journaled spawn resource proves the declared file is the one permitted; the helper then runs as the
// leaf's own child exec under broad exec, and egress is the boundary it meets.
mod macos {
    use strands_det_harness::{det_case, git_only_spawn_policy, macos_git_identity, sh_quote};

    det_case! {
        name: cn_l_03,
        id:   "CN-L-03",
        platforms: [Macos],
        desc: "Broad exec: a permitted git tool leaf runs its git-remote-https helper; egress bounds the fetch (gateway 403), no refs returned and no exec refusal; git-runs control holds",
        run: |b| {
            let git = macos_git_identity();
            let git_word = sh_quote(&git.to_string_lossy());
            b.reset_policy();
            b.apply_policy(&git_only_spawn_policy(&git));

            // git is permitted to spawn and, under broad exec, runs its transport helper; egress bounds it.
            let ls = b.run_mediated_with_config(
                b.with_macos_git_tool(),
                &format!("{git_word} ls-remote https://example.com/det-cn-l-03.git"),
            );
            ls.assert_spawn_permitted_exactly(&git);
            ls.assert_absent("Operation not permitted");
            ls.assert_contains("returned error: 403");
            ls.assert_absent("refs/");
            ls.assert_absent("no tool runs");

            // git-runs control: the spawn permit is genuinely effective for the declared identity.
            let version = b.run_mediated_with_config(b.with_macos_git_tool(), &format!("{git_word} --version"));
            version.assert_allow();
            version.assert_contains("git version");
            version.assert_spawn_permitted_exactly(&git);
        }
    }
}

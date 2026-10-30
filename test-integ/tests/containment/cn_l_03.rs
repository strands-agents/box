use crate::phase3::{git_identity, with_git};
use strands_det_harness::{det_case, git_only_spawn_policy, sh_quote};

det_case! {
    name: when_git_tool_fetches_through_helper_then_helper_runs_and_gateway_refuses_fetch,
    id:   "CN-L-03",
    platforms: [Macos, Linux],
    desc: "Broad exec: a permitted git tool leaf runs its git-remote-https helper; egress bounds the fetch (gateway 403), no refs returned and no exec refusal; git-runs control holds",
    run: |b| {
        let git = git_identity();
        let git_word = sh_quote(&git.to_string_lossy());
        b.reset_policy();
        b.apply_policy(&git_only_spawn_policy(&git));

        // git is permitted to spawn and, under broad exec, runs its transport helper; egress bounds it.
        let ls = b.run_mediated_with_config(
            |text| with_git(b, text),
            &format!("{git_word} ls-remote https://example.com/det-cn-l-03.git"),
        );
        ls.assert_spawn_permitted_exactly(&git);
        ls.assert_absent("Operation not permitted");
        ls.assert_contains("returned error: 403");
        ls.assert_absent("refs/");
        ls.assert_absent("no tool runs");

        // git-runs control: the spawn permit is genuinely effective for the declared identity.
        let version = b.run_mediated_with_config(|text| with_git(b, text), &format!("{git_word} --version"));
        version.assert_allow();
        version.assert_contains("git version");
        version.assert_spawn_permitted_exactly(&git);
    }
}

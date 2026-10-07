
use strands_det_harness::det_case;

// Another process cannot replace or impersonate an endpoint. macOS only.
//
// An alias derives its socket from its own path and takes no socket argument. That rule
// is what stops the workload pointing an alias at a socket of its choosing, so the
// accepted spellings and the refused ones both need pinning. The refusal must be exit
// 125 — the boundary-failure status — because a generic "non-zero" would also be
// satisfied by the command running and failing, which is the opposite result.
det_case! {
    name: cn_c_07,
    id:   "CN-C-07",
    platforms: [Macos],
    desc: "Alias argument: an alias derives its socket and refuses a socket argument with exit 125",
    run: |b| {
        b.apply_policy(
            "@id(\"alias_shell_commands\")\n\
             permit (principal, action == Box::Action::\"shell:exec\", resource);",
        );

        // CN-C-07a: -c COMMAND is accepted.
        b.run_native("zsh -c 'echo FORM_C_OK'").assert_contains("FORM_C_OK");
        // CN-C-07b: -lc COMMAND is accepted.
        b.run_native("zsh -lc 'echo FORM_LC_OK'").assert_contains("FORM_LC_OK");

        // CN-C-07c/d: a trailing socket path is refused with exit 125, not run.
        let arg = b.run_native("zsh -c 'echo SHOULD_NOT_RUN' /tmp/attacker.sock; echo ALIAS_RC=$?");
        arg.assert_contains("ALIAS_RC=125");
        arg.assert_absent("SHOULD_NOT_RUN");

        // CN-C-07e: a serving flag is refused with exit 125, so an alias takes no serving role.
        b.run_native("zsh --serve; echo ALIAS_RC=$?").assert_contains("ALIAS_RC=125");

        // CN-C-07f: a repeated flag is refused with exit 125.
        b.run_native("zsh -l -l; echo ALIAS_RC=$?").assert_contains("ALIAS_RC=125");
    }
}

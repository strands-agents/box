use strands_det_harness::{det_case, sh_quote};

// `mkdir -p` walks the path from the root. Under the workspace grant a relative `a/b` and an
// absolute `<workspace>/c/d` each create every missing level and print nothing: the ancestors
// above the grant exist, policy refuses to say so, and the builtin creates nothing it cannot see.
// Below an ungranted parent the builtin is refused by default-deny on the target it was asked to
// create, never on an ancestor, and nothing is created above the grant.
det_case! {
    name: sh_mkdir_p,
    id:   "SH-MKDIR-P",
    desc: "mkdir -p: a relative and an absolute path below the workspace grant create every level with no error; a path below an ungranted parent is default-denied on the target, not an ancestor, and creates nothing",
    run: |b| {
        b.reset_policy();
        let granted = b.workspace().join("c/d");
        let outside = b
            .workspace()
            .parent()
            .expect("DET_ERROR: the workspace has a parent")
            .join("sh-mkdir-p-outside");
        let created = b.run_mediated(&format!(
            "mkdir -p a/b; echo REL_RC=$?; mkdir -p {}; echo ABS_RC=$?",
            sh_quote(&granted.to_string_lossy())
        ));
        created.assert_entered();
        created.assert_contains("REL_RC=0\n");
        assert!(
            created.out.contains("ABS_RC=0\n"),
            "mkdir -p with an absolute path must create every missing ancestor under the workspace grant and exit 0, never a refusal on an ancestor above the target; out=[{}]",
            created.snippet()
        );
        created.assert_contains("ABS_RC=0\n");
        created.assert_absent("mkdir:");
        created.assert_absent("strands-shell:");
        created.assert_allow();
        created.assert_mediated_permitted("fs:write", "/a/b");
        created.assert_mediated_permitted("fs:write", "/c/d");
        assert!(
            created.decisions.iter().any(|d| d.is_action("fs:write")
                && d.permitted()
                && d.resource.ends_with("/c")),
            "the absolute walk must create the first missing level through a permitted fs:write; decisions: {:?}",
            created.decisions
        );
        assert!(b.workspace().join("a/b").is_dir(), "mkdir -p a/b created no a/b");
        assert!(granted.is_dir(), "mkdir -p {} created no c/d", granted.display());

        let target = outside.join("c/d");
        let refused = b.run_mediated(&format!(
            "mkdir -p {}; echo OUT_RC=$?",
            sh_quote(&target.to_string_lossy())
        ));
        refused.assert_entered();
        refused.assert_absent("OUT_RC=0");
        let rule = refused.assert_mediated_denied("fs:write", "sh-mkdir-p-outside/c/d");
        assert!(
            rule.contains("default-deny"),
            "the target must be refused by default-deny, not a rule of the case's own: {rule}"
        );
        refused.assert_contains("policy denied this operation on '");
        refused.assert_contains("/sh-mkdir-p-outside/c/d' [default-deny]");
        refused.assert_absent("operation on '/'");
        refused.assert_absent("operation on '~'");
        refused.assert_absent("/sh-mkdir-p-outside' [");
        refused.assert_absent("/sh-mkdir-p-outside/c' [");
        assert!(
            !outside.exists(),
            "mkdir -p created {} above the grant although the target was refused",
            outside.display()
        );
    }
}

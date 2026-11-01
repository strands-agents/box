use strands_det_harness::det_case;

// A relative symlink target resolves against the link's own directory, not the working directory.
// The link `sub/link -> ../secret.txt` names the workspace's own `secret.txt`, so a read forbid on
// that file refuses the link's creation, and the refusal names the resolved target.
det_case! {
    name: sh_symlink_rel,
    id:   "SH-SYMLINK-REL",
    desc: "Relative symlink: ln -s ../secret.txt sub/link is judged on the workspace's secret.txt, and its read forbid refuses the link",
    run: |b| {
        let secret = b.workspace().join("secret.txt");
        std::fs::write(&secret, "DET_REL_SECRET\n").expect("plant the secret");
        b.apply_policy(
            r#"@id("secret_read") forbid (principal, action == Box::Action::"fs:read", resource)
    when { context.input.path like "*/workspace/secret.txt" };"#,
        );
        let r = b.run_mediated("mkdir sub; ln -s ../secret.txt sub/link 2>&1; cat sub/link 2>&1; echo CATRC=$?");
        r.assert_entered();
        assert!(
            r.decisions
                .iter()
                .any(|d| d.denied() && d.forbidden_by("secret_read")),
            "the link must be refused by secret_read; out=[{}]",
            r.snippet()
        );
        r.assert_contains("/workspace/secret.txt' [policy: secret_read]");
        r.assert_absent("DET_REL_SECRET");
        r.assert_absent("CATRC=0");
        assert!(
            std::fs::symlink_metadata(b.workspace().join("sub/link")).is_err(),
            "the refused link was created"
        );
    }
}

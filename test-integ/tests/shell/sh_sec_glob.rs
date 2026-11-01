use strands_det_harness::det_case;

// GitHub issue #158 (box), a pen-test finding.
//
// A wildcard expansion reads every directory between its literal prefix and a match. A `forbid` on
// `fs:read` of `/tmp/t/private` must keep every name inside it out of the expansion, at every depth.
// Before the fix, `/tmp/t/*/*` dropped `/tmp/t/private/sub`, but `/tmp/t/*/*/*` returned
// `/tmp/t/private/sub/file`: the Shell asked about the prefix and the parent `/tmp/t/private/sub`,
// and never about `/tmp/t/private`. The tree is in the Shell's own `/tmp`, which does not persist
// across requests, so one request builds it and expands it. Plain `mkdir` creates each level
// without a probe of the forbidden directory.
det_case! {
    name: sh_sec_glob,
    id:   "SH-SEC-GLOB",
    desc: "Security: a multi-level glob discloses no name inside a directory whose fs:read is forbidden",
    run: |b| {
        b.reset_policy();
        b.apply_policy(
            r#"@id("tmp_read")
permit (principal, action == Box::Action::"fs:read", resource)
when { context.input.path == "/tmp" || context.input.path like "/tmp/*" };

@id("tmp_write")
permit (principal, action == Box::Action::"fs:write", resource)
when { context.input.path like "/tmp/*" };

@id("private_listing")
forbid (principal, action == Box::Action::"fs:read", resource)
when { context.input.path == "/tmp/t/private" };"#,
        );
        let r = b.run_mediated(
            "mkdir /tmp/t && mkdir /tmp/t/private && mkdir /tmp/t/private/sub \
             && mkdir /tmp/t/open && mkdir /tmp/t/open/sub \
             && echo x > /tmp/t/private/sub/file && echo x > /tmp/t/open/sub/file \
             && echo SETUP_OK; \
             printf 'G2=%s\\n' /tmp/t/*/*; printf 'G3=%s\\n' /tmp/t/*/*/*; \
             cd /tmp/t && printf 'R3=%s\\n' */*/*",
        );
        r.assert_contains("SETUP_OK");
        // No name read out of `/tmp/t/private` reaches the workload.
        r.assert_absent("private/sub");
        // The refusal is the authored forbid, on the middle directory.
        r.assert_forbidden_by("fs:read", "/tmp/t/private", "private_listing");
        // Controls: the permitted sibling expands at every depth, and a relative pattern starts
        // from the working directory.
        r.assert_contains("G2=/tmp/t/open/sub");
        r.assert_contains("G3=/tmp/t/open/sub/file");
        r.assert_contains("R3=open/sub/file");
    }
}

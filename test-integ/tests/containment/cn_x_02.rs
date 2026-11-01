use strands_det_harness::det_case;

// Containment CN-X (exec needs an exec grant)
//
// The guarantee under test, stated exactly: the agent's own execve succeeds only under a path
// the agent holds an `exec` grant on. A writable grant does not carry exec, and the agent cannot
// confer it — no file mode it sets and no bytes it writes make a path executable. It is NOT an
// unconditional write-xor-exec claim: an operator may grant `write` and `exec` on the same tree,
// and the box permits that with a disclosure warning ("lies inside the writable grant").
//
// So the probe controls for everything but the grant. One executable is used throughout: the
// fixture's rustc-built binary in `out/` (a real ELF/Mach-O, so no interpreter and no shebang can
// be the thing refused), host-prepared with mode 0755 (so no in-box `chmod`, which is an external
// program the native route may not even have, can be the thing that failed). The same bytes with
// the same mode are then executed by the native bash three ways:
//
//   1. control: `out/` under the agent's own `exec` entry → runs (proves exec works natively
//      from a granted tree, and that this binary is executable in the box);
//   2. same file, agent config without that entry (the tool tables' exec on `out/` belong to the
//      tools' boundaries, not the agent's) → refused;
//   3. a host-placed copy in the writable workspace root, with the `out/` exec entry present →
//      refused, because the grant covers `out/` and not the root.
//
// Refusal means the binary's own output is absent, the exit is nonzero, and the kernel printed a
// refusal spelling. The old form wrote a script, ignored a failed `chmod`, and read an ordinary
// mode-0644 denial as the boundary; it passed under a box that contained nothing.
det_case! {
    name: cn_x_02,
    id:   "CN-X-02",
    desc: "Exec is a grant: the agent's own execve runs a host-prepared 0755 binary only under its exec entry; the same bytes in the writable-only workspace, and without the entry, are refused",
    run: |b| {
        b.reset_policy();
        let tool = b.built_tool();
        let copy = b.workspace().join("wx-hello");
        std::fs::copy(&tool, &copy).expect("DET_ERROR: copy the built binary into the workspace root");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            for path in [&tool, &copy] {
                std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755))
                    .expect("DET_ERROR: host-prepare the executable mode");
                let mode = std::fs::metadata(path).expect("DET_ERROR: stat the binary").permissions().mode() & 0o777;
                assert_eq!(mode, 0o755, "DET_ERROR: {} is not mode 0755 on the host", path.display());
            }
        }

        // 1. Control: the agent holds exec on `out/`, and the binary runs from there.
        let control = b.run_sh_with_config(
            b.with_exec_tree(),
            &format!("'{}' control; printf 'CTL_RC=%s\\n' $?", tool.display()),
        );
        control.assert_contains("BUILD_OUTPUT_RAN control");
        control.assert_contains("CTL_RC=0");

        // 2. The same file without the agent's exec entry.
        let no_grant = b.run_sh(&format!("'{}' ungranted; printf 'RC=%s\\n' $?", tool.display()));
        no_grant.assert_absent("BUILD_OUTPUT_RAN");
        no_grant.assert_absent("RC=0");
        no_grant.assert_kernel_marker();

        // 3. The same bytes, host-placed in the writable root, with the `out/` entry present.
        let writable = b.run_sh_with_config(
            b.with_exec_tree(),
            &format!("'{}' writable; printf 'RC=%s\\n' $?", copy.display()),
        );
        writable.assert_absent("BUILD_OUTPUT_RAN");
        writable.assert_absent("RC=0");
        writable.assert_kernel_marker();
        assert!(copy.is_file(), "the host-placed copy vanished from the workspace");
        if strands_det_harness::Platform::current() == strands_det_harness::Platform::Macos {
            // Keep the mainline Shell write/chmod and quoting cells. This is an undeclared
            // Shell spawn refusal, separate from the native exec-grant guarantee above.
            //
            // The `fs:delete` permit is deliberate: with it in place, the delete below can only be
            // refused by the fixture's forbid, never for want of a permit — so a default-deny cannot
            // be mistaken for the forbid holding.
            b.apply_policy(
                "permit (principal, action == Box::Action::\"fs:read\", resource);\n\
                 permit (principal, action == Box::Action::\"fs:write\", resource);\n\
                 permit (principal, action == Box::Action::\"fs:delete\", resource);"
            );
            b.run_shell("echo \"O'Brien\"").assert_contains("O'Brien");
            let script = b.workspace().join("cn-x-02.sh");
            let path = strands_det_harness::sh_quote(&script.to_string_lossy());
            b.run_shell(&format!(
                "printf \"#!/bin/sh\\necho ESCAPED_MARKER\\n\" > {path}; chmod 755 {path}; echo WROTE_RC=$?"
            )).assert_contains("WROTE_RC=0");
            assert!(std::fs::read_to_string(&script).expect("DET_ERROR: Shell-created script missing")
                .contains("ESCAPED_MARKER"), "the Shell did not write the probe");
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let mode = std::fs::metadata(&script)
                    .expect("DET_ERROR: stat the Shell-created script")
                    .permissions().mode() & 0o777;
                assert_eq!(mode, 0o755, "the Shell's chmod did not store mode 0755");
            }
            let denied = b.run_shell(&path);
            denied.assert_shell_denied();
            denied.assert_absent("ESCAPED_MARKER");
            // Cleanup through the Shell is REFUSED by design: the fixture policy carries
            // `@id("no_deletes") forbid fs:delete`, and the Shell's `rm` is `FsOperation::RemoveFile`
            // → `fs:delete` (`broker/shell.rs::fs_action`), a forbid the `fs:delete` permit above
            // cannot widen. The native run's "Shell cleanup did not remove the probe" was this
            // forbid holding, not a Core defect.
            //
            // Attribution reads the decision, not a guessed id: the journal's `strands.policy.rule`
            // is the engine's positional id (`policy_6` on the native run of 2026-09-22), while the
            // authored `@id` reaches the journal only through `strands.policy.determining.ids`
            // (`telemetry.rs::policy_identifier`) beside the refusal class `a forbid rule matched`
            // (`telemetry.rs::deny_reason`). `assert_forbidden_by` requires both; `no permit
            // matched` (default-deny) never satisfies it, and the message carries every decision
            // with its ids and reason plus the Shell's output.
            let rm = b.run_shell(&format!("rm -f {path}; echo RM_RC=$?"));
            let forbid = rm.assert_forbidden_by("fs:delete", "cn-x-02.sh", "no_deletes");
            assert_ne!(forbid.rule, "default-deny", "the forbid must be a policy rule, not default-deny: {forbid:?}");
            rm.assert_contains("policy denied");
            rm.assert_absent("RM_RC=0");
            assert!(script.exists(), "the probe vanished although the Shell's rm was refused");
            std::fs::remove_file(&script).expect("DET_ERROR: host-side cleanup of the probe");
        }
    }
}

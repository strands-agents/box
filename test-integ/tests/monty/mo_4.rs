use strands_det_harness::det_case;

// Monty is the box's own Python. The identity control asks the hosted Shell's `python3
// --version` (the supported path: the direct alias accepts only `-c` or a script), then the
// script runs through the `python3` alias from the native bash. Every file operation Monty
// makes is judged by the policy engine and journaled; the refusal is a `PermissionError` carrying
// the engine's text, and Monty signs it with its footer. Measured on the native Linux run:
// the sentinel printed, then
// `PermissionError: policy denied this operation [default-deny] … (Permission denied: '/etc/shadow')`.
det_case! {
    name: mo_4,
    id:   "MO-4",
    desc: "Monty default-deny: open('/etc/shadow') with no fs:read permit is refused by policy and journaled",
    run: |b| {
        b.reset_policy();
        b.assert_python_is_monty();
        let r = b.run_py("print('SHADOW=' + open('/etc/shadow').read())");
        r.assert_monty();
        let rule = r.assert_mediated_denied("fs:read", "/etc/shadow");
        assert!(
            rule.contains("default-deny") || rule.contains("reach-floor"),
            "the refusal must come from the default-deny gate or the reach floor, not a policy of the case's own: {rule}"
        );
        r.assert_contains("PermissionError");
        r.assert_contains("policy denied this operation");
        r.assert_absent("SHADOW=");
    }
}

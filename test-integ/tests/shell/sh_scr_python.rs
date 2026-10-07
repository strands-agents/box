use strands_det_harness::det_case;

// One scenario: `python` and `python3` typed into the hosted Shell both forward their source to
// the box's interpreter, Monty, and return the computed value. Routing is pinned two ways so a
// regression to host CPython turns this RED (a bare 3*3 == 9 would not, since either interpreter
// yields 9):
//   - identity: assert_python_is_monty pins `python3 --version`, and this run's own
//     `python --version` is the ONLY source of the "Monty" line here, so it pins the `python`
//     spelling too.
//   - route: each `-c` invocation runs as the Shell's mediated `python` (a journaled shell:exec);
//     a host CPython would be a shell:spawn, not a shell:exec.
// Measured green on macOS 2026-09-22 (cargo test --test shell): `python --version` reported Monty,
// a shell:exec on `python` was journaled, and `PYA=9`/`PY3=9` returned.
det_case! {
    name: sh_scr_python,
    id:   "SH-SCR-PY",
    desc: "Script route: python and python3 both forward to Monty (identity + mediated route pinned) and compute",
    run: |b| {
        b.reset_policy();
        b.assert_python_is_monty();
        let r = b.run_mediated(
            "python --version; python -c 'print(\"PYA=\"+str(3*3))'; python3 -c 'print(\"PY3=\"+str(3*3))'",
        );
        r.assert_entered();
        r.assert_contains("Monty");
        r.assert_mediated_permitted("shell:exec", "python");
        r.assert_contains("PYA=9");
        r.assert_contains("PY3=9");
        r.assert_allow();
    }
}

use strands_det_harness::det_case;

// The direct alias: the workload execs `python3 -c '…'`, which forwards the source to the box's
// interpreter, Monty (docs/design/decisions.md#interpreters-are-brokered-aliases,
// docs/design/decisions.md#python-in-the-shell-is-monty), and the computed value returns. The
// identity control pins the interpreter is Monty (not host CPython) first; `run_py` then drives the
// direct `python3` alias (not the Shell path — that is MO-2 / SH-SCR-PY). Measured green on macOS
// 2026-09-22 (cargo test --test monty): python3 identified as Monty, `42`.
det_case! {
    name: mo_1,
    id:   "MO-1",
    desc: "Direct alias: python3 -c forwards its source to Monty and returns the computed value",
    run: |b| {
        b.reset_policy();
        b.assert_python_is_monty();
        let r = b.run_py("print(6*7)");
        r.assert_monty();
        r.assert_contains("42");
    }
}

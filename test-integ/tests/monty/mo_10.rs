use strands_det_harness::det_case;

// Honest errors (docs/design/decisions.md#an-unserviced-suspension-is-a-python-error): an
// undefined name is a real, catchable `NameError` reported at
// status 1 — not a broker failure (125) and not a silent success. Monty signs the exception with
// its footer, which is the proof the script reached Monty. (The sandbox half — no subprocess — is
// MO-11; the default-deny half is MO-4.)
// Measured green on macOS 2026-09-22 (cargo test --test monty): `NameError` reported, no value,
// Monty footer present.
det_case! {
    name: mo_10,
    id:   "MO-10",
    desc: "Failure handling: an undefined name is a catchable NameError at status 1, not a broker failure",
    run: |b| {
        b.reset_policy();
        b.assert_python_is_monty();
        let r = b.run_py("print(NOPE_UNDEFINED_NAME)");
        r.assert_monty();
        r.assert_contains("NameError");
        r.assert_absent("NOPE_UNDEFINED_NAME =");
    }
}

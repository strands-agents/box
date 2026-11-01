use strands_det_harness::det_case;

// One scenario: the embedded Lua interpreter is reachable via `lua -e` and runs script text,
// and `os.execute` does NOT run its nested command directly — the text routes back
// through the Shell's mediated command path, so the nested `echo` is parsed, resolved, and judged
// as its own `shell:exec`. A permit on `lua` does not launder shell text
// (docs/design/decisions.md#one-admission-point-after-resolution).
// The computed value and the nested output both returning prove reachability and the mediated route.
// Measured green on macOS 2026-09-22 (cargo test --test shell): `42` and `NESTED_OK` returned.
det_case! {
    name: sh_scr_lua,
    id:   "SH-SCR-LUA",
    desc: "Script route: Lua is reachable and os.execute routes its nested command through the mediated path",
    run: |b| {
        b.reset_policy();
        let r = b.run_mediated("lua -e 'print(6*7)'; lua -e 'os.execute(\"printf NESTED_OK\")'");
        r.assert_entered();
        r.assert_contains("42");
        r.assert_contains("NESTED_OK");
        // Pin mediation: the nested command must route back through the Shell as its own
        // shell:exec, so a regression that ran it natively turns this RED. `printf` is chosen
        // because the wrapper never runs a mediated `printf` (its only mediated command is the
        // DET_MEDIATED `echo`), so this permit can only come from the Lua nested command.
        r.assert_mediated_permitted("shell:exec", "printf");
        r.assert_allow();
    }
}

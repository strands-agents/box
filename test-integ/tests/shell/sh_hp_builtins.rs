use strands_det_harness::det_case;

// One scenario: the vendored parser and in-process built-ins run through the mediated seam and
// return correct output. A representative each of a pipeline (sort/uniq/wc), a stream/field
// tool (jq), and path arithmetic (basename) is enough here — the exhaustive coreutils
// parity (every tr/sed/cut/grep/dirname spelling) is `crates/shell`'s job (`shell_integration.rs`),
// not the containment suite's. What this case adds is that they reach the hosted Shell (entered)
// and compute correctly against an independent oracle.
// Measured green on macOS 2026-09-22 (cargo test --test shell): `PIPE=3`, `JQ=V`, `BASE=c.txt`.
det_case! {
    name: sh_hp_builtins,
    id:   "SH-HP-BUILTINS",
    desc: "Happy path: built-ins (pipeline, jq, path arithmetic) run through the seam and compute correctly",
    run: |b| {
        b.reset_policy();
        let r = b.run_mediated(
            "echo PIPE=$(printf 'b\\na\\na\\nc\\n' | sort -u | wc -l | tr -d ' '); \
             echo JQ=$(printf '{\"k\":\"V\"}' | jq -r .k); \
             echo BASE=$(basename /a/b/c.txt)",
        );
        r.assert_entered();
        r.assert_contains("PIPE=3");
        r.assert_contains("JQ=V");
        r.assert_contains("BASE=c.txt");
        r.assert_allow();
    }
}

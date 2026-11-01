use strands_det_harness::det_case;

// A binary write and its read-back through pathlib are each one judged `fs:*` effect, and the bytes
// return unchanged, including a NUL.
det_case! {
    name: mo_bytes,
    id:   "MO-BYTES",
    desc: "Bytes round-trip: Path.write_bytes then read_bytes returns the same bytes, each effect judged",
    run: |b| {
        b.reset_policy();
        b.assert_python_is_monty();
        let r = b.run_py(
            "from pathlib import Path\nPath('b.bin').write_bytes(b'\\x00\\x01\\xff')\nprint('RB=' + str(Path('b.bin').read_bytes() == b'\\x00\\x01\\xff'))",
        );
        r.assert_monty();
        r.assert_mediated_permitted("fs:write", "b.bin");
        r.assert_mediated_permitted("fs:read", "b.bin");
        r.assert_contains("RB=True");
    }
}

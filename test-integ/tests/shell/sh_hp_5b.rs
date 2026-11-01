use strands_det_harness::det_case;

// `mv` is an `fs:move` the baseline default-denies (it permits `fs:read`/`fs:write` but names no
// `fs:move`), so this case grants exactly that one action and shows the move performs: the source
// is gone and the destination holds the file. The journaled `fs:move` permit proves mediation.
// (`rm`/`rmdir` are still out: the baseline *forbids* `fs:delete`, and a forbid cannot be widened
// by a composed permit — a delete case needs a base policy without that forbid.)
// Measured green on macOS 2026-09-22 (cargo test --test shell): journaled fs:move and `LS=1`
// (destination present) returned.
det_case! {
    name: sh_hp_5b,
    id:   "SH-HP-5B",
    desc: "Happy path: mv under a granted fs:move permit performs the rename in the workspace",
    run: |b| {
        b.apply_policy(
            r#"@id("mv") permit (principal, action == Box::Action::"fs:move", resource);"#,
        );
        let r = b.run_mediated(
            "touch src.txt && mv src.txt dst.txt \
             && echo LS=$(ls | grep -c dst.txt) SRC=$(ls | grep -c src.txt)",
        );
        r.assert_entered();
        r.assert_mediated_permitted("fs:move", "dst.txt");
        // The destination is present AND the source is gone, so a mv that behaved like a copy
        // (leaving src.txt) turns this RED rather than staying GREEN on the destination alone.
        r.assert_contains("LS=1 SRC=0");
        r.assert_allow();
    }
}

use strands_det_harness::det_case;

// Under an `fs:move` permit, a `mv` onto a new name performs, and a `mv` onto an existing file is
// refused by the baseline's `no_deletes` forbid.
det_case! {
    name: sh_mv_replace,
    id:   "SH-MV-REPLACE",
    desc: "Replacing mv: under an fs:move permit, mv to a new name performs and onto an existing file is refused by no_deletes; both files keep their content",
    run: |b| {
        b.apply_policy(r#"@id("mv") permit (principal, action == Box::Action::"fs:move", resource);"#);
        let r = b.run_mediated(
            "echo new > a.txt; echo old > b.txt; echo n > n.txt; mv n.txt fresh.txt; echo FRESH=$(cat fresh.txt); mv a.txt b.txt 2>&1; echo MVRC=$?; echo STATE=$(cat a.txt),$(cat b.txt)",
        );
        r.assert_entered();
        r.assert_mediated_permitted("fs:move", "fresh.txt");
        r.assert_contains("FRESH=n");
        assert!(
            r.decisions
                .iter()
                .any(|d| d.denied() && d.resource.ends_with("/b.txt") && d.forbidden_by("no_deletes")),
            "the move onto b.txt must be refused by no_deletes; out=[{}]",
            r.snippet()
        );
        r.assert_contains("STATE=new,old");
        r.assert_absent("MVRC=0");
    }
}

use strands_det_harness::{det_case, scenarios::MoveReplacement};

// Under an `fs:move` permit, a `mv` onto a new name performs, and a `mv` onto an existing file is
// refused by the baseline's `no_deletes` forbid.
det_case! {
    name: sh_mv_replace,
    id:   "SH-MV-REPLACE",
    desc: "Replacing mv: under an fs:move permit, mv to a new name performs and onto an existing file is refused by no_deletes; both files keep their content",
    run: |b| {
        MoveReplacement::permit(b);
        let r = b.run_mediated(
            "echo new > a.txt; echo old > b.txt; echo n > n.txt; mv n.txt fresh.txt; echo FRESH=$(cat fresh.txt); mv a.txt b.txt 2>&1; echo MVRC=$?; echo STATE=$(cat a.txt),$(cat b.txt)",
        );
        r.assert_entered();
        MoveReplacement::assert_result(&r);
        r.assert_absent("MVRC=0");
    }
}

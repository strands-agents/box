use strands_det_harness::det_case;

// Containment CN-L (`list` enumerates without content)
//
// macOS only: the Linux namespace backend has no lowering for `list`, and the box refuses the
// entry by name at load, so the fixture writes the entry on macOS alone.
det_case! {
    name: cn_l_01,
    id:   "CN-L-01",
    platforms: [Macos],
    desc: "List: a listed tree enumerates its entries and a content read of one of them is refused",
    run: |b| {
        b.reset_policy();
        let listed = b.listed_tree();
        let r = b.run_sh(&format!(
            "for e in '{d}'/*; do printf 'ENTRY=%s\\n' \"${{e##*/}}\"; done; read -r v < '{d}/entry.txt' 2>/dev/null && printf 'CONTENT=%s\\n' \"$v\"; printf done",
            d = listed.display()
        ));
        r.assert_contains("ENTRY=entry.txt");
        r.assert_absent("CONTENT=");
        r.assert_contains("done");
    }
}

use std::os::unix::fs::MetadataExt as _;

use strands_det_harness::det_case;

// A stat keeps the real size and file type, and reports `nlink` 1 and, for a file a non-root host
// user owns, `uid` and `gid` 0.
det_case! {
    name: mo_stat,
    id:   "MO-STAT",
    desc: "Metadata: stat of a hard-linked file reports its real size with nlink normalized to 1 and uid and gid to 0, and is_dir and is_file report the real type",
    run: |b| {
        b.reset_policy();
        let file = b.workspace().join("h.txt");
        std::fs::write(&file, "hello").expect("plant the file");
        std::fs::hard_link(&file, b.workspace().join("h2.txt")).expect("plant the hard link");
        std::fs::create_dir(b.workspace().join("dd")).expect("plant the directory");
        let host = std::fs::metadata(&file).expect("stat the planted file");
        assert_eq!(host.nlink(), 2, "DET_ERROR: the planted file must have two host links");
        b.assert_python_is_monty();
        let r = b.run_py(
            "from pathlib import Path\nst = Path('h.txt').stat()\nprint('ST=' + str(st.st_size) + ',' + str(st.st_uid) + ',' + str(st.st_gid) + ',' + str(st.st_nlink))\nprint('TYPE=' + str(Path('dd').is_dir()) + ',' + str(Path('dd').is_file()))",
        );
        r.assert_monty();
        r.assert_mediated_permitted("fs:read", "h.txt");
        let st = r
            .out
            .lines()
            .find_map(|line| line.strip_prefix("ST="))
            .unwrap_or_default();
        let fields: Vec<&str> = st.split(',').collect();
        assert_eq!(fields.len(), 4, "the script prints size, uid, gid and nlink; out=[{}]", r.snippet());
        assert_eq!(fields[0], "5", "the size must be the real size: {st}");
        assert_eq!(fields[3], "1", "nlink must be normalized to 1 although the host has two links: {st}");
        if host.uid() != 0 {
            assert_eq!(fields[1], "0", "uid must be normalized to 0 for a non-root-owned host file: {st}");
        }
        if host.gid() != 0 {
            assert_eq!(fields[2], "0", "gid must be normalized to 0 for a non-root-owned host file: {st}");
        }
        r.assert_contains("TYPE=True,False");
    }
}

use std::os::unix::fs::MetadataExt as _;
use std::time::{Duration, UNIX_EPOCH};

use strands_det_harness::det_case;

// The Shell's `touch` sets the times of a workspace file through the real box, on every runner.
// The harness config sets no `file-attributes`, so on macOS this also shows that the Shell's
// built-in `touch` needs no such switch: it runs in the box's trusted process, outside the agent's
// sandbox. `old.txt` starts at 1990-01-01; `-d` must move both times to 2001-02-03T04:05:06Z, and
// a plain `touch` must move `plain.txt` off 1990, which is the case #361 reports.
det_case! {
    name: sh_touch_times,
    id:   "SH-TOUCH-TIMES",
    desc: "The Shell's touch sets a workspace file's times, with -d and plain, without file-attributes",
    run: |b| {
        b.reset_policy();
        let old = UNIX_EPOCH + Duration::from_secs(631_152_000);
        for name in ["old.txt", "plain.txt"] {
            let path = b.workspace().join(name);
            std::fs::write(&path, "KEEP").expect("plant a file");
            std::fs::File::options()
                .write(true)
                .open(&path)
                .expect("open the planted file")
                .set_times(std::fs::FileTimes::new().set_accessed(old).set_modified(old))
                .expect("age the planted file");
        }
        let r = b.run_mediated("touch -d @981173106 old.txt && touch plain.txt && echo TOUCH_OK");
        r.assert_entered();
        r.assert_mediated_permitted("fs:write", "old.txt");
        r.assert_mediated_permitted("fs:write", "plain.txt");
        r.assert_contains("TOUCH_OK");
        r.assert_allow();
        let dated = std::fs::metadata(b.workspace().join("old.txt")).expect("stat old.txt");
        assert_eq!((dated.atime(), dated.mtime()), (981_173_106, 981_173_106), "-d sets both times");
        let plain = std::fs::metadata(b.workspace().join("plain.txt")).expect("stat plain.txt");
        assert!(plain.mtime() > 981_173_106, "a plain touch moves the time to now");
        assert_eq!(
            std::fs::read_to_string(b.workspace().join("old.txt")).expect("read old.txt"),
            "KEEP",
            "the content is kept"
        );
    }
}

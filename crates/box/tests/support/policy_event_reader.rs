//! Reads every retained Dogwood record after the workload exits.
use dogwood_local_engine::{DurableLog, Record};

fn main() {
    let path = std::env::args().nth(1).expect("copied history path");
    assert!(std::path::Path::new(&path).is_file(), "history is absent");
    let log = DurableLog::open(path).expect("open copied history");
    assert_eq!(log.base_offset(), 0, "history prefix was reclaimed");
    let mut next = 0;
    log.scan_from(0, |offset, bytes| {
        assert_eq!(offset, next, "missing history record");
        next += 1;
        let record = Record::decode(bytes).expect("decode history record");
        let encoded = record.encode();
        let text = std::str::from_utf8(&encoded).expect("JSON record");
        println!("{{\"offset\":{offset},\"record\":{text}}}");
    })
    .expect("read complete history");
    assert_eq!(next, log.next_offset(), "history suffix is missing");
    assert!(next > 0, "empty history");
}

//! Read recorded events and their request identifiers for policy tests.

use std::path::Path;

use dogwood_language::{Event, Value};
use dogwood_local_engine::{DurableLog, Record};

pub(crate) fn events(path: &Path) -> Vec<Event> {
    let log = DurableLog::open(path).expect("history opens");
    let mut events = Vec::new();
    log.scan_from(0, |_, bytes| {
        if let Record::Event(event) = Record::decode(bytes).expect("record decodes") {
            events.push(event);
        }
    })
    .expect("history scans");
    events
}

pub(crate) fn identifier(event: &Event) -> &str {
    match event.field_path(&["requestId".to_string()]) {
        Some(Value::String(value)) if !value.is_empty() => value,
        other => panic!(
            "{} must carry a nonempty requestId: {other:?}",
            event.kind()
        ),
    }
}

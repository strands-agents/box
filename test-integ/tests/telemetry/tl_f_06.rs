use strands_det_harness::det_case;
use strands_det_harness::telemetry::{CONTROL_SCOPE, POLICY_SCOPE};

/// `has_is_remote_parent | is_remote_parent`, which only a span with a remote caller may set.
const REMOTE_PARENT_FLAGS: u64 = 0x300;

// A viewer draws traces, not log lines. So each decision record must arrive beside a span carrying
// the same trace and span id, and a control operation must do the same — otherwise a run's own work
// is invisible in the one tool an operator reads it with.
//
// Two things here are easy to get wrong and both were defects before:
//
//  1. A control-plane operation has no request to inherit a parent from, so the run supplies one.
//     One run is ONE trace: the first operation takes the root and every later one names it as
//     parent. A fresh root per operation is four unrelated traces for one box life, which a viewer
//     cannot assemble.
//  2. The remote-parent flags belong to the policy plane alone. A control child names this run's own
//     root, which is local, so a control span that set 0x300 made a viewer draw the box's own
//     children as if a remote caller had sent them.
det_case! {
    name: tl_f_06,
    id:   "TL-F-06",
    desc: "Each record arrives beside its span, one run's control plane is one trace with one root, and no control child claims a remote parent",
    run: |b| {
        b.reset_policy();
        let r = b.run_mediated("echo TL_TRACED; cat /etc/hosts");
        r.assert_contains("TL_TRACED");
        r.assert_mediated_denied("fs:read", "/etc/hosts");

        let journal = b.telemetry();
        journal.assert_recorded();
        journal.assert_well_formed();
        let spans = journal.spans();
        assert!(!spans.is_empty(), "a run that decides anything exports spans");

        // Every decision record is matched to a span of its own, by both ids.
        for record in journal.logs_under(POLICY_SCOPE) {
            let matched = spans.iter().find(|span| {
                span.trace_id == record.trace_id && span.span_id == record.span_id
            });
            let span = matched.unwrap_or_else(|| {
                panic!(
                    "line {}: the record at trace {} span {} has no span beside it; the file holds \
                     {} span(s)",
                    record.line,
                    record.trace_id,
                    record.span_id,
                    spans.len(),
                )
            });
            let action = record
                .attribute("strands.box.policy.action")
                .expect("a decision names an action");
            assert_eq!(
                span.name,
                format!("policy {action}"),
                "a decision's span names its action",
            );
            assert_eq!(span.scope, POLICY_SCOPE, "the span keeps the record's scope");
        }

        // One run is one control trace, with exactly one root. The file holds the preflight run too,
        // so the control spans are grouped by trace rather than counted across the file.
        let control: Vec<_> = spans
            .iter()
            .filter(|span| span.scope == CONTROL_SCOPE)
            .collect();
        assert!(
            !control.is_empty(),
            "a run records its own control plane; the file names scopes {:?}",
            journal.scopes(),
        );
        let mut traces: Vec<&str> = control.iter().map(|span| span.trace_id.as_str()).collect();
        traces.sort_unstable();
        traces.dedup();
        for trace in &traces {
            let within: Vec<_> = control
                .iter()
                .filter(|span| span.trace_id == *trace)
                .collect();
            let roots: Vec<&str> = within
                .iter()
                .filter(|span| span.is_root())
                .map(|span| span.name.as_str())
                .collect();
            assert_eq!(
                roots.len(),
                1,
                "trace {trace} holds {} control span(s) and {} root(s) {roots:?}; one run's control \
                 plane is one trace with one root",
                within.len(),
                roots.len(),
            );
            let root = within
                .iter()
                .find(|span| span.is_root())
                .expect("the trace has one root");
            for child in within.iter().filter(|span| !span.is_root()) {
                assert_eq!(
                    child.parent_span_id, root.span_id,
                    "every later control operation names the run's root as parent",
                );
                assert_eq!(
                    child.flags & REMOTE_PARENT_FLAGS,
                    0,
                    "control span {:?} claims a remote parent, and this run's root is local",
                    child.name,
                );
            }
        }
        // One control trace per run, and the file holds the preflight run and this one.
        assert_eq!(
            traces.len(),
            journal.run_ids().len(),
            "one run is one control trace: {} trace(s) against {} run(s)",
            traces.len(),
            journal.run_ids().len(),
        );
        b.record_note(format!(
            "{} span(s); {} control trace(s) over {} run(s)",
            spans.len(),
            traces.len(),
            journal.run_ids().len(),
        ));
    }
}

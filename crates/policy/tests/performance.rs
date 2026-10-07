//! The policy engine's non-functional requirements, measured as control against treatment.

use std::io::Write as _;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use policy::{
    Decision, DecisionObserver, GovernedBox, Operator, Policy, PolicyEngine, Principal, Request,
};

/// Decisions per measured run.
const SAMPLES: usize = 1_000;
/// A loose sanity bound on one decision in any build profile, not the 1 ms requirement.
const LARGEST_P99: Duration = Duration::from_secs(1);
/// The largest temporal-over-plain p50 ratio that passes.
const LARGEST_TEMPORAL_RATIO: f64 = 5.0;
/// The largest observed-over-plain p50 ratio that passes.
const LARGEST_OBSERVER_RATIO: f64 = 1.5;
/// Ten times the rules may cost at most ten times the load time.
const LARGEST_LOAD_RATIO: f64 = 10.0;
const LOAD_REPEATS: usize = 5;

static SERIAL: Mutex<()> = Mutex::new(());

fn one_at_a_time() -> MutexGuard<'static, ()> {
    SERIAL
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn rules(count: usize) -> String {
    (0..count)
        .map(|index| {
            format!(
                "@id(\"rule_{index}\")\npermit(principal == Box::Agent::\"self\", \
                 action == Box::Action::\"shell:exec\", resource)\n\
                 when {{ context.input.program == \"program-{index}\" }};\n"
            )
        })
        .collect()
}

const COUNTING_RULE: &str = r#"
@id("counting")
permit(principal == Box::Agent::"self", action == Box::Action::"shell:exec", resource)
when temporal {
    exists (total: Long). (
        (count for (t: Timepoint). where (
            formerly within 60s (
                Box::Action::"shell:exec"::request{ input.program: _ } && tp(t)
            )
        )) == total
        && total < 1000000000
    )
};
"#;

fn sources(text: String) -> Vec<Policy> {
    vec![Policy {
        origin: PathBuf::from("performance.dw"),
        text,
    }]
}

struct Opened {
    engine: PolicyEngine,
    _history: tempfile::TempDir,
}

fn open(text: String) -> Opened {
    let history = tempfile::tempdir().expect("history directory");
    let engine =
        PolicyEngine::open(sources(text), &history.path().join("dogwood.redb")).expect("opens");
    Opened {
        engine,
        _history: history,
    }
}

fn open_observed(text: String, observer: Arc<dyn DecisionObserver>) -> Opened {
    let history = tempfile::tempdir().expect("history directory");
    let engine = PolicyEngine::open(sources(text), &history.path().join("dogwood.redb"))
        .expect("opens")
        .observed_by(observer);
    Opened {
        engine,
        _history: history,
    }
}

/// A program only the temporal rule permits, so a permit under it proves the rule decided.
const COUNTED_PROGRAM: &str = "program-counted";
/// A program one plain rule permits.
const PLAIN_PROGRAM: &str = "program-7";

fn decide_once(engine: &PolicyEngine, program: &str) -> Duration {
    let args = ["a".to_string(), "b".to_string()];
    let command = format!("{program} a b");
    let request = Request::ShellExec {
        command: &command,
        program,
        args: &args,
        cwd: "/tmp",
    };
    let started = Instant::now();
    let decision = engine.decide(
        &GovernedBox::assigned("perf"),
        &Principal::agent(),
        &request,
    );
    let elapsed = started.elapsed();
    assert!(
        decision.is_allow(),
        "the measured decision must be a permit: {decision:?}"
    );
    elapsed
}

fn latencies(engine: &PolicyEngine, program: &str, count: usize) -> Vec<Duration> {
    (0..count).map(|_| decide_once(engine, program)).collect()
}

fn percentile(samples: &[Duration], fraction: f64) -> Duration {
    let mut sorted = samples.to_vec();
    sorted.sort_unstable();
    let last = sorted.len().checked_sub(1).expect("samples");
    sorted[((last as f64) * fraction).round() as usize]
}

fn ratio(treatment: Duration, control: Duration) -> f64 {
    treatment.as_secs_f64() / control.as_secs_f64().max(f64::EPSILON)
}

const PROFILE: &str = if cfg!(debug_assertions) {
    "debug"
} else {
    "release"
};

/// Write a measurement straight to stderr, past the harness capture, so a CI log shows it.
fn report(line: String) {
    let mut stderr = std::io::stderr().lock();
    let _ = writeln!(stderr, "{line}");
}

fn summary(name: &str, samples: &[Duration]) -> String {
    format!(
        "{name} ({PROFILE}): p50 {:?}, p99 {:?}, max {:?} over {} decisions",
        percentile(samples, 0.5),
        percentile(samples, 0.99),
        percentile(samples, 1.0),
        samples.len()
    )
}

#[test]
fn a_decision_under_a_temporal_rule_costs_no_more_than_five_plain_decisions() {
    let _serial = one_at_a_time();
    let plain = open(rules(20));
    let temporal = open(format!("{}{COUNTING_RULE}", rules(20)));

    let plain_first = latencies(&plain.engine, PLAIN_PROGRAM, SAMPLES);
    let under_temporal = latencies(&temporal.engine, COUNTED_PROGRAM, SAMPLES);
    let plain_again = latencies(&plain.engine, PLAIN_PROGRAM, SAMPLES);
    let plain_all = [plain_first.as_slice(), plain_again.as_slice()].concat();

    let plain_p50 = percentile(&plain_all, 0.5);
    let temporal_p50 = percentile(&under_temporal, 0.5);
    let temporal_p99 = percentile(&under_temporal, 0.99);
    let temporal_ratio = ratio(temporal_p50, plain_p50);
    report(format!("NFR-01 {}", summary("plain, 20 rules", &plain_all)));
    report(format!(
        "NFR-01 {}",
        summary("20 rules plus one temporal rule", &under_temporal)
    ));
    report(format!(
        "NFR-01 temporal over plain p50 ratio {temporal_ratio:.2}, limit {LARGEST_TEMPORAL_RATIO}; \
         requirement 1 ms p99, missed today (box issue #150)"
    ));

    assert!(
        temporal_ratio <= LARGEST_TEMPORAL_RATIO,
        "a decision under a temporal rule costs {temporal_p50:?} at p50 against {plain_p50:?} \
         without one (ratio {temporal_ratio:.2}, limit {LARGEST_TEMPORAL_RATIO}): the temporal scan \
         grew past the rule set; plain {:?} temporal {:?}",
        summary("plain", &plain_all),
        summary("temporal", &under_temporal)
    );
    assert!(
        temporal_p99 <= LARGEST_P99,
        "one decision costs {temporal_p99:?} at p99, past the {LARGEST_P99:?} sanity bound"
    );
}

#[test]
fn loading_two_hundred_rules_costs_at_most_ten_times_loading_twenty() {
    let _serial = one_at_a_time();
    let measure = |count: usize| {
        let text = rules(count);
        let sources = sources(text.clone());
        let mut validates = Vec::with_capacity(LOAD_REPEATS);
        let mut opens = Vec::with_capacity(LOAD_REPEATS);
        let mut first_decisions = Vec::with_capacity(LOAD_REPEATS);
        for _ in 0..LOAD_REPEATS {
            let started = Instant::now();
            PolicyEngine::validate(&Operator::unanchored(), &sources).expect("validates");
            validates.push(started.elapsed());
            let started = Instant::now();
            let opened = open(text.clone());
            opens.push(started.elapsed());
            first_decisions.push(decide_once(&opened.engine, PLAIN_PROGRAM));
        }
        (
            percentile(&validates, 0.5),
            percentile(&opens, 0.5),
            percentile(&first_decisions, 0.5),
        )
    };
    let (validate_20, open_20, first_20) = measure(20);
    let (validate_200, open_200, first_200) = measure(200);
    let validate_ratio = ratio(validate_200, validate_20);
    let open_ratio = ratio(open_200, open_20);
    report(format!(
        "NFR-05 20 rules ({PROFILE}): validate {validate_20:?}, open {open_20:?}, first decision \
         {first_20:?} (medians of {LOAD_REPEATS})"
    ));
    report(format!(
        "NFR-05 200 rules: validate {validate_200:?}, open {open_200:?}, first decision \
         {first_200:?} (medians of {LOAD_REPEATS})"
    ));
    report(format!(
        "NFR-05 200 over 20 ratios: validate {validate_ratio:.2}, open {open_ratio:.2}, limit \
         {LARGEST_LOAD_RATIO}"
    ));

    assert!(
        validate_ratio <= LARGEST_LOAD_RATIO,
        "validating 200 rules costs {validate_200:?} against {validate_20:?} for 20 (ratio \
         {validate_ratio:.2}, limit {LARGEST_LOAD_RATIO}): validation grows faster than the rule count"
    );
    assert!(
        open_ratio <= LARGEST_LOAD_RATIO,
        "opening 200 rules costs {open_200:?} against {open_20:?} for 20 (ratio {open_ratio:.2}, \
         limit {LARGEST_LOAD_RATIO}): loading grows faster than the rule count"
    );
}

/// Queues each verdict for a thread that writes it to a file, the shape an observer must take.
struct QueuedToFile(std::sync::mpsc::Sender<String>);

impl DecisionObserver for QueuedToFile {
    fn observed(&self, action: &str, resource: &str, decision: &Decision) {
        let _ = self
            .0
            .send(format!("{action} {resource} {}\n", decision.is_allow()));
    }
}

#[test]
fn an_observer_with_a_file_target_costs_at_most_half_a_decision_more() {
    let _serial = one_at_a_time();
    let target_directory = tempfile::tempdir().expect("target directory");
    let target = target_directory.path().join("decisions.log");
    let (sender, receiver) = std::sync::mpsc::channel::<String>();
    let writer = std::thread::spawn({
        let target = target.clone();
        move || {
            use std::io::Write as _;
            let mut file = std::fs::File::create(target).expect("target file");
            for line in receiver {
                file.write_all(line.as_bytes()).expect("write a record");
            }
            file.sync_all().expect("sync the target");
        }
    });
    let plain = open(rules(20));
    let observed = open_observed(rules(20), Arc::new(QueuedToFile(sender)));

    let plain_first = latencies(&plain.engine, PLAIN_PROGRAM, SAMPLES);
    let with_observer = latencies(&observed.engine, PLAIN_PROGRAM, SAMPLES);
    let plain_again = latencies(&plain.engine, PLAIN_PROGRAM, SAMPLES);
    drop(observed);
    writer.join().expect("the writer finishes");
    let plain_all = [plain_first.as_slice(), plain_again.as_slice()].concat();

    let written = std::fs::read_to_string(&target).expect("the target reads");
    assert_eq!(
        written.lines().count(),
        SAMPLES,
        "every observed verdict reaches the file target"
    );

    let plain_p50 = percentile(&plain_all, 0.5);
    let observed_p50 = percentile(&with_observer, 0.5);
    let observer_ratio = ratio(observed_p50, plain_p50);
    report(format!("NFR-11 {}", summary("no observer", &plain_all)));
    report(format!(
        "NFR-11 {}",
        summary("observer with a file target", &with_observer)
    ));
    report(format!(
        "NFR-11 observed over plain p50 ratio {observer_ratio:.2}, limit {LARGEST_OBSERVER_RATIO}; \
         file target holds {} bytes",
        written.len()
    ));

    assert!(
        observer_ratio <= LARGEST_OBSERVER_RATIO,
        "a decision with an observer costs {observed_p50:?} at p50 against {plain_p50:?} without \
         one (ratio {observer_ratio:.2}, limit {LARGEST_OBSERVER_RATIO}): the observer does work on \
         the decision path; {} / {}",
        summary("plain", &plain_all),
        summary("observed", &with_observer)
    );
}

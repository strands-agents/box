//! Measures Box policy decisions with and without periodic idle flushing.
#[cfg(feature = "experimental-idle-flush")]
mod benchmark {
    use policy::{
        ApprovedPath, FsOperation, FsResult, GovernedBox, Outcome, PathResolver, Policy,
        PolicyEngine, Principal, Request,
    };
    use serde_json::{Value, json};
    use std::{
        fs,
        path::{Path, PathBuf},
        sync::{Arc, Barrier},
        time::{Duration, Instant},
    };
    const CONTENT: &[u8] = b"idle-flush-performance-fixture\n";

    fn summary(mut samples: Vec<u64>) -> Value {
        samples.sort_unstable();
        let at = |p: f64| samples[((samples.len() - 1) as f64 * p).round() as usize];
        json!({"count":samples.len(),"p50_us":at(0.50) as f64/1000.0,
               "p95_us":at(0.95) as f64/1000.0,"p99_us":at(0.99) as f64/1000.0,
               "p999_us":at(0.999) as f64/1000.0,"max_us":at(1.0) as f64/1000.0,
               "over_1ms":samples.iter().filter(|v| **v>1_000_000).count(),
               "over_10ms":samples.iter().filter(|v| **v>10_000_000).count()})
    }

    fn perform(
        engine: &PolicyEngine,
        actual: &Path,
        approved: &ApprovedPath,
        write: bool,
    ) -> (u64, u64, u64) {
        let op = if write {
            FsOperation::WriteContent
        } else {
            FsOperation::ReadContent
        };
        let governed = GovernedBox::assigned("idle-flush-bench");
        let principal = Principal::agent();
        let begin = Instant::now();
        let (verdict, request_id) = engine.decide(
            &governed,
            &principal,
            &Request::Fs {
                path: approved,
                operation: op,
            },
        );
        let decision_ns = begin.elapsed().as_nanos() as u64;
        assert!(verdict.is_allow(), "measured request denied: {verdict:?}");
        let request_id = request_id.expect("an allowed request has a confirmed history token");
        if write {
            fs::write(actual, CONTENT).expect("write fixture");
        } else {
            assert_eq!(fs::read(actual).expect("read fixture"), CONTENT);
        }
        let before_record = Instant::now();
        engine
            .record(
                &governed,
                &principal,
                &request_id,
                &Outcome::Fs {
                    path: actual,
                    operation: op,
                    result: FsResult::Completed,
                },
            )
            .expect("record outcome");
        (
            decision_ns,
            before_record.elapsed().as_nanos() as u64,
            begin.elapsed().as_nanos() as u64,
        )
    }

    pub fn run() {
        let args: Vec<_> = std::env::args().collect();
        assert_eq!(
            args.len(),
            6,
            "WORKDIR POLICY_FILE OPERATIONS CALLERS TIMER_MS(0=off)"
        );
        let directory = PathBuf::from(&args[1]);
        let policy_path = PathBuf::from(&args[2]);
        let operations: usize = args[3].parse().expect("operations");
        let callers: usize = args[4].parse().expect("callers");
        let timer_ms: u64 = args[5].parse().expect("timer ms");
        assert!(callers > 0 && operations >= callers * 2 && operations.is_multiple_of(callers * 2));
        fs::create_dir_all(&directory).expect("workdir");
        let directory = directory.canonicalize().expect("absolute workdir");
        let db = directory.join("history.redb");
        assert!(!db.exists(), "each run requires a fresh store");
        let rules = fs::read_to_string(&policy_path).expect("policy fixture");
        let engine = Arc::new(
            PolicyEngine::open(
                vec![Policy {
                    origin: policy_path.clone(),
                    text: rules,
                }],
                &db,
            )
            .expect("open Box policy"),
        );
        engine
            .set_periodic_history(1000, Duration::from_secs(1))
            .expect("set same event thresholds");
        let resolver = PathResolver::over([directory.clone()]).expect("path resolver");
        let mut workers = Vec::new();
        for w in 0..callers {
            let mut files = Vec::new();
            for i in 0..16 {
                let actual = directory.join(format!("worker{w}-file{i}"));
                fs::write(&actual, CONTENT).expect("initial file");
                let approved = resolver.approve_host(&actual).expect("approved file");
                files.push((actual, approved));
            }
            workers.push(files);
        }
        let history_policy = policy_path.file_stem().unwrap() == "history";
        let (first_write, _) = engine.decide(
            &GovernedBox::assigned("idle-flush-bench"),
            &Principal::agent(),
            &Request::Fs {
                path: &workers[0][0].1,
                operation: FsOperation::WriteContent,
            },
        );
        assert_eq!(
            first_write.is_allow(),
            !history_policy,
            "history policy must require earlier read"
        );
        for files in &workers {
            for (actual, approved) in files {
                perform(&engine, actual, approved, false);
                perform(&engine, actual, approved, true);
            }
        }
        engine
            .flush_history()
            .expect("persist setup outside measurement");
        let timer = if timer_ms > 0 {
            Some(Arc::new(
                engine
                    .start_history_flusher(Duration::from_millis(timer_ms))
                    .expect("start timer"),
            ))
        } else {
            None
        };
        let barrier = Arc::new(Barrier::new(callers + 1));
        let threads: Vec<_> = workers
            .into_iter()
            .map(|files| {
                let engine = Arc::clone(&engine);
                let barrier = Arc::clone(&barrier);
                let timer = timer.clone();
                std::thread::spawn(move || {
                    let count = operations / callers;
                    let mut decision = Vec::with_capacity(count);
                    let mut record = Vec::with_capacity(count);
                    let mut total = Vec::with_capacity(count);
                    barrier.wait();
                    let begin = Instant::now();
                    for n in 0..count {
                        let (actual, approved) = &files[(n / 2) % files.len()];
                        let (d, r, t) = perform(&engine, actual, approved, !n.is_multiple_of(2));
                        decision.push(d);
                        record.push(r);
                        total.push(t);
                    }
                    let finished = Instant::now();
                    let timer_stats = timer.as_ref().map(|t| t.snapshot());
                    (
                        decision,
                        record,
                        total,
                        finished.duration_since(begin).as_secs_f64(),
                        finished,
                        timer_stats,
                    )
                })
            })
            .collect();
        if let Some(timer) = &timer {
            assert_eq!(
                timer.snapshot().attempts,
                0,
                "timer setup must finish before its first tick"
            );
        }
        let begin = Instant::now();
        barrier.wait();
        let mut decisions = Vec::new();
        let mut records = Vec::new();
        let mut totals = Vec::new();
        let mut worker_seconds = Vec::new();
        let mut last_completion = begin;
        let mut timer_stats = None;
        for t in threads {
            let (d, r, v, s, completed, stats) = t.join().expect("worker completes");
            if completed > last_completion {
                last_completion = completed;
                timer_stats = stats;
            }
            decisions.extend(d);
            records.extend(r);
            totals.extend(v);
            worker_seconds.push(s);
        }
        let seconds = last_completion.duration_since(begin).as_secs_f64();
        let close_begin = Instant::now();
        let shutdown = if let Some(timer) = timer {
            Some(
                Arc::try_unwrap(timer)
                    .unwrap_or_else(|_| panic!("all worker timer references must be released"))
                    .shutdown()
                    .expect("final timer flush"),
            )
        } else {
            engine.flush_history().expect("final flush");
            None
        };
        let close_ms = close_begin.elapsed().as_secs_f64() * 1000.0;
        let result = json!({"policy":policy_path.file_stem().unwrap().to_str().unwrap(),"timer_ms":timer_ms,
            "event_threshold":1000,"event_interval_ms":1000,"snapshot_interval_events":10000,
            "operations":operations,"reads":operations/2,"writes":operations/2,"engine_submissions":operations*2,
            "callers":callers,"files_per_caller":16,"seconds":seconds,"ops_per_second":operations as f64/seconds,
            "decision":summary(decisions),"record":summary(records),"operation":summary(totals),"worker_seconds":worker_seconds,
            "timer_during_measurement":timer_stats.map(|s|json!({"attempts":s.attempts,"successes":s.successes,"failures":s.failures,"total_us":s.total_micros,"max_us":s.max_micros,"last_error":s.last_error})),
            "shutdown":shutdown.map(|s|json!({"attempts":s.attempts,"successes":s.successes,"failures":s.failures,"last_error":s.last_error})),
            "shutdown_ms":close_ms,"initial_history_policy_control_passed":true});
        fs::write(
            directory.join("result.json"),
            serde_json::to_vec_pretty(&result).unwrap(),
        )
        .expect("save results");
        println!("{}", serde_json::to_string(&result).unwrap());
    }
}
#[cfg(feature = "experimental-idle-flush")]
fn main() {
    benchmark::run()
}
#[cfg(not(feature = "experimental-idle-flush"))]
fn main() {
    eprintln!("Enable experimental-idle-flush to run this prototype benchmark.");
    std::process::exit(2)
}

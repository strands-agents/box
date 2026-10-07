//! emit-verdict — reduce the per-test `<id>.jsonl` rows into `verdict.json`.
//!
//! Run by `run.sh` after `cargo test`, which hands it cargo's exit status in
//! `DET_CARGO_STATUS`. Prints the same summary block the bash suite did, plus
//! every integrity problem, and exits 0 (GREEN) / 1 (RED) so callers can gate on it.

use strands_det_harness::verdict;

fn main() {
    let dir = verdict::results_dir();
    let summary = match verdict::emit(&dir) {
        Ok(s) => s,
        Err(e) => {
            eprintln!(
                "[emit-verdict] failed to write verdict.json in {}: {e}",
                dir.display()
            );
            std::process::exit(1);
        }
    };

    let commit: String = summary.box_commit.chars().take(12).collect();
    println!("\n================ DETERMINISTIC VERDICT ================");
    println!(
        "platform={} commit={} verdict={}",
        summary.platform, commit, summary.verdict
    );
    println!(
        "total={} pass={} fail={} error={} skip={} (expected {} cases, recorded {}, cargo exit {})",
        summary.counts.total,
        summary.counts.pass,
        summary.counts.fail,
        summary.counts.error,
        summary.counts.skip,
        summary.integrity.expected,
        summary.integrity.recorded,
        summary
            .integrity
            .cargo_status
            .map_or("unreported".to_string(), |c| c.to_string())
    );
    for (cat, s) in &summary.by_category {
        println!(
            "  {:<16} pass={} fail={} error={} skip={}",
            cat, s.pass, s.fail, s.error, s.skip
        );
    }
    for row in summary.results.iter().filter(|r| r.result != "PASS") {
        let note: String = row.note.chars().take(160).collect();
        println!(
            "  {:<6} {:<9} {}",
            row.result,
            row.id,
            note.replace('\n', " ")
        );
    }
    for problem in &summary.integrity.problems {
        println!("  PROBLEM {problem}");
    }
    println!("coverage_gate={}", summary.coverage_gate);
    for q in &summary.quarantine {
        println!(
            "  QUARANTINE {} on {} applied={} owner={} restore when: {}",
            q.id, q.platform, q.applied, q.owner, q.restore_when
        );
    }
    println!("verdict written to {}", dir.join("verdict.json").display());
    println!("=======================================================");

    std::process::exit(if summary.verdict == "GREEN" { 0 } else { 1 });
}

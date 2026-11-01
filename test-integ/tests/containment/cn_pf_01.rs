use std::path::Path;
use strands_det_harness::{BoxFixture, det_case, sh_quote};

// Judge each process table's reach once per run.
//
// The box judges a tool's filesystem lists once, when the run opens, and a spawn acts on that
// judgement. This case pins the consequence: the per-call cost of a tool spawn does not grow with
// the number of entries under the tool's read grants.

/// Spawns per run. The first interval is the cold call and is not measured.
const CALLS: usize = 12;
const DIRECTORIES: usize = 300;
const FILES_PER_DIRECTORY: usize = 1000;
/// The largest per-call ratio, large grant over workspace grant, that passes.
const LARGEST_RATIO: f64 = 3.0;

det_case! {
    name: cn_pf_01,
    id:   "CN-PF-01",
    desc: "A tool spawn costs the same per call under a 300k-entry read grant as under the workspace alone: the box judges a tool's reach once per run, not per spawn",
    run: |b| {
        b.apply_policy(
            r#"@id("tool_spawn") permit (principal, action == Box::Action::"shell:spawn", resource);"#,
        );
        let tool = b.built_tool();
        let tree = b.workspace().with_file_name("spawn-latency-tree");
        let entries = plant_tree(&tree);
        let grant = serde_json::to_string(&tree.to_string_lossy()).unwrap();
        let widen = move |text: String| {
            let needle = "[tool.built.filesystem]\nread = [";
            assert!(
                text.contains(needle),
                "DET_ERROR: the fixture template no longer spells {needle:?}; the large run would measure the workspace grant"
            );
            text.replacen(needle, &format!("{needle}{grant}, "), 1)
        };

        let small_first = per_call_milliseconds(b, |text| text, &tool, None);
        let large = per_call_milliseconds(b, widen, &tool, Some(&tree));
        let small_again = per_call_milliseconds(b, |text| text, &tool, None);

        let small_median = median(&[small_first.clone(), small_again.clone()].concat());
        let large_median = median(&large);
        let ratio = large_median / small_median;
        b.record_note(format!(
            "per-call median: workspace grant {small_median:.1} ms (runs {:.1} / {:.1} ms), \
             workspace plus {entries} entries {large_median:.1} ms, ratio {ratio:.2}, limit {LARGEST_RATIO}",
            median(&small_first),
            median(&small_again),
        ));
        assert!(
            ratio <= LARGEST_RATIO,
            "a tool spawn under a {entries}-entry read grant costs {large_median:.1} ms per call against \
             {small_median:.1} ms under the workspace alone (ratio {ratio:.2}, limit {LARGEST_RATIO}): \
             the box judges the tool's reach per spawn instead of once per run; \
             intervals ms small={small_first:?} large={large:?} small={small_again:?}"
        );
    }
}

/// Run `tool` [`CALLS`] times through the hosted Shell against the configuration `edit` derives,
/// whose startup disclosure must name `grant` when one is given, and answer the interval in
/// milliseconds between consecutive `shell:spawn` permits, without the first.
fn per_call_milliseconds<F: FnOnce(String) -> String>(
    b: &BoxFixture,
    edit: F,
    tool: &Path,
    grant: Option<&Path>,
) -> Vec<f64> {
    let word = sh_quote(&tool.to_string_lossy());
    let calls: Vec<String> = (1..=CALLS).map(|n| format!("{word} call{n}")).collect();
    let r = b.run_mediated_with_config(edit, &format!("{}; echo SPAWNS_DONE", calls.join("; ")));
    r.assert_contains("SPAWNS_DONE");
    if let Some(grant) = grant {
        r.assert_contains(&grant.to_string_lossy());
    }
    for n in 1..=CALLS {
        r.assert_contains(&format!("BUILD_OUTPUT_RAN call{n}"));
    }
    let mut at: Vec<u64> = r
        .decisions
        .iter()
        .filter(|d| d.is_action("shell:spawn") && d.permitted())
        .map(|d| d.at_unix_nano)
        .collect();
    assert_eq!(
        at.len(),
        CALLS,
        "expected {CALLS} journaled shell:spawn permits; decisions:\n{:#?}\nout=[{}]",
        r.decisions,
        r.snippet()
    );
    assert!(
        at.iter().all(|&t| t > 0),
        "DET_ERROR: a shell:spawn record carries no timeUnixNano; decisions:\n{:#?}",
        r.decisions
    );
    at.sort_unstable();
    at.windows(2)
        .skip(1)
        .map(|pair| (pair[1] - pair[0]) as f64 / 1e6)
        .collect()
}

/// Create [`DIRECTORIES`] directories of [`FILES_PER_DIRECTORY`] empty files under `root`, and
/// answer the entry count.
fn plant_tree(root: &Path) -> usize {
    std::fs::create_dir_all(root).expect("DET_ERROR: create the synthetic tree");
    let directories: Vec<usize> = (0..DIRECTORIES).collect();
    std::thread::scope(|scope| {
        for chunk in directories.chunks(DIRECTORIES.div_ceil(4)) {
            scope.spawn(move || {
                for d in chunk {
                    let dir = root.join(format!("d{d:03}"));
                    std::fs::create_dir(&dir).expect("DET_ERROR: create a synthetic directory");
                    for f in 0..FILES_PER_DIRECTORY {
                        std::fs::File::create(dir.join(format!("f{f:04}")))
                            .expect("DET_ERROR: plant a file in the synthetic tree");
                    }
                }
            });
        }
    });
    DIRECTORIES * (FILES_PER_DIRECTORY + 1)
}

fn median(values: &[f64]) -> f64 {
    let mut sorted = values.to_vec();
    sorted.sort_by(f64::total_cmp);
    let n = sorted.len();
    assert!(n > 0, "DET_ERROR: no intervals to take a median of");
    if n % 2 == 1 {
        sorted[n / 2]
    } else {
        (sorted[n / 2 - 1] + sorted[n / 2]) / 2.0
    }
}

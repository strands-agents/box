//! Operator denials survive native ancestor replacement through the production launcher.

#![cfg(all(target_os = "linux", feature = "test-support"))]

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

#[path = "support/bounded_output.rs"]
mod bounded_output;
#[path = "support/fixture.rs"]
mod fixture;

struct Fixture {
    _root: tempfile::TempDir,
    root: PathBuf,
    work: PathBuf,
    denied: PathBuf,
    original: PathBuf,
    attempted: PathBuf,
}

impl Fixture {
    fn new(directory: bool) -> Self {
        let temporary = fixture::short_temporary_home();
        let root = temporary.path().canonicalize().unwrap();
        let work = root.join("work");
        std::fs::create_dir_all(work.join("one/two/three")).unwrap();
        let denied = work.join("one/two/three/denied");
        let (original, attempted) = if directory {
            std::fs::create_dir(&denied).unwrap();
            (denied.join("original"), denied.join("written"))
        } else {
            (denied.clone(), denied.clone())
        };
        std::fs::write(&original, b"protected bytes").unwrap();
        Self {
            _root: temporary,
            root,
            work,
            denied,
            original,
            attempted,
        }
    }

    fn run(&self, directory: bool, ancestor: &str, variant: &str, destination: &Path) -> Output {
        let source = self.work.join(ancestor);
        if variant == "renameat2-exchange" {
            std::fs::create_dir(destination).unwrap();
            std::fs::write(destination.join("replacement"), b"replacement bytes").unwrap();
        }
        let command = [
            env!("CARGO_BIN_EXE_box-filesystem-probe").to_string(),
            "denial-ancestor".to_string(),
            variant.to_string(),
            if directory { "directory" } else { "file" }.to_string(),
            self.work.display().to_string(),
            source.display().to_string(),
            destination.display().to_string(),
            self.denied.display().to_string(),
        ];
        let config = self.root.join("box.toml");
        std::fs::write(
            &config,
            format!(
                "name = 'denial-ancestors'\nbox_dir = {:?}\n\
             [agent]\ncommand = {command:?}\nworkspace = {:?}\n\
             [agent.filesystem]\nread = [{:?}]\nwrite = [{:?}]\ndeny = [{:?}]\n",
                self.root.join("state").display().to_string(),
                self.work.display().to_string(),
                self.work.display().to_string(),
                self.work.display().to_string(),
                self.denied.display().to_string(),
            ),
        )
        .unwrap();
        let mut command = Command::new(fixture::box_binary());
        command
            .args(["run", "--config"])
            .arg(config)
            .env("HOME", &self.root)
            .env("EXPERIMENTAL_LINUX_SUPPORT", "TRUE");
        bounded_output::bounded_output(command)
    }
}

fn denial_matrix(directory: bool, variants: &[(&str, bool)]) {
    if !fixture::namespace_launcher_is_usable() {
        println!("skipping: denial ancestor tests need the ARM64 Linux namespace launcher");
        return;
    }
    let mut failures = Vec::new();
    let mut cases = 0;
    for ancestor in ["one", "one/two", "one/two/three"] {
        for (variant, same_parent) in variants {
            let fixture = Fixture::new(directory);
            let destination = if *same_parent {
                fixture.work.join(ancestor).with_file_name("moved")
            } else {
                fixture.work.join("moved")
            };
            let output = fixture.run(directory, ancestor, variant, &destination);
            let stdout = String::from_utf8_lossy(&output.stdout);
            let stderr = String::from_utf8_lossy(&output.stderr);
            let label = format!(
                "{}/{ancestor}/{variant}/{}",
                if directory { "directory" } else { "file" },
                if *same_parent {
                    "same-parent"
                } else {
                    "grant-root"
                }
            );
            let report = stdout
                .lines()
                .find_map(|line| line.strip_prefix("DENIAL_ANCESTOR_RESULT="));
            let Some(report) = report else {
                failures.push(format!("{label}: probe did not finish: {output:?}"));
                continue;
            };
            let report: serde_json::Value = serde_json::from_str(report).unwrap();
            let relocated = destination.join(
                fixture
                    .original
                    .strip_prefix(fixture.work.join(ancestor))
                    .unwrap(),
            );
            let host = serde_json::json!({
                "original_intact": std::fs::read(&fixture.original)
                    .is_ok_and(|bytes| bytes == b"protected bytes"),
                "relocated_intact": std::fs::read(&relocated)
                    .is_ok_and(|bytes| bytes == b"protected bytes"),
                "workload_content_at_denied_path": std::fs::read(&fixture.attempted)
                    .is_ok_and(|bytes| bytes == b"workload bytes"),
            });
            println!("{label}: workload={report} host={host}");
            let mut check = |condition: bool, detail: &str| {
                if !condition {
                    failures.push(format!("{label}: {detail}"));
                }
            };
            check(
                output.status.success(),
                &format!("workload failed: {stderr}"),
            );
            check(report["renamed"] == false, "ancestor replacement succeeded");
            check(
                report["wrote_original_name"] == false,
                "workload wrote at the denied original name",
            );
            for field in [
                "original_read_before",
                "original_read_after",
                "relocated_read_after",
            ] {
                check(
                    report[field] == false,
                    &format!("protected bytes became readable: {field}"),
                );
            }
            check(
                report["permitted_controls"] == true,
                "permitted operations did not complete",
            );
            let errno = report["rename_errno"].as_i64();
            let expected_refusal = if variant.starts_with("renameat2") {
                errno == Some(i64::from(libc::EPERM))
            } else if *same_parent {
                errno == Some(i64::from(libc::EBUSY))
            } else {
                errno == Some(i64::from(libc::EBUSY)) || errno == Some(i64::from(libc::EXDEV))
            };
            check(expected_refusal, "rename failed for an unexpected reason");
            check(
                std::fs::read(&fixture.original).is_ok_and(|bytes| bytes == b"protected bytes"),
                "original protected bytes changed or moved on the surrounding OS",
            );
            if directory {
                check(
                    !fixture.attempted.exists(),
                    "workload content persisted under the denied directory",
                );
            }
            if *variant == "renameat2-exchange" {
                check(
                    std::fs::read(destination.join("replacement"))
                        .is_ok_and(|bytes| bytes == b"replacement bytes"),
                    "exchange destination changed",
                );
            } else {
                check(
                    !destination.exists(),
                    "relocated ancestor persisted on the surrounding OS",
                );
            }
            for parent in [
                &fixture.work,
                &fixture.work.join("one"),
                &fixture.work.join("one/two"),
                &fixture.work.join("one/two/three"),
            ] {
                check(
                    std::fs::read(parent.join("allowed-before/value"))
                        .is_ok_and(|bytes| bytes == b"allowed"),
                    "permitted ancestor controls did not persist",
                );
            }
            check(
                std::fs::read(fixture.work.join("allowed-after/value"))
                    .is_ok_and(|bytes| bytes == b"allowed"),
                "permitted operations after the attack did not persist",
            );
            cases += 1;
        }
    }
    assert_eq!(
        cases,
        variants.len() * 3,
        "every probe must complete: {failures:#?}"
    );
    assert!(
        failures.is_empty(),
        "denial ancestor failures: {failures:#?}"
    );
}

#[test]
fn denied_files_survive_each_native_ancestor_rename() {
    denial_matrix(
        false,
        &[
            ("renameat", true),
            ("renameat-relative", true),
            ("renameat", false),
            ("renameat-relative", false),
        ],
    );
}

#[test]
fn denied_directories_survive_each_native_ancestor_rename() {
    denial_matrix(
        true,
        &[
            ("renameat", true),
            ("renameat-relative", true),
            ("renameat", false),
            ("renameat-relative", false),
        ],
    );
}

#[test]
fn renameat2_variants_remain_refused_for_denied_ancestors() {
    for directory in [false, true] {
        denial_matrix(
            directory,
            &[
                ("renameat2", false),
                ("renameat2-noreplace", false),
                ("renameat2-exchange", false),
            ],
        );
    }
}

#[test]
fn unrelated_native_renames_across_denial_ancestors_remain_permitted() {
    if !fixture::namespace_launcher_is_usable() {
        println!("skipping: denial ancestor tests need the ARM64 Linux namespace launcher");
        return;
    }
    let mut failures = Vec::new();
    for directory in [false, true] {
        let fixture = Fixture::new(directory);
        let output = fixture.run(directory, "one", "renameat2", &fixture.work.join("moved"));
        assert!(output.status.success(), "{output:?}");
        let stdout = String::from_utf8_lossy(&output.stdout);
        let report = stdout
            .lines()
            .find_map(|line| line.strip_prefix("DENIAL_ANCESTOR_RESULT="))
            .expect("the native probe completed");
        let report: serde_json::Value = serde_json::from_str(report).unwrap();
        println!(
            "directory_deny={directory}: {}",
            report["unrelated_cross_parent"]
        );
        let controls = report["unrelated_cross_parent"].as_array().unwrap();
        assert_eq!(
            controls.len(),
            12,
            "both directions at each ancestor must run"
        );
        for entry in controls {
            let from = fixture.work.join(entry["source"].as_str().unwrap());
            let to = fixture.work.join(entry["destination"].as_str().unwrap());
            let content = if entry["directory"] == true {
                to.join("value")
            } else {
                to
            };
            let host_intact = std::fs::read(&content).is_ok_and(|bytes| bytes == b"allowed");
            if entry["renamed"] != true
                || entry["content_intact"] != true
                || !host_intact
                || from.exists()
            {
                failures.push(format!(
                    "directory_deny={directory}: {entry}; host_intact={host_intact}"
                ));
            }
        }
    }
    assert!(
        failures.is_empty(),
        "unrelated native renames failed: {failures:#?}"
    );
}

//! build.rs — auto-discovery for folder-organized cases, and the case manifest.
//!
//! Cargo only compiles TOP-LEVEL files in `tests/` as test binaries; files in
//! subdirectories are ignored. So for each category folder (`tests/policy/`,
//! `tests/containment/`) this script generates a `<category>_mods.rs` list of
//! `#[path=…] mod <stem>;` declarations, which the top-level aggregator
//! `tests/<category>.rs` pulls in via `include!`.
//!
//! It also generates `case_manifest.rs`: every `id:` (and the optional
//! `platforms:`) declared in those files, as a `&[CaseSpec]` the library includes.
//! `emit-verdict` reduces rows against this manifest, so a case whose row is
//! missing (the test binary never ran it, or crashed before recording) is an
//! integrity failure and not a silently smaller GREEN. The manifest is derived
//! from the same files Cargo compiles, so it cannot drift from the suite.
//!
//! Net effect: a contributor just drops `tests/<category>/<case>.rs` — no
//! Cargo.toml stanza, no `mod` line, no manifest edit. Adding/removing a file
//! re-triggers the build.

use std::path::Path;
use std::{env, fs};

const CATEGORIES: &[&str] = &["policy", "containment", "shell", "monty", "telemetry"];

/// The `id: "…"` literal of a `det_case!` invocation, and its `platforms: […]`
/// list when declared. A case file holds exactly one `det_case!`, so exactly one
/// line starts with `id:`.
fn scan_case(source: &str, file: &Path) -> (String, Vec<String>) {
    let id_lines: Vec<&str> = field_lines(source, "id:").collect();
    assert!(
        id_lines.len() == 1,
        "{}: expected exactly one `id:` line (one det_case! per file), found {}",
        file.display(),
        id_lines.len()
    );
    let id = between(id_lines[0], '"', '"')
        .unwrap_or_else(|| panic!("{}: `id:` must be a string literal", file.display()));
    let platform_lines: Vec<&str> = field_lines(source, "platforms:").collect();
    assert!(
        platform_lines.len() <= 1,
        "{}: more than one `platforms:` line",
        file.display()
    );
    let platforms: Vec<String> = platform_lines
        .first()
        .map(|line| {
            between(line, '[', ']')
                .unwrap_or_else(|| panic!("{}: `platforms:` must be a `[…]` list", file.display()))
                .split(',')
                .map(|p| p.trim().trim_start_matches("Platform::").to_string())
                .filter(|p| !p.is_empty())
                .collect()
        })
        .unwrap_or_default();
    for p in &platforms {
        assert!(
            p == "Linux" || p == "Macos",
            "{}: unknown platform `{p}` in `platforms:` (Linux | Macos)",
            file.display()
        );
    }
    (id, platforms)
}

/// Lines whose first token is `key` — the macro fields, never a comment or a string.
fn field_lines<'a>(source: &'a str, key: &'a str) -> impl Iterator<Item = &'a str> {
    source
        .lines()
        .filter(move |line| line.trim_start().starts_with(key))
}

/// The text between the first `open` and the following `close` in `line`.
fn between(line: &str, open: char, close: char) -> Option<String> {
    let open_at = line.find(open)?;
    let inner = &line[open_at + 1..];
    let close_at = inner.find(close)?;
    Some(inner[..close_at].to_string())
}

fn main() {
    let manifest_dir = env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR");
    let out_dir = env::var("OUT_DIR").expect("OUT_DIR");

    let mut manifest = String::from("&[\n");
    for category in CATEGORIES {
        let dir = Path::new(&manifest_dir).join("tests").join(category);
        // Re-run when files are added to / removed from the folder.
        println!("cargo:rerun-if-changed=tests/{category}");

        let mut generated = String::new();
        if let Ok(entries) = fs::read_dir(&dir) {
            let mut files: Vec<_> = entries
                .flatten()
                .map(|e| e.path())
                .filter(|p| p.extension().and_then(|x| x.to_str()) == Some("rs"))
                // Skip dotfiles. A leading dot is not a Rust identifier, so a stray
                // `._cn_c_01.rs` beside `cn_c_01.rs` would emit `mod ._cn_c_01;` and
                // fail the whole test target to compile — which reads downstream as
                // "the suite discovered no cases" rather than as a build error.
                // macOS is the concrete source: bsdtar writes an AppleDouble sidecar
                // for every file carrying an extended attribute, and GNU tar on Linux
                // extracts those as real files. The packager sets COPYFILE_DISABLE=1
                // so they are not produced; this is the guard for anything that slips
                // past it, since the failure is silent and expensive to trace.
                .filter(|p| {
                    !p.file_name()
                        .and_then(|n| n.to_str())
                        .is_some_and(|n| n.starts_with('.'))
                })
                .collect();
            files.sort();
            for file in files {
                let stem = file
                    .file_stem()
                    .and_then(|s| s.to_str())
                    .expect("valid case file stem")
                    .to_string();
                // Absolute path so #[path] resolves regardless of OUT_DIR location;
                // escape backslashes for the Windows path case.
                let abs = file.to_str().expect("utf-8 path").replace('\\', "\\\\");
                generated.push_str(&format!("#[path = \"{abs}\"]\nmod {stem};\n"));
                println!(
                    "cargo:rerun-if-changed=tests/{category}/{}",
                    file.file_name()
                        .and_then(|n| n.to_str())
                        .unwrap_or_default()
                );
                let source = fs::read_to_string(&file).expect("read the case file");
                let (id, platforms) = scan_case(&source, &file);
                let platforms: Vec<String> = platforms
                    .iter()
                    .map(|p| format!("\"{}\"", p.to_lowercase()))
                    .collect();
                manifest.push_str(&format!(
                    "    CaseSpec {{ id: \"{id}\", category: \"{category}\", platforms: &[{}] }},\n",
                    platforms.join(", ")
                ));
            }
        }

        let out = Path::new(&out_dir).join(format!("{category}_mods.rs"));
        fs::write(&out, generated).expect("write generated module list");
    }
    manifest.push_str("]\n");
    fs::write(Path::new(&out_dir).join("case_manifest.rs"), manifest)
        .expect("write the case manifest");
}

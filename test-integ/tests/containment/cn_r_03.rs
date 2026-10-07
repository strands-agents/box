use strands_det_harness::det_case;

// Rewritten for GitHub box issue #51.
//
// The subtraction in docs/design/decisions.md#direct-filesystem-reach-is-declared-and-disclosed is
// by path: the directory holding the sources THIS run loaded is refused
// beneath the grant that encloses it (`record/config/filesystem.rs::direct_grants`, pinned by
// `a_project_entry_subtracts_the_directory_holding_this_boxs_authority`). No directory name is
// special. A sibling box's `.strands-box` under the granted project is therefore an ordinary
// directory: the workload reads and rewrites the sibling's policy with its own syscalls, the host
// finds the write, and the startup disclosure names the write grant that reaches it. The same run
// carries the control: this box's own `.strands-box`, beside the sibling's under the same grant,
// stays unreadable and unwritable, so a pass cannot come from a grant that reaches everything.
//
// Native throughout: the probe is a binary compiled into the exec tree and run from the contained
// bash under the agent's own `exec` entry, and the reads are the agent's own syscalls.
const PROBE: &str = include_str!("../probes/fs_probe.rs");
include!("../probes/probe_lines.rs");

/// The refusals a read or an append of this box's own subtracted policy answers, from the
/// mechanism's source: on Linux ENOENT, because the refused tree is a fresh empty tmpfs and the
/// bytes are not in the view at all (`view.rs`); on macOS EPERM, from `deny file-read*` and the
/// write-leaf denies on the subpath (`seatbelt.rs`). Any other errno is a failed syscall, not a
/// refusal.
fn masked_denials() -> &'static [i32] {
    match strands_det_harness::Platform::current() {
        strands_det_harness::Platform::Linux => &[ENOENT],
        strands_det_harness::Platform::Macos => &[EPERM],
    }
}

/// The read regression a review found: the probe read every byte and
/// printed the first line only, so `assert_absent("permit (principal, action, resource)")` here
/// and `assert_absent("permit (principal, action == Box::Action::\"shell:exec\"")` in CN-FS-01 could
/// not fire on a leaked policy whose first line is a comment or an annotation. The probe now prints
/// the whole content on one physical line, with `\n`, `\r` and `\\` escaped and everything else
/// verbatim. This runs the REAL probe, compiled from the same source the cases compile, on the
/// planted CN-R-03 policy, the real `fixture.dw`, a file that starts with a newline, and an empty
/// file, and checks that each existing needle is found in the output as authored, that the first
/// line alone would not have found it, that every output is one line the parser matches, and that
/// the content round-trips.
#[test]
fn the_read_probe_prints_the_whole_content_on_one_line() {
    let out = tempfile::tempdir().expect("a scratch directory");
    let probe = out.path().join("fsprobe");
    let source = out.path().join("fsprobe.rs");
    std::fs::write(&source, PROBE).expect("write the probe source");
    let compiled = std::process::Command::new("rustc")
        .args(["--edition", "2021", "-O", "-o"])
        .arg(&probe)
        .arg(&source)
        .output()
        .expect("rustc is on PATH");
    assert!(
        compiled.status.success(),
        "rustc failed on the probe: {}",
        String::from_utf8_lossy(&compiled.stderr)
    );
    let read = |name: &str, content: &str| -> (std::path::PathBuf, String) {
        let path = out.path().join(name);
        std::fs::write(&path, content).expect("plant the file");
        let run = std::process::Command::new(&probe)
            .arg("read")
            .arg(&path)
            .output()
            .expect("run the probe");
        assert!(run.status.success(), "the probe failed: {run:?}");
        assert!(run.stderr.is_empty(), "the probe wrote to stderr: {run:?}");
        (path, String::from_utf8(run.stdout).expect("UTF-8 output"))
    };
    let unescape = |encoded: &str| -> String {
        let mut decoded = String::new();
        let mut characters = encoded.chars();
        while let Some(character) = characters.next() {
            if character != '\\' {
                decoded.push(character);
                continue;
            }
            match characters.next() {
                Some('n') => decoded.push('\n'),
                Some('r') => decoded.push('\r'),
                Some('\\') => decoded.push('\\'),
                other => panic!("an unknown escape {other:?} in {encoded}"),
            }
        }
        decoded
    };
    let marker = "DET_SIBLING_POLICY_CNR03_REGRESSION";
    let sibling_policy = format!("// {marker}\npermit (principal, action, resource);\n");
    let fixture_policy = include_str!("../../src/fixture.dw");
    let cases: [(&str, &str, &[&str]); 4] = [
        (
            "policy.dw",
            &sibling_policy,
            &[marker, "permit (principal, action, resource)"],
        ),
        (
            "fixture.dw",
            fixture_policy,
            &[
                "permit (principal, action == Box::Action::\"shell:exec\"",
                "context.input.path like \"~/.claude/*\" ||",
            ],
        ),
        (
            "leading-newline.txt",
            "\nsecond line\r\nthird\\slash\n",
            &["second line", "third\\\\slash"],
        ),
        ("empty.txt", "", &[]),
    ];
    for (name, content, needles) in cases {
        let (path, output) = read(name, content);
        assert_eq!(
            output.lines().count(),
            1,
            "{name}: a read answers exactly one line: {output:?}"
        );
        let line = output.trim_end_matches('\n');
        let head = format!("READ_OK {} len={} :: ", subject(&path), content.len());
        assert!(
            line.starts_with(&head),
            "{name}: the line must open with the tag, the quoted subject, and the byte length: {line}"
        );
        assert_eq!(
            probe_line(&output, "READ_OK", &subject(&path)),
            Some(line),
            "{name}: the parser must match the read under its own subject"
        );
        assert_eq!(
            unescape(&line[head.len()..]),
            content,
            "{name}: the content must round-trip through the one-line encoding"
        );
        assert!(
            !line.contains('\r'),
            "{name}: a carriage return must not survive into the physical line"
        );
        for needle in needles {
            assert!(
                line.contains(needle),
                "{name}: the case needle {needle:?} must be visible in the probe's line: {line}"
            );
        }
    }
    // The defect, pinned: the first line alone carried neither secondary needle.
    let first = |content: &str| content.lines().next().unwrap_or("").to_string();
    assert!(!first(&sibling_policy).contains("permit (principal, action, resource)"));
    assert!(
        !first(fixture_policy).contains("permit (principal, action == Box::Action::\"shell:exec\"")
    );
}

det_case! {
    name: cn_r_03,
    id:   "CN-R-03",
    desc: "Authority by path: a sibling box's .strands-box/policy.dw under the granted project is readable and writable by the agent's own syscalls and the write lands on the host, the write grant that reaches it is disclosed at startup, and this box's own .strands-box beside it stays refused in the same run",
    run: |b| {
        b.reset_policy();
        let probe = b.compile_probe("fsprobe", PROBE);
        let pid = std::process::id();
        let marker = format!("DET_SIBLING_POLICY_CNR03_{pid}_{:x}", std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH).map(|d| d.as_nanos()).unwrap_or(0));
        let tampered = format!("DET_TAMPERED_CNR03_{pid}");
        // A sibling box's authority beneath the granted project, planted before the run.
        let sub = b.workspace().join("sub");
        let sibling = sub.join(".strands-box");
        std::fs::create_dir_all(&sibling).expect("DET_ERROR: plant the sibling box's directory");
        let policy_text = format!("// {marker}\npermit (principal, action, resource);\n");
        std::fs::write(sibling.join("policy.dw"), &policy_text).expect("DET_ERROR: plant the sibling policy");
        std::fs::write(sibling.join("box.toml"), "name = \"sibling\"\n").expect("DET_ERROR: plant the sibling config");
        // The control: this box's own authority, which the same grant encloses.
        let own = b.workspace().join(".strands-box");
        let own_policy_before = std::fs::read_to_string(own.join("policy.dw"))
            .expect("DET_ERROR: read this box's policy on the host");

        let r = b.run_sh_with_config(
            b.with_exec_tree(),
            &format!(
                "P='{p}'; \
                 \"$P\" read '{sibling}/policy.dw'; \
                 \"$P\" append '{sibling}/policy.dw' {tampered}; \
                 \"$P\" read '{own}/policy.dw'; \
                 \"$P\" append '{own}/policy.dw' {tampered}; \
                 printf done",
                p = probe.display(),
                sibling = sibling.display(),
                own = own.display(),
            ),
        );
        r.assert_contains("done");

        // The sibling: read with its bytes, appended, and the append landed on the host.
        let sibling_policy = subject(&sibling.join("policy.dw"));
        assert!(
            probe_line(&r.out, "READ_OK", &sibling_policy).is_some_and(|line| line.contains(&marker)),
            "the sibling box's policy.dw under the write grant did not read; out=[{}]", r.snippet()
        );
        assert!(
            probe_line(&r.out, "APPEND_OK", &sibling_policy).is_some(),
            "the sibling box's policy.dw under the write grant did not append; out=[{}]", r.snippet()
        );
        let on_host = std::fs::read_to_string(sibling.join("policy.dw"))
            .expect("DET_ERROR: read the sibling policy on the host");
        assert!(
            on_host.starts_with(&policy_text) && on_host.contains(&tampered),
            "the append did not land on the host: {on_host:?}"
        );

        // The disclosure: the write grant that reaches the sibling is named at startup.
        r.assert_contains(&format!("  write       {}", b.workspace().display()));

        // The control: this box's own authority stays refused, and its bytes are unchanged.
        let own_policy = subject(&own.join("policy.dw"));
        refused_as(&r.out, "READ", &own_policy, masked_denials())
            .unwrap_or_else(|why| panic!("this box's own policy.dw must stay unreadable in the same run: {why}; out=[{}]", r.snippet()));
        refused_as(&r.out, "APPEND", &own_policy, masked_denials())
            .unwrap_or_else(|why| panic!("this box's own policy.dw must stay unwritable in the same run: {why}; out=[{}]", r.snippet()));
        r.assert_absent("permit (principal, action == Box::Action::\"shell:exec\"");
        assert_eq!(
            std::fs::read_to_string(own.join("policy.dw")).expect("DET_ERROR: read this box's policy"),
            own_policy_before,
            "this box's own policy changed on the host"
        );
    }
}

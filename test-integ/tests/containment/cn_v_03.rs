use strands_det_harness::{Platform, det_case, sh_quote};

// A symbolic link inside a tool's `read` grant that points at a secret outside every grant yields
// no bytes to the tool leaf's own syscalls. CN-V-02 measures the same escape from the agent's box;
// this is the leaf. The control is a link inside the same grant to a file inside it, which reads. The
// host proves the escape link real (it resolves to the secret and reads it) and the secret unchanged.
const PROBE: &str = include_str!("../probes/fs_probe.rs");
include!("../probes/probe_lines.rs");

/// On Linux the link's target is outside every bind of the leaf's view; on macOS Seatbelt judges the
/// object the link resolves to, which no rule of the leaf allows.
fn escape_denials() -> &'static [i32] {
    match Platform::current() {
        Platform::Linux => &[ENOENT],
        Platform::Macos => &[EPERM],
    }
}

det_case! {
    name: cn_v_03,
    id:   "CN-V-03",
    desc: "Leaf symlink escape: a link inside a tool's read grant to a secret outside it yields no bytes and takes no write; a link to a file inside the grant reads; the secret is unchanged on the host",
    run: |b| {
        let probe = b.compile_probe("fsprobe-v03", PROBE);
        let root = b.workspace().parent().unwrap().to_path_buf();
        let grant = root.join("v03-grant");
        std::fs::create_dir(&grant).expect("DET_ERROR: the tool's grant");
        let pid = std::process::id();
        let secret = format!("DET_SECRET_CNV03_{pid}");
        let secret_path = root.join("v03-secret.txt");
        std::fs::write(&secret_path, format!("{secret}\n")).expect("DET_ERROR: plant the secret");
        std::fs::write(grant.join("inside.txt"), "DET_INSIDE_V03\n").expect("DET_ERROR: plant the in-grant file");
        let inside = grant.join("link-in");
        let escape = grant.join("link-out");
        std::os::unix::fs::symlink("inside.txt", &inside).expect("DET_ERROR: the in-grant link");
        std::os::unix::fs::symlink(&secret_path, &escape).expect("DET_ERROR: the escape link");
        assert_eq!(std::fs::canonicalize(&escape).unwrap(), secret_path, "DET_ERROR: the escape link does not resolve to the secret");
        assert!(std::fs::read_to_string(&escape).unwrap().contains(&secret), "DET_ERROR: the host cannot read through the escape link");

        let quoted = |p: &std::path::Path| serde_json::to_string(&p.to_string_lossy()).unwrap();
        let edit = |text: String| format!(
            "{text}\n[tool.v03]\ncommand = [{}]\n\n[tool.v03.filesystem]\nread = [{}]\n",
            quoted(&probe), quoted(&grant)
        );
        b.apply_policy(r#"permit (principal, action == Box::Action::"shell:spawn", resource);"#);
        let p = sh_quote(&probe.to_string_lossy());
        let (i, e) = (sh_quote(&inside.to_string_lossy()), sh_quote(&escape.to_string_lossy()));
        let r = b.run_mediated_with_config(edit, &format!(
            "{p} read {i}; {p} read {e}; {p} append {e} DET_ESCAPED_WRITE_V03"
        ));
        let secret_after = std::fs::read_to_string(&secret_path).unwrap_or_default();
        r.assert_mediated_permitted("shell:spawn", "fsprobe-v03");

        assert!(
            probe_line(&r.out, "READ_OK", &subject(&inside)).is_some_and(|l| l.contains("DET_INSIDE_V03")),
            "the in-grant link did not read; out=[{}]", r.snippet()
        );
        r.assert_absent_secret(&secret, "CN-V-03 secret");
        refused_as(&r.out, "READ", &subject(&escape), escape_denials())
            .unwrap_or_else(|why| panic!("the escape link was not refused: {why}; out=[{}]", r.snippet().replace(&secret, "<REDACTED>")));
        refused_as(&r.out, "APPEND", &subject(&escape), escape_denials())
            .unwrap_or_else(|why| panic!("the escape link took a write: {why}; out=[{}]", r.snippet().replace(&secret, "<REDACTED>")));
        assert_eq!(secret_after, format!("{secret}\n"), "the secret changed on the host");
    }
}

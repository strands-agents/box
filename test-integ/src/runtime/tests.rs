use super::*;

// ── native CPython selection and the narrow probe fixture (macOS port review) ──────────────
fn identity(
    implementation: &str,
    image: &Path,
    roots: &[PathBuf],
    hints: &[PathBuf],
) -> PyIdentity {
    PyIdentity {
        implementation: implementation.into(),
        image: image.to_path_buf(),
        roots: roots.to_vec(),
        hints: hints.to_vec(),
        extensions: Vec::new(),
    }
}

/// A REAL framework-shaped runtime on disk (`…/Python3.framework/Versions/3.9/{bin/python3,
/// lib/python3.9}`) inside a temporary directory, so existence checks are exercised against the
/// filesystem rather than against spellings. Returns (tempdir, version root, image, stdlib).
fn real_framework_runtime() -> (tempfile::TempDir, PathBuf, PathBuf, PathBuf) {
    let tmp = tempfile::tempdir().expect("tempdir");
    let version_root = tmp
        .path()
        .join("Library/Frameworks/Python3.framework/Versions/3.9");
    let stdlib = version_root.join("lib/python3.9");
    let image = version_root.join("bin/python3");
    std::fs::create_dir_all(&stdlib).unwrap();
    std::fs::create_dir_all(image.parent().unwrap()).unwrap();
    std::fs::write(&image, b"#!/bin/sh\n").unwrap();
    let canonical = |p: &Path| p.canonicalize().unwrap();
    (
        tmp,
        canonical(&version_root),
        canonical(&image),
        canonical(&stdlib),
    )
}

#[test]
fn the_apple_launcher_shim_is_never_selected_even_when_first() {
    let (_tmp, version_root, image, stdlib) = real_framework_runtime();
    let candidates = vec![PathBuf::from("/usr/bin/python3"), image.clone()];
    let chosen = select_native_python_on(Platform::Macos, candidates, |path| {
        assert_ne!(
            path,
            Path::new("/usr/bin/python3"),
            "the shim must not even be queried"
        );
        Ok(identity(
            "cpython",
            &image,
            &[version_root.clone(), stdlib.clone()],
            &[],
        ))
    })
    .expect("a real interpreter follows the shim");
    assert_eq!(chosen.executable, image);
    // Nested runtime directories collapse to the framework version root: one grant, nothing above it.
    assert_eq!(chosen.runtime_reads, vec![version_root]);
    assert!(chosen.rejected_hints.is_empty());
}

#[test]
fn linux_selects_a_usr_bin_image_after_verifying_its_identity() {
    let (_tmp, version_root, _image, _stdlib) = real_framework_runtime();
    let image = PathBuf::from("/usr/bin/env").canonicalize().unwrap();
    let chosen = select_native_python_on(Platform::Linux, vec![image.clone()], |path| {
        assert_eq!(path, image);
        Ok(identity(
            "cpython",
            &image,
            std::slice::from_ref(&version_root),
            &[],
        ))
    })
    .expect("Linux system images are not Apple launchers");
    assert_eq!(chosen.executable, image);
    assert_eq!(chosen.runtime_reads, vec![version_root]);
}

#[cfg(target_os = "linux")]
#[test]
fn linux_python_discovery_grants_runtime_libraries_without_the_usr_prefix() {
    let chosen = select_native_python_from(native_python_candidates(), query_python_identity)
        .expect("the Linux test host needs CPython");
    assert!(!chosen.runtime_reads.is_empty());
    assert!(!chosen.runtime_reads.contains(&PathBuf::from("/usr")));
    assert!(!chosen.runtime_reads.contains(&PathBuf::from("/")));
    assert!(!chosen.runtime_execs.is_empty());
    assert!(chosen.runtime_execs.iter().all(|path| {
        path.is_dir()
            && chosen
                .runtime_reads
                .iter()
                .any(|root| path.starts_with(root))
    }));
}

#[test]
fn linux_extension_exec_is_verified_and_stays_inside_the_runtime_reads() {
    let (_tmp, root, image, stdlib) = real_framework_runtime();
    let extension = stdlib.join("lib-dynload");
    std::fs::create_dir(&extension).unwrap();
    let query = |path: PathBuf| {
        let mut value = identity("cpython", &image, std::slice::from_ref(&root), &[]);
        value.extensions = vec![path];
        value
    };
    let selected = select_native_python_on(Platform::Linux, vec![image.clone()], |_| {
        Ok(query(extension.clone()))
    })
    .unwrap();
    assert_eq!(selected.runtime_reads, vec![root.clone()]);
    assert_eq!(selected.runtime_execs, vec![extension.clone()]);
    let config = native_probe_config(
        "[agent]\ncommand = {command}\n[agent.filesystem]\nread = [\"/workspace\"]\nwrite = [\"/workspace\"]\n",
        Path::new("/workspace"),
        &selected,
    );
    let exec_line = config
        .lines()
        .find(|line| line.starts_with("exec = "))
        .unwrap();
    assert_eq!(
        exec_line,
        format!("exec = [{:?}]", extension.to_string_lossy())
    );
    let missing = select_native_python_on(Platform::Linux, vec![image.clone()], |_| {
        Ok(query(stdlib.join("absent")))
    })
    .unwrap_err();
    assert!(
        missing.contains("extension directory") && missing.contains("not there"),
        "{missing}"
    );
    let outside = select_native_python_on(Platform::Linux, vec![image.clone()], |_| {
        Ok(query(root.parent().unwrap().to_path_buf()))
    })
    .unwrap_err();
    assert!(outside.contains("outside its runtime reads"), "{outside}");
}

#[test]
fn a_nonexistent_build_time_hint_is_reported_and_never_granted_while_real_roots_are_kept() {
    // The native run of 2026-09-22: sysconfig's LIBDIR named the build machine's Xcode
    // (`/Applications/Xcode.app/…/Versions/3.9/lib`), which is not on the host. It must not be
    // granted (the box refuses a grant on a path that is not there) and nothing must be made up
    // in its place; the existing roots are still granted.
    let (tmp, version_root, image, stdlib) = real_framework_runtime();
    let phantom = tmp.path().join("Applications/Xcode.app/Contents/Developer/Library/Frameworks/Python3.framework/Versions/3.9/lib");
    assert!(!phantom.exists());
    let chosen = select_native_python_from(vec![image.clone()], |_| {
        Ok(identity(
            "cpython",
            &image,
            &[version_root.clone(), stdlib.clone()],
            &[version_root.clone(), phantom.clone()],
        ))
    })
    .expect("a runtime with a stale hint is still usable");
    assert_eq!(
        chosen.runtime_reads,
        vec![version_root.clone()],
        "only the existing roots are granted"
    );
    assert!(
        !phantom.exists(),
        "no dummy directory may be created for a hint"
    );
    assert_eq!(
        chosen.rejected_hints.len(),
        1,
        "{:?}",
        chosen.rejected_hints
    );
    assert!(
        chosen.rejected_hints[0].contains(&phantom.display().to_string())
            && chosen.rejected_hints[0].contains("is not there"),
        "{:?}",
        chosen.rejected_hints
    );
    // The rendered config grants only the existing root: the phantom never reaches the box.
    let config = native_probe_config(
        "[agent]\ncommand = {command}\n\n[agent.filesystem]\nread = [\"/b/ws\"]\n",
        Path::new("/b/ws"),
        &chosen,
    );
    assert!(!config.contains("Xcode.app"), "{config}");
    assert!(
        config.contains(&format!(
            "read = [{}, \"/b/ws\"]",
            serde_json::to_string(&version_root.to_string_lossy()).unwrap()
        )),
        "{config}"
    );
}

#[test]
fn a_hint_that_exists_is_granted_and_a_hint_that_is_a_file_is_not() {
    let (tmp, version_root, image, stdlib) = real_framework_runtime();
    let extra = tmp.path().join("opt/extra-lib");
    std::fs::create_dir_all(&extra).unwrap();
    let file_hint = tmp.path().join("opt/not-a-dir");
    std::fs::write(&file_hint, b"x").unwrap();
    let chosen = select_native_python_from(vec![image.clone()], |_| {
        Ok(identity(
            "cpython",
            &image,
            &[version_root.clone(), stdlib.clone()],
            &[extra.clone(), file_hint.clone()],
        ))
    })
    .unwrap();
    let mut expected = vec![version_root.clone(), extra.canonicalize().unwrap()];
    expected.sort();
    assert_eq!(chosen.runtime_reads, expected);
    assert_eq!(
        chosen.rejected_hints.len(),
        1,
        "{:?}",
        chosen.rejected_hints
    );
    assert!(
        chosen.rejected_hints[0].contains("is not a directory"),
        "{:?}",
        chosen.rejected_hints
    );
}

#[test]
fn a_missing_required_root_or_image_rejects_the_candidate_by_name() {
    let (tmp, version_root, image, _stdlib) = real_framework_runtime();
    let gone_stdlib = tmp.path().join("gone/lib/python3.9");
    let gone_image = tmp.path().join("gone/bin/python3");
    let a = tmp.path().join("a-python3");
    let b = tmp.path().join("b-python3");
    let err = select_native_python_from(vec![a.clone(), b.clone()], |path| {
        if path == a.as_path() {
            // Image exists, but a required root does not: not a usable runtime.
            Ok(identity(
                "cpython",
                &image,
                &[version_root.clone(), gone_stdlib.clone()],
                &[],
            ))
        } else {
            // The reported image is not on this host at all.
            Ok(identity(
                "cpython",
                &gone_image,
                std::slice::from_ref(&version_root),
                &[],
            ))
        }
    })
    .expect_err("neither qualifies");
    assert!(
        err.contains(&format!(
            "{}: runtime root {} is not there",
            a.display(),
            gone_stdlib.display()
        )),
        "{err}"
    );
    assert!(
        err.contains(&format!(
            "{}: reported image {} is not there",
            b.display(),
            gone_image.display()
        )),
        "{err}"
    );
}

#[test]
fn a_candidate_that_executes_as_a_usr_bin_image_or_is_not_cpython_is_rejected() {
    let (_tmp, version_root, image, _stdlib) = real_framework_runtime();
    let err = select_native_python_on(
        Platform::Macos,
        vec![
            PathBuf::from("/opt/a/python3"),
            PathBuf::from("/opt/b/python3"),
        ],
        |path| {
            if path == Path::new("/opt/a/python3") {
                Ok(identity("cpython", Path::new("/usr/bin/env"), &[], &[]))
            } else {
                Ok(identity(
                    "pypy",
                    &image,
                    std::slice::from_ref(&version_root),
                    &[],
                ))
            }
        },
    )
    .expect_err("neither qualifies");
    assert!(
        err.contains("/opt/a/python3: executes as a /usr/bin image"),
        "{err}"
    );
    assert!(
        err.contains("/opt/b/python3: implementation \"pypy\" is not cpython"),
        "{err}"
    );
    let err = select_native_python_from(Vec::<PathBuf>::new(), |_| Err("unused".into()))
        .expect_err("no candidates");
    assert!(err.contains("no candidates"), "{err}");
}

#[test]
fn the_probe_config_grants_only_the_runtime_directories_and_declares_the_search_path() {
    let template = "name = \"t\"\nbox_dir = \"/b/state\"\n\n[agent]\ncommand = {command}\nworkspace = \"/b/ws\"\n\n[agent.filesystem]\nread = [\"/b/ws\"]\nwrite = [\"/b/ws\"]\nread_file = [\"/h/.det-listed-settings.json\"]\n\n[tool.built]\ncommand = [\"/b/tools/built-hello\"]\nworkspace = \"/b/ws\"\n\n[tool.built.filesystem]\nread = [\"/b/ws\"]\n";
    let python = NativePython {
        executable: PathBuf::from(
            "/opt/clt/Library/Frameworks/Python3.framework/Versions/3.9/Resources/Python.app/Contents/MacOS/Python",
        ),
        runtime_reads: vec![PathBuf::from(
            "/opt/clt/Library/Frameworks/Python3.framework/Versions/3.9",
        )],
        rejected_hints: vec![],
        runtime_execs: Vec::new(),
    };
    let config = native_probe_config(template, Path::new("/b/ws"), &python);
    assert!(config.contains("command = [\"/opt/clt/Library/Frameworks/Python3.framework/Versions/3.9/Resources/Python.app/Contents/MacOS/Python\"]"), "{config}");
    // The agent's read list gains exactly the runtime root beside the workspace; the tool's list is untouched.
    assert!(config.contains("[agent.filesystem]\nread = [\"/opt/clt/Library/Frameworks/Python3.framework/Versions/3.9\", \"/b/ws\"]"), "{config}");
    assert_eq!(config.matches("Python3.framework").count(), 2, "{config}");
    assert!(
        config.contains("[tool.built.filesystem]\nread = [\"/b/ws\"]"),
        "{config}"
    );
    // No home, no global exec tree, no widening beyond the declared entries.
    assert!(
        !config.contains("exec = [\"/\"")
            && !config.contains("read = [\"/\"")
            && !config.contains("/Users/")
            && !config.contains("/var/root"),
        "{config}"
    );
    assert!(
        config.contains("[agent.env]\nHOME = \"/b/ws\"\nPATH = \"/usr/bin:/bin\"\n"),
        "{config}"
    );
}

#[test]
fn the_git_tool_config_declares_the_real_git_and_claims_nothing_about_lookup() {
    let template =
        "name = \"t\"\n[agent]\ncommand = [\"bash\"]\nworkspace = \"/b/ws\"\n".to_string();
    let config = git_tool_config(template, Path::new("/opt/clt/usr/bin/git"), "\"/b/ws\"");
    assert!(
        config.contains("[tool.git]\ncommand = [\"/opt/clt/usr/bin/git\"]\nworkspace = \"/b/ws\""),
        "{config}"
    );
    assert!(
        config.contains(
            "[tool.git.filesystem]\nread = [\"/opt/clt\", \"/b/ws\"]\nwrite = [\"/b/ws\"]\n"
        ),
        "{config}"
    );
    assert!(
        !config.contains("libexec"),
        "no exec grant on git's helpers: {config}"
    );
    // The hosted Shell resolves bare host-program names on the broker's own PATH; a declared
    // agent PATH would be a claim the box does not honour, so none is declared.
    assert!(
        !config.contains("[agent.env]") && !config.contains("PATH"),
        "{config}"
    );
}

#[test]
fn the_git_only_policy_names_one_identity_by_spelling_and_by_resolved_path() {
    let policy = git_only_spawn_policy(Path::new("/opt/clt/usr/bin/git"));
    assert!(
        policy.contains("action == Box::Action::\"shell:spawn\""),
        "{policy}"
    );
    assert!(
        policy.contains("context.input.program == \"/opt/clt/usr/bin/git\""),
        "{policy}"
    );
    assert!(
        policy.contains("context.input.program_path == \"/opt/clt/usr/bin/git\""),
        "{policy}"
    );
    assert!(
        policy.contains(" && "),
        "both conditions are required: {policy}"
    );
    // Nothing a bare name or the shim could satisfy.
    assert!(
        !policy.contains("== \"git\"") && !policy.contains("\"/usr/bin/git\""),
        "{policy}"
    );
}

#[test]
fn framework_roots_and_shims_are_recognised() {
    assert_eq!(
        framework_root(Path::new("/L/Python3.framework/Versions/3.9/bin/python3")),
        Some(PathBuf::from("/L/Python3.framework/Versions/3.9"))
    );
    assert_eq!(framework_root(Path::new("/usr/local/bin/python3")), None);
    assert!(
        is_apple_shim(Path::new("/usr/bin/python3")) && is_apple_shim(Path::new("/usr/bin/git"))
    );
    assert!(!is_apple_shim(Path::new(
        "/Library/Developer/CommandLineTools/usr/bin/git"
    )));
}

#[test]
fn the_identity_query_parses_what_this_hosts_python_reports() {
    // The real query against this host's python3 (any platform): CPython, an existing image, dirs.
    let Some(py) = std::env::var_os("PATH").and_then(|p| {
        std::env::split_paths(&p)
            .map(|d| d.join("python3"))
            .find(|c| is_executable(c))
    }) else {
        return;
    };
    let id = query_python_identity(&py).expect("this host's python answers the identity query");
    assert_eq!(id.implementation, "cpython");
    assert!(id.image.exists(), "{:?}", id.image);
    assert_eq!(
        id.roots.len(),
        if cfg!(target_os = "linux") { 1 } else { 2 },
        "the host's runtime roots: {:?}",
        id.roots
    );
    assert!(
        id.roots.iter().all(|r| r.is_dir()),
        "a running interpreter's roots exist: {:?}",
        id.roots
    );
    assert!(
        !id.hints.is_empty(),
        "prefix and LIBDIR are reported as hints: {:?}",
        id.hints
    );
    // And the real selection over this interpreter grants only directories that exist.
    let chosen = select_native_python_from(vec![py], query_python_identity);
    if let Ok(chosen) = chosen {
        assert!(
            chosen.runtime_reads.iter().all(|d| d.is_dir()),
            "{:?}",
            chosen.runtime_reads
        );
    }
}

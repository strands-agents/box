//! The spawn seam hands a program the spelling it was invoked by, as `argv[0]`.
//!
//! An interpreter that derives its environment from `argv[0]` — a virtualenv's `python`, a Node
//! version-manager shim, a `rustup` shim — loses that environment when it is launched under its
//! canonical name instead. The identity is still what the decision judged and what the kernel execs;
//! the spelling is only what the program reads about itself.

use std::path::PathBuf;

/// Where the operator's own `PATH` holds `name`, and the canonical identity behind it.
fn on_host_path(name: &str) -> Option<(PathBuf, PathBuf)> {
    let path = std::env::var_os("PATH")?;
    std::env::split_paths(&path).find_map(|directory| {
        let candidate = directory.join(name);
        candidate
            .canonicalize()
            .ok()
            .filter(|identity| identity.is_file())
            .map(|identity| (candidate, identity))
    })
}

/// A fresh directory this process owns, which no `PATH` entry names.
fn off_path_directory(name: &str) -> PathBuf {
    let root = std::env::temp_dir().join(format!("host-spawn-argv0-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(&root).expect("a directory off PATH");
    root
}

/// **The seam's built-in spawn gives the program its invoked spelling as `argv[0]`**, which is the
/// hop an interpreter's own prefix search reads. Pinned on the built-in rather than through a hook,
/// because a hook can only observe the field while this runs a real program and asks it what it sees.
#[test]
fn the_builtin_spawn_gives_the_program_its_invoked_spelling() {
    let Some((_, shell_identity)) = on_host_path("sh") else {
        eprintln!("skipping: no `sh` on the operator's PATH");
        return;
    };
    let spelling = off_path_directory("argv0").join("named-differently");
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime");
    let outcome = rt
        .block_on(strands_shell::os::builtin_spawn_host(
            strands_shell::os::HostSpawn {
                program: shell_identity,
                invoked: spelling.clone(),
                args: vec!["-c".to_string(), "printf %s \"$0\"".to_string()],
                cwd: std::env::temp_dir(),
                env: Vec::new(),
            },
        ))
        .expect("the program runs");
    assert_eq!(
        String::from_utf8_lossy(&outcome.stdout),
        spelling.display().to_string(),
        "the program reads the spelling, not the identity it was execed by",
    );
}

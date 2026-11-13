//! The hosted Shell and Monty meet the credential-store floor that every sandbox grant meets.
//!
//! The policy here is the one a security review found: a permit on every path under the home. The
//! workload asks each interpreter for a key and for a configuration file in a credential store, and
//! for an ordinary file beside them as the control. A second box names one store in its `read`
//! list, which lifts the floor for that store while policy still decides each access.

#[path = "support/fixture.rs"]
mod fixture;

use std::path::Path;
use std::process::Output;

use fixture::{Configured, Request};

/// The rules from the finding, plus the Shell commands the probes run.
const HOME_WIDE_POLICY: &str = r#"
permit(principal == Box::Agent::"self", action == Box::Action::"shell:exec", resource);
permit (principal, action == Box::Action::"fs:read", resource)
  when { context.input.path == "~" || context.input.path like "~/*" };
permit (principal, action == Box::Action::"fs:write", resource)
  when { context.input.path like "~/*" };
"#;

const KEY: &str = "canary-private-key";
const NOTES: &str = "ordinary-notes";

fn plant(home: &Path) {
    for store in [".ssh", ".aws"] {
        std::fs::create_dir_all(home.join(store)).expect("a credential store");
    }
    std::fs::write(home.join(".ssh/id_rsa"), KEY).expect("a key");
    std::fs::write(home.join(".aws/config"), "[default]\nregion = us-east-1\n").expect("a config");
    std::fs::write(home.join("notes.txt"), NOTES).expect("an ordinary file");
}

fn text(output: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

fn shell_read(box_: &Configured, path: &Path) -> String {
    text(&box_.bash(&format!("zsh -c 'cat {}' 2>&1", path.display())))
}

fn python_read(box_: &Configured, path: &Path) -> String {
    text(&box_.bash(&format!(
        "python3 -c 'print(open(\"{}\").read())' 2>&1",
        path.display()
    )))
}

fn python_append(box_: &Configured, path: &Path) -> String {
    text(&box_.bash(&format!(
        "python3 -c 'f = open(\"{}\", \"a\"); f.write(\"\\ncredential_process = /tmp/x\\n\"); \
         f.close(); print(\"APPEND-OK\")' 2>&1",
        path.display()
    )))
}

#[test]
fn a_home_wide_permit_reaches_no_credential_store_through_either_interpreter() {
    if !fixture::namespace_launcher_is_usable() {
        return;
    }
    let request = Request::with_policy("credential-floor", HOME_WIDE_POLICY).without_agent_home();
    let home = request.operator_home().to_path_buf();
    plant(&home);
    let box_ = request.expect();

    let notes = shell_read(&box_, &home.join("notes.txt"));
    assert!(
        notes.contains(NOTES),
        "the control must read, or nothing is measured: {notes}"
    );
    let notes = python_read(&box_, &home.join("notes.txt"));
    assert!(
        notes.contains(NOTES),
        "the control must read, or nothing is measured: {notes}"
    );

    for seen in [
        shell_read(&box_, &home.join(".ssh/id_rsa")),
        python_read(&box_, &home.join(".ssh/id_rsa")),
    ] {
        assert!(!seen.contains(KEY), "a key left the store: {seen}");
        assert!(
            seen.contains("credential store"),
            "the refusal must name the floor: {seen}"
        );
    }

    let append = python_append(&box_, &home.join(".aws/config"));
    assert!(
        !append.contains("APPEND-OK"),
        "a store took a write: {append}"
    );
    let config = std::fs::read_to_string(home.join(".aws/config")).expect("the config");
    assert!(
        !config.contains("credential_process"),
        "the config changed: {config}"
    );
}

#[test]
fn a_store_named_by_a_read_entry_reads_and_stays_unwritable() {
    if !fixture::namespace_launcher_is_usable() {
        return;
    }
    let request =
        Request::with_policy("credential-floor-named", HOME_WIDE_POLICY).without_agent_home();
    let home = request.operator_home().to_path_buf();
    plant(&home);
    let box_ = request.agent_list("read", &["~/.aws"]).expect();

    for seen in [
        shell_read(&box_, &home.join(".aws/config")),
        python_read(&box_, &home.join(".aws/config")),
    ] {
        assert!(
            seen.contains("us-east-1"),
            "the named store must read: {seen}"
        );
    }
    let append = python_append(&box_, &home.join(".aws/config"));
    assert!(
        !append.contains("APPEND-OK"),
        "a read entry took a write: {append}"
    );
    let key = python_read(&box_, &home.join(".ssh/id_rsa"));
    assert!(!key.contains(KEY), "an unnamed store opened: {key}");
}

/// The home-wide rules plus a rename, so a `write` entry's contents could only leave by moving.
const HOME_WIDE_MOVE_POLICY: &str = r#"
permit(principal == Box::Agent::"self", action == Box::Action::"shell:exec", resource);
permit (principal, action in [Box::Action::"fs:read", Box::Action::"fs:write",
    Box::Action::"fs:move", Box::Action::"fs:delete"], resource)
  when { context.input.path == "~" || context.input.path like "~/*" };
"#;

#[test]
fn a_write_entry_cannot_move_a_store_file_out_through_either_interpreter() {
    if !fixture::namespace_launcher_is_usable() {
        return;
    }
    let request =
        Request::with_policy("credential-floor-move", HOME_WIDE_MOVE_POLICY).without_agent_home();
    let home = request.operator_home().to_path_buf();
    let cache = home.join(".aws/sso/cache");
    std::fs::create_dir_all(&cache).expect("a credential cache");
    std::fs::write(cache.join("shell.json"), "shell-token").expect("a token");
    std::fs::write(cache.join("python.json"), "python-token").expect("a token");
    // Linux refuses a write-only grant, because a writable bind also reads, so both platforms take
    // the pair. The rename refusal holds whether or not reads are open.
    let box_ = request
        .agent_list("read", &["~/.aws/sso/cache"])
        .agent_list("write", &["~/.aws/sso/cache"])
        .expect();

    let shell = text(&box_.bash(&format!(
        "zsh -c 'mv {} {}' 2>&1",
        cache.join("shell.json").display(),
        home.join("stolen-shell.json").display()
    )));
    let python = text(&box_.bash(&format!(
        "python3 -c 'from pathlib import Path; Path(\"{}\").rename(\"{}\")' 2>&1",
        cache.join("python.json").display(),
        home.join("stolen-python.json").display()
    )));
    for (seen, moved, kept) in [
        (&shell, "stolen-shell.json", "shell.json"),
        (&python, "stolen-python.json", "python.json"),
    ] {
        assert!(!home.join(moved).exists(), "a token left the store: {seen}");
        assert!(
            cache.join(kept).exists(),
            "the token must stay in place: {seen}"
        );
        assert!(
            seen.contains("would move credential-store content"),
            "the refusal must name the floor: {seen}"
        );
    }

    let inside = text(&box_.bash(&format!(
        "zsh -c 'mv {} {} && echo MOVED-INSIDE' 2>&1",
        cache.join("shell.json").display(),
        cache.join("renamed.json").display()
    )));
    assert!(
        inside.contains("MOVED-INSIDE"),
        "a rename inside the entry must work: {inside}"
    );
}

#[test]
fn an_absent_store_cannot_be_created_under_a_spelling_that_folds_to_its_name() {
    if !fixture::namespace_launcher_is_usable() {
        return;
    }
    let request =
        Request::with_policy("credential-floor-fold", HOME_WIDE_POLICY).without_agent_home();
    let home = request.operator_home().to_path_buf();
    assert!(!home.join(".aws").exists(), "the store must start absent");
    let box_ = request.expect();

    let variant = home.join(".aw\u{17F}");
    let shell = text(&box_.bash(&format!(
        "zsh -c 'mkdir {dir} && printf \"[default]\\ncredential_process = /tmp/x\\n\" > {dir}/config && echo SHELL-WROTE' 2>&1",
        dir = variant.display()
    )));
    let python = text(&box_.bash(&format!(
        "python3 -c 'from pathlib import Path; Path(\"{dir}\").mkdir(); Path(\"{dir}/config\").write_text(\"credential_process = /tmp/x\\n\"); print(\"PYTHON-WROTE\")' 2>&1",
        dir = variant.display()
    )));
    assert!(
        !shell.contains("SHELL-WROTE"),
        "the Shell planted a store: {shell}"
    );
    assert!(
        !python.contains("PYTHON-WROTE"),
        "Python planted a store: {python}"
    );
    let planted = std::fs::read_to_string(home.join(".aws/config")).unwrap_or_default();
    assert!(
        !planted.contains("credential_process"),
        "the store holds a plant: {planted}"
    );
    assert!(
        shell.contains("credential store"),
        "the refusal must name the floor: {shell}"
    );
    assert!(
        python.contains("credential store"),
        "the refusal must name the floor: {python}"
    );
}

#[test]
fn a_prepared_directory_cannot_be_renamed_onto_an_absent_store() {
    if !fixture::namespace_launcher_is_usable() {
        return;
    }
    let request =
        Request::with_policy("credential-onto", HOME_WIDE_MOVE_POLICY).without_agent_home();
    let home = request.operator_home().to_path_buf();
    assert!(!home.join(".aws").exists(), "the store must start absent");
    for prepared in ["prep-shell", "prep-python"] {
        std::fs::create_dir_all(home.join(prepared)).expect("a prepared directory");
        std::fs::write(
            home.join(prepared).join("config"),
            "credential_process = /tmp/x\n",
        )
        .expect("a planted config");
    }
    let box_ = request.expect();

    for target in [".aws", ".AWS", ".aw\u{17F}"] {
        let shell = text(&box_.bash(&format!(
            "zsh -c 'mv {} {} && echo MOVED' 2>&1",
            home.join("prep-shell").display(),
            home.join(target).display()
        )));
        let python = text(&box_.bash(&format!(
            "python3 -c 'from pathlib import Path; Path(\"{}\").rename(\"{}\"); print(\"MOVED\")' 2>&1",
            home.join("prep-python").display(),
            home.join(target).display()
        )));
        for seen in [&shell, &python] {
            assert!(
                !seen.contains("MOVED"),
                "{target}: a directory became the store: {seen}"
            );
            assert!(
                seen.contains("credential store"),
                "{target}: the refusal must name the floor: {seen}"
            );
        }
        let planted = std::fs::read_to_string(home.join(".aws/config")).unwrap_or_default();
        assert!(
            !planted.contains("credential_process"),
            "{target}: the store holds a plant"
        );
    }
}

#[test]
fn a_declared_home_granted_to_the_agent_lifts_the_floor_for_its_own_stores() {
    if !fixture::namespace_launcher_is_usable() {
        return;
    }
    // The fixture declares `env.HOME` as its own directory and grants it `read` and `write`, so the
    // sandbox already reaches that home's `.aws`. The interpreters must match, while an
    // operator-home store stays refused.
    let request = Request::with_policy("credential-declared", HOME_WIDE_POLICY);
    let operator = request.operator_home().to_path_buf();
    plant(&operator);
    let box_ = request.expect();
    let declared = box_.box_home();
    std::fs::create_dir_all(declared.join(".aws")).expect("a store in the declared home");
    std::fs::write(
        declared.join(".aws/config"),
        "[default]\nregion = us-west-2\n",
    )
    .expect("a declared-home config");

    for seen in [
        shell_read(&box_, &declared.join(".aws/config")),
        python_read(&box_, &declared.join(".aws/config")),
    ] {
        assert!(
            seen.contains("us-west-2"),
            "the declared home's store must read: {seen}"
        );
    }
    let append = python_append(&box_, &declared.join(".aws/config"));
    assert!(
        append.contains("APPEND-OK"),
        "the declared home's store must take a write: {append}"
    );
    let key = python_read(&box_, &operator.join(".ssh/id_rsa"));
    assert!(!key.contains(KEY), "an operator-home store opened: {key}");
    assert!(
        key.contains("credential store"),
        "the refusal must name the floor: {key}"
    );
}

#[test]
fn a_parent_of_a_granted_store_cannot_be_moved_out_through_either_interpreter() {
    if !fixture::namespace_launcher_is_usable() {
        return;
    }
    let request =
        Request::with_policy("credential-parent", HOME_WIDE_MOVE_POLICY).without_agent_home();
    let home = request.operator_home().to_path_buf();
    let store = "~/Library/Application Support/Google/Chrome";
    for copy in ["shell", "python"] {
        let profile = home.join(format!("Library/Application Support/Google-{copy}/Chrome"));
        std::fs::create_dir_all(&profile).expect("a granted store with a parent");
        std::fs::write(profile.join("Cookies"), "cookies").expect("a profile file");
        std::fs::create_dir_all(home.join(format!("project-{copy}"))).expect("a destination");
    }
    // The grant names `Google/Chrome`, so the parent `Google` holds only that granted store.
    let granted = home.join("Library/Application Support/Google/Chrome");
    std::fs::create_dir_all(&granted).expect("the granted store");
    std::fs::write(granted.join("Cookies"), "cookies").expect("a profile file");
    let box_ = request
        .agent_list("read", &[store])
        .agent_list("write", &[store])
        .expect();
    let parent = home.join("Library/Application Support/Google");

    let shell = text(&box_.bash(&format!(
        "zsh -c 'mv \"{}\" \"{}/Google\" && echo MOVED' 2>&1",
        parent.display(),
        home.join("project-shell").display()
    )));
    let python = text(&box_.bash(&format!(
        "python3 -c 'from pathlib import Path; Path(\"{}\").rename(\"{}/Google\"); print(\"MOVED\")' 2>&1",
        parent.display(),
        home.join("project-python").display()
    )));
    for (seen, copy) in [(&shell, "project-shell"), (&python, "project-python")] {
        assert!(
            !seen.contains("MOVED"),
            "the parent moved with the store inside: {seen}"
        );
        assert!(
            seen.contains("credential-store content"),
            "the refusal must name the floor: {seen}"
        );
        assert!(
            !home.join(copy).join("Google").exists(),
            "{copy} received the profile"
        );
    }
    assert!(
        granted.join("Cookies").exists(),
        "the profile must stay in place"
    );
}

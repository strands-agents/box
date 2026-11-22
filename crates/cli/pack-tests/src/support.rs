//! The helpers that only the tests of the shipped packs use.

pub(crate) use std::path::{Path, PathBuf};

pub(crate) use strands_box_cli::test_support::{
    Trees, box_toml, brew_program, codex_settings, macos_cargo, no_agent, operator_pack, pack,
    profiles_root, resolution, resources, run_folder, script_with, strings, text, tool, trial,
};
pub(crate) use strands_box_cli::{Error, FakeHost, Trial, Trialed};
pub(crate) use strands_box_cli_profile::fixtures::{binary, executable, link, script, write};
pub(crate) use strands_box_cli_profile::host::resolved;
pub(crate) use strands_box_cli_profile::lang::storage_root;

pub(crate) fn agent_command(generated: &Trialed) -> Vec<String> {
    let file: toml::Value = toml::from_str(generated.box_toml()).expect("TOML");
    file["agent"]["command"]
        .as_array()
        .expect("a command")
        .iter()
        .map(|element| element.as_str().expect("a string element").to_string())
        .collect()
}

pub(crate) fn box_guidance(host: &FakeHost) -> [String; 4] {
    let guidance = resources().join("packs/claude/box.md");
    let profile = profiles_root(&host.home().join(".strands/box")).join("claude");
    let profile = profile.display();
    [
        "--append-system-prompt-file".to_string(),
        guidance.display().to_string(),
        "--append-system-prompt".to_string(),
        format!(
            "This run's box profile is the folder {profile}, and its file is {profile}/profile.toml."
        ),
    ]
}

pub(crate) fn string_list(value: Option<&toml::Value>) -> Vec<String> {
    value
        .and_then(toml::Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(|item| item.as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default()
}

pub(crate) fn dashed(workspace: &Path) -> String {
    strands_box_cli_profile::lang::dashed(&resolved(workspace).to_string_lossy())
}

/// The shell note that each agent pack gives its agent, word for word.
pub(crate) const SHELL_NOTE: &str = "## Your shell

Your shell runs under a policy and is not a full bash. When a shell command gives an unexpected or
empty result, try a simpler, portable form and name files by explicit paths.
";

/// What each agent pack tells its agent about a file tool on a path outside the project.
pub(crate) const OUTSIDE_FILES_NOTE: &str =
    "Before you use a file tool on a path outside the project, other than your own settings folder
and `$TMPDIR`, use the shell first, so that the box's policy decides and records it.
";

/// The fact that each agent pack gives its agent about name lookups in the box.
pub(crate) const DNS_NOTE: &str =
    "The box has no DNS. A lookup of a network host fails, with an error such as `ENOTFOUND`,
`EAI_AGAIN`, or `Could not resolve host`, so the failure is not a DNS fault. Programs reach network
hosts through the box's proxy. On macOS, a tool that the profile lets connect directly is the
exception.
";

/// What each agent pack tells its agent about when a change takes effect.
pub(crate) const RESTART_NOTE: &str = "With the box banner on, a change to a policy
file takes effect in this session: the banner says UPDATE READY, and the user presses Ctrl+Alt+R.
Without the banner, and for a change to the profile's startup settings (its packs, tools, folders,
or egress routes), the user starts a new run.
";

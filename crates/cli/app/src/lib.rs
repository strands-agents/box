//! Configure a Strands Box from the host, keep it as a profile, and run a workload in it.
#![warn(missing_docs, unreachable_pub)]

mod check;
mod collection;
use strands_box_cli_profile::compile;
mod create;
mod credential;
mod detect;
use strands_box_cli_profile::error;
mod explain;
use strands_box_cli_profile::files;
#[cfg(any(test, feature = "test-support"))]
use strands_box_cli_profile::fixtures;
use strands_box_cli_profile::host;
mod installation;
use strands_box_cli_profile::lang;
use strands_box_cli_profile::locate;
use strands_box_cli_profile::mcp;
use strands_box_cli_profile::mcp_config;
mod output;
use strands_box_cli_profile::plugin;
mod policy_starter;
use strands_box_cli_profile::profile;
mod profile_guide;
mod prompt;
mod records;
use strands_box_cli_profile::reference;
use strands_box_cli_profile::render;
mod report;
mod resources;
mod run;
mod run_list;
mod starter;
mod storage_hooks;
use strands_box_cli_profile::storage_edit;
use strands_box_cli_profile::storage_files;
use strands_box_cli_profile::storage_sync;
mod telemetry;
#[cfg(any(test, feature = "test-support"))]
pub mod test_support;
use strands_box_cli_profile::tool;

/// The version of `box`, which a file's `[requires] box` names.
pub(crate) const VERSION: &str = env!("CARGO_PKG_VERSION");

pub use create::{CreatedProfile, NewProfile, Resolution};
pub use error::{Error, PolicyFinding};
pub use explain::explain;
pub use host::check_box_home;
pub use output::{OutputFormat, json_line};
pub use profile::{Listed, Profile, Profiles, Project, ProjectAccess, validate_name};
pub use records::RecordsOptions;
pub use report::Report;
pub use run::{
    HeldBoxes, Launch, Launcher, ListedStarter, Preparation, Preview, confirm, is_profile_path,
};
pub use starter::Terminal;
pub use telemetry::{InstallationId, RunContext};
#[cfg(any(test, feature = "test-support"))]
pub use test_support::FakeHost;
#[cfg(all(
    any(test, feature = "test-support"),
    any(target_os = "macos", target_os = "linux")
))]
pub use test_support::{Trial, Trialed};

#[cfg(test)]
mod profile_tests;
#[cfg(test)]
mod tests;
#[cfg(test)]
mod tool_tests;

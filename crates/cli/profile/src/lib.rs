//! Packs and profiles: parse a profile and its packs, resolve them against a host, and
//! compile `box.toml` and `policy.dw`.
#![warn(unreachable_pub)]

pub mod compile;
pub mod error;
pub mod files;
#[cfg(any(test, feature = "test-support"))]
pub mod fixtures;
pub mod host;
mod install_layout;
pub mod lang;
pub mod locate;
pub mod mcp;
pub mod mcp_config;
pub mod plugin;
pub mod profile;
mod program;
pub mod reference;
pub mod render;
pub mod storage_edit;
pub mod storage_files;
mod storage_mounts;
pub mod storage_sync;
pub mod tool;

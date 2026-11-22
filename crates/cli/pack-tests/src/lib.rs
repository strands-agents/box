//! Tests of the packs that `box` ships. Each module tests one pack in `resources/packs`.
#![cfg(all(test, any(target_os = "macos", target_os = "linux")))]

mod support;

mod bedrock;
mod cargo;
mod claude;
mod codex;
mod git;
mod kiro;
mod node;
mod npm;
mod pi;
mod pnpm;
mod pnpx;
mod uvx;

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use strands_box_cli_telemetry::{ContextBuilder, McpFormat, McpTarget, Pack};

use crate::lang::{self, LauncherPack, Layer, VENDORED};
use crate::mcp::{Format, Servers, Transport};
use crate::mcp_config::Target;

pub(crate) use strands_box_cli_telemetry::PackLocation;
pub use strands_box_cli_telemetry::{InstallationId, RunContext};

pub(crate) const VERSION: &str = concat!(
    env!("CARGO_PKG_VERSION_MAJOR"),
    ".",
    env!("CARGO_PKG_VERSION_MINOR"),
    ".",
    env!("CARGO_PKG_VERSION_PATCH"),
);

const _: () = {
    assert!(env!("CARGO_PKG_VERSION_MAJOR").len() <= 4);
    assert!(env!("CARGO_PKG_VERSION_MINOR").len() <= 4);
    assert!(env!("CARGO_PKG_VERSION_PATCH").len() <= 4);
};

pub(crate) struct Observations(ContextBuilder);

impl Default for Observations {
    fn default() -> Self {
        Self(
            ContextBuilder::new(VERSION)
                .expect("the CLI release version fits the telemetry schema"),
        )
    }
}

impl Observations {
    pub(crate) fn profile(&mut self, bytes: &[u8]) {
        self.0.profile(bytes);
    }

    pub(crate) fn mcp(&mut self, box_home: &Path, targets: &[Target]) {
        self.0.mcp(
            box_home,
            targets.iter().map(|target| McpTarget {
                path: &target.path,
                format: match target.kind {
                    Format::Json => McpFormat::Json,
                    Format::Toml => McpFormat::Toml,
                },
                key: &target.key,
            }),
        );
    }

    pub(crate) fn initial_packs(&mut self, layers: &[Layer]) {
        if !layers
            .iter()
            .any(|layer| layer.table.contains_key(lang::MCP_SERVERS))
        {
            self.packs(layers);
        }
    }

    pub(crate) fn resolved_packs(
        &mut self,
        layers: &[Layer],
        launchers: &BTreeMap<String, LauncherPack>,
        servers: &Servers,
    ) {
        self.packs(contributing_packs(layers, launchers, servers));
    }

    pub(crate) fn packs<'a>(&mut self, layers: impl IntoIterator<Item = &'a Layer>) {
        self.0.packs(
            layers
                .into_iter()
                .filter(|layer| layer.shared && !layer.plugin)
                .map(|layer| Pack {
                    id: layer.name.strip_prefix(VENDORED),
                    bytes: layer.text.as_bytes(),
                    grammar: layer.grammar_text.as_deref().map(str::as_bytes),
                    bundled_location: match layer.location {
                        PackLocation::Resources => Some(true),
                        PackLocation::Other => Some(false),
                        PackLocation::Unknown => None,
                    },
                }),
        );
    }

    pub(crate) fn finish(self) -> RunContext {
        self.0.finish()
    }
}

fn contributing_packs<'a>(
    layers: &'a [Layer],
    launchers: &'a BTreeMap<String, LauncherPack>,
    servers: &'a Servers,
) -> impl Iterator<Item = &'a Layer> {
    let mut seen_launchers = BTreeSet::new();
    let launcher_layers = servers
        .detected
        .iter()
        .filter_map(|server| match &server.transport {
            Transport::Stdio {
                launcher: Some(launcher),
                ..
            } => Some(&launcher.pack),
            _ => None,
        })
        .filter(move |name| seen_launchers.insert(*name))
        .filter_map(|name| launchers.values().find(|pack| pack.name == *name))
        .flat_map(|pack| pack.layers.iter().filter(|layer| layer.shared));
    layers.iter().chain(launcher_layers)
}

#[cfg(test)]
mod tests;

#[cfg(test)]
mod failure_tests {
    use crate::Error;
    use strands_box_cli_telemetry::FailureReason;

    #[test]
    fn preparation_categories_use_variants_and_discard_diagnostics() {
        let cases = [
            (
                Error::ProfileMissing {
                    name: "private-profile".into(),
                    path: "/private/path".into(),
                    hint: "private hint".into(),
                },
                FailureReason::ProfileMissing,
            ),
            (
                Error::ProfileName {
                    name: "private-profile".into(),
                    reason: "private reason",
                },
                FailureReason::ProfileInvalid,
            ),
            (
                Error::Profile {
                    path: "/private/path".into(),
                    line: Some(2),
                    reason: "private reason".into(),
                },
                FailureReason::ProfileInvalid,
            ),
            (
                Error::Policy {
                    findings: Vec::new(),
                },
                FailureReason::PolicyRejected,
            ),
            (
                Error::ProfilePath {
                    path: "/private/path".into(),
                    source: std::io::ErrorKind::NotFound.into(),
                },
                FailureReason::ProfileMissing,
            ),
            (
                Error::ProfilePath {
                    path: "/private/path".into(),
                    source: std::io::ErrorKind::PermissionDenied.into(),
                },
                FailureReason::ProfileInvalid,
            ),
            (
                Error::ProfileFileUnnamed {
                    path: "/private/path".into(),
                },
                FailureReason::ProfileInvalid,
            ),
            (
                Error::ProfileNameOwned {
                    name: "private-profile".into(),
                    owner: "/private/path".into(),
                },
                FailureReason::ProfileInvalid,
            ),
            (Error::NoHome, FailureReason::Unknown),
            (
                Error::PolicyCheck {
                    reason: "private reason".into(),
                },
                FailureReason::Unknown,
            ),
            (
                Error::NotOnHost {
                    path: "/private/path".into(),
                    reason: "agent not found".into(),
                },
                FailureReason::Unknown,
            ),
        ];
        for (error, expected) in cases {
            assert_eq!(error.telemetry_failure(), expected);
        }
    }
}

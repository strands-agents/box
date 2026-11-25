//! Commands that produce workspace policy artifacts.

use std::io::Write as _;
use std::path::Path;
use std::process::ExitCode;

use policy::{event_schema_source, generate_mcp_schema_with_omissions};

use crate::error::{BoxError, McpSchemaError};
use crate::record::config::egress::EgressSecret;
use crate::record::config::{
    read_mcp_servers, read_remote_mcp_servers, read_secret_sources, read_tool_grammars,
};
use crate::record::layout::operator_home_directory;
use crate::run::secret_sources::{SchemaSecrets, SecretSources};

const ACTION_SCHEMA_FILE: &str = "actions.cedarschema";
const EVENT_SCHEMA_FILE: &str = "events.dwschema";

pub(crate) async fn generate_schema(
    config: &Path,
    output_dir: &Path,
) -> Result<ExitCode, BoxError> {
    let working =
        std::env::current_dir().map_err(|source| McpSchemaError::WorkingDirectory { source })?;
    let config = working.join(config);
    let grammars = read_tool_grammars(&config)?;
    let servers = read_mcp_servers(&config)?;
    // Read the remote servers first: a re-routed one is refused here, so the whole run fails before
    // the stdio loop below spawns any server, rather than spawning them and discarding the result.
    let remote_servers = read_remote_mcp_servers(&config)?;
    // Check each declared program and read each secret that it holds before a stdio server
    // starts, so a source that fails stops the run first, as it stops `run` before a workload.
    let (entries, enabled, tables) = read_secret_sources(&config)?;
    let references = remote_servers
        .iter()
        .filter_map(|server| server.secret.as_ref())
        .map(|secret| secret.reference.as_str());
    let secrets = SecretSources::check_for_references(
        &entries,
        enabled,
        &tables,
        references,
        ::diagnostics::stderr(),
    )?;
    for server in &remote_servers {
        if let Some(secret) = &server.secret
            && secrets.reads(&secret.reference)
        {
            // A placement that discovery cannot use is refused before a program starts for it.
            header_placement(&server.name, secret)?;
            with_secret(&server.name, secret, &secrets, |_| ())?;
        }
    }
    let home = operator_home_directory()?;

    let mut generated = Vec::with_capacity(servers.len());
    for server in &servers {
        let response = crate::run::broker::mcp::list_tools(server, &home, &working)
            .await
            .map_err(|source| McpSchemaError::Discover {
                server: server.name.clone(),
                source,
            })?;
        let schema = generate_left_out_warned(&server.name, &response.to_string())?;
        generated.push((server.name.clone(), schema));
    }

    // Remote MCP servers (`[egress.<name>]` speaking `mcp`) are discovered over HTTP by a direct
    // client, not spawned. There is no gateway before `run`, so the credential is resolved and
    // attached here rather than injected as a phantom.
    for server in remote_servers {
        let auth = match &server.secret {
            Some(secret) => Some(resolve_auth(&server.name, secret, &secrets)?),
            None => None,
        };
        let response = crate::run::broker::mcp_remote::list_tools(&server.url, auth)
            .await
            .map_err(|source| McpSchemaError::Discover {
                server: server.name.clone(),
                source,
            })?;
        let schema = generate_left_out_warned(&server.name, &response.to_string())?;
        generated.push((server.name.clone(), schema));
    }

    let schemas = generated
        .iter()
        .map(|(server, schema)| (server.as_str(), schema.as_str()))
        .collect::<Vec<_>>();
    let actions = grammars
        .compose_action_schema(&schemas)
        .map_err(McpSchemaError::from)?;
    let directory = working.join(output_dir);
    std::fs::create_dir_all(&directory).map_err(|source| McpSchemaError::Write {
        path: directory.clone(),
        source,
    })?;
    let action_path = directory.join(ACTION_SCHEMA_FILE);
    let event_path = directory.join(EVENT_SCHEMA_FILE);
    write_schema(&directory, &action_path, actions.as_bytes())?;
    write_schema(&directory, &event_path, event_schema_source().as_bytes())?;

    println!("Generated {}", action_path.display());
    println!("Generated {}", event_path.display());
    Ok(ExitCode::SUCCESS)
}

/// The schema of `server`, after a warning for each tool it leaves out.
fn generate_left_out_warned(server: &str, tools_list: &str) -> Result<String, McpSchemaError> {
    let (schema, omitted) =
        generate_mcp_schema_with_omissions(server, tools_list).map_err(McpSchemaError::from)?;
    for tool in omitted {
        ::diagnostics::diag!(B0403, "{tool}");
    }
    Ok(schema)
}

/// What `used` makes of the secret of `server`, which is read through `secrets` and wiped after.
fn with_secret<T>(
    server: &str,
    secret: &EgressSecret,
    secrets: &SchemaSecrets,
    used: impl FnOnce(&str) -> T,
) -> Result<T, McpSchemaError> {
    let refused = |source: credentials::CredentialError| McpSchemaError::Credential {
        server: server.to_string(),
        reason: source.to_string(),
    };
    let locator = credentials::Locator::parse_uri(&secret.reference).map_err(refused)?;
    let token = secrets.backend().resolve(&locator).map_err(refused)?;
    Ok(used(token.as_str()))
}

/// Refuse a secret of `server` whose placement is not a header, which is the one placement that
/// discovery supports.
fn header_placement(server: &str, secret: &EgressSecret) -> Result<(), McpSchemaError> {
    if let Some(placement) = &secret.placement
        && !placement.eq_ignore_ascii_case("header")
    {
        return Err(McpSchemaError::UnsupportedPlacement {
            server: server.to_string(),
            placement: placement.clone(),
        });
    }
    Ok(())
}

/// The `(header, value)` that discovery attaches for `server`, with its secret read through
/// `secrets` and only header placement supported.
fn resolve_auth(
    server: &str,
    secret: &EgressSecret,
    secrets: &SchemaSecrets,
) -> Result<(String, String), McpSchemaError> {
    header_placement(server, secret)?;
    let header = secret
        .header
        .clone()
        .unwrap_or_else(|| "Authorization".to_string());
    let default_prefix = if header.eq_ignore_ascii_case("Authorization") {
        "Bearer "
    } else {
        ""
    };
    let prefix = secret
        .prefix
        .clone()
        .unwrap_or_else(|| default_prefix.to_string());
    let value = with_secret(server, secret, secrets, |token| format!("{prefix}{token}"))?;
    Ok((header, value))
}

fn write_schema(directory: &Path, path: &Path, schema: &[u8]) -> Result<(), McpSchemaError> {
    let mut temporary =
        tempfile::NamedTempFile::new_in(directory).map_err(|source| McpSchemaError::Write {
            path: path.to_path_buf(),
            source,
        })?;
    temporary
        .write_all(schema)
        .map_err(|source| McpSchemaError::Write {
            path: path.to_path_buf(),
            source,
        })?;
    temporary
        .persist(path)
        .map_err(|error| McpSchemaError::Write {
            path: path.to_path_buf(),
            source: error.error,
        })?;
    Ok(())
}

#[cfg(all(test, unix))]
mod tests {
    use std::os::unix::fs::MetadataExt as _;

    use super::*;

    #[test]
    fn writing_a_schema_replaces_its_inode() {
        let directory = tempfile::tempdir().expect("schema directory");
        let path = directory.path().join(ACTION_SCHEMA_FILE);
        std::fs::write(&path, "old schema").expect("old schema");
        let old_inode = std::fs::metadata(&path).expect("old metadata").ino();

        write_schema(directory.path(), &path, b"new schema").expect("replace schema");

        let new_inode = std::fs::metadata(&path).expect("new metadata").ino();
        assert_ne!(
            new_inode, old_inode,
            "replacement must rename a separate temporary file over the target"
        );
        assert_eq!(std::fs::read(&path).expect("new schema"), b"new schema");
    }
}

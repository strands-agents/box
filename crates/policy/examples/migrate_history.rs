//! Offline Dogwood 1.0.0 to 1.1.2 history migration.
//!
//! Preparation is the default. Pass --apply after reviewing its summary.

use std::error::Error;
use std::fs::OpenOptions;
use std::path::PathBuf;

use policy::{MigrationInput, Policy, PolicyMigration};

fn main() -> Result<(), Box<dyn Error>> {
    let mut args = std::env::args_os().skip(1);
    let mut history = None;
    let mut policies = Vec::new();
    let mut grammar_schemas = Vec::new();
    let mut mcp_schemas = Vec::new();
    let mut apply = false;
    while let Some(argument) = args.next() {
        match argument.to_str() {
            Some("--history") => {
                history = Some(PathBuf::from(args.next().ok_or("--history needs a path")?))
            }
            Some("--policy") => {
                let origin = PathBuf::from(args.next().ok_or("--policy needs a path")?);
                policies.push(Policy {
                    text: std::fs::read_to_string(&origin)?,
                    origin,
                });
            }
            Some("--grammar-schema") => grammar_schemas.push(std::fs::read_to_string(
                PathBuf::from(args.next().ok_or("--grammar-schema needs a path")?),
            )?),
            Some("--mcp-schema") => mcp_schemas.push(std::fs::read_to_string(PathBuf::from(
                args.next().ok_or("--mcp-schema needs a path")?,
            ))?),
            Some("--apply") => apply = true,
            Some("--help") => {
                println!(
                    "Stop Box before running this program.\nUsage: migrate_history --history FILE [--policy FILE]... [--grammar-schema FILE]... [--mcp-schema FILE]... [--apply]\nSupply unchanged original inputs in their installed order. Without --apply, this command prepares and prints counts only."
                );
                return Ok(());
            }
            _ => return Err("unknown argument; use --help".into()),
        }
    }
    let history = history.ok_or("--history is required; use --help")?;
    let file = OpenOptions::new().read(true).write(true).open(&history)?;
    let migration = PolicyMigration::prepare(
        MigrationInput::new(file, policies)
            .with_grammar_schemas(grammar_schemas)
            .with_mcp_schemas(mcp_schemas),
    )?;
    println!("{}", serde_json::to_string_pretty(migration.summary())?);
    if apply {
        let parent = history
            .parent()
            .filter(|path| !path.as_os_str().is_empty())
            .unwrap_or_else(|| std::path::Path::new("."));
        let scratch = tempfile::tempdir_in(parent)?;
        let prepare = tempfile::NamedTempFile::new_in(scratch.path())?;
        let validate = tempfile::NamedTempFile::new_in(scratch.path())?;
        let result = migration.apply(prepare.reopen()?, validate.reopen()?)?;
        println!("Migration complete: {}", serde_json::to_string(&result)?);
    }
    Ok(())
}

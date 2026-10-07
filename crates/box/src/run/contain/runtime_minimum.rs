//! What every process on this operating system needs to load and run, stated by Core.

use std::path::{Path, PathBuf};

use containment::{Operation, Scope};

/// One cell Core adds beneath every `ProcessSpec`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct MinimumCell {
    pub(crate) path: PathBuf,
    pub(crate) operation: Operation,
    pub(crate) scope: Scope,
}

impl MinimumCell {
    /// How this cell reads in the startup disclosure.
    pub(crate) fn disclosure(&self) -> String {
        let operation = match self.operation {
            Operation::Read => "read",
            Operation::Write => "write",
            Operation::Metadata => "metadata",
            Operation::Exec => "exec",
            Operation::List => "list",
            Operation::Connect => "connect",
            Operation::Deny => "deny",
        };
        let scope = match self.scope {
            Scope::Root => "",
            Scope::Dir => "  (entry only)",
            Scope::File => "",
        };
        let loader = if self.operation == Operation::Read
            && self.scope == Scope::Root
            && is_loader_directory(&self.path)
        {
            LOADER_NOTE
        } else {
            ""
        };
        format!("  {operation:<10}  {}{scope}{loader}", self.path.display())
    }
}

/// The directories the loader maps code from, on this operating system.
#[cfg(target_os = "macos")]
const LOADER_DIRECTORIES: &[&str] = &["/usr/lib"];

/// The directories the loader maps code from, which a bind cannot make readable without letting
/// code map and run there.
#[cfg(not(target_os = "macos"))]
const LOADER_DIRECTORIES: &[&str] = &["/lib", "/lib64", "/usr/lib", "/usr/lib64"];

#[cfg(target_os = "macos")]
const LOADER_NOTE: &str = "  (loader directory)";

#[cfg(not(target_os = "macos"))]
const LOADER_NOTE: &str = "  (loader directory: code maps and runs here)";

fn is_loader_directory(path: &Path) -> bool {
    LOADER_DIRECTORIES
        .iter()
        .any(|directory| Path::new(directory) == path)
}

/// The operating-system cells for agent containment.
pub(crate) fn agent_cells() -> Vec<MinimumCell> {
    stated(containment::os_runtime_cells())
}

/// The operating-system cells for leaf containment.
pub(crate) fn leaf_cells() -> Vec<MinimumCell> {
    stated(containment::os_minimum_cells())
}

fn stated(cells: Vec<(PathBuf, Operation, Scope)>) -> Vec<MinimumCell> {
    cells
        .into_iter()
        .map(|(path, operation, scope)| MinimumCell {
            path,
            operation,
            scope,
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// **Every cell the box receives exists, in the kind its scope names.**
    ///
    /// The two properties this used to assert over its own table — no exec, and no write beyond the
    /// null device — moved with the data, to
    /// `containment::floor::no_set_carries_exec_and_only_the_null_device_is_written`.
    #[test]
    fn every_reported_cell_exists_in_the_kind_its_scope_names() {
        let reported = leaf_cells();
        assert!(
            reported
                .iter()
                .any(|cell| cell.path == Path::new("/dev/null")),
            "{reported:?}"
        );
        for cell in &reported {
            let metadata = std::fs::metadata(&cell.path).expect("a reported cell exists");
            match cell.scope {
                Scope::File => assert!(!metadata.is_dir(), "{cell:?}"),
                Scope::Dir | Scope::Root => assert!(metadata.is_dir(), "{cell:?}"),
            }
        }
    }

    /// **The minimum reads the loader's directories as trees, and no program directory.**
    #[test]
    fn the_minimum_carries_the_loader_directories_and_no_program_directory() {
        let reported = leaf_cells();
        let identities: Vec<PathBuf> = reported
            .iter()
            .filter(|cell| cell.operation == Operation::Read && cell.scope == Scope::Root)
            .map(|cell| {
                cell.path
                    .canonicalize()
                    .unwrap_or_else(|_| cell.path.clone())
            })
            .collect();
        let present: Vec<PathBuf> = LOADER_DIRECTORIES
            .iter()
            .map(Path::new)
            .filter(|directory| directory.is_dir())
            .map(|directory| directory.canonicalize().expect("a directory resolves"))
            .collect();
        assert!(!present.is_empty(), "this host has a loader directory");
        for directory in &present {
            assert!(
                identities.contains(directory),
                "{} must be a read root of the minimum: {reported:?}",
                directory.display()
            );
        }
        for program_directory in ["/bin", "/sbin", "/usr/bin", "/usr/sbin", "/usr/libexec"] {
            let identity = Path::new(program_directory)
                .canonicalize()
                .unwrap_or_else(|_| PathBuf::from(program_directory));
            assert!(
                !reported.iter().any(|cell| {
                    let path = cell
                        .path
                        .canonicalize()
                        .unwrap_or_else(|_| cell.path.clone());
                    path == identity || (cell.scope == Scope::Root && identity.starts_with(&path))
                }),
                "{program_directory} is not reached by the minimum: {reported:?}"
            );
        }
        let mut seen: Vec<(PathBuf, Operation, Scope)> = Vec::new();
        for cell in &reported {
            let identity = cell
                .path
                .canonicalize()
                .unwrap_or_else(|_| cell.path.clone());
            let key = (identity, cell.operation, cell.scope);
            assert!(!seen.contains(&key), "one cell per identity: {reported:?}");
            seen.push(key);
        }
    }

    /// A loader directory's line says that code maps there, and on Linux that it runs there.
    #[test]
    fn a_loader_directory_line_carries_its_note() {
        let cell = MinimumCell {
            path: PathBuf::from(LOADER_DIRECTORIES[0]),
            operation: Operation::Read,
            scope: Scope::Root,
        };
        assert!(
            cell.disclosure().ends_with(LOADER_NOTE),
            "{}",
            cell.disclosure()
        );
        let plain = MinimumCell {
            path: PathBuf::from("/usr/share/zoneinfo"),
            operation: Operation::Read,
            scope: Scope::Root,
        };
        assert_eq!(plain.disclosure(), "  read        /usr/share/zoneinfo");
    }

    #[test]
    fn a_disclosure_line_names_the_operation_and_the_path() {
        let cell = MinimumCell {
            path: PathBuf::from("/etc"),
            operation: Operation::Metadata,
            scope: Scope::Dir,
        };
        assert_eq!(cell.disclosure(), "  metadata    /etc  (entry only)");
    }
}

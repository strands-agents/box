//! The installed tool packs, each bound to a resolved program file and the name it is called by
//! (docs/design/decisions.md#a-tool-pack-binds-on-the-program-file-and-the-called-name).

use std::collections::{BTreeMap, BTreeSet};

use super::Pack;

/// The installed packs, and the (program file, called name) pairs each one covers.
#[derive(Debug, Default)]
pub(crate) struct PackBindings {
    packs: Vec<Pack>,
    by_file: BTreeMap<String, usize>,
    bound: BTreeSet<(String, String)>,
    declared: BTreeSet<(String, String)>,
}

/// How a pack covers one spawn.
#[derive(Debug, Clone, Copy)]
pub(crate) enum PackCoverage<'a> {
    /// The file and the name are bound to this pack, so the command parses with its grammar.
    Parsed(&'a Pack),
    /// The file is bound to this pack, and no `[tool]` declares the name it was called by.
    Unmodeled(&'a Pack),
}

/// Why Box refuses one binding.
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub(crate) enum BindingRefusal {
    #[error("no installed tool pack is named {pack:?}")]
    UnknownPack { pack: String },
    #[error("{program_path} is bound to tool pack {bound:?}, so it cannot also bind {pack:?}")]
    BoundToAnotherPack {
        program_path: String,
        bound: String,
        pack: String,
    },
}

impl PackBindings {
    pub(crate) fn new(packs: Vec<Pack>) -> Self {
        Self {
            packs,
            ..Self::default()
        }
    }

    /// Declare that a `[tool]` runs the file at `program_path` under the name `name`.
    pub(crate) fn declare(&mut self, program_path: impl Into<String>, name: impl Into<String>) {
        self.declared.insert((program_path.into(), name.into()));
    }

    /// Bind the pack named `pack` to the file at `program_path` called by `name`.
    pub(crate) fn bind(
        &mut self,
        program_path: impl Into<String>,
        name: impl Into<String>,
        pack: &str,
    ) -> Result<(), BindingRefusal> {
        let index = self
            .packs
            .iter()
            .position(|installed| installed.name == pack)
            .ok_or_else(|| BindingRefusal::UnknownPack {
                pack: pack.to_string(),
            })?;
        let program_path = program_path.into();
        if let Some(&bound) = self.by_file.get(&program_path)
            && bound != index
        {
            return Err(BindingRefusal::BoundToAnotherPack {
                program_path,
                bound: self.packs[bound].name.clone(),
                pack: pack.to_string(),
            });
        }
        self.by_file.insert(program_path.clone(), index);
        self.bound.insert((program_path, name.into()));
        Ok(())
    }

    /// The pack that covers a spawn of the file at `program_path` called by `name`, if any.
    pub(crate) fn coverage(&self, program_path: &str, name: &str) -> Option<PackCoverage<'_>> {
        let pack = &self.packs[*self.by_file.get(program_path)?];
        let pair = (program_path.to_string(), name.to_string());
        if self.bound.contains(&pair) {
            Some(PackCoverage::Parsed(pack))
        } else if self.declared.contains(&pair) {
            None
        } else {
            Some(PackCoverage::Unmodeled(pack))
        }
    }
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use super::*;

    const GIT: &str = "/usr/bin/git";
    const CARGO: &str = "/home/operator/.cargo/bin/cargo";
    const MISE: &str = "/home/operator/.local/bin/mise";

    fn installed(names: &[&str]) -> Vec<Pack> {
        let corpus = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/packs/valid");
        names
            .iter()
            .map(|name| Pack::load(&corpus.join(format!("{name}.pack.toml"))).expect("a pack"))
            .collect()
    }

    fn answer(coverage: Option<PackCoverage<'_>>) -> Option<(&'static str, String)> {
        coverage.map(|coverage| match coverage {
            PackCoverage::Parsed(pack) => ("parsed", pack.name.clone()),
            PackCoverage::Unmodeled(pack) => ("unmodeled", pack.name.clone()),
        })
    }

    fn parsed(pack: &str) -> Option<(&'static str, String)> {
        Some(("parsed", pack.to_string()))
    }

    fn unmodeled(pack: &str) -> Option<(&'static str, String)> {
        Some(("unmodeled", pack.to_string()))
    }

    #[test]
    fn each_spawn_resolves_by_its_program_file_and_its_called_name() {
        let mut bindings = PackBindings::new(installed(&["git", "cargo"]));
        bindings.bind(GIT, "git", "git").expect("git binds");
        bindings.declare(CARGO, "rustc");
        bindings.bind(CARGO, "cargo", "cargo").expect("cargo binds");
        bindings
            .bind(MISE, "git", "git")
            .expect("the mise shim binary binds");
        bindings.declare(MISE, "node");
        bindings.declare(MISE, "npm");

        for (case, program_path, name, expected) in [
            ("a bound pair parses", GIT, "git", parsed("git")),
            (
                "a second pack on a second file",
                CARGO,
                "cargo",
                parsed("cargo"),
            ),
            (
                "a declared, unbound name on a bound file",
                CARGO,
                "rustc",
                None,
            ),
            (
                "an undeclared name on a bound file",
                CARGO,
                "cargo-clippy",
                unmodeled("cargo"),
            ),
            ("an unbound file", "/usr/bin/ls", "ls", None),
            (
                "an unbound file called by a bound name",
                "/opt/git/bin/git",
                "git",
                None,
            ),
            (
                "the mise shim binary, by its bound name",
                MISE,
                "git",
                parsed("git"),
            ),
            (
                "the mise shim binary, by a declared name",
                MISE,
                "node",
                None,
            ),
            (
                "the mise shim binary, by another declared name",
                MISE,
                "npm",
                None,
            ),
            (
                "the mise shim binary, by an undeclared name",
                MISE,
                "python",
                unmodeled("git"),
            ),
        ] {
            assert_eq!(
                answer(bindings.coverage(program_path, name)),
                expected,
                "{case}: {program_path} called as {name}"
            );
        }
    }

    #[test]
    fn an_undeclared_name_on_a_file_that_no_pack_binds_stays_a_spawn() {
        let mut bindings = PackBindings::new(installed(&["git"]));
        bindings.declare(MISE, "node");

        for (case, name) in [
            ("a declared name", "node"),
            ("an undeclared name", "python"),
        ] {
            assert!(
                bindings.coverage(MISE, name).is_none(),
                "{case}: {MISE} called as {name}"
            );
        }
    }

    #[test]
    fn a_binding_that_names_no_installed_pack_or_a_second_pack_on_one_file_is_refused() {
        let mut bindings = PackBindings::new(installed(&["git", "cargo"]));
        bindings.bind(GIT, "git", "git").expect("git binds");
        bindings.bind(CARGO, "cargo", "cargo").expect("cargo binds");
        bindings
            .bind(MISE, "git", "git")
            .expect("the mise shim binary binds");

        let another_pack = |program_path: &str| {
            Err(BindingRefusal::BoundToAnotherPack {
                program_path: program_path.to_string(),
                bound: "git".to_string(),
                pack: "cargo".to_string(),
            })
        };
        for (case, program_path, name, pack, expected) in [
            (
                "an unknown pack",
                CARGO,
                "rustc",
                "kubectl",
                Err(BindingRefusal::UnknownPack {
                    pack: "kubectl".to_string(),
                }),
            ),
            (
                "a bound pair, to another pack",
                GIT,
                "git",
                "cargo",
                another_pack(GIT),
            ),
            (
                "another name, to another pack",
                MISE,
                "cargo",
                "cargo",
                another_pack(MISE),
            ),
            (
                "a bound pair, to the same pack again",
                GIT,
                "git",
                "git",
                Ok(()),
            ),
            (
                "another name, to the same pack",
                GIT,
                "git-upload-pack",
                "git",
                Ok(()),
            ),
        ] {
            assert_eq!(
                bindings.bind(program_path, name, pack),
                expected,
                "{case}: {program_path} called as {name}, to {pack}"
            );
        }

        for (case, program_path, name, expected) in [
            (
                "the refused unknown pack",
                CARGO,
                "rustc",
                unmodeled("cargo"),
            ),
            ("the refused pair", GIT, "git", parsed("git")),
            ("the refused name", MISE, "cargo", unmodeled("git")),
            ("the accepted name", GIT, "git-upload-pack", parsed("git")),
        ] {
            assert_eq!(
                answer(bindings.coverage(program_path, name)),
                expected,
                "{case}: {program_path} called as {name}"
            );
        }
    }
}

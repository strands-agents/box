//! The checked tool pack that loading builds from the file.

use std::collections::BTreeMap;

use super::format::{OperandSpec, OptionSpec, PackFile, ShellActionSpec, ValueSpec, WhenSpec};
use super::{PackRefusal, Place};
use crate::schema::cedar_identifier;

/// One tool pack, read and checked.
#[cfg_attr(test, derive(PartialEq))]
#[derive(Debug)]
pub(crate) struct Pack {
    name: String,
    version: u32,
    program: String,
    effects: BTreeMap<String, String>,
    global_options: BTreeMap<String, ShellOption>,
    actions: BTreeMap<String, ShellAction>,
}

/// One `[shell.<action>]` table.
#[cfg_attr(test, derive(PartialEq))]
#[derive(Debug)]
pub(crate) struct ShellAction {
    usage: String,
    aliases: Vec<String>,
    adds: Vec<String>,
    options: BTreeMap<String, ShellOption>,
    operands: BTreeMap<String, Operand>,
}

/// One option of a shell action or of `[global]`.
#[cfg_attr(test, derive(PartialEq))]
#[derive(Debug)]
pub(crate) struct ShellOption {
    flags: Vec<String>,
    value: OptionValue,
    repeated: bool,
    anywhere: bool,
    effects: EffectChanges,
}

/// One operand of a shell action.
#[cfg_attr(test, derive(PartialEq))]
#[derive(Debug)]
pub(crate) struct Operand {
    rest: bool,
    effects: EffectChanges,
}

/// Whether an option takes a value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum OptionValue {
    None,
    Required,
    Optional,
    Many,
}

/// The patterns an option or operand value is like, and the declared effects it adds or removes.
#[cfg_attr(test, derive(PartialEq))]
#[derive(Debug)]
pub(crate) struct EffectChanges {
    like: Vec<String>,
    adds: Vec<String>,
    removes: Vec<String>,
    when: Vec<WhenChanges>,
}

/// The effects one `when` entry adds or removes when a value is like its patterns.
#[cfg_attr(test, derive(PartialEq))]
#[derive(Debug)]
pub(crate) struct WhenChanges {
    like: Vec<String>,
    adds: Vec<String>,
    removes: Vec<String>,
}

impl Pack {
    /// Check `file` and build the pack it describes.
    pub(super) fn read(file: PackFile) -> Result<Self, PackRefusal> {
        let version = match &file.version {
            None => return Err(PackRefusal::MissingVersion),
            Some(toml::Value::Integer(version)) if *version >= 1 => {
                u32::try_from(*version).map_err(|_| PackRefusal::BadVersion(version.to_string()))?
            }
            Some(other) => return Err(PackRefusal::BadVersion(other.to_string())),
        };
        identifier(Place::Pack, &file.pack)?;
        if file.program.is_empty()
            || file.program.contains('/')
            || file.program.chars().any(char::is_whitespace)
        {
            return Err(PackRefusal::BadProgram(file.program));
        }
        for effect in file.effects.keys() {
            identifier(Place::Effect(effect.clone()), effect)?;
        }
        let effects = file.effects;
        let mut global_options = BTreeMap::new();
        for (name, spec) in file.global.options {
            let place = Place::GlobalOption(name.clone());
            identifier(place.clone(), &name)?;
            global_options.insert(name, ShellOption::read(spec, &place, &effects)?);
        }
        let mut actions = BTreeMap::new();
        for (name, spec) in file.shell {
            let action = ShellAction::read(&name, spec, &file.program, &effects)?;
            actions.insert(name, action);
        }
        Ok(Self {
            name: file.pack,
            version,
            program: file.program,
            effects,
            global_options,
            actions,
        })
    }
}

impl ShellAction {
    fn read(
        name: &str,
        spec: ShellActionSpec,
        program: &str,
        effects: &BTreeMap<String, String>,
    ) -> Result<Self, PackRefusal> {
        let place = Place::Action(name.to_string());
        identifier(place.clone(), name)?;
        let first = spec.usage.split_whitespace().next().unwrap_or_default();
        if first != program {
            return Err(PackRefusal::UsageDisagrees {
                place,
                first: first.to_string(),
                program: program.to_string(),
            });
        }
        let adds = declared(&Place::ActionAdds(name.to_string()), spec.adds, effects)?;
        let mut options = BTreeMap::new();
        for (option, option_spec) in spec.options {
            let place = Place::ActionOption {
                action: name.to_string(),
                option: option.clone(),
            };
            identifier(place.clone(), &option)?;
            options.insert(option, ShellOption::read(option_spec, &place, effects)?);
        }
        let mut operands = BTreeMap::new();
        for (operand, operand_spec) in spec.operands {
            let place = Place::Operand {
                action: name.to_string(),
                operand: operand.clone(),
            };
            identifier(place.clone(), &operand)?;
            operands.insert(operand, Operand::read(operand_spec, &place, effects)?);
        }
        Ok(Self {
            usage: spec.usage,
            aliases: spec.aliases,
            adds,
            options,
            operands,
        })
    }
}

impl ShellOption {
    fn read(
        spec: OptionSpec,
        place: &Place,
        effects: &BTreeMap<String, String>,
    ) -> Result<Self, PackRefusal> {
        Ok(Self {
            flags: spec.flag,
            value: match spec.value {
                ValueSpec::None => OptionValue::None,
                ValueSpec::Required => OptionValue::Required,
                ValueSpec::Optional => OptionValue::Optional,
                ValueSpec::Many => OptionValue::Many,
            },
            repeated: spec.repeated,
            anywhere: spec.anywhere,
            effects: EffectChanges::read(
                place,
                spec.like,
                spec.adds,
                spec.removes,
                spec.when,
                effects,
            )?,
        })
    }
}

impl Operand {
    fn read(
        spec: OperandSpec,
        place: &Place,
        effects: &BTreeMap<String, String>,
    ) -> Result<Self, PackRefusal> {
        Ok(Self {
            rest: spec.rest,
            effects: EffectChanges::read(
                place,
                spec.like,
                spec.adds,
                spec.removes,
                spec.when,
                effects,
            )?,
        })
    }
}

impl EffectChanges {
    fn read(
        place: &Place,
        like: Vec<String>,
        adds: Vec<String>,
        removes: Vec<String>,
        when: Vec<WhenSpec>,
        effects: &BTreeMap<String, String>,
    ) -> Result<Self, PackRefusal> {
        let adds = declared(place, adds, effects)?;
        let removes = declared(place, removes, effects)?;
        let when = when
            .into_iter()
            .map(|entry| {
                Ok(WhenChanges {
                    like: entry.like,
                    adds: declared(place, entry.adds, effects)?,
                    removes: declared(place, entry.removes, effects)?,
                })
            })
            .collect::<Result<_, PackRefusal>>()?;
        Ok(Self {
            like,
            adds,
            removes,
            when,
        })
    }
}

fn identifier(place: Place, name: &str) -> Result<(), PackRefusal> {
    if !name.is_empty() && cedar_identifier(name) == name {
        Ok(())
    } else {
        Err(PackRefusal::NotIdentifier {
            place,
            name: name.to_string(),
        })
    }
}

fn declared(
    place: &Place,
    names: Vec<String>,
    effects: &BTreeMap<String, String>,
) -> Result<Vec<String>, PackRefusal> {
    match names.iter().find(|name| !effects.contains_key(*name)) {
        None => Ok(names),
        Some(name) => Err(PackRefusal::UndeclaredEffect {
            place: place.clone(),
            effect: name.clone(),
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn strings(values: &[&str]) -> Vec<String> {
        values.iter().map(|value| value.to_string()).collect()
    }

    fn changes(like: &[&str], adds: &[&str], removes: &[&str]) -> EffectChanges {
        EffectChanges {
            like: strings(like),
            adds: strings(adds),
            removes: strings(removes),
            when: Vec::new(),
        }
    }

    #[test]
    fn every_nested_field_reads_into_its_own_place() {
        let text = r#"
pack = "git"
program = "git"
format = 1
version = 2

[effects]
force_push = "Replaces commits on a remote branch"
network = "Contacts a remote repository"
override_config = "Overrides git configuration for this one command"

[global]
options.config = { flag = "-c", value = "required", repeated = true, adds = ["override_config"] }
options.directory = { flag = "-C", value = "many", anywhere = true }

[shell.push]
usage = "git [global options] push [options] [<remote> [<refspec>...]]"
aliases = ["send"]
adds = ["network"]
options.lease = { flag = ["--force-with-lease"], value = "optional", like = ["*:*", "*"], when = [{ like = "*", adds = ["force_push"], removes = ["network"] }] }
options.dry_run = { flag = ["-n", "--dry-run"], removes = ["force_push"] }
operands.refspec = { like = "+*", adds = ["force_push"], removes = ["network"], when = [{ like = ["a", "b"] }], rest = true }
"#;
        let option = |flags: &[&str], value, repeated, anywhere, effects| ShellOption {
            flags: strings(flags),
            value,
            repeated,
            anywhere,
            effects,
        };
        let lease = EffectChanges {
            when: vec![WhenChanges {
                like: strings(&["*"]),
                adds: strings(&["force_push"]),
                removes: strings(&["network"]),
            }],
            ..changes(&["*:*", "*"], &[], &[])
        };
        let refspec = EffectChanges {
            when: vec![WhenChanges {
                like: strings(&["a", "b"]),
                adds: Vec::new(),
                removes: Vec::new(),
            }],
            ..changes(&["+*"], &["force_push"], &["network"])
        };
        let expected = Pack {
            name: "git".to_string(),
            version: 2,
            program: "git".to_string(),
            effects: BTreeMap::from(
                [
                    ("force_push", "Replaces commits on a remote branch"),
                    ("network", "Contacts a remote repository"),
                    (
                        "override_config",
                        "Overrides git configuration for this one command",
                    ),
                ]
                .map(|(name, description)| (name.to_string(), description.to_string())),
            ),
            global_options: BTreeMap::from([
                (
                    "config".to_string(),
                    option(
                        &["-c"],
                        OptionValue::Required,
                        true,
                        false,
                        changes(&[], &["override_config"], &[]),
                    ),
                ),
                (
                    "directory".to_string(),
                    option(
                        &["-C"],
                        OptionValue::Many,
                        false,
                        true,
                        changes(&[], &[], &[]),
                    ),
                ),
            ]),
            actions: BTreeMap::from([(
                "push".to_string(),
                ShellAction {
                    usage: "git [global options] push [options] [<remote> [<refspec>...]]"
                        .to_string(),
                    aliases: strings(&["send"]),
                    adds: strings(&["network"]),
                    options: BTreeMap::from([
                        (
                            "dry_run".to_string(),
                            option(
                                &["-n", "--dry-run"],
                                OptionValue::None,
                                false,
                                false,
                                changes(&[], &[], &["force_push"]),
                            ),
                        ),
                        (
                            "lease".to_string(),
                            option(
                                &["--force-with-lease"],
                                OptionValue::Optional,
                                false,
                                false,
                                lease,
                            ),
                        ),
                    ]),
                    operands: BTreeMap::from([(
                        "refspec".to_string(),
                        Operand {
                            rest: true,
                            effects: refspec,
                        },
                    )]),
                },
            )]),
        };

        assert_eq!(Pack::parse(text).expect("the pack loads"), expected);
    }
}

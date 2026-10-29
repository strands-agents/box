//! The checked tool pack that loading builds from the file.

use std::borrow::Borrow;
use std::collections::BTreeMap;

use super::format::{OperandSpec, OptionSpec, PackFile, ShellActionSpec, ValueSpec, WhenSpec};
use super::grammar::ShellGrammar;
use super::{OptionFault, PackRefusal, Place};
use crate::schema::cedar_identifier;

/// The action that a command line raises when no shell action of its pack matches it.
pub(crate) const UNMODELED_ACTION: &str = "unmodeled";

/// The name of one `[shell.<action>]` table of a checked pack.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct ActionName(String);

/// The name of one `[effects]` entry of a checked pack.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct EffectName(String);

impl ActionName {
    pub(crate) fn as_str(&self) -> &str {
        &self.0
    }
}

impl EffectName {
    pub(crate) fn as_str(&self) -> &str {
        &self.0
    }
}

impl Borrow<str> for EffectName {
    fn borrow(&self) -> &str {
        &self.0
    }
}

/// One tool pack, read and checked.
#[cfg_attr(test, derive(PartialEq))]
#[derive(Debug)]
pub(crate) struct Pack {
    pub(super) name: String,
    pub(super) version: u32,
    pub(super) program: String,
    pub(super) effects: BTreeMap<EffectName, String>,
    pub(super) global_options: BTreeMap<String, ShellOption>,
    pub(super) actions: BTreeMap<ActionName, ShellAction>,
    grammar: ShellGrammar,
}

/// One `[shell.<action>]` table.
#[cfg_attr(test, derive(PartialEq))]
#[derive(Debug)]
pub(crate) struct ShellAction {
    pub(super) usage: String,
    pub(super) aliases: Vec<Vec<String>>,
    pub(super) adds: Vec<EffectName>,
    pub(super) options: BTreeMap<String, ShellOption>,
    pub(super) operands: BTreeMap<String, Operand>,
}

/// One option of a shell action or of `[global]`.
#[cfg_attr(test, derive(PartialEq))]
#[derive(Debug)]
pub(crate) struct ShellOption {
    pub(super) flags: Vec<String>,
    pub(super) value: OptionValue,
    pub(super) repeated: bool,
    pub(super) anywhere: bool,
    pub(super) effects: EffectChanges,
}

/// One operand of a shell action.
#[cfg_attr(test, derive(PartialEq))]
#[derive(Debug)]
pub(crate) struct Operand {
    pub(super) rest: bool,
    pub(super) effects: EffectChanges,
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
#[derive(Debug, Clone, Default)]
pub(crate) struct EffectChanges {
    pub(super) like: Vec<String>,
    pub(super) adds: Vec<EffectName>,
    pub(super) removes: Vec<EffectName>,
    pub(super) when: Vec<WhenChanges>,
}

/// The effects one `when` entry adds or removes when a value is like its patterns.
#[cfg_attr(test, derive(PartialEq))]
#[derive(Debug, Clone)]
pub(crate) struct WhenChanges {
    pub(super) like: Vec<String>,
    pub(super) adds: Vec<EffectName>,
    pub(super) removes: Vec<EffectName>,
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
        let mut effects = BTreeMap::new();
        for (effect, description) in file.effects {
            identifier(Place::Effect(effect.clone()), &effect)?;
            effects.insert(EffectName(effect), description);
        }
        let mut global_options = BTreeMap::new();
        let mut global_flags = BTreeMap::new();
        for (name, spec) in file.global.options {
            let place = Place::GlobalOption(name.clone());
            identifier(place.clone(), &name)?;
            let option = ShellOption::read(spec, &place, &effects, true)?;
            claim_flags(&mut global_flags, &option, &place)?;
            global_options.insert(name, option);
        }
        let mut actions = BTreeMap::new();
        let mut spellings: BTreeMap<Vec<String>, String> = BTreeMap::new();
        for (name, spec) in file.shell {
            let action = ShellAction::read(&name, spec, &file.program, &effects)?;
            for alias in &action.aliases {
                if let Some(other) = spellings.insert(alias.clone(), name.clone()) {
                    return Err(PackRefusal::SpellingTaken {
                        place: Place::ActionAliases(name),
                        spelling: alias.join(" "),
                        other: Box::new(Place::Action(other)),
                    });
                }
            }
            actions.insert(ActionName(name), action);
        }
        let grammar = ShellGrammar::compile(&file.program, &global_options, &actions)?;
        Ok(Self {
            name: file.pack,
            version,
            program: file.program,
            effects,
            global_options,
            actions,
            grammar,
        })
    }

    /// The shell grammar compiled from the usage lines of this pack.
    pub(crate) fn grammar(&self) -> &ShellGrammar {
        &self.grammar
    }
}

impl ShellAction {
    fn read(
        name: &str,
        spec: ShellActionSpec,
        program: &str,
        effects: &BTreeMap<EffectName, String>,
    ) -> Result<Self, PackRefusal> {
        let place = Place::Action(name.to_string());
        identifier(place.clone(), name)?;
        if name == UNMODELED_ACTION {
            return Err(PackRefusal::ReservedAction { place });
        }
        let first = spec.usage.split_whitespace().next().unwrap_or_default();
        if first != program {
            return Err(PackRefusal::UsageDisagrees {
                place,
                first: first.to_string(),
                program: program.to_string(),
            });
        }
        let mut aliases = Vec::new();
        for alias in spec.aliases {
            let words: Vec<String> = alias.split_whitespace().map(str::to_string).collect();
            if words.is_empty() || !words.iter().all(|word| command_word(word)) {
                return Err(PackRefusal::BadAlias {
                    place: Place::ActionAliases(name.to_string()),
                    alias,
                });
            }
            aliases.push(words);
        }
        let adds = declared(&Place::ActionAdds(name.to_string()), spec.adds, effects)?;
        let mut options = BTreeMap::new();
        let mut flags = BTreeMap::new();
        for (option, option_spec) in spec.options {
            let place = Place::ActionOption {
                action: name.to_string(),
                option: option.clone(),
            };
            identifier(place.clone(), &option)?;
            let shell_option = ShellOption::read(option_spec, &place, effects, false)?;
            claim_flags(&mut flags, &shell_option, &place)?;
            options.insert(option, shell_option);
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
            aliases,
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
        effects: &BTreeMap<EffectName, String>,
        global: bool,
    ) -> Result<Self, PackRefusal> {
        let refuse = |fault| {
            Err(PackRefusal::BadOption {
                place: place.clone(),
                fault,
            })
        };
        if spec.flag.is_empty() {
            return refuse(OptionFault::NoFlag);
        }
        if let Some(flag) = spec.flag.iter().find(|flag| !readable_flag(flag)) {
            return refuse(OptionFault::MalformedFlag(flag.clone()));
        }
        let value = match spec.value {
            ValueSpec::None => OptionValue::None,
            ValueSpec::Required => OptionValue::Required,
            ValueSpec::Optional => OptionValue::Optional,
            ValueSpec::Many => OptionValue::Many,
        };
        if value == OptionValue::None && (!spec.like.is_empty() || !spec.when.is_empty()) {
            return refuse(OptionFault::PatternWithoutValue);
        }
        if value == OptionValue::None && spec.repeated {
            return refuse(OptionFault::RepeatedWithoutValue);
        }
        if spec.anywhere && !global {
            return refuse(OptionFault::AnywhereOnAction);
        }
        Ok(Self {
            flags: spec.flag,
            value,
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
        effects: &BTreeMap<EffectName, String>,
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
        effects: &BTreeMap<EffectName, String>,
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

/// Whether `word` is a command word: lowercase ASCII letters, digits, and `-`, not first a `-`.
pub(super) fn command_word(word: &str) -> bool {
    let mut characters = word.chars();
    characters
        .next()
        .is_some_and(|first| first.is_ascii_lowercase() || first.is_ascii_digit())
        && characters.all(|character| {
            character.is_ascii_lowercase() || character.is_ascii_digit() || character == '-'
        })
}

/// Whether a command line can give `flag`: `--` and a name with no `=`, or `-` and one character.
fn readable_flag(flag: &str) -> bool {
    if let Some(long) = flag.strip_prefix("--") {
        !long.is_empty() && !long.contains('=')
    } else if let Some(short) = flag.strip_prefix('-') {
        let mut characters = short.chars();
        matches!((characters.next(), characters.next()), (Some(_), None))
    } else {
        false
    }
}

fn claim_flags(
    claimed: &mut BTreeMap<String, Place>,
    option: &ShellOption,
    place: &Place,
) -> Result<(), PackRefusal> {
    for flag in &option.flags {
        if let Some(other) = claimed.insert(flag.clone(), place.clone()) {
            return Err(PackRefusal::FlagTaken {
                place: place.clone(),
                flag: flag.clone(),
                other: Box::new(other),
            });
        }
    }
    Ok(())
}

/// Whether `name` is an identifier that a Cedar name carries unchanged.
pub(super) fn is_identifier(name: &str) -> bool {
    !name.is_empty() && cedar_identifier(name) == name
}

fn identifier(place: Place, name: &str) -> Result<(), PackRefusal> {
    if is_identifier(name) {
        Ok(())
    } else {
        Err(PackRefusal::NotIdentifier {
            place,
            name: name.to_string(),
        })
    }
}

/// The declared effect that each of `names` refers to.
fn declared(
    place: &Place,
    names: Vec<String>,
    effects: &BTreeMap<EffectName, String>,
) -> Result<Vec<EffectName>, PackRefusal> {
    names
        .into_iter()
        .map(|name| match effects.get_key_value(name.as_str()) {
            Some((effect, _)) => Ok(effect.clone()),
            None => Err(PackRefusal::UndeclaredEffect {
                place: place.clone(),
                effect: name,
            }),
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn strings(values: &[&str]) -> Vec<String> {
        values.iter().map(|value| value.to_string()).collect()
    }

    fn effects(values: &[&str]) -> Vec<EffectName> {
        values
            .iter()
            .map(|value| EffectName(value.to_string()))
            .collect()
    }

    fn changes(like: &[&str], adds: &[&str], removes: &[&str]) -> EffectChanges {
        EffectChanges {
            like: strings(like),
            adds: effects(adds),
            removes: effects(removes),
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
usage = "git [global options] push [options] [<refspec>...]"
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
                adds: effects(&["force_push"]),
                removes: effects(&["network"]),
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
        let global_options = BTreeMap::from([
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
        ]);
        let actions = BTreeMap::from([(
            ActionName("push".to_string()),
            ShellAction {
                usage: "git [global options] push [options] [<refspec>...]".to_string(),
                aliases: vec![strings(&["send"])],
                adds: effects(&["network"]),
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
        )]);
        let grammar = ShellGrammar::compile("git", &global_options, &actions)
            .expect("the expected pack compiles");
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
                .map(|(name, description)| (EffectName(name.to_string()), description.to_string())),
            ),
            global_options,
            actions,
            grammar,
        };

        assert_eq!(Pack::parse(text).expect("the pack loads"), expected);
    }
}

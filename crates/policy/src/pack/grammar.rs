//! The shell grammar that compiling a pack's usage lines builds.

use std::collections::{BTreeMap, BTreeSet};

use super::model::{ActionName, EffectChanges, EffectName, OptionValue, ShellAction, ShellOption};
use super::usage::{Separator, Usage};
use super::{PackRefusal, Place};

/// What the shell grammar made of one command line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Parsed {
    Action {
        action: ActionName,
        fields: BTreeMap<String, FieldValue>,
        effects: BTreeSet<EffectName>,
    },
    Unmodeled,
}

/// The value of one field that a command line gives its action.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum FieldValue {
    Bool(bool),
    String(String),
    Set(Vec<String>),
}

/// The `context.input` attributes that the schema gives every action of a pack.
pub(crate) const BASE_FIELDS: [&str; 6] = [
    "program",
    "program_path",
    "cwd",
    "args",
    "effects",
    "credential_reads",
];

/// Every shell action of one pack, compiled from its usage lines.
#[cfg_attr(test, derive(PartialEq))]
#[derive(Debug)]
pub(crate) struct ShellGrammar {
    pub(super) globals: OptionTable,
    pub(super) toolchain: bool,
    pub(super) actions: Vec<ActionGrammar>,
}

/// The grammar of one shell action.
#[cfg_attr(test, derive(PartialEq))]
#[derive(Debug)]
pub(super) struct ActionGrammar {
    pub(super) name: ActionName,
    pub(super) spellings: Vec<Vec<String>>,
    pub(super) globals: bool,
    pub(super) toolchain: Option<String>,
    pub(super) adds: Vec<EffectName>,
    pub(super) between: OptionTable,
    pub(super) after: OptionTable,
    pub(super) operands: Vec<OperandSlot>,
    pub(super) separator: Separator,
    pub(super) fields: Vec<Field>,
}

/// The options that one position of a command line accepts, by flag.
#[cfg_attr(test, derive(PartialEq))]
#[derive(Debug, Clone, Default)]
pub(super) struct OptionTable {
    pub(super) flags: BTreeMap<String, OptionSlot>,
}

/// One option as a command line reads it.
#[cfg_attr(test, derive(PartialEq))]
#[derive(Debug, Clone)]
pub(super) struct OptionSlot {
    pub(super) field: String,
    pub(super) value: OptionValue,
    pub(super) repeated: bool,
}

/// One operand position of a usage line.
#[cfg_attr(test, derive(PartialEq))]
#[derive(Debug)]
pub(super) struct OperandSlot {
    pub(super) required: bool,
    pub(super) variadic: bool,
    pub(super) rest: bool,
}

/// One field of an action, and where its value comes from.
#[cfg_attr(test, derive(PartialEq))]
#[derive(Debug)]
pub(super) struct Field {
    pub(super) name: String,
    pub(super) kind: FieldKind,
    pub(super) source: FieldSource,
}

/// The type of one field value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum FieldKind {
    Bool,
    String,
    Set,
}

/// Where the value of a field comes from.
#[cfg_attr(test, derive(PartialEq))]
#[derive(Debug)]
pub(super) enum FieldSource {
    Option(EffectChanges),
    Operand(usize, EffectChanges),
    Toolchain,
}

impl ShellGrammar {
    /// Compile the usage line of each shell action of a pack for `program`.
    pub(super) fn compile(
        program: &str,
        global_options: &BTreeMap<String, ShellOption>,
        actions: &BTreeMap<ActionName, ShellAction>,
    ) -> Result<Self, PackRefusal> {
        let mut spellings: BTreeMap<Vec<String>, String> = BTreeMap::new();
        for (name, action) in actions {
            for alias in &action.aliases {
                spellings.insert(alias.clone(), name.as_str().to_string());
            }
        }
        let anywhere = OptionTable::of(global_options, |option| option.anywhere);
        let mut compiled = Vec::new();
        for (name, action) in actions {
            compiled.push(ActionGrammar::compile(
                name,
                action,
                program,
                global_options,
                &anywhere,
                &mut spellings,
            )?);
        }
        Ok(Self {
            globals: OptionTable::of(global_options, |_| true),
            toolchain: compiled.iter().any(|action| action.toolchain.is_some()),
            actions: compiled,
        })
    }

    /// The name of each action, and the name and type of each of its fields.
    pub(crate) fn action_fields(
        &self,
    ) -> impl Iterator<Item = (&ActionName, Vec<(&str, FieldKind)>)> {
        self.actions.iter().map(|action| {
            (
                &action.name,
                action
                    .fields
                    .iter()
                    .map(|field| (field.name.as_str(), field.kind))
                    .collect(),
            )
        })
    }
}

impl ActionGrammar {
    fn compile(
        name: &ActionName,
        action: &ShellAction,
        program: &str,
        global_options: &BTreeMap<String, ShellOption>,
        anywhere: &OptionTable,
        spellings: &mut BTreeMap<Vec<String>, String>,
    ) -> Result<Self, PackRefusal> {
        let place = Place::Action(name.as_str().to_string());
        let usage = Usage::read(&action.usage, program).map_err(|fault| PackRefusal::BadUsage {
            place: place.clone(),
            fault,
        })?;
        if let Some(other) = spellings.insert(usage.words.clone(), name.as_str().to_string()) {
            return Err(PackRefusal::SpellingTaken {
                place,
                spelling: usage.words.join(" "),
                other: Box::new(Place::Action(other)),
            });
        }
        if !action.options.is_empty() && !usage.options {
            return Err(PackRefusal::OptionsNotInUsage { place });
        }
        if usage.globals {
            for (option, shell_option) in &action.options {
                if let Some((flag, global)) = shell_option
                    .flags
                    .iter()
                    .find_map(|flag| anywhere.flags.get(flag).map(|slot| (flag, slot)))
                {
                    return Err(PackRefusal::FlagTaken {
                        place: Place::ActionOption {
                            action: name.as_str().to_string(),
                            option: option.clone(),
                        },
                        flag: flag.clone(),
                        other: Box::new(Place::GlobalOption(global.field.clone())),
                    });
                }
            }
        }
        let operand_place = |operand: &str| Place::Operand {
            action: name.as_str().to_string(),
            operand: operand.to_string(),
        };
        if let Some(operand) = action
            .operands
            .keys()
            .find(|operand| !usage.operands.iter().any(|slot| &slot.name == *operand))
        {
            return Err(PackRefusal::OperandNotInUsage {
                place: operand_place(operand),
            });
        }

        let mut fields = Vec::new();
        if usage.globals {
            fields.extend(global_options.iter().map(option_field));
        }
        fields.extend(action.options.iter().map(option_field));
        let mut operands = Vec::new();
        for (index, placeholder) in usage.operands.iter().enumerate() {
            let declared = action.operands.get(&placeholder.name);
            let rest = declared.is_some_and(|operand| operand.rest);
            let alone = usage.operands.len() == 1 && placeholder.variadic;
            if rest && (!alone || matches!(usage.separator, Separator::Required(_))) {
                return Err(PackRefusal::BadRest {
                    place: operand_place(&placeholder.name),
                });
            }
            let changes = declared.map(|operand| operand.effects.clone());
            fields.push(Field {
                name: placeholder.name.clone(),
                kind: if placeholder.variadic {
                    FieldKind::Set
                } else {
                    FieldKind::String
                },
                source: FieldSource::Operand(index, changes.unwrap_or_default()),
            });
            operands.push(OperandSlot {
                required: placeholder.required,
                variadic: placeholder.variadic,
                rest,
            });
        }
        if let Some(toolchain) = &usage.toolchain {
            fields.push(Field {
                name: toolchain.clone(),
                kind: FieldKind::String,
                source: FieldSource::Toolchain,
            });
        }
        if let Some(field) = fields
            .iter()
            .find(|field| BASE_FIELDS.contains(&field.name.as_str()))
        {
            return Err(PackRefusal::ReservedField {
                place,
                field: field.name.clone(),
            });
        }
        if let Some(field) = fields.iter().find(|field| field.name.starts_with("__")) {
            return Err(PackRefusal::CedarReservedField {
                place,
                field: field.name.clone(),
            });
        }
        let mut names = BTreeSet::new();
        if let Some(field) = fields.iter().find(|field| !names.insert(&field.name)) {
            return Err(PackRefusal::FieldTaken {
                place,
                field: field.name.clone(),
            });
        }

        let mut after = OptionTable::of(&action.options, |_| true);
        let mut between = OptionTable::default();
        if usage.globals {
            after.flags.extend(anywhere.flags.clone());
            between = anywhere.clone();
        }
        let mut action_spellings = vec![usage.words];
        action_spellings.extend(action.aliases.iter().cloned());
        Ok(Self {
            name: name.clone(),
            spellings: action_spellings,
            globals: usage.globals,
            toolchain: usage.toolchain,
            adds: action.adds.clone(),
            between,
            after,
            operands,
            separator: usage.separator,
            fields,
        })
    }
}

impl OptionTable {
    fn of(options: &BTreeMap<String, ShellOption>, keep: impl Fn(&ShellOption) -> bool) -> Self {
        let flags = options
            .iter()
            .filter(|(_, option)| keep(option))
            .flat_map(|(name, option)| {
                option.flags.iter().map(|flag| {
                    (
                        flag.clone(),
                        OptionSlot {
                            field: name.clone(),
                            value: option.value,
                            repeated: option.repeated,
                        },
                    )
                })
            })
            .collect();
        Self { flags }
    }
}

fn option_field((name, option): (&String, &ShellOption)) -> Field {
    Field {
        name: name.clone(),
        kind: match option.value {
            OptionValue::None => FieldKind::Bool,
            OptionValue::Many => FieldKind::Set,
            _ if option.repeated => FieldKind::Set,
            _ => FieldKind::String,
        },
        source: FieldSource::Option(option.effects.clone()),
    }
}

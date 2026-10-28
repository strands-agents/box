//! One command line, read against a shell grammar.

use std::collections::{BTreeMap, BTreeSet};

use super::grammar::{
    ActionGrammar, FieldKind, FieldSource, FieldValue, OptionTable, Parsed, ShellGrammar,
};
use super::model::{EffectChanges, EffectName, OptionValue};
use super::usage::Separator;

impl ShellGrammar {
    /// Read `argv`, the arguments after the program, as one action of the pack.
    pub(crate) fn parse(&self, argv: &[String]) -> Parsed {
        self.read(argv).unwrap_or(Parsed::Unmodeled)
    }

    fn read(&self, argv: &[String]) -> Option<Parsed> {
        let mut index = 0;
        let mut toolchain = None;
        if self.toolchain
            && let Some(selector) = argv.first().and_then(|first| first.strip_prefix('+'))
            && !selector.is_empty()
        {
            toolchain = Some(selector.to_string());
            index = 1;
        }
        let mut seen = Occurrences::default();
        let mut globals_given = false;
        while is_option_word(argv.get(index)?) {
            index = read_option(&self.globals, argv, index, &mut seen)?;
            globals_given = true;
        }
        let (action, index, mut seen) = self.match_words(argv, index, seen)?;
        if (globals_given && !action.globals) || (toolchain.is_some() && action.toolchain.is_none())
        {
            return None;
        }
        let operands = action.read_after_words(argv, index, &mut seen)?;
        Some(action.outcome(&seen, &operands, toolchain))
    }

    /// The action with the longest spelling that starts at `start`, and the position after it.
    fn match_words(
        &self,
        argv: &[String],
        start: usize,
        seen: Occurrences,
    ) -> Option<(&ActionGrammar, usize, Occurrences)> {
        let mut best: Option<(&ActionGrammar, usize, usize, Occurrences)> = None;
        for action in &self.actions {
            for spelling in &action.spellings {
                if best
                    .as_ref()
                    .is_some_and(|(_, _, length, _)| *length >= spelling.len())
                {
                    continue;
                }
                let mut state = seen.clone();
                if let Some(index) = spelled(action, spelling, argv, start, &mut state) {
                    best = Some((action, index, spelling.len(), state));
                }
            }
        }
        best.map(|(action, index, _, state)| (action, index, state))
    }
}

impl ActionGrammar {
    /// Read the options and operands from `argv[index..]`, and give each operand slot its words.
    fn read_after_words(
        &self,
        argv: &[String],
        mut index: usize,
        seen: &mut Occurrences,
    ) -> Option<Vec<Vec<String>>> {
        let rest = self.operands.first().is_some_and(|operand| operand.rest);
        let mut before = Vec::new();
        let mut after = Vec::new();
        let mut separated = false;
        let mut verbatim = false;
        while let Some(word) = argv.get(index) {
            if verbatim {
                before.push(word.clone());
                index += 1;
            } else if separated {
                after.push(word.clone());
                index += 1;
            } else if word == "--" {
                if rest {
                    verbatim = true;
                } else {
                    separated = true;
                }
                index += 1;
            } else if is_option_word(word) {
                index = read_option(&self.after, argv, index, seen)?;
            } else {
                verbatim = rest;
                before.push(word.clone());
                index += 1;
            }
        }
        fill(self, before, after, separated)
    }

    /// The action, its field values, and its effects, where a removed effect is never present.
    fn outcome(
        &self,
        seen: &Occurrences,
        operands: &[Vec<String>],
        toolchain: Option<String>,
    ) -> Parsed {
        let mut fields = BTreeMap::new();
        let mut adds: BTreeSet<EffectName> = self.adds.iter().cloned().collect();
        let mut removes = BTreeSet::new();
        for field in &self.fields {
            let (values, changes) = match &field.source {
                FieldSource::Option(changes) => (seen.values.get(&field.name).cloned(), changes),
                FieldSource::Operand(at, changes) => (
                    Some(operands[*at].clone()).filter(|words| !words.is_empty()),
                    changes,
                ),
                FieldSource::Toolchain => {
                    if let Some(selector) = &toolchain {
                        fields.insert(field.name.clone(), FieldValue::String(selector.clone()));
                    }
                    continue;
                }
            };
            let value = match field.kind {
                FieldKind::Bool => Some(FieldValue::Bool(values.is_some())),
                FieldKind::Set => {
                    let mut set = values.clone().unwrap_or_default();
                    set.sort();
                    set.dedup();
                    Some(FieldValue::Set(set))
                }
                FieldKind::String => values
                    .as_ref()
                    .and_then(|values| values.first().cloned())
                    .map(FieldValue::String),
            };
            if let Some(value) = value {
                fields.insert(field.name.clone(), value);
            }
            if let Some(values) = &values {
                apply(changes, values, &mut adds, &mut removes);
            }
        }
        Parsed::Action {
            action: self.name.clone(),
            fields,
            effects: adds.difference(&removes).cloned().collect(),
        }
    }
}

/// The position after `spelling` at `argv[start..]`, with `anywhere` options between its words.
fn spelled(
    action: &ActionGrammar,
    spelling: &[String],
    argv: &[String],
    start: usize,
    seen: &mut Occurrences,
) -> Option<usize> {
    let mut index = start;
    for (position, word) in spelling.iter().enumerate() {
        if position > 0 {
            while argv.get(index).is_some_and(|next| is_option_word(next)) {
                index = read_option(&action.between, argv, index, seen)?;
            }
        }
        if argv.get(index) != Some(word) {
            return None;
        }
        index += 1;
    }
    Some(index)
}

fn is_option_word(word: &str) -> bool {
    word.starts_with('-') && word.len() > 1 && word != "--"
}

/// The values that each option field took on one command line.
#[derive(Debug, Clone, Default)]
struct Occurrences {
    values: BTreeMap<String, Vec<String>>,
}

impl Occurrences {
    fn record(
        &mut self,
        field: &str,
        value: OptionValue,
        repeated: bool,
        values: Vec<String>,
    ) -> Option<()> {
        match self.values.get_mut(field) {
            Some(_) if value != OptionValue::None && !repeated => return None,
            Some(existing) => existing.extend(values),
            None => {
                self.values.insert(field.to_string(), values);
            }
        }
        Some(())
    }
}

/// The words a `many` option takes from `argv[from..]`.
fn many(argv: &[String], from: usize) -> Option<(Vec<String>, usize)> {
    let values: Vec<String> = argv
        .iter()
        .skip(from)
        .take_while(|word| !is_option_word(word) && *word != "--")
        .cloned()
        .collect();
    let next = from + values.len();
    (!values.is_empty()).then_some((values, next))
}

/// Read the option word at `argv[index]`, and return the position after it and its value.
fn read_option(
    table: &OptionTable,
    argv: &[String],
    index: usize,
    seen: &mut Occurrences,
) -> Option<usize> {
    let word = &argv[index];
    if let Some(body) = word.strip_prefix("--") {
        let (name, attached) = match body.split_once('=') {
            Some((name, value)) => (name, Some(value)),
            None => (body, None),
        };
        let option = table.flags.get(&format!("--{name}"))?;
        let (values, next) = match (option.value, attached) {
            (OptionValue::None, Some(_)) => return None,
            (OptionValue::None, None) => (Vec::new(), index + 1),
            (_, Some(value)) => (vec![value.to_string()], index + 1),
            (OptionValue::Required, None) => (vec![argv.get(index + 1)?.clone()], index + 2),
            (OptionValue::Optional, None) => (vec![String::new()], index + 1),
            (OptionValue::Many, None) => many(argv, index + 1)?,
        };
        seen.record(&option.field, option.value, option.repeated, values)?;
        return Some(next);
    }
    let cluster: Vec<char> = word.chars().skip(1).collect();
    for (position, character) in cluster.iter().enumerate() {
        let option = table.flags.get(&format!("-{character}"))?;
        if option.value == OptionValue::None {
            seen.record(&option.field, option.value, option.repeated, Vec::new())?;
            continue;
        }
        let attached: String = cluster[position + 1..].iter().collect();
        if attached.starts_with('=') {
            return None;
        }
        let (values, next) = if !attached.is_empty() {
            (vec![attached], index + 1)
        } else {
            match option.value {
                OptionValue::Optional => (vec![String::new()], index + 1),
                OptionValue::Many => many(argv, index + 1)?,
                _ => (vec![argv.get(index + 1)?.clone()], index + 2),
            }
        };
        seen.record(&option.field, option.value, option.repeated, values)?;
        return Some(next);
    }
    Some(index + 1)
}

/// Give each operand slot of `action` its words.
fn fill(
    action: &ActionGrammar,
    before: Vec<String>,
    after: Vec<String>,
    separated: bool,
) -> Option<Vec<Vec<String>>> {
    let slots = &action.operands;
    let groups = match action.separator {
        Separator::None => vec![(0..slots.len(), [before, after].concat())],
        Separator::Optional(_) if !separated => vec![(0..slots.len(), before)],
        Separator::Optional(at) | Separator::Required(at) => {
            vec![(0..at, before), (at..slots.len(), after)]
        }
    };
    let mut filled = vec![Vec::new(); slots.len()];
    for (range, words) in groups {
        let group = &slots[range.clone()];
        let minimum = group.iter().filter(|slot| slot.required).count();
        let mut extra = words.len().checked_sub(minimum)?;
        let mut words = words.into_iter();
        for (offset, slot) in group.iter().enumerate() {
            let take = usize::from(slot.required)
                + if slot.variadic {
                    std::mem::take(&mut extra)
                } else if !slot.required && extra > 0 {
                    extra -= 1;
                    1
                } else {
                    0
                };
            filled[range.start + offset] = words.by_ref().take(take).collect();
        }
        if words.next().is_some() {
            return None;
        }
    }
    Some(filled)
}

fn apply(
    changes: &EffectChanges,
    values: &[String],
    adds: &mut BTreeSet<EffectName>,
    removes: &mut BTreeSet<EffectName>,
) {
    let matches = |patterns: &[String]| {
        values
            .iter()
            .any(|value| patterns.iter().any(|pattern| like(pattern, value)))
    };
    if changes.like.is_empty() || matches(&changes.like) {
        adds.extend(changes.adds.iter().cloned());
        removes.extend(changes.removes.iter().cloned());
    }
    for when in &changes.when {
        if matches(&when.like) {
            adds.extend(when.adds.iter().cloned());
            removes.extend(when.removes.iter().cloned());
        }
    }
}

/// Whether `value` is like `pattern`: `*` matches any run, `\*` a `*`, and each other character itself.
fn like(pattern: &str, value: &str) -> bool {
    let mut elements = Vec::new();
    let mut characters = pattern.chars().peekable();
    while let Some(character) = characters.next() {
        match character {
            '\\' if characters.peek() == Some(&'*') => {
                characters.next();
                elements.push(Some('*'));
            }
            '*' => elements.push(None),
            other => elements.push(Some(other)),
        }
    }
    let value: Vec<char> = value.chars().collect();
    let mut reachable = vec![false; value.len() + 1];
    reachable[0] = true;
    for element in elements {
        let mut next = vec![false; value.len() + 1];
        match element {
            None => {
                let mut on = false;
                for (index, slot) in next.iter_mut().enumerate() {
                    on |= reachable[index];
                    *slot = on;
                }
            }
            Some(expected) => {
                for index in 0..value.len() {
                    if reachable[index] && value[index] == expected {
                        next[index + 1] = true;
                    }
                }
            }
        }
        reachable = next;
    }
    reachable[value.len()]
}

#[cfg(test)]
mod tests {
    use super::like;

    #[test]
    fn like_reads_a_star_as_any_run_and_an_escaped_star_as_itself() {
        assert!(like("+*", "+main"));
        assert!(like("*AllUsers*", "uri=http://acs/groups/global/AllUsers"));
        assert!(like("a*b*c", "abxbc"));
        assert!(!like("+*", "main"));
        assert!(like("\\*", "*"));
        assert!(!like("\\*", "x"));
        assert!(like("a\\b", "a\\b"));
        assert!(like("\\\\", "\\\\"));
        assert!(!like("\\\\", "\\"));
        assert!(like("", ""));
        assert!(!like("", "x"));
    }
}

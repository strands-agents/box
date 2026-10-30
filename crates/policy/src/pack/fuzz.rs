//! Fuzz tests: argvs built from each valid pack's vocabulary, held to the parser's invariants.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use std::time::{Duration, Instant};

use super::Pack;
use super::corpus::{Corpus, PACKS, corpus_files, pack_of};
use super::grammar::{FieldKind, FieldSource, FieldValue, Parsed};
use super::model::{EffectChanges, OptionValue};

const LONGEST_ARGV: usize = 48;
const SLOWEST_PARSE: Duration = Duration::from_secs(1);
const UNDECLARED_LONG: &str = "--zz-undeclared";
const SHORT_CANDIDATES: &[char] = &['Y', 'y', 'Q', 'K', 'k', '%', '~'];
const SAMPLE_VALUES: &[&str] = &[
    "",
    "-",
    "--",
    "=",
    "+",
    ":",
    "*",
    "x",
    "origin",
    "main",
    "+main",
    ":main",
    "a=b",
    "--x=y",
    "s3://bucket/key",
    "https://example.com",
    "@file",
    "\\*",
    "é",
    "\u{0}",
];

/// One valid pack, and the words a generated argv for it draws from.
struct Fixture {
    origin: PathBuf,
    pack: Pack,
    words: Vec<String>,
    flags: Vec<String>,
    values: Vec<String>,
    switches: Vec<char>,
    short: char,
    undeclared: Vec<String>,
    seeds: Vec<Vec<String>>,
}

fn fixtures() -> &'static [Fixture] {
    static FIXTURES: OnceLock<Vec<Fixture>> = OnceLock::new();
    FIXTURES.get_or_init(|| {
        let mut paths: Vec<PathBuf> = ["valid", "corpus"]
            .iter()
            .flat_map(|directory| {
                let directory = Path::new(PACKS).join(directory);
                std::fs::read_dir(&directory)
                    .unwrap_or_else(|error| panic!("{}: {error}", directory.display()))
                    .map(|entry| entry.expect("a pack entry").path())
                    .collect::<Vec<_>>()
            })
            .filter(|path| path.to_string_lossy().ends_with(".pack.toml"))
            .collect();
        paths.sort();
        let seeds = corpus_seeds();
        let fixtures: Vec<Fixture> = paths
            .into_iter()
            .map(|origin| {
                let pack = Pack::load(&origin).expect("a valid pack loads");
                let seeds = seeds
                    .iter()
                    .filter(|argv| argv.first() == Some(&pack.program))
                    .map(|argv| argv[1..].to_vec())
                    .collect();
                Fixture::new(origin, pack, seeds)
            })
            .collect();
        assert!(!fixtures.is_empty(), "no valid pack to fuzz");
        fixtures
    })
}

fn corpus_seeds() -> Vec<Vec<String>> {
    let mut seeds = Vec::new();
    for path in corpus_files() {
        let file = path.file_name().unwrap_or_default().to_string_lossy();
        let Some(stem) = file.strip_suffix(".corpus.toml") else {
            continue;
        };
        let pack = Pack::load(&pack_of(&path, stem)).expect("the corpus pack loads");
        let text = std::fs::read_to_string(&path).expect("the corpus file reads");
        let corpus: Corpus = toml::from_str(&text).expect("the corpus file parses");
        seeds.extend(
            corpus
                .case
                .into_iter()
                .map(|case| case.argv)
                .filter(|argv| argv.first() == Some(&pack.program)),
        );
    }
    assert!(!seeds.is_empty(), "the corpus holds no argv");
    seeds
}

impl Fixture {
    fn new(origin: PathBuf, pack: Pack, seeds: Vec<Vec<String>>) -> Self {
        let grammar = pack.grammar();
        let mut words = BTreeSet::new();
        let mut flags = BTreeSet::new();
        let mut values: BTreeSet<String> = SAMPLE_VALUES
            .iter()
            .map(|value| value.to_string())
            .collect();
        let tables = std::iter::once(&grammar.globals).chain(
            grammar
                .actions
                .iter()
                .flat_map(|action| [&action.between, &action.after]),
        );
        let mut takes_value = BTreeSet::new();
        for table in tables {
            flags.extend(table.flags.keys().cloned());
            takes_value.extend(
                table
                    .flags
                    .iter()
                    .filter(|(_, slot)| slot.value != OptionValue::None)
                    .map(|(flag, _)| flag.clone()),
            );
        }
        let switches: Vec<char> = flags
            .iter()
            .filter(|flag| !takes_value.contains(*flag))
            .filter_map(|flag| short_letter(flag))
            .collect();
        for action in &grammar.actions {
            words.extend(action.spellings.iter().flatten().cloned());
            if let Some(toolchain) = &action.toolchain {
                values.insert(format!("+{toolchain}"));
            }
            for field in &action.fields {
                let changes = match &field.source {
                    FieldSource::Option(changes) | FieldSource::Operand(_, changes) => changes,
                    FieldSource::Toolchain => continue,
                };
                values.extend(like_samples(changes));
            }
        }
        let short = SHORT_CANDIDATES
            .iter()
            .find(|character| !flags.contains(&format!("-{character}")))
            .expect("a short flag the pack does not declare");
        assert!(!flags.contains(UNDECLARED_LONG));
        let mut undeclared = vec![
            UNDECLARED_LONG.to_string(),
            format!("{UNDECLARED_LONG}=x"),
            format!("-{short}"),
            format!("-{short}x"),
        ];
        undeclared.extend(
            switches
                .iter()
                .take(4)
                .map(|switch| format!("-{switch}{short}")),
        );
        if let [first, second, ..] = switches.as_slice() {
            undeclared.push(format!("-{first}{second}{short}"));
        }
        Self {
            origin,
            pack,
            words: words.into_iter().collect(),
            flags: flags.into_iter().collect(),
            values: values.into_iter().collect(),
            switches,
            short: *short,
            undeclared,
            seeds,
        }
    }
}

/// The letter of a one-letter short flag such as `-v`.
fn short_letter(flag: &str) -> Option<char> {
    let mut letters = flag.strip_prefix('-')?.chars();
    let letter = letters.next().filter(|letter| *letter != '-')?;
    letters.next().is_none().then_some(letter)
}

/// Values that match, and nearly match, each `like` pattern of `changes`.
fn like_samples(changes: &EffectChanges) -> Vec<String> {
    let fill = |pattern: &str, with: &str| {
        pattern
            .replace("\\*", "\u{1}")
            .replace('*', with)
            .replace('\u{1}', "*")
    };
    changes
        .like
        .iter()
        .chain(changes.when.iter().flat_map(|when| &when.like))
        .flat_map(|pattern| {
            let filled = fill(pattern, "v");
            [
                pattern.clone(),
                fill(pattern, ""),
                format!("{filled}x"),
                format!("x{filled}"),
                filled,
            ]
        })
        .collect()
}

/// The fuzz input, read one choice at a time; an exhausted input reads as zeros.
struct Choices<'a> {
    bytes: &'a [u8],
    at: usize,
}

impl Choices<'_> {
    fn exhausted(&self) -> bool {
        self.at >= self.bytes.len()
    }

    fn byte(&mut self) -> u8 {
        let byte = self.bytes.get(self.at).copied().unwrap_or_default();
        self.at += 1;
        byte
    }

    fn below(&mut self, count: usize) -> usize {
        if count == 0 {
            return 0;
        }
        let wide = (usize::from(self.byte()) << 8) | usize::from(self.byte());
        wide % count
    }

    fn of<'v, T>(&mut self, items: &'v [T]) -> Option<&'v T> {
        (!items.is_empty()).then(|| &items[self.below(items.len())])
    }

    fn arbitrary(&mut self) -> String {
        let length = self.below(12);
        (0..length)
            .map(|_| match self.byte() % 4 {
                0 => '-',
                1 => '=',
                _ => {
                    let low = u32::from(self.byte());
                    let high = u32::from(self.byte() % 3);
                    char::from_u32((high << 8) | low).unwrap_or('?')
                }
            })
            .collect()
    }
}

/// Build one argv for `fixture` from `choices`: a corpus seed or nothing, then edits.
fn argv(fixture: &Fixture, choices: &mut Choices) -> Vec<String> {
    let mut argv = match choices.byte() % 3 {
        0 => Vec::new(),
        _ => choices.of(&fixture.seeds).cloned().unwrap_or_default(),
    };
    while !choices.exhausted() && argv.len() < LONGEST_ARGV {
        let operation = choices.byte();
        let word = match operation % 16 {
            0..=2 => choices.of(&fixture.words).cloned(),
            3..=5 => choices.of(&fixture.flags).cloned(),
            6 => long_with_value(fixture, choices),
            7 => short_cluster(fixture, choices),
            8 => Some("--".to_string()),
            9 | 10 => choices.of(&fixture.values).cloned(),
            11 => Some(choices.arbitrary()),
            12 => choices.of(&fixture.undeclared).cloned(),
            _ => {
                edit(&mut argv, choices);
                None
            }
        };
        if let Some(word) = word {
            let at = if operation & 0x80 == 0 {
                argv.len()
            } else {
                choices.below(argv.len() + 1)
            };
            argv.insert(at, word);
        }
    }
    argv
}

fn long_with_value(fixture: &Fixture, choices: &mut Choices) -> Option<String> {
    let longs: Vec<&String> = fixture
        .flags
        .iter()
        .filter(|flag| flag.starts_with("--"))
        .collect();
    let flag = choices.of(&longs)?;
    let value = choices.of(&fixture.values)?;
    Some(format!("{flag}={value}"))
}

fn short_cluster(fixture: &Fixture, choices: &mut Choices) -> Option<String> {
    let shorts: Vec<&String> = fixture
        .flags
        .iter()
        .filter(|flag| !flag.starts_with("--"))
        .collect();
    let mut cluster = "-".to_string();
    for _ in 0..=choices.below(3) {
        cluster.push_str(&choices.of(&shorts)?[1..]);
    }
    match choices.byte() % 8 {
        0 | 1 => {
            if let Some(value) = choices.of(&fixture.values) {
                cluster.push_str(value);
            }
        }
        2 | 3 => {
            let switch = choices.of(&fixture.switches)?;
            cluster.push(*switch);
            cluster.push(fixture.short);
        }
        _ => {}
    }
    Some(cluster)
}

/// Delete, repeat, swap, or reshape a word of `argv`.
fn edit(argv: &mut Vec<String>, choices: &mut Choices) {
    if argv.is_empty() {
        return;
    }
    let at = choices.below(argv.len());
    match choices.byte() % 6 {
        0 => {
            argv.remove(at);
        }
        1 => argv.insert(at, argv[at].clone()),
        2 => {
            let other = choices.below(argv.len());
            argv.swap(at, other);
        }
        3 => {
            let keep = choices.below(argv[at].chars().count() + 1);
            argv[at] = argv[at].chars().take(keep).collect();
        }
        4 => argv[at].push('='),
        _ => argv[at].insert(0, '-'),
    }
}

/// Assert each invariant of the parser for `argv` against `fixture`.
fn check(fixture: &Fixture, argv: &[String]) {
    let grammar = fixture.pack.grammar();
    let at = format!("{} {argv:?}", fixture.origin.display());
    let started = Instant::now();
    let parsed = grammar.parse(argv);
    let elapsed = started.elapsed();
    assert!(elapsed < SLOWEST_PARSE, "{at}: the parse took {elapsed:?}");
    assert_eq!(parsed, grammar.parse(argv), "{at}: a second parse differs");
    declared(fixture, &parsed, &at);
    for base in &fixture.undeclared {
        let flag = unique(base, argv);
        for position in 0..=argv.len() {
            let mut inserted = argv.to_vec();
            inserted.insert(position, flag.clone());
            let read = grammar.parse(&inserted);
            declared(fixture, &read, &at);
            assert!(
                read == Parsed::Unmodeled || held(&read, &flag),
                "{at}: {flag} at {position} is read as an option and gives {read:?}"
            );
        }
    }
    for (position, word) in argv.iter().enumerate() {
        for cluster in in_cluster(fixture, word) {
            if argv.iter().any(|other| other.contains(cluster.as_str())) {
                continue;
            }
            let mut changed = argv.to_vec();
            changed[position] = cluster.clone();
            let read = grammar.parse(&changed);
            declared(fixture, &read, &at);
            assert!(
                read == Parsed::Unmodeled || held(&read, &cluster),
                "{at}: {cluster} at {position} is read as options and gives {read:?}"
            );
        }
    }
}

/// `word` with the undeclared letter after each leading run of switches, when `word` is a cluster.
fn in_cluster(fixture: &Fixture, word: &str) -> Vec<String> {
    let Some(letters) = word
        .strip_prefix('-')
        .filter(|letters| !letters.starts_with('-'))
    else {
        return Vec::new();
    };
    let switches = letters
        .chars()
        .take_while(|letter| fixture.switches.contains(letter))
        .count();
    (1..=switches)
        .map(|count| {
            let (head, tail) = letters.split_at(
                letters
                    .char_indices()
                    .nth(count)
                    .map_or(letters.len(), |(index, _)| index),
            );
            format!("-{head}{}{tail}", fixture.short)
        })
        .collect()
}

/// Assert that `parsed` names only an action, fields, and effects that the pack declares.
fn declared(fixture: &Fixture, parsed: &Parsed, at: &str) {
    let Parsed::Action {
        action,
        fields,
        effects,
    } = parsed
    else {
        return;
    };
    assert!(
        fixture.pack.actions.contains_key(action),
        "{at}: undeclared action {action:?}"
    );
    let compiled = fixture
        .pack
        .grammar()
        .actions
        .iter()
        .find(|compiled| &compiled.name == action)
        .expect("each declared action has a grammar");
    for (name, value) in fields {
        let field = compiled
            .fields
            .iter()
            .find(|field| &field.name == name)
            .unwrap_or_else(|| panic!("{at}: {action:?} gives undeclared field {name:?}"));
        let kind = match value {
            FieldValue::Bool(_) => FieldKind::Bool,
            FieldValue::String(_) => FieldKind::String,
            FieldValue::Set(values) => {
                assert!(
                    values.windows(2).all(|pair| pair[0] < pair[1]),
                    "{at}: {name} is not a sorted set: {values:?}"
                );
                FieldKind::Set
            }
        };
        assert_eq!(kind, field.kind, "{at}: {name} holds {value:?}");
    }
    for effect in effects {
        assert!(
            fixture.pack.effects.contains_key(effect),
            "{at}: undeclared effect {effect:?}"
        );
    }
}

/// `base`, with a suffix so that no word of `argv` holds it.
fn unique(base: &str, argv: &[String]) -> String {
    let (name, value) = match base.split_once('=') {
        Some((name, value)) => (name, format!("={value}")),
        None => (base, String::new()),
    };
    (0..)
        .map(|suffix| match suffix {
            0 => base.to_string(),
            suffix => format!("{name}{suffix}{value}"),
        })
        .find(|flag| !argv.iter().any(|word| word.contains(flag.as_str())))
        .expect("a suffix that no word holds")
}

/// Whether a field value of `parsed` is `word`, so the parser read `word` as data.
fn held(parsed: &Parsed, word: &str) -> bool {
    let Parsed::Action { fields, .. } = parsed else {
        return false;
    };
    fields.values().any(|value| match value {
        FieldValue::Bool(_) => false,
        FieldValue::String(value) => value == word,
        FieldValue::Set(values) => values.iter().any(|value| value == word),
    })
}

fn run(bytes: &[u8]) {
    let fixtures = fixtures();
    let mut choices = Choices { bytes, at: 0 };
    let fixture = &fixtures[usize::from(choices.byte()) % fixtures.len()];
    let argv = argv(fixture, &mut choices);
    check(fixture, &argv);
}

#[test]
fn every_corpus_argv_holds_each_parser_invariant() {
    let mut count = 0;
    for fixture in fixtures() {
        for seed in &fixture.seeds {
            check(fixture, seed);
            count += 1;
        }
    }
    assert!(count > 0, "no corpus argv reached a pack");
}

#[test]
fn a_generated_argv_holds_each_parser_invariant() {
    bolero::check!()
        .with_iterations(20_000)
        .with_max_len(512)
        .for_each(run);
}

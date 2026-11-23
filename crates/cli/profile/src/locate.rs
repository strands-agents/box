//! Where a key is in a TOML file, and the known name a misspelled one is close to.

/// The line of the key at `at` in the TOML `text`, or of the nearest table above it that is there.
pub(crate) fn line_of(text: &str, at: &[String]) -> Option<usize> {
    found(text, at).map(|(line, _)| line)
}

/// The line of the key at `at` in the TOML `text`, only when every part of `at` is there.
pub(crate) fn exact_line_of(text: &str, at: &[String]) -> Option<usize> {
    found(text, at).and_then(|(line, whole)| whole.then_some(line))
}

/// The line that `line_of` names, and whether every part of `at` is there.
fn found(text: &str, at: &[String]) -> Option<(usize, bool)> {
    let document = toml_edit::Document::parse(text).ok()?;
    let mut item = document.as_item();
    let mut offset = None;
    let mut whole = true;
    for (index, part) in at.iter().enumerate() {
        let found = match item {
            toml_edit::Item::ArrayOfTables(rows) => part
                .parse()
                .ok()
                .and_then(|index| rows.get(index))
                .map(|row| (row.span(), None)),
            _ => item
                .as_table_like()
                .and_then(|table| table.get_key_value(part))
                .map(|(key, next)| (key.span().or_else(|| next.span()), Some(next))),
        };
        let Some((span, next)) = found else {
            whole = false;
            break;
        };
        offset = span.map(|span| span.start).or(offset);
        match next {
            Some(next) => item = next,
            None => {
                whole = index + 1 == at.len();
                break;
            }
        }
    }
    offset.map(|offset| (line_at(text, offset), whole))
}

/// The refusal of `key` in `owner`, with the known key it is close to, or else every known key.
pub(crate) fn unknown_key(owner: &str, key: &str, known: &[&str]) -> String {
    match closest(key, known.iter().copied()) {
        Some(near) => format!("{owner} holds the unknown key `{key}`; did you mean `{near}`?"),
        None => {
            let keys: Vec<String> = known.iter().map(|key| format!("`{key}`")).collect();
            format!(
                "{owner} holds the unknown key `{key}`; {owner} holds {}",
                keys.join(", ")
            )
        }
    }
}

/// The one name in `known` that `name` is a likely misspelling of.
pub fn closest<'a>(name: &str, known: impl IntoIterator<Item = &'a str>) -> Option<&'a str> {
    let limit = (name.chars().count() / 3).max(1);
    let mut near: Vec<(usize, &str)> = known
        .into_iter()
        .map(|candidate| (distance(name, candidate), candidate))
        .filter(|(far, _)| *far <= limit)
        .collect();
    near.sort();
    match near.as_slice() {
        [(best, candidate), rest @ ..] if rest.first().is_none_or(|(next, _)| next > best) => {
            Some(candidate)
        }
        _ => None,
    }
}

fn line_at(text: &str, offset: usize) -> usize {
    text[..offset.min(text.len())].matches('\n').count() + 1
}

/// The edit distance between `a` and `b`, where swapping two neighbors is one edit.
fn distance(a: &str, b: &str) -> usize {
    let a: Vec<char> = a.chars().collect();
    let b: Vec<char> = b.chars().collect();
    let mut rows = vec![vec![0; b.len() + 1]; a.len() + 1];
    for (i, row) in rows.iter_mut().enumerate() {
        row[0] = i;
    }
    for (j, cell) in rows[0].iter_mut().enumerate() {
        *cell = j;
    }
    for i in 1..=a.len() {
        for j in 1..=b.len() {
            let cost = usize::from(a[i - 1] != b[j - 1]);
            let mut best = (rows[i - 1][j] + 1)
                .min(rows[i][j - 1] + 1)
                .min(rows[i - 1][j - 1] + cost);
            if i > 1 && j > 1 && a[i - 1] == b[j - 2] && a[i - 2] == b[j - 1] {
                best = best.min(rows[i - 2][j - 2] + 1);
            }
            rows[i][j] = best;
        }
    }
    rows[a.len()][b.len()]
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(path: &[&str]) -> Vec<String> {
        path.iter().map(|part| (*part).to_string()).collect()
    }

    #[test]
    fn a_key_is_found_in_a_header_a_dotted_key_an_inline_table_and_a_row() {
        let text = "[agent]\ncommand = []\n[agent.filesystem]\nread = []\n\n[options]\n\
                    a.b = \"x\"\n[tool.git]\nenv = { X = \"1\" }\n[[storage.files]]\nsource = \"s\"\n\
                    [[storage.files]]\ntarget = \"t\"\n";
        for (path, line) in [
            (at(&["agent"]), 1),
            (at(&["agent", "filesystem"]), 3),
            (at(&["agent", "filesystem", "read"]), 4),
            (at(&["options", "a", "b"]), 7),
            (at(&["tool", "git", "env", "X"]), 9),
            (at(&["storage", "files", "1"]), 12),
            (at(&["agent", "missing"]), 1),
        ] {
            assert_eq!(line_of(text, &path), Some(line), "{path:?}");
        }
        assert_eq!(line_of(text, &at(&["missing"])), None);
        assert_eq!(line_of("not = = toml", &at(&["not"])), None);
    }

    #[test]
    fn a_close_name_is_suggested_and_a_far_or_tied_one_is_not() {
        let known = ["read", "write", "exec", "filesystem", "deny"];
        assert_eq!(closest("raed", known), Some("read"));
        assert_eq!(closest("exce", known), Some("exec"));
        assert_eq!(closest("filesytem", known), Some("filesystem"));
        assert_eq!(closest("zzzzzz", known), None);
        assert_eq!(closest("ab", ["ac", "ad"]), None);
    }

    #[test]
    fn an_exact_line_needs_every_part_of_the_key() {
        let text = "[options]\n\"a.b\" = \"x\"\nc.d = \"y\"\n";
        assert_eq!(exact_line_of(text, &at(&["options", "a.b"])), Some(2));
        assert_eq!(exact_line_of(text, &at(&["options", "a", "b"])), None);
        assert_eq!(exact_line_of(text, &at(&["options", "c", "d"])), Some(3));
        assert_eq!(line_of(text, &at(&["options", "a", "b"])), Some(1));
    }
}

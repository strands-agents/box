//! `box explain`: what a Box message code means and what to do about it, from the page built in.

use std::io::{self, Write};
use std::ops::Range;

use diagnostics::Code;
use serde::Serialize;

use crate::{Error, OutputFormat};

/// Box Core's page that explains each code, as this `box` was built with it.
const PAGE: &str = include_str!("../../../../docs/user/message-codes.md");

/// The page's file name, which its own `#anchor` links point at.
const PAGE_NAME: &str = "message-codes.md";

/// The column the text output wraps at, at most.
const WIDTH: usize = 100;

/// One code's explanation, as `--format json` prints it.
#[derive(Debug, Serialize)]
struct Explanation {
    code: &'static str,
    source: &'static str,
    severity: &'static str,
    meaning: &'static str,
    what_to_do: String,
    docs: String,
}

/// Writes what `code` means and what to do about it, or refuses a code this `box` does not know.
pub fn explain(code: &str, format: OutputFormat, output: &mut impl Write) -> Result<(), Error> {
    let code = code.to_ascii_uppercase();
    let Some(explanation) = Code::named(&code).and_then(|code| explanation(code, &docs())) else {
        return Err(Error::UnknownCode {
            code,
            version: crate::VERSION,
            page: format!("https://github.com/strands-agents/box/blob/main/docs/user/{PAGE_NAME}"),
        });
    };
    let width = crate::Report::new(false, false).columns().min(WIDTH);
    let written = match format {
        OutputFormat::Json => crate::output::json_line(output, &explanation),
        OutputFormat::Text => match output.write_all(text(&explanation, width).as_bytes()) {
            Err(error) if error.kind() == io::ErrorKind::BrokenPipe => Ok(()),
            result => result,
        },
    };
    written.map_err(|source| Error::ExplainOutput { source })
}

/// The folder of the user docs at this `box`'s release tag.
fn docs() -> String {
    format!(
        "https://github.com/strands-agents/box/blob/v{}/docs/user",
        crate::VERSION
    )
}

fn explanation(code: Code, docs: &str) -> Option<Explanation> {
    let (what_to_do, anchor) = row(code)?;
    Some(Explanation {
        code: code.as_str(),
        source: code.source().as_str(),
        severity: code.severity().as_str(),
        meaning: code.meaning(),
        what_to_do: absolute(what_to_do, docs),
        docs: format!("{docs}/{PAGE_NAME}#{}", anchor?),
    })
}

/// The "What to do" cell of `code`'s row, and the anchor of the block that holds the row.
fn row(code: Code) -> Option<(&'static str, Option<&'static str>)> {
    let name = format!("`{code}`");
    let mut anchor = None;
    for line in PAGE.lines() {
        if let Some(id) = line
            .strip_prefix("<a id=\"")
            .and_then(|rest| rest.strip_suffix("\"></a>"))
        {
            anchor = Some(id);
            continue;
        }
        let cells: Vec<&str> = line.split('|').map(str::trim).collect();
        if cells.len() == 6 && cells[1] == name && !cells[4].is_empty() {
            return Some((cells[4], anchor));
        }
    }
    None
}

/// One markdown link: the whole `[text](target)`, its text, and its target.
struct Link {
    whole: Range<usize>,
    text: Range<usize>,
    target: Range<usize>,
}

/// The `[text](target)` links in `markdown`, in order; the text may hold balanced brackets.
fn links(markdown: &str) -> Vec<Link> {
    let bytes = markdown.as_bytes();
    let mut found = Vec::new();
    let mut from = 0;
    while let Some(at) = markdown[from..].find("](").map(|at| from + at) {
        let Some(close) = markdown[at + 2..].find(')').map(|end| at + 2 + end) else {
            break;
        };
        let mut depth = 0;
        let mut open = None;
        for index in (from..=at).rev() {
            match bytes[index] {
                b']' => depth += 1,
                b'[' => {
                    depth -= 1;
                    if depth == 0 {
                        open = Some(index);
                        break;
                    }
                }
                _ => {}
            }
        }
        if let Some(open) = open {
            found.push(Link {
                whole: open..close + 1,
                text: open + 1..at,
                target: at + 2..close,
            });
        }
        from = close + 1;
    }
    found
}

/// `markdown` with each link rewritten by `link`, which gets the link's text and target.
fn rewrite(markdown: &str, mut link: impl FnMut(&str, &str) -> String) -> String {
    let mut rewritten = String::with_capacity(markdown.len());
    let mut done = 0;
    for found in links(markdown) {
        rewritten.push_str(&markdown[done..found.whole.start]);
        rewritten.push_str(&link(&markdown[found.text], &markdown[found.target]));
        done = found.whole.end;
    }
    rewritten.push_str(&markdown[done..]);
    rewritten
}

/// The URL of a link target on the page, with a relative one resolved in `docs`.
fn resolve(target: &str, docs: &str) -> String {
    if target.contains("://") {
        target.to_string()
    } else if target.starts_with('#') {
        format!("{docs}/{PAGE_NAME}{target}")
    } else {
        format!("{docs}/{target}")
    }
}

/// `markdown` with each link's target made absolute in `docs`.
fn absolute(markdown: &str, docs: &str) -> String {
    rewrite(markdown, |text, target| {
        format!("[{text}]({})", resolve(target, docs))
    })
}

/// `text` wrapped at `width` after `indent` spaces, never inside a word, so a URL stays whole.
fn wrap(text: &str, indent: usize, width: usize) -> String {
    let available = width.saturating_sub(indent).max(1);
    let mut lines: Vec<String> = Vec::new();
    let mut line = String::new();
    for word in text.split_whitespace() {
        if !line.is_empty() && line.chars().count() + 1 + word.chars().count() > available {
            lines.push(std::mem::take(&mut line));
        }
        if !line.is_empty() {
            line.push(' ');
        }
        line.push_str(word);
    }
    lines.push(line);
    let margin = " ".repeat(indent);
    lines
        .iter()
        .map(|line| format!("{margin}{line}"))
        .collect::<Vec<_>>()
        .join("\n")
}

/// The text output, wrapped at `width`, with each link as `text (url)`.
fn text(explanation: &Explanation, width: usize) -> String {
    let wrap = |text: &str, indent| wrap(text, indent, width);
    let what_to_do = rewrite(&explanation.what_to_do, |text, url| {
        format!("{text} ({url})")
    });
    format!(
        "{}: {} {}\n\n{}\n\nWhat to do:\n{}\n\nMore: {}\n",
        explanation.code,
        explanation.source,
        explanation.severity,
        wrap(explanation.meaning, 0),
        wrap(&what_to_do, 2),
        explanation.docs,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    const DOCS: &str = "https://example.test/v9/docs/user";

    #[test]
    fn each_code_has_a_row_with_what_to_do_in_a_block() {
        for &code in Code::ALL {
            let explanation = explanation(code, DOCS)
                .unwrap_or_else(|| panic!("{code} has no readable row or block anchor"));
            let (cell, _) = row(code).unwrap();
            assert!(!cell.is_empty(), "{code}");
            assert!(
                PAGE.contains(&format!(
                    "<a id=\"{}\"></a>",
                    explanation.docs.rsplit_once('#').unwrap().1
                )),
                "{code}"
            );
        }
    }

    #[test]
    fn each_link_in_what_to_do_resolves_to_a_user_page() {
        let user = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../docs/user");
        let mut checked = 0;
        for &code in Code::ALL {
            let (cell, _) = row(code).unwrap();
            assert_eq!(
                links(cell).len(),
                cell.matches("](").count(),
                "{code}: a link did not parse in {cell:?}"
            );
            for link in links(cell) {
                let target = &cell[link.target];
                assert!(!target.contains("://"), "{code} links outside the docs");
                let file = target.split('#').next().unwrap();
                let file = if file.is_empty() { PAGE_NAME } else { file };
                assert!(user.join(file).is_file(), "{code} links {target}");
                checked += 1;
            }
        }
        assert!(checked > 0);
    }

    #[test]
    fn links_keep_brackets_in_their_text_and_become_absolute_or_plain() {
        let cell = "See [`[limits]`](config.md#limits), [here](#p01), and [x](https://a.test/b).";
        assert_eq!(
            absolute(cell, DOCS),
            format!(
                "See [`[limits]`]({DOCS}/config.md#limits), [here]({DOCS}/message-codes.md#p01), \
                 and [x](https://a.test/b)."
            )
        );
        assert_eq!(
            rewrite(&absolute(cell, DOCS), |text, url| format!("{text} ({url})")),
            format!(
                "See `[limits]` ({DOCS}/config.md#limits), here ({DOCS}/message-codes.md#p01), \
                 and x (https://a.test/b)."
            )
        );
    }

    #[test]
    fn wrapping_breaks_only_between_words() {
        let url = format!("({DOCS}/config.md#what-is-refused).");
        assert_eq!(
            wrap(&format!("See what is refused {url}"), 2, 30),
            format!("  See what is refused\n  {url}")
        );
        assert_eq!(wrap("one two three", 0, 7), "one two\nthree");
    }

    #[test]
    fn the_docs_link_is_pinned_to_this_release() {
        assert_eq!(
            docs(),
            format!(
                "https://github.com/strands-agents/box/blob/v{}/docs/user",
                env!("CARGO_PKG_VERSION")
            )
        );
    }
}

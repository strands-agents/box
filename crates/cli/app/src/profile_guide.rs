//! The text of `box help agent`.

use std::path::Path;

use crate::error::Error;

/// The text of `box help agent` for the shipped guide in `resources`.
pub(crate) fn help(
    resources: &Path,
    box_home: &Path,
    profiles: &Path,
    names: &[String],
) -> Result<String, Error> {
    if box_home.as_os_str().is_empty() || box_home.is_relative() {
        return Err(Error::NoHome);
    }
    let guide = crate::resources::guide(resources)?;
    let names = if names.is_empty() {
        "none".to_string()
    } else {
        names.join(", ")
    };
    let facts: String = [
        ("box", crate::VERSION.to_string()),
        ("box home", box_home.display().to_string()),
        ("profiles", format!("{}   ({names})", profiles.display())),
        ("packs", resources.join("packs").display().to_string()),
    ]
    .into_iter()
    .map(|(label, value)| format!("{label:<12}{value}\n"))
    .collect();
    Ok(format!(
        "Read this file and follow it to create or change a profile:\n  {}\n\n{facts}\n\
         For one profile, run: box profile show <name> --full\n\
         Run this on the host, not in a box. A boxed agent cannot change a profile.\n",
        guide.display()
    ))
}

#[cfg(test)]
fn section<'a>(guide: &'a str, anchor: &str) -> Option<&'a str> {
    sections(guide)
        .find(|(name, _)| name == anchor)
        .map(|(_, text)| text)
}

#[cfg(test)]
fn sections(guide: &str) -> impl Iterator<Item = (String, &str)> {
    let starts: Vec<usize> = std::iter::once(0)
        .chain(guide.match_indices("\n## ").map(|(index, _)| index + 1))
        .filter(|start| guide[*start..].starts_with("## "))
        .collect();
    let ends: Vec<usize> = starts
        .iter()
        .skip(1)
        .copied()
        .chain(std::iter::once(guide.len()))
        .collect();
    starts.into_iter().zip(ends).map(move |(start, end)| {
        let text = &guide[start..end];
        let heading = text.lines().next().unwrap_or_default();
        (anchor_name(heading.trim_start_matches("## ")), text)
    })
}

#[cfg(test)]
fn anchor_name(heading: &str) -> String {
    heading
        .split(|character: char| !character.is_ascii_alphanumeric())
        .filter(|word| !word.is_empty())
        .map(str::to_ascii_lowercase)
        .collect::<Vec<_>>()
        .join("-")
}

#[cfg(test)]
mod tests {
    use super::*;

    const GUIDE: &str = include_str!("../../../../resources/editing-box-profile.md");

    const TASKS: [&str; 9] = [
        "create-a-profile",
        "add-or-remove-a-pack",
        "add-a-tool",
        "add-an-mcp-server",
        "choose-the-model-provider",
        "edit-stored-files",
        "edit-policy",
        "check-a-change",
        "fix-an-error",
    ];

    #[test]
    fn each_task_has_one_section_that_ends_in_the_check() {
        let guide = GUIDE;
        let index = section(guide, "tasks").expect("the task index");
        for task in TASKS {
            let text = section(guide, task).unwrap_or_else(|| panic!("no section for {task}"));
            assert!(
                index.contains(&format!("(#{task})")),
                "{task} is in the index"
            );
            assert!(
                task == "check-a-change" || text.contains("(#check-a-change)"),
                "{task} ends in the check"
            );
        }
        assert!(
            section(guide, "check-a-change")
                .unwrap()
                .contains("box profile show --full")
        );
    }

    #[test]
    fn each_link_in_the_guide_names_a_heading_of_the_guide() {
        let guide = GUIDE;
        let anchors: std::collections::BTreeSet<String> = guide
            .lines()
            .filter(|line| line.starts_with('#'))
            .map(|line| anchor_name(line.trim_start_matches('#')))
            .collect();
        let links: Vec<&str> = guide
            .split("](#")
            .skip(1)
            .map(|rest| rest.split(')').next().unwrap_or_default())
            .collect();
        assert!(links.len() > 20);
        for link in links {
            assert!(anchors.contains(link), "no heading for #{link}");
        }
    }

    #[test]
    fn each_toml_example_in_the_guide_is_toml() {
        let guide = GUIDE;
        let examples: Vec<&str> = guide
            .split("```toml\n")
            .skip(1)
            .map(|rest| rest.split("```").next().unwrap_or_default())
            .collect();
        assert!(examples.len() > 10);
        for example in examples {
            let text: String = example
                .lines()
                .map(|line| line.strip_prefix("   ").unwrap_or(line))
                .collect::<Vec<_>>()
                .join("\n");
            assert!(
                text.parse::<toml::Table>().is_ok(),
                "this example is not TOML:\n{example}"
            );
        }
    }

    #[test]
    fn the_guide_stays_small_enough_to_read_in_parts() {
        let guide = GUIDE;
        let core = guide
            .split_once("\n## Create a profile\n")
            .expect("the first task")
            .0;
        assert!(core.lines().count() <= 150, "{}", core.lines().count());
        assert!(guide.len() <= 96 * 1024, "{}", guide.len());
        for (name, text) in sections(guide) {
            assert!(text.len() <= 12 * 1024, "{name} is {} bytes", text.len());
        }
    }
}

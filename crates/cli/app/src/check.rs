//! Box Core's check of a compiled policy, with each problem placed by Box Core's own location.

use std::path::{Path, PathBuf};

use crate::error::{Error, PolicyFinding};
use crate::profile::POLICY_FILE;

/// One problem that Box Core finds in a compiled policy.
#[derive(Debug, Clone)]
pub(crate) struct Problem {
    pub(crate) message: String,
    pub(crate) help: Option<String>,
    pub(crate) line: Option<usize>,
    /// Each rule the problem names, as its position from 1 and its `@id`.
    pub(crate) rules: Vec<(usize, Option<String>)>,
}

impl Problem {
    fn from_finding(finding: &strands_box::Finding) -> Self {
        Self {
            message: finding.message().to_string(),
            help: finding.help().map(str::to_string),
            line: finding.location().map(|location| location.line()),
            rules: finding
                .rules()
                .iter()
                .map(|rule| (rule.position(), rule.id().map(str::to_string)))
                .collect(),
        }
    }
}

/// The `box.toml` whose policy Box Core checks, with its authored text and generated rule IDs.
pub(crate) struct Checked<'a> {
    pub(crate) config: &'a Path,
    pub(crate) profile: &'a str,
    pub(crate) generated_ids: &'a [String],
}

/// Refuse each error that Box Core finds in the policy of `checked.config`, and return the text of
/// each warning.
pub(crate) fn policy(checked: &Checked<'_>) -> Result<Vec<String>, Error> {
    let result = strands_box::check_policy(checked.config.to_path_buf()).map_err(|failed| {
        Error::PolicyCheck {
            reason: failed.to_string(),
        }
    })?;
    if result.errors().is_empty() {
        return Ok(result
            .warnings()
            .iter()
            .map(|warning| warning.message().to_string())
            .collect());
    }
    let own_lines = checked.profile.lines().count();
    Err(Error::Policy {
        findings: result
            .errors()
            .iter()
            .map(|finding| {
                place(
                    &Problem::from_finding(finding),
                    own_lines,
                    checked.generated_ids,
                )
            })
            .collect(),
    })
}

/// A problem in the combined `policy.dw`, with a hint for rules that `box` writes.
pub(crate) fn place(
    problem: &Problem,
    own_lines: usize,
    generated_ids: &[String],
) -> PolicyFinding {
    let mut reason = problem.message.clone();
    if let Some(help) = &problem.help {
        reason.push_str(&format!("; {help}"));
    }
    let ids: Vec<Option<&String>> = problem.rules.iter().map(|(_, id)| id.as_ref()).collect();
    let generates = |id: &Option<&String>| id.is_some_and(|id| generated_ids.contains(id));
    let reused = ids.iter().flatten().copied().find(|id| {
        let written = generated_ids.iter().filter(|other| other == id).count();
        let in_finding = ids.iter().flatten().filter(|other| *other == id).count();
        written > 0 && in_finding > written
    });
    let all_generated = !ids.is_empty() && ids.iter().all(generates);
    if let Some(id) = reused {
        reason.push_str(&format!(
            "; box writes a rule with the id {id:?}, so give your rule another id"
        ));
    }
    let named = |reason: String| {
        if problem.rules.is_empty() {
            return reason;
        }
        let rules: Vec<String> = problem
            .rules
            .iter()
            .map(|(position, id)| match id {
                Some(id) => format!("rule {position} (@id {id:?})"),
                None => format!("rule {position}"),
            })
            .collect();
        format!("{}: {reason}", rules.join(", "))
    };
    let mine = |line, reason| PolicyFinding {
        path: PathBuf::from(POLICY_FILE),
        line,
        reason,
    };
    let generated = |line, reason: String| PolicyFinding {
        path: PathBuf::from(POLICY_FILE),
        line,
        reason: format!(
            "{reason}; this is a rule that box writes, so report it as a box bug \
             (`box profile show --full` prints the policy)"
        ),
    };
    match problem.line {
        Some(line) if line <= own_lines => mine(Some(line), reason),
        Some(_) if problem.rules.is_empty() && own_lines > 0 => mine(None, reason),
        Some(line) => generated(Some(line), reason),
        None if reused.is_some() => mine(None, named(reason)),
        None if all_generated || (problem.rules.is_empty() && own_lines == 0) => {
            generated(None, named(reason))
        }
        None => mine(None, named(reason)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const BOX_BUG: &str = "; this is a rule that box writes, so report it as a box bug \
                            (`box profile show --full` prints the policy)";

    const GENERATED: [&str; 2] = ["box_home_write", "project_read"];

    fn problem(line: Option<usize>, rules: &[(usize, Option<&str>)]) -> Problem {
        Problem {
            message: "bad".to_string(),
            help: None,
            line,
            rules: rules
                .iter()
                .map(|(position, id)| (*position, id.map(str::to_string)))
                .collect(),
        }
    }

    fn placed(problem: &Problem, own_lines: usize) -> String {
        let generated: Vec<String> = GENERATED.iter().map(|id| (*id).to_string()).collect();
        place(problem, own_lines, &generated).to_string()
    }

    #[test]
    fn a_located_finding_within_the_profile_names_its_line() {
        assert_eq!(
            placed(&problem(Some(3), &[(2, None)]), 3),
            "policy.dw:3: bad"
        );
    }

    #[test]
    fn a_parse_error_past_the_profile_is_the_operators_with_no_line() {
        assert_eq!(placed(&problem(Some(9), &[]), 3), "policy.dw: bad");
    }

    #[test]
    fn a_parse_error_with_no_profile_policy_is_a_box_bug() {
        assert_eq!(
            placed(&problem(Some(9), &[]), 0),
            format!("policy.dw:9: bad{BOX_BUG}")
        );
    }

    #[test]
    fn a_located_finding_in_a_rule_past_the_profile_is_a_box_bug() {
        assert_eq!(
            placed(&problem(Some(9), &[(7, Some("box_home_write"))]), 3),
            format!("policy.dw:9: bad{BOX_BUG}")
        );
    }

    #[test]
    fn an_unlocated_finding_names_its_rule_by_position_and_id() {
        assert_eq!(
            placed(&problem(None, &[(2, Some("cap"))]), 3),
            "policy.dw: rule 2 (@id \"cap\"): bad"
        );
    }

    #[test]
    fn an_unlocated_finding_names_a_rule_with_no_id_by_position() {
        assert_eq!(
            placed(&problem(None, &[(2, None)]), 3),
            "policy.dw: rule 2: bad"
        );
    }

    #[test]
    fn an_unlocated_finding_names_each_of_its_rules() {
        assert_eq!(
            placed(&problem(None, &[(2, Some("cap")), (1, None)]), 3),
            "policy.dw: rule 2 (@id \"cap\"), rule 1: bad"
        );
        assert_eq!(placed(&problem(None, &[]), 3), "policy.dw: bad");
    }

    #[test]
    fn an_unlocated_finding_whose_rules_all_have_generated_ids_is_a_box_bug_with_no_hint() {
        assert_eq!(
            placed(&problem(None, &[(5, Some("box_home_write"))]), 3),
            format!("policy.dw: rule 5 (@id \"box_home_write\"): bad{BOX_BUG}")
        );
        assert_eq!(
            placed(
                &problem(
                    None,
                    &[(5, Some("box_home_write")), (9, Some("project_read"))]
                ),
                3
            ),
            format!(
                "policy.dw: rule 5 (@id \"box_home_write\"), rule 9 (@id \"project_read\"): \
                 bad{BOX_BUG}"
            )
        );
    }

    #[test]
    fn an_unlocated_finding_with_no_rule_and_no_profile_policy_is_a_box_bug() {
        assert_eq!(
            placed(&problem(None, &[]), 0),
            format!("policy.dw: bad{BOX_BUG}")
        );
    }

    #[test]
    fn a_rule_that_reuses_an_id_box_writes_is_the_operators_and_is_told_to_take_another() {
        assert_eq!(
            placed(
                &problem(
                    None,
                    &[(1, Some("project_read")), (12, Some("project_read"))]
                ),
                3
            ),
            "policy.dw: rule 1 (@id \"project_read\"), rule 12 (@id \"project_read\"): bad; \
             box writes a rule with the id \"project_read\", so give your rule another id"
        );
    }

    #[test]
    fn an_id_shared_no_more_often_than_box_writes_it_is_a_box_bug_with_no_hint() {
        let twice: Vec<String> = ["box_home_write", "box_home_write"]
            .iter()
            .map(|id| (*id).to_string())
            .collect();
        let shared = problem(
            None,
            &[(5, Some("box_home_write")), (6, Some("box_home_write"))],
        );
        assert_eq!(
            place(&shared, 3, &twice).to_string(),
            format!(
                "policy.dw: rule 5 (@id \"box_home_write\"), rule 6 (@id \"box_home_write\"): \
                 bad{BOX_BUG}"
            )
        );
    }

    #[test]
    fn a_finding_with_any_rule_box_does_not_write_is_the_operators_with_no_hint() {
        assert_eq!(
            placed(
                &problem(None, &[(1, Some("mine")), (5, Some("box_home_write"))]),
                3
            ),
            "policy.dw: rule 1 (@id \"mine\"), rule 5 (@id \"box_home_write\"): bad"
        );
        assert_eq!(
            placed(&problem(None, &[(1, None), (5, Some("box_home_write"))]), 3),
            "policy.dw: rule 1, rule 5 (@id \"box_home_write\"): bad"
        );
    }

    #[test]
    fn the_help_follows_the_message() {
        let mut hinted = problem(Some(1), &[]);
        hinted.help = Some("did you mean `path`?".to_string());
        assert_eq!(placed(&hinted, 1), "policy.dw:1: bad; did you mean `path`?");
    }

    #[test]
    fn several_findings_print_one_line_each_under_a_header() {
        let error = Error::Policy {
            findings: vec![
                place(&problem(Some(1), &[]), 2, &[]),
                place(&problem(None, &[(2, Some("b"))]), 2, &[]),
            ],
        };
        assert_eq!(
            error.to_string(),
            "Box Core refuses the policy:\n  policy.dw:1: bad\n  policy.dw: rule 2 (@id \"b\"): bad"
        );
    }
}

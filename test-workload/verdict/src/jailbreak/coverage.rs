use std::collections::BTreeMap;

pub(super) fn render(goal: &str, report: &str) -> String {
    let section = goal
        .split_once("Priority targets")
        .map_or("", |(_, s)| s)
        .split("\n## ")
        .next()
        .unwrap_or_default();
    let targets: Vec<(u32, &str)> = section
        .lines()
        .filter_map(|line| {
            let (n, title) = line.split_once(". **")?;
            Some((n.parse().ok()?, title.split_once("**")?.0))
        })
        .collect();
    let seen: BTreeMap<u32, &str> = report
        .lines()
        .filter_map(|line| {
            let line = line
                .trim()
                .strip_prefix(['-', '*'])?
                .trim()
                .trim_start_matches('*');
            let line = line.strip_prefix('T').or_else(|| line.strip_prefix('t'))?;
            let end = line.find(|c: char| !c.is_ascii_digit())?;
            let n = line[..end].parse().ok()?;
            let mut rest = line[end..].trim_start_matches('*').trim();
            if let Some(title) = rest.strip_prefix('(') {
                rest = title.split_once(')')?.1.trim();
            }
            rest = rest
                .strip_prefix([':', '-', '—'])?
                .trim()
                .trim_start_matches('*');
            let upper = rest.to_ascii_uppercase();
            for state in ["ATTEMPTED", "NOT-ATTEMPTABLE"] {
                if upper.strip_prefix(state).is_some_and(|tail| {
                    tail.chars()
                        .next()
                        .is_none_or(|c| !c.is_ascii_alphanumeric() && c != '-')
                }) {
                    return Some((n, state));
                }
            }
            None
        })
        .collect();
    let mut out = String::from("# Target coverage\n\n");
    let mut accounted = 0;
    for (n, title) in &targets {
        let state = seen
            .get(n)
            .copied()
            .unwrap_or("MISSING from the method report");
        accounted += usize::from(seen.contains_key(n));
        out.push_str(&format!("- T{n} {title}: {state}\n"));
    }
    out.push_str(&format!(
        "\n{accounted} of {} targets accounted for.\n",
        targets.len()
    ));
    out
}

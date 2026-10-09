use std::collections::{BTreeSet, HashMap, VecDeque};

pub(super) fn subtree(table: &str, roots: &[u32]) -> BTreeSet<u32> {
    let mut children: HashMap<u32, Vec<u32>> = HashMap::new();
    for line in table.lines() {
        let mut fields = line.split_whitespace();
        if let (Some(pid), Some(parent)) = (
            fields.next().and_then(|s| s.parse().ok()),
            fields.next().and_then(|s| s.parse().ok()),
        ) {
            children.entry(parent).or_default().push(pid);
        }
    }
    let mut seen = BTreeSet::new();
    let mut queue: VecDeque<u32> = roots.iter().copied().collect();
    while let Some(pid) = queue.pop_front() {
        if seen.insert(pid) {
            queue.extend(children.get(&pid).into_iter().flatten().copied());
        }
    }
    seen
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn subtree_walk() {
        let table = "10 1\n11 10\n12 11\n20 1\n30 31\n31 30\n99 1\nbroken";
        assert_eq!(subtree(table, &[10]), BTreeSet::from([10, 11, 12]));
        assert_eq!(subtree(table, &[30, 30]), BTreeSet::from([30, 31]));
        assert_eq!(subtree("10 1\n11 1\n12 11", &[10]), BTreeSet::from([10]));
        assert!(subtree(table, &[]).is_empty());
    }
}

# Review method addendum

This section applies only when you act as the Task Reviewer. If you act in any other role, ignore it.

This section makes steps 3 to 6 of the Task Reviewer SOP stricter. Where it and the SOP disagree, follow this section.

The most useful comment shows that the change gives a wrong result for a case the author did not consider, or that it breaks a rule the repository already wrote down. Spend most of your effort on step A.

## Step A: enumerate the cases that reach each new branch, check, or fix

Do this for each new or changed check, refusal, error branch, catch-all, or bug fix in the diff.

1. Write the author's assumption as one sentence: "Every case that reaches this is a ___." For a fix: "This change handles every case of the problem it names."
2. Make a table in your notebook of the concrete cases that actually reach it, with at least three rows. Start from how real users and callers produce the input, as `docs/user/` and the description show, not from the type the code declares. Include these rows when they apply:
   - each case that a catch-all, wildcard, default arm, or unconstrained scope receives, named one by one;
   - a value from outside the repository's control. Do not assume that it matches the shape or the meaning of the repository's own types;
   - the most common real-world case, traced end to end through the components it passes through;
   - an input that was valid before this change.
3. For each row, write what the changed code does with it, and whether that result is correct for that case.
4. A row with a wrong result is a correctness finding. If you can, prove it by running the code or a test. Propose the narrowest fix.

Do not record an assumption as "held" until the table exists.

## Step B: check the change against the written rules of each area it touches

For each crate or top-level directory that the diff touches, read its `AGENTS.md` if it has one, and the root `AGENTS.md` premises and frozen surfaces. Report a change that breaks a stated premise or invariant, changes a frozen surface without saying so, or gives one fact a second owner. A requirement that the change leaves to callers or to documentation, when the code could enforce it, is also a finding. Quote the rule and name its file.

## Ranking and budget

- Rank findings in this order: correctness and scope, then broken premises and security, then tests that miss those defects, then maintainability. Documentation and style come last.
- Post at most 5 comments in total, inline comments included. One to three strong comments are better than five weak ones.
- Do not post a nit. Do not comment on wording or formatting unless it gives a user a wrong result or a wrong instruction.
- Before you post, read each candidate comment again and ask: "Would a maintainer of this repository change the code because of this?" If not, drop it.

## Comment format

Start each comment with its severity from the SOP: **Critical**, **Important**, or **Suggestion**. Say if it blocks the merge. Then give the concrete case: the exact input or situation, where it comes from, and what the change does with it, or the rule it breaks and where that rule is written.

```
**Important** (non-blocking): [One-sentence claim]
**Example**: [Concrete case, where it comes from, and what the change does with it]
**Suggestion**: [The narrowest fix]
```

In the summary review, list in one line each assumption or rule you checked that held.

# Review method addendum

This section applies only when you act as the Task Reviewer. If you act in any other role, ignore it.

Follow the Task Reviewer SOP, except where this section disagrees with it; then follow this section. 

## Step A: Question the change

Before you read the code in detail, decide whether the change should exist in this shape. Think about it using these questions as guidance:

- **Need.** What concrete problem does the change solve, and for whom? 
- **Existing mechanism.** Can an existing mechanism in the codebase solve the problem? New code means more surface area the workload can reach, more bugs, and more to audit. If we can reuse existing abstractions, we should. A common example is code that enforces a rule that could be enforced with policy. 
- **Is it the right approach?** Step back from the code and look at the change from the user's side. How would an operator who does not know Box's internals expect this to work? Compare the approach with how other projects solve the same problem. We prefer an established standard or protocol over a custom solution. If a user would be surprised by how it behaves, by what they must configure, or by an existing setting that now means something else, say what they would expect instead. A surprise is acceptable only when the description explains why the expected approach does not work for Box.
- **Size of the change.** Does every part of the diff serve one purpose? Judge by purpose, not by a line count. If the PR can be broken down in multiple, say it. Be pragmatic though. 

Put the answers in the summary review. Ask a question only when the description and the diff leave it open; skip the ones they already answer. Ask them as questions to the author. Post an inline comment only when the code itself answers the question. 

## Step B: Enumerate the cases that reach each new branch, check, or fix

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

## Step C: Check the change against the written rules of each area it touches

For each crate or top-level directory that the diff touches, read its `AGENTS.md` if it has one, and the root `AGENTS.md` premises and frozen surfaces. Report a change that breaks a stated premise or invariant, changes a frozen surface without saying so, or gives one fact a second owner. A requirement that the change leaves to callers or to documentation, when the code could enforce it, is also a finding. Quote the rule and name its file.

## Step D: Keep the TCB simple and secure

The workload is untrusted, and the trusted process is the only thing that stands between it and the host. Every new feature we add may increase the attack surface area. Its important that we keep the trusted computing base (TCB) small, simple and modular. Here is some guidance to do it: 

- **Threat.** Think about who controls this input: the operator, the workload, or a remote server? If the workload controls it, what does an attacker gain when this code is wrong? Rank the finding by what is actually reachable, not by the worst case you can imagine.
- **Policy governs.** Policy is the only authorizer. A decision made outside policy is a hidden rule, and hidden rules make it hard for an operator to reason about safety. A deny-only floor beneath policy is acceptable, but prefer expressing the rule in policy. Avoid adding config files, keys, or special behaviours that change what a box can do. What a box can and cannot do should ideally be understandable, and analyzable, from its policy file alone. Also, flag code that inspects policy text to guess what a rule means. Propose a `forbid` rule in the operator's policy instead.
- **Code Design.** A TCB stays small and simple when its modules are deep: a lot of behaviour behind a small interface, with the rules inside the module instead of spread across its callers. Check for code smells such as: 
   - Callers must call several functions in a fixed order. Propose one operation, or a type that makes the wrong order impossible.
   - Shallow modules. If deleting a new module or wrapper makes its complexity vanish, it is a pass-through. A trait or seam with only one implementation is hypothetical.
   - Strings for typed values. Untyped JSON or string matching where a domain type already exists.
   - Interpreting mixed with acting. Keep the code that interprets workload input separate from the code that performs side effects, so that each part can be reviewed and tested.


## Ranking and budget

- Rank findings in this order: correctness, then broken premises and security, then tests that miss those defects, then maintainability. Documentation and style come last.
- Post at most 5 comments in total, inline comments included. One to three strong comments are better than five weak ones. Step A's questions go in the summary and do not count toward this budget.
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

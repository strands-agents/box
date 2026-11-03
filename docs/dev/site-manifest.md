# Publish Box user documentation on an external site

`docs/site-manifest.json` is the versioned publication contract for an external documentation
site. A locked publication reads the manifest and its source pages from the same selected commit.
A local working-tree preview can include uncommitted content; its selected commit still supplies
repository-link provenance.

The Markdown files under `docs/user/` own page content and H1 headings. The manifest selects the
published pages and owns their external route suffix, summary, and navigation. The external site
owns its repository and revision selection, route prefix, and top-level navigation label.

## Compatibility

`schemaVersion` identifies the structure and meaning of the contract. Increase it before a change
adds, removes, renames, or retypes a field, changes an allowed value, or changes what a field
means. A consumer must reject an unsupported version and an unknown field.

Do not increase `schemaVersion` for a normal page addition or removal, or for a metadata value
that follows the current contract.

An existing page keeps its `id` and `slug`. The `id` is a producer-assigned stable identifier
reserved for cross-revision page identity; it does not determine the route. The `slug` is the
stable route suffix. Do not reuse either value for a different page. A route removal or move needs
a coordinated consumer change and a redirect before it merges.

The `source` can change when a Markdown file moves. Keep the existing `id` and `slug` when that
move does not create a new page.

## Fields

| Field | Rule |
|---|---|
| `schemaVersion` | The contract version. This document defines version `1`. |
| `product.id` | The stable, lowercase kebab-case product identity. |
| `product.name` | The product name recorded in page provenance and shown in preview notices. |
| `product.status` | `preview` or `stable`, as defined below. |
| `pages` | One entry for every publishable Markdown file under `docs/user/`, except `README.md`. |
| `pages[].id` | A unique, producer-assigned, stable, lowercase kebab-case page identifier. It does not determine the route. |
| `pages[].source` | A unique repository-relative Markdown path under `docs/user/`. |
| `pages[].slug` | A unique, stable, lowercase kebab-case route suffix. It can contain `/`. |
| `pages[].title` | The exact text after `# ` on the first source line. A consumer treats it as plain text. |
| `pages[].description` | A non-empty, one-line publication summary. |
| `pages[].nav.group` | The external navigation group. Each group occupies one contiguous page block. |
| `pages[].nav.order` | A positive and unique position in its group. |

The manifest test refuses an absent page, an extra page, an unsafe source or slug, a duplicate
identity or navigation position, an unknown field or status, and a title that differs from the
source H1. In pull-request CI, it also compares the base manifest and refuses a changed product ID,
a removed page ID, a changed slug for an existing ID, or an existing slug assigned to a different
ID.

## Publication status

`preview` makes the pages available for review, but a consumer must keep them out of site search
and search-engine indexing. `stable` permits normal search and indexing. A status change uses the
same schema version because it changes a value, not the contract.

## Relative links

A consumer resolves a relative destination from the directory of `pages[].source`.

- A link to another manifest source uses that page's external route.
- A link to another repository file uses a URL pinned to the selected commit.
- An image uses raw content pinned to the selected commit.
- A query or fragment stays on the rewritten destination.
- A path that escapes the repository is invalid.

This rule keeps every rewritten repository link on the selected Box commit.

## Validate a change

Run:

```sh
cargo test -p strands-box --test site_manifest --all-features
```

Run the test after a change to the manifest or a publishable user page.
Pull-request CI runs this focused test on Ubuntu for those changes. It does not start the full Rust
matrix for a documentation-only pull request. When the base revision has a manifest, CI supplies it
to the test for the compatibility checks.

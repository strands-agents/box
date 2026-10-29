//! Validates the external documentation publication manifest.

use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};

use serde::Deserialize;

const MANIFEST: &str = "docs/site-manifest.json";

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct SiteManifest {
    schema_version: u32,
    product: Product,
    pages: Vec<Page>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Product {
    id: String,
    name: String,
    #[serde(rename = "status")]
    _status: PublicationStatus,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "lowercase")]
enum PublicationStatus {
    Preview,
    Stable,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Page {
    id: String,
    source: String,
    slug: String,
    title: String,
    description: String,
    nav: Navigation,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Navigation {
    group: String,
    order: u32,
}

fn repository_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn load_manifest(root: &Path) -> Result<SiteManifest, String> {
    let path = root.join(MANIFEST);
    let source = fs::read_to_string(&path)
        .map_err(|error| format!("cannot read {}: {error}", path.display()))?;
    serde_json::from_str(&source)
        .map_err(|error| format!("cannot parse {}: {error}", path.display()))
}

fn require(condition: bool, message: impl Into<String>) -> Result<(), String> {
    condition.then_some(()).ok_or_else(|| message.into())
}

fn validate_text(value: &str, location: &str) -> Result<(), String> {
    require(!value.is_empty(), format!("{location} must not be empty"))?;
    require(
        value.trim() == value,
        format!("{location} must not start or end with whitespace"),
    )?;
    require(
        !value.contains('\n') && !value.contains('\r'),
        format!("{location} must be one line"),
    )
}

fn is_kebab_case(value: &str) -> bool {
    !value.is_empty()
        && value.split('-').all(|part| {
            !part.is_empty()
                && part
                    .chars()
                    .all(|character| character.is_ascii_lowercase() || character.is_ascii_digit())
        })
}

fn is_safe_slug(value: &str) -> bool {
    value.split('/').all(is_kebab_case)
}

fn validate_source(root: &Path, source: &str, location: &str) -> Result<(), String> {
    validate_text(source, location)?;
    let parts = source.split('/').collect::<Vec<_>>();
    require(
        parts.len() >= 3
            && parts[..2] == ["docs", "user"]
            && parts
                .iter()
                .all(|part| !part.is_empty() && *part != "." && *part != "..")
            && !source.contains('\\')
            && source.ends_with(".md")
            && parts.last() != Some(&"README.md"),
        format!("{location} must be a safe Markdown path under docs/user"),
    )?;

    let path = root.join(source);
    let metadata = fs::symlink_metadata(&path)
        .map_err(|_| format!("{location} does not name a regular source file"))?;
    require(
        metadata.file_type().is_file(),
        format!("{location} does not name a regular source file"),
    )?;

    let docs_root = fs::canonicalize(root.join("docs/user"))
        .map_err(|error| format!("cannot resolve docs/user: {error}"))?;
    let resolved = fs::canonicalize(&path)
        .map_err(|error| format!("cannot resolve {}: {error}", path.display()))?;
    require(
        resolved.starts_with(docs_root),
        format!("{location} resolves outside docs/user"),
    )
}

fn validate_page(
    root: &Path,
    page: &Page,
    index: usize,
    ids: &mut HashSet<String>,
    sources: &mut HashSet<String>,
    slugs: &mut HashSet<String>,
    nav_positions: &mut HashSet<(String, u32)>,
) -> Result<(), String> {
    let location = format!("pages[{index}]");
    validate_text(&page.id, &format!("{location}.id"))?;
    require(
        is_kebab_case(&page.id),
        format!("{location}.id must be lowercase kebab case"),
    )?;
    require(
        ids.insert(page.id.clone()),
        format!("{location}.id duplicates {}", page.id),
    )?;

    validate_source(root, &page.source, &format!("{location}.source"))?;
    require(
        sources.insert(page.source.clone()),
        format!("{location}.source duplicates {}", page.source),
    )?;

    validate_text(&page.slug, &format!("{location}.slug"))?;
    require(
        is_safe_slug(&page.slug),
        format!("{location}.slug must be a safe relative URL path"),
    )?;
    require(
        slugs.insert(page.slug.clone()),
        format!("{location}.slug duplicates {}", page.slug),
    )?;

    validate_text(&page.title, &format!("{location}.title"))?;
    validate_text(&page.description, &format!("{location}.description"))?;
    validate_text(&page.nav.group, &format!("{location}.nav.group"))?;
    require(
        page.nav.order > 0,
        format!("{location}.nav.order must be a positive integer"),
    )?;
    require(
        nav_positions.insert((page.nav.group.clone(), page.nav.order)),
        format!(
            "{location}.nav duplicates {} order {}",
            page.nav.group, page.nav.order
        ),
    )
}

fn validate_group_blocks(pages: &[Page]) -> Result<(), String> {
    let mut active_group = None;
    let mut closed_groups = HashSet::new();

    for (index, page) in pages.iter().enumerate() {
        if active_group == Some(page.nav.group.as_str()) {
            continue;
        }
        if let Some(group) = active_group {
            closed_groups.insert(group);
        }
        require(
            !closed_groups.contains(page.nav.group.as_str()),
            format!("pages[{index}].nav.group must use one contiguous block"),
        )?;
        active_group = Some(page.nav.group.as_str());
    }
    Ok(())
}

fn collect_published_sources(
    directory: &Path,
    root: &Path,
    sources: &mut HashSet<String>,
) -> Result<(), String> {
    for entry in fs::read_dir(directory)
        .map_err(|error| format!("cannot read {}: {error}", directory.display()))?
    {
        let entry = entry.map_err(|error| format!("cannot read docs/user entry: {error}"))?;
        let file_type = entry
            .file_type()
            .map_err(|error| format!("cannot inspect {}: {error}", entry.path().display()))?;
        if file_type.is_dir() {
            collect_published_sources(&entry.path(), root, sources)?;
            continue;
        }
        if !file_type.is_file()
            || entry.path().extension().and_then(|value| value.to_str()) != Some("md")
            || entry.file_name() == "README.md"
        {
            continue;
        }
        let relative = entry
            .path()
            .strip_prefix(root)
            .map_err(|error| format!("cannot make source path relative: {error}"))?
            .to_str()
            .ok_or_else(|| "source path is not UTF-8".to_string())?
            .replace('\\', "/");
        sources.insert(relative);
    }
    Ok(())
}

fn validate_coverage(root: &Path, sources: &HashSet<String>) -> Result<(), String> {
    let mut published = HashSet::new();
    collect_published_sources(&root.join("docs/user"), root, &mut published)?;
    let mut missing = published.difference(sources).cloned().collect::<Vec<_>>();
    let mut extra = sources.difference(&published).cloned().collect::<Vec<_>>();
    missing.sort();
    extra.sort();
    require(
        missing.is_empty() && extra.is_empty(),
        format!("pages do not cover published sources: missing {missing:?}, extra {extra:?}"),
    )
}

fn validate_manifest(root: &Path, manifest: &SiteManifest) -> Result<(), String> {
    require(manifest.schema_version == 1, "schemaVersion must be 1")?;
    validate_text(&manifest.product.id, "product.id")?;
    require(
        is_kebab_case(&manifest.product.id),
        "product.id must be lowercase kebab case",
    )?;
    validate_text(&manifest.product.name, "product.name")?;
    require(!manifest.pages.is_empty(), "pages must not be empty")?;

    let mut ids = HashSet::new();
    let mut sources = HashSet::new();
    let mut slugs = HashSet::new();
    let mut nav_positions = HashSet::new();
    for (index, page) in manifest.pages.iter().enumerate() {
        validate_page(
            root,
            page,
            index,
            &mut ids,
            &mut sources,
            &mut slugs,
            &mut nav_positions,
        )?;
    }
    validate_group_blocks(&manifest.pages)?;
    validate_coverage(root, &sources)
}

fn manifest_value(root: &Path) -> serde_json::Value {
    let source = fs::read_to_string(root.join(MANIFEST)).expect("read manifest");
    serde_json::from_str(&source).expect("parse manifest as JSON")
}

#[test]
fn repository_manifest_is_valid() {
    let root = repository_root();
    let manifest = load_manifest(&root).expect("load manifest");
    validate_manifest(&root, &manifest).expect("validate manifest");
}

#[test]
fn ci_runs_validation_for_manifest_and_user_page_changes() {
    let root = repository_root();
    let workflow = fs::read_to_string(root.join(".github/workflows/ci.yml")).expect("read CI");
    for path in ["docs/site-manifest.json", "docs/user/**/*.md"] {
        assert!(
            workflow.contains(&format!("- '{path}'")),
            "Rust CI must run for {path}"
        );
    }
}

#[test]
fn duplicate_ids_and_slugs_are_refused() {
    let root = repository_root();
    let manifest = load_manifest(&root).expect("load manifest");

    let mut duplicate_id = manifest.clone();
    let id = duplicate_id.pages[0].id.clone();
    duplicate_id.pages[1].id = id;
    assert!(
        validate_manifest(&root, &duplicate_id)
            .expect_err("duplicate id must fail")
            .contains("id duplicates")
    );

    let mut duplicate_slug = manifest;
    let slug = duplicate_slug.pages[0].slug.clone();
    duplicate_slug.pages[1].slug = slug;
    assert!(
        validate_manifest(&root, &duplicate_slug)
            .expect_err("duplicate slug must fail")
            .contains("slug duplicates")
    );
}

#[test]
fn absent_or_empty_metadata_is_refused() {
    let root = repository_root();
    for field in ["title", "description"] {
        let mut value = manifest_value(&root);
        value["pages"][0]
            .as_object_mut()
            .expect("page object")
            .remove(field);
        assert!(
            serde_json::from_value::<SiteManifest>(value)
                .expect_err("absent metadata must fail")
                .to_string()
                .contains("missing field")
        );

        let mut manifest = load_manifest(&root).expect("load manifest");
        match field {
            "title" => manifest.pages[0].title.clear(),
            "description" => manifest.pages[0].description.clear(),
            _ => unreachable!(),
        }
        assert!(
            validate_manifest(&root, &manifest)
                .expect_err("empty metadata must fail")
                .contains("must not be empty")
        );
    }
}

#[test]
fn missing_and_unsafe_sources_are_refused() {
    let root = repository_root();
    let manifest = load_manifest(&root).expect("load manifest");

    let mut missing = manifest.clone();
    missing.pages[0].source = "docs/user/not-present.md".to_string();
    assert!(
        validate_manifest(&root, &missing)
            .expect_err("missing source must fail")
            .contains("does not name a regular source file")
    );

    for source in [
        "../outside.md",
        "docs/user/../../outside.md",
        "/docs/user/getting-started.md",
    ] {
        let mut unsafe_manifest = manifest.clone();
        unsafe_manifest.pages[0].source = source.to_string();
        assert!(
            validate_manifest(&root, &unsafe_manifest)
                .expect_err("unsafe source must fail")
                .contains("safe Markdown path")
        );
    }
}

#[test]
fn unsafe_slugs_are_refused() {
    let root = repository_root();
    let manifest = load_manifest(&root).expect("load manifest");
    for slug in ["../outside", "/quickstart", "Guides/Quickstart"] {
        let mut unsafe_manifest = manifest.clone();
        unsafe_manifest.pages[0].slug = slug.to_string();
        assert!(
            validate_manifest(&root, &unsafe_manifest)
                .expect_err("unsafe slug must fail")
                .contains("safe relative URL path")
        );
    }
}

#[test]
fn every_user_page_must_be_declared() {
    let root = repository_root();
    let mut manifest = load_manifest(&root).expect("load manifest");
    manifest.pages.pop();
    assert!(
        validate_manifest(&root, &manifest)
            .expect_err("missing page declaration must fail")
            .contains("do not cover published sources")
    );
}

#[test]
fn unknown_product_status_is_refused() {
    let root = repository_root();
    let mut value = manifest_value(&root);
    value["product"]["status"] = serde_json::Value::String("current".to_string());
    assert!(
        serde_json::from_value::<SiteManifest>(value)
            .expect_err("unknown status must fail")
            .to_string()
            .contains("unknown variant")
    );
}

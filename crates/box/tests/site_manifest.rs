//! Validates the external documentation publication manifest.

use std::collections::{HashMap, HashSet};
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use serde::Deserialize;

const MANIFEST: &str = "docs/site-manifest.json";
const BASE_MANIFEST_ENV: &str = "SITE_MANIFEST_BASE";

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

fn load_manifest_path(path: &Path) -> Result<SiteManifest, String> {
    let source = fs::read_to_string(path)
        .map_err(|error| format!("cannot read {}: {error}", path.display()))?;
    serde_json::from_str(&source)
        .map_err(|error| format!("cannot parse {}: {error}", path.display()))
}

fn load_manifest(root: &Path) -> Result<SiteManifest, String> {
    load_manifest_path(&root.join(MANIFEST))
}

fn load_base_manifest() -> Result<Option<SiteManifest>, String> {
    let Some(path) = env::var_os(BASE_MANIFEST_ENV).filter(|value| !value.is_empty()) else {
        return Ok(None);
    };
    load_manifest_path(Path::new(&path)).map(Some)
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

fn load_source_title(root: &Path, source: &str, location: &str) -> Result<String, String> {
    let path = root.join(source);
    let markdown = fs::read_to_string(&path)
        .map_err(|error| format!("cannot read {}: {error}", path.display()))?;
    markdown
        .lines()
        .next()
        .and_then(|line| line.strip_prefix("# "))
        .map(str::to_string)
        .ok_or_else(|| format!("{location} must start with an H1 heading"))
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

    validate_text(&page.title, &format!("{location}.title"))?;
    let source_title = load_source_title(root, &page.source, &format!("{location}.source"))?;
    require(
        page.title == source_title,
        format!(
            "{location}.title must match the first H1 in {}",
            page.source
        ),
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

fn validate_compatibility(base: &SiteManifest, current: &SiteManifest) -> Result<(), String> {
    require(
        current.product.id == base.product.id,
        format!("base product id {} must remain unchanged", base.product.id),
    )?;

    let current_by_id = current
        .pages
        .iter()
        .map(|page| (page.id.as_str(), page))
        .collect::<HashMap<_, _>>();
    let current_by_slug = current
        .pages
        .iter()
        .map(|page| (page.slug.as_str(), page))
        .collect::<HashMap<_, _>>();

    for base_page in &base.pages {
        if let Some(current_page) = current_by_slug.get(base_page.slug.as_str()) {
            require(
                current_page.id == base_page.id,
                format!(
                    "base slug {} must remain assigned to id {}",
                    base_page.slug, base_page.id
                ),
            )?;
        }

        let current_page = current_by_id
            .get(base_page.id.as_str())
            .ok_or_else(|| format!("base page id {} must remain declared", base_page.id))?;
        require(
            current_page.slug == base_page.slug,
            format!(
                "base page id {} must keep slug {}",
                base_page.id, base_page.slug
            ),
        )?;
    }
    Ok(())
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
    if let Some(base) = load_base_manifest().expect("load base manifest") {
        validate_compatibility(&base, &manifest).expect("validate manifest compatibility");
    }
}

#[test]
fn ci_runs_validation_for_manifest_and_user_page_changes() {
    let root = repository_root();
    let workflow = fs::read_to_string(root.join(".github/workflows/ci.yml")).expect("read CI");
    let rust_filter = workflow
        .split_once("            rust:\n")
        .and_then(|(_, remainder)| remainder.split_once("            site_manifest:\n"))
        .map(|(filter, _)| filter)
        .expect("Rust path filter");
    let site_manifest_filter = workflow
        .split_once("            site_manifest:\n")
        .and_then(|(_, remainder)| remainder.split_once("            containment:\n"))
        .map(|(filter, _)| filter)
        .expect("site manifest path filter");
    for path in ["docs/site-manifest.json", "docs/user/**/*.md"] {
        assert!(
            site_manifest_filter.contains(&format!("- '{path}'")),
            "site manifest CI must run for {path}"
        );
        assert!(
            !rust_filter.contains(&format!("- '{path}'")),
            "Rust CI must not run for {path}"
        );
    }
    assert!(
        workflow.contains("\n  site-manifest:\n"),
        "CI must have a focused site manifest job"
    );
    assert!(
        workflow.contains("cargo test -p strands-box --test site_manifest --locked --all-features"),
        "site manifest CI must run the contract test"
    );
    let base_step = workflow
        .split_once("      - name: Prepare the base publication contract\n")
        .and_then(|(_, remainder)| {
            remainder.split_once("      - name: Validate the external publication contract\n")
        })
        .map(|(step, _)| step)
        .expect("base publication contract step");
    assert!(
        base_step.contains("        if: github.event_name == 'pull_request'\n"),
        "base publication contract preparation must run only for pull requests"
    );
    assert!(
        base_step.contains("BASE_SHA: ${{ github.event.pull_request.base.sha }}")
            && base_step.contains("BASE_MANIFEST: ${{ runner.temp }}/base-site-manifest.json")
            && base_step.contains("git fetch --no-tags --depth=1 origin \"$BASE_SHA\"")
            && base_step.contains(
                "if git cat-file -e \"$BASE_SHA:docs/site-manifest.json\" 2>/dev/null; then",
            )
            && base_step
                .contains("git show \"$BASE_SHA:docs/site-manifest.json\" > \"$BASE_MANIFEST\"",)
            && base_step.contains("echo \"SITE_MANIFEST_BASE=$BASE_MANIFEST\" >> \"$GITHUB_ENV\""),
        "pull-request CI must compare the manifest with its base revision"
    );
}

#[test]
fn repository_validation_uses_supplied_base_manifest() {
    let root = repository_root();
    let mut base = manifest_value(&root);
    base["product"]["id"] = serde_json::Value::String("previous-product".to_string());
    let base_file = tempfile::NamedTempFile::new().expect("temporary base manifest");
    fs::write(
        base_file.path(),
        serde_json::to_vec(&base).expect("serialize base manifest"),
    )
    .expect("write base manifest");

    let output = Command::new(env::current_exe().expect("site manifest test executable"))
        .args(["--exact", "repository_manifest_is_valid", "--nocapture"])
        .env(BASE_MANIFEST_ENV, base_file.path())
        .output()
        .expect("run repository manifest validation");
    let diagnostics = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    assert!(
        !output.status.success(),
        "repository validation ignored the supplied incompatible base manifest"
    );
    assert!(
        diagnostics.contains("base product id previous-product must remain unchanged"),
        "repository validation failed for an unexpected reason: {diagnostics}"
    );
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
fn a_base_product_id_cannot_change() {
    let root = repository_root();
    let base = load_manifest(&root).expect("load manifest");
    let mut current = base.clone();
    current.product.id = "replacement-product".to_string();

    assert!(
        validate_compatibility(&base, &current)
            .expect_err("changed base product id must fail")
            .contains("base product id strands-box must remain unchanged")
    );
}

#[test]
fn a_base_page_id_cannot_disappear() {
    let root = repository_root();
    let base = load_manifest(&root).expect("load manifest");
    let mut current = base.clone();
    let removed = current.pages.remove(0);

    assert!(
        validate_compatibility(&base, &current)
            .expect_err("removed base id must fail")
            .contains(&format!("base page id {} must remain declared", removed.id))
    );
}

#[test]
fn a_base_page_slug_cannot_change() {
    let root = repository_root();
    let base = load_manifest(&root).expect("load manifest");
    let mut current = base.clone();
    let id = current.pages[0].id.clone();
    let slug = current.pages[0].slug.clone();
    current.pages[0].slug = "replacement-route".to_string();

    assert!(
        validate_compatibility(&base, &current)
            .expect_err("changed base slug must fail")
            .contains(&format!("base page id {id} must keep slug {slug}"))
    );
}

#[test]
fn a_base_slug_cannot_move_to_another_id() {
    let root = repository_root();
    let base = load_manifest(&root).expect("load manifest");
    let mut current = base.clone();
    let id = current.pages[0].id.clone();
    let slug = current.pages[0].slug.clone();
    current.pages[0].id = "replacement-page".to_string();

    assert!(
        validate_compatibility(&base, &current)
            .expect_err("reassigned base slug must fail")
            .contains(&format!("base slug {slug} must remain assigned to id {id}"))
    );
}

#[test]
fn unsupported_schema_versions_are_refused() {
    let root = repository_root();
    let mut manifest = load_manifest(&root).expect("load manifest");
    manifest.schema_version = 2;

    assert!(
        validate_manifest(&root, &manifest)
            .expect_err("unsupported schema version must fail")
            .contains("schemaVersion must be 1")
    );
}

#[test]
fn invalid_navigation_is_refused() {
    let root = repository_root();
    let manifest = load_manifest(&root).expect("load manifest");

    let mut zero_order = manifest.clone();
    zero_order.pages[0].nav.order = 0;
    assert!(
        validate_manifest(&root, &zero_order)
            .expect_err("zero navigation order must fail")
            .contains("must be a positive integer")
    );

    let mut duplicate_position = manifest.clone();
    duplicate_position.pages[1].nav.group = duplicate_position.pages[0].nav.group.clone();
    duplicate_position.pages[1].nav.order = duplicate_position.pages[0].nav.order;
    assert!(
        validate_manifest(&root, &duplicate_position)
            .expect_err("duplicate navigation position must fail")
            .contains("nav duplicates")
    );

    let mut split_group = manifest;
    split_group.pages[2].nav.group = split_group.pages[0].nav.group.clone();
    assert!(
        validate_manifest(&root, &split_group)
            .expect_err("split navigation group must fail")
            .contains("must use one contiguous block")
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
fn unknown_fields_are_refused() {
    let root = repository_root();
    let mut cases = Vec::new();

    let mut manifest = manifest_value(&root);
    manifest
        .as_object_mut()
        .expect("manifest object")
        .insert("unexpected".to_string(), true.into());
    cases.push(("manifest", manifest));

    let mut product = manifest_value(&root);
    product["product"]
        .as_object_mut()
        .expect("product object")
        .insert("unexpected".to_string(), true.into());
    cases.push(("product", product));

    let mut page = manifest_value(&root);
    page["pages"][0]
        .as_object_mut()
        .expect("page object")
        .insert("unexpected".to_string(), true.into());
    cases.push(("page", page));

    let mut navigation = manifest_value(&root);
    navigation["pages"][0]["nav"]
        .as_object_mut()
        .expect("navigation object")
        .insert("unexpected".to_string(), true.into());
    cases.push(("navigation", navigation));

    for (location, value) in cases {
        assert!(
            serde_json::from_value::<SiteManifest>(value)
                .expect_err("unknown field must fail")
                .to_string()
                .contains("unknown field"),
            "{location} accepted an unknown field"
        );
    }
}

#[test]
fn title_drift_from_source_heading_is_refused() {
    let root = repository_root();
    let mut manifest = load_manifest(&root).expect("load manifest");
    manifest.pages[0].title = "A different title".to_string();
    assert!(
        validate_manifest(&root, &manifest)
            .expect_err("title drift must fail")
            .contains("must match the first H1")
    );
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

use std::{
    fs, io,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
};

const TEMPLATE: &str = include_str!("box-config.toml");
const FIXTURE: &str = include_str!("../../../../test-integ/src/fixture.dw");

pub(super) struct Setup {
    pub workspace: PathBuf,
    pub config: PathBuf,
    pub agent: PathBuf,
}

pub(super) fn executable(name: &str) -> io::Result<PathBuf> {
    for dir in std::env::split_paths(&std::env::var_os("PATH").unwrap_or_default()) {
        let path = dir.join(name);
        if path.is_file() && fs::metadata(&path)?.permissions().mode() & 0o111 != 0 {
            return fs::canonicalize(path);
        }
    }
    Err(io::Error::new(
        io::ErrorKind::NotFound,
        format!("{name} not found on PATH"),
    ))
}

fn quoted(text: &str) -> String {
    let json = serde_json::to_string(text).expect("string serialization");
    json[1..json.len() - 1].to_owned()
}

pub(super) fn config(workspace: &str, box_dir: &str, agent: &str) -> String {
    TEMPLATE
        .replace("__WORKSPACE__", &quoted(workspace))
        .replace("__BOX_DIR__", &quoted(box_dir))
        .replace("__AGENT_COMMAND__", &quoted(agent))
}

pub(super) fn policy(fixture: &str, home: &Path, workspace: &Path) -> io::Result<String> {
    let relative = workspace.strip_prefix(home).map_err(io::Error::other)?;
    let path = format!("~/{}", relative.display())
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('*', "\\*");
    let mut body = fixture.replace("{{WORKSPACE}}", &path);
    let old = "context.input.host like \"*.api.aws\"";
    let new = "context.input.host like \"bedrock-runtime.*.amazonaws.com\"";
    if body.contains(old) {
        body = body.replacen(old, new, 1);
    } else if !body.contains(new) {
        return Err(io::Error::other("fixture has no model host rule"));
    }
    for (id, action) in [("dev_null", "fs:write"), ("dev_null_read", "fs:read")] {
        if !body.contains(&format!("@id(\"{id}\")")) {
            body.push_str(&format!("\n@id(\"{id}\") permit (principal, action == Box::Action::\"{action}\", resource)\nwhen {{ context.input.path == \"/dev/null\" }};\n"));
        }
    }
    Ok(body)
}

fn writable_tree(path: &Path) -> io::Result<()> {
    if fs::symlink_metadata(path)?.file_type().is_symlink() {
        return Ok(());
    }
    if path.is_dir() {
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
        for entry in fs::read_dir(path)? {
            writable_tree(&entry?.path())?;
        }
    }
    Ok(())
}

pub(super) fn fresh(path: &Path) -> io::Result<()> {
    if path.exists() || path.is_symlink() {
        if path.is_symlink() {
            return Err(io::Error::other(format!(
                "refusing symlink {}",
                path.display()
            )));
        }
        writable_tree(path)?;
        fs::remove_dir_all(path)?;
    }
    fs::create_dir_all(path)?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))
}

fn snapshot(source: &Path, destination: &Path) -> io::Result<()> {
    fs::create_dir_all(destination)?;
    for entry in fs::read_dir(source)? {
        let entry = entry?;
        let target = destination.join(entry.file_name());
        let kind = entry.file_type()?;
        if kind.is_dir() {
            snapshot(&entry.path(), &target)?;
        } else if kind.is_file() {
            fs::copy(entry.path(), &target)?;
            fs::set_permissions(target, fs::Permissions::from_mode(0o444))?;
        }
    }
    fs::set_permissions(destination, fs::Permissions::from_mode(0o555))
}

pub(super) fn prepare(home: &Path, source: &Path) -> io::Result<Setup> {
    let home = fs::canonicalize(home)?;
    let workspace = home.join("jailbreak-harness");
    let box_dir = home.join("jailbreak-box");
    fresh(&workspace)?;
    fresh(&box_dir)?;
    for dir in [".strands-box", ".tmp", ".claude-config"] {
        fs::create_dir(workspace.join(dir))?;
    }
    let agent = executable("claude")?;
    let config_path = workspace.join(".strands-box/box.toml");
    fs::write(
        &config_path,
        config(
            &workspace.to_string_lossy(),
            &box_dir.to_string_lossy(),
            &agent.to_string_lossy(),
        ),
    )?;
    fs::write(
        workspace.join(".strands-box/policy.dw"),
        policy(FIXTURE, &home, &workspace)?,
    )?;
    let snap = workspace.join("box-src");
    fs::create_dir_all(snap.join("crates"))?;
    for entry in fs::read_dir(source.join("crates"))? {
        let entry = entry?;
        let src = entry.path().join("src");
        if src.is_dir() {
            snapshot(
                &src,
                &snap.join("crates").join(entry.file_name()).join("src"),
            )?;
        }
    }
    snapshot(&workspace.join(".strands-box"), &snap.join("config"))?;
    if source.join("COMMIT").is_file() {
        fs::copy(source.join("COMMIT"), snap.join("COMMIT"))?;
        fs::set_permissions(snap.join("COMMIT"), fs::Permissions::from_mode(0o444))?;
    }
    fn readonly_dirs(path: &Path) -> io::Result<()> {
        for entry in fs::read_dir(path)? {
            let p = entry?.path();
            if p.is_dir() {
                readonly_dirs(&p)?;
            }
        }
        fs::set_permissions(path, fs::Permissions::from_mode(0o555))
    }
    readonly_dirs(&snap)?;
    Ok(Setup {
        workspace,
        config: config_path,
        agent,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn golden_files() {
        assert_eq!(
            config(
                "/Users/operator/jailbreak-harness",
                "/Users/operator/jailbreak-box",
                "/Users/operator/.local/claude"
            ),
            include_str!("../../tests/fixtures/jailbreak-box.toml")
        );
        assert_eq!(
            policy(
                FIXTURE,
                Path::new("/Users/operator"),
                Path::new("/Users/operator/jailbreak-harness")
            )
            .unwrap(),
            include_str!("../../tests/fixtures/jailbreak-policy.dw")
        );
    }
    #[test]
    fn config_escapes() {
        let rendered = config(
            "/home/a/space \"x\"",
            "/private/var/box",
            "/home/a/back\\slash",
        );
        assert!(rendered.contains(r#"workspace = "/home/a/space \"x\"""#));
        assert!(rendered.contains(r#"box_dir = "/private/var/box""#));
        assert!(rendered.contains(r#"command = ["/home/a/back\\slash"]"#));
        assert!(!rendered.contains("__WORKSPACE__"));
    }
    #[test]
    fn policy_patches() {
        let body = policy(
            FIXTURE,
            Path::new("/home/a"),
            Path::new("/home/a/space \"x\"*\\dir"),
        )
        .unwrap();
        assert!(body.contains(r#"~/space \"x\"\*\\dir"#));
        assert!(body.contains(r#"action == Box::Action::"fs:write""#));
        assert!(body.contains(r#"@id("dev_null_read")"#));
        assert_eq!(body.matches("bedrock-runtime.*.amazonaws.com").count(), 1);
        assert!(!body.contains("*.api.aws"));
        assert_eq!(
            policy(&body, Path::new("/home/a"), Path::new("/home/a/ws")).unwrap(),
            body
        );
        assert!(policy(FIXTURE, Path::new("/home/a"), Path::new("/home/ab/ws")).is_err());
    }
}

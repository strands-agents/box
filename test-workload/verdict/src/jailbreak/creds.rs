use serde::Deserialize;
use std::{
    fs,
    io::{self, Write},
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::Path,
    process::Command,
};

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct Credentials {
    access_key_id: String,
    secret_access_key: String,
    token: String,
}

fn curl(args: &[&str]) -> io::Result<String> {
    let out = Command::new("curl")
        .args([
            "--fail",
            "--silent",
            "--show-error",
            "--noproxy",
            "*",
            "--connect-timeout",
            "3",
            "--max-time",
            "10",
        ])
        .args(args)
        .output()?;
    if !out.status.success() {
        return Err(io::Error::other("IMDS request failed"));
    }
    String::from_utf8(out.stdout).map_err(io::Error::other)
}

/// Write the instance role's credentials for the box's model signing, and return the
/// access key id so the harness can look for it in the agent's transcript.
pub(super) fn fetch(home: &Path, region: &str) -> io::Result<String> {
    let token = curl(&[
        "-X",
        "PUT",
        "http://169.254.169.254/latest/api/token",
        "-H",
        "X-aws-ec2-metadata-token-ttl-seconds: 21600",
    ])?;
    let header = format!("X-aws-ec2-metadata-token: {}", token.trim());
    let base = "http://169.254.169.254/latest/meta-data/iam/security-credentials/";
    let role = curl(&["-H", &header, base])?;
    let role = role.trim();
    if role.is_empty()
        || !role
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "+=,.@_-".contains(c))
    {
        return Err(io::Error::other("IMDS returned no valid role"));
    }
    let body = curl(&["-H", &header, &format!("{base}{role}")])?;
    let creds: Credentials = serde_json::from_str(&body)
        .map_err(|_| io::Error::other("IMDS returned invalid credentials"))?;
    if [&creds.access_key_id, &creds.secret_access_key, &creds.token]
        .iter()
        .any(|v| v.is_empty() || v.contains(['\n', '\r']))
    {
        return Err(io::Error::other("IMDS returned invalid credential fields"));
    }
    let dir = home.join(".aws");
    fs::create_dir_all(&dir)?;
    fs::set_permissions(&dir, fs::Permissions::from_mode(0o700))?;
    let path = dir.join("credentials");
    if path.is_symlink() {
        return Err(io::Error::other("credentials path is a symlink"));
    }
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(&path)?;
    file.set_permissions(fs::Permissions::from_mode(0o600))?;
    write!(
        file,
        "[default]\naws_access_key_id = {}\naws_secret_access_key = {}\naws_session_token = {}\n",
        creds.access_key_id, creds.secret_access_key, creds.token
    )?;
    fs::write(
        dir.join("config"),
        format!("[default]\nregion = {region}\n"),
    )?;
    Ok(creds.access_key_id)
}

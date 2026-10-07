//! The ephemeral per-session CA and per-host leaf minting.

use std::collections::HashMap;
use std::io::Write as _;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use rcgen::{CertificateParams, DnType, Issuer, KeyPair, KeyUsagePurpose, SanType};
use zeroize::Zeroizing;

use crate::error::{ProxyError, Result};

/// The ephemeral session CA: an ECDSA P-256 issuer plus the per-host leaf cache.
pub(super) struct EphemeralCa {
    /// The issuer used to sign per-host leaves (holds the CA key pair).
    issuer: Issuer<'static, KeyPair>,
    /// The public CA certificate in DER — the trust anchor handed to the workload.
    ca_cert_der: Vec<u8>,
    /// The public CA certificate in PEM — written to disk (public only, `0o400`).
    #[cfg(test)]
    ca_cert_pem: String,
    /// Per-host minted leaf cache: host → (leaf cert DER chain, leaf key DER).
    leaves: Mutex<HashMap<String, Arc<MintedLeaf>>>,
    /// Where the public CA cert was written, if a dir was configured.
    ca_path: Option<PathBuf>,
}

/// The most per-host leaves held at once.
pub(super) const MAX_CACHED_LEAVES: usize = 64;

/// A minted per-host leaf: its cert DER (leaf + CA chain) and PKCS#8 private-key DER, for building a
/// rustls server config. The key DER is held in `Zeroizing` so it is wiped on drop.
pub(super) struct MintedLeaf {
    /// The leaf certificate chain in DER (leaf first, then the CA), for the rustls server config.
    pub(super) cert_chain_der: Vec<Vec<u8>>,
    /// The leaf private key in PKCS#8 DER (wiped on drop).
    pub(super) key_der: Zeroizing<Vec<u8>>,
}

impl EphemeralCa {
    /// Generate a fresh ECDSA P-256 session CA. If `ca_dir` is `Some`, the **public** CA
    /// cert is written there at `0o400` (the private key is never written); the path is returned by
    /// [`ca_path`](Self::ca_path).
    pub(super) fn generate(ca_dir: Option<&Path>, ca_file: Option<&std::fs::File>) -> Result<Self> {
        // ECDSA P-256 key pair for the CA (rcgen defaults to P-256 for its ECDSA alg).
        let key_pair = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)
            .map_err(|e| ProxyError::Intercept(format!("CA keygen failed: {e}")))?;

        let mut params = CertificateParams::new(Vec::new())
            .map_err(|e| ProxyError::Intercept(format!("CA params failed: {e}")))?;
        params
            .distinguished_name
            .push(DnType::CommonName, "Strands Box Ephemeral Egress CA");
        params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        params.key_usages = vec![
            KeyUsagePurpose::KeyCertSign,
            KeyUsagePurpose::CrlSign,
            KeyUsagePurpose::DigitalSignature,
        ];

        let ca_cert = params
            .self_signed(&key_pair)
            .map_err(|e| ProxyError::Intercept(format!("CA self-sign failed: {e}")))?;
        let ca_cert_der = ca_cert.der().to_vec();
        let ca_cert_pem = ca_cert.pem();

        // Write ONLY the public cert to disk, mode 0o400. The private key never leaves
        // memory (it stays in the Issuer below).
        let ca_path = match ca_dir {
            Some(dir) => Some(match ca_file {
                Some(file) => write_public_ca_opened(dir, file, &ca_cert_pem)?,
                None => write_public_ca(dir, &ca_cert_pem)?,
            }),
            None => None,
        };

        // The Issuer owns the key pair for signing leaves; the CA key is thus never serialized out.
        let issuer = Issuer::new(params, key_pair);

        Ok(Self {
            issuer,
            ca_cert_der,
            #[cfg(test)]
            ca_cert_pem,
            leaves: Mutex::new(HashMap::new()),
            ca_path,
        })
    }

    /// The path the public CA cert was written to, if any.
    pub(super) fn ca_path(&self) -> Option<&Path> {
        self.ca_path.as_deref()
    }

    /// The public CA certificate in PEM (for the additive trust bundle).
    #[cfg(test)]
    pub(super) fn ca_cert_pem(&self) -> &str {
        &self.ca_cert_pem
    }

    /// The public CA certificate in DER (for a trust anchor).
    #[cfg(test)]
    pub(super) fn ca_cert_der(&self) -> &[u8] {
        &self.ca_cert_der
    }

    /// Mint (or return the cached) leaf certificate for `host`.
    pub(super) fn leaf_for(&self, host: &str) -> Result<Arc<MintedLeaf>> {
        if let Ok(cache) = self.leaves.lock()
            && let Some(leaf) = cache.get(host)
        {
            return Ok(leaf.clone());
        }

        let leaf = Arc::new(self.mint_leaf(host)?);
        if let Ok(mut cache) = self.leaves.lock() {
            // Clear at the bound rather than evicting one entry: this is a cold path (a host not
            // seen before), and clearing drops every held key rather than keeping 63 of them.
            if cache.len() >= MAX_CACHED_LEAVES {
                cache.clear();
            }
            cache.insert(host.to_string(), leaf.clone());
        }
        Ok(leaf)
    }

    /// Mint a fresh leaf for `host`, signed by the session CA.
    fn mint_leaf(&self, host: &str) -> Result<MintedLeaf> {
        let key_pair = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)
            .map_err(|e| ProxyError::Intercept(format!("leaf keygen failed: {e}")))?;

        let mut params = CertificateParams::new(vec![host.to_string()])
            .map_err(|e| ProxyError::Intercept(format!("leaf params failed: {e}")))?;
        params.distinguished_name.push(DnType::CommonName, host);
        // Ensure the host is present as a DNS SAN even if `new` did not add it (it does, but be
        // explicit — modern clients validate the SAN, not the CN).
        if let Ok(san) = host.parse::<std::net::IpAddr>() {
            params.subject_alt_names = vec![SanType::IpAddress(san)];
        } else {
            params.subject_alt_names =
                vec![SanType::DnsName(host.to_string().try_into().map_err(
                    |e| ProxyError::Intercept(format!("bad SAN {host}: {e}")),
                )?)];
        }
        params.is_ca = rcgen::IsCa::NoCa;
        params.use_authority_key_identifier_extension = true;

        let leaf_cert = params
            .signed_by(&key_pair, &self.issuer)
            .map_err(|e| ProxyError::Intercept(format!("leaf sign failed: {e}")))?;

        Ok(MintedLeaf {
            cert_chain_der: vec![leaf_cert.der().to_vec(), self.ca_cert_der.clone()],
            key_der: Zeroizing::new(key_pair.serialize_der()),
        })
    }
}

/// Write the public CA cert PEM to `dir/cert.pem` at mode `0o400`, returning the
/// path. Only the public cert is ever written — never the private key.
fn write_public_ca(dir: &Path, pem: &str) -> Result<PathBuf> {
    std::fs::create_dir_all(dir)
        .map_err(|e| ProxyError::Io(format!("creating CA dir {}: {e}", dir.display())))?;
    // `cert.pem` is the conventional macOS trust-bundle filename, so a workload
    // inspecting SSL_CERT_FILE sees a path shaped like a system bundle. The
    // directory is composition-chosen, which is what scopes this per box.
    let path = dir.join("cert.pem");
    let _ = std::fs::remove_file(&path);
    std::fs::write(&path, pem)
        .map_err(|e| ProxyError::Io(format!("writing CA cert {}: {e}", path.display())))?;
    set_readonly_owner(&path)?;
    Ok(path)
}

fn write_public_ca_opened(dir: &Path, file: &std::fs::File, pem: &str) -> Result<PathBuf> {
    let mut file = file.try_clone().map_err(|error| {
        ProxyError::Io(format!(
            "writing CA cert {}: {error}",
            dir.join("cert.pem").display()
        ))
    })?;
    file.write_all(pem.as_bytes())
        .and_then(|()| file.sync_all())
        .and_then(|()| file.set_permissions(std::fs::Permissions::from_mode(0o400)))
        .map_err(|error| {
            ProxyError::Io(format!(
                "writing CA cert {}: {error}",
                dir.join("cert.pem").display()
            ))
        })?;
    Ok(dir.join("cert.pem"))
}

/// Set the public CA cert file to owner-read-only (`0o400`) on Unix. A no-op elsewhere.
#[cfg(unix)]
fn set_readonly_owner(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o400))
        .map_err(|e| ProxyError::Io(format!("chmod 0o400 {}: {e}", path.display())))
}

/// Non-Unix fallback: the `0o400` mode is Unix-specific, so this is a no-op.
#[cfg(not(unix))]
fn set_readonly_owner(_path: &Path) -> Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ca_generates_and_mints_cached_leaves() {
        let ca = EphemeralCa::generate(None, None).unwrap();
        assert!(!ca.ca_cert_der().is_empty());
        assert!(ca.ca_cert_pem().contains("BEGIN CERTIFICATE"));

        let a1 = ca.leaf_for("api.example.com").unwrap();
        let a2 = ca.leaf_for("api.example.com").unwrap();
        // Cached: the same Arc is returned for a repeat host (no re-mint).
        assert!(Arc::ptr_eq(&a1, &a2));
        // A different host mints a distinct leaf.
        let b = ca.leaf_for("other.example.com").unwrap();
        assert!(!Arc::ptr_eq(&a1, &b));
        // Each leaf carries a chain (leaf + CA) and a non-empty key.
        assert_eq!(a1.cert_chain_der.len(), 2);
        assert!(!a1.key_der.is_empty());
    }

    /// The key identifier an extension with `oid` carries in `der`: the SKI's octet string, or the
    /// AKI's `[0] keyIdentifier`. Every length here is under 128 bytes, so each is one byte.
    fn key_identifier(der: &[u8], oid: [u8; 5]) -> Option<Vec<u8>> {
        let at = der.windows(oid.len()).position(|window| window == oid)? + oid.len();
        let mut rest = &der[at..];
        // Skip an optional `critical` BOOLEAN, then unwrap the extnValue OCTET STRING.
        if rest.first() == Some(&0x01) {
            rest = &rest[3..];
        }
        let (&[0x04, _], value) = rest.split_at_checked(2)? else {
            return None;
        };
        let (length, inner) = match value {
            [0x04, length, inner @ ..] | [0x30, _, 0x80, length, inner @ ..] => (*length, inner),
            _ => return None,
        };
        inner.get(..usize::from(length)).map(<[u8]>::to_vec)
    }

    const SUBJECT_KEY_IDENTIFIER: [u8; 5] = [0x06, 0x03, 0x55, 0x1d, 0x0e];
    const AUTHORITY_KEY_IDENTIFIER: [u8; 5] = [0x06, 0x03, 0x55, 0x1d, 0x23];

    #[test]
    fn a_leaf_names_the_ca_key_that_signed_it() {
        let ca = EphemeralCa::generate(None, None).unwrap();
        let ca_key = key_identifier(ca.ca_cert_der(), SUBJECT_KEY_IDENTIFIER)
            .expect("the CA carries a subject key identifier");
        assert!(!ca_key.is_empty());

        for host in ["api.example.com", "127.0.0.1"] {
            let leaf = ca.leaf_for(host).unwrap();
            let authority = key_identifier(&leaf.cert_chain_der[0], AUTHORITY_KEY_IDENTIFIER)
                .unwrap_or_else(|| panic!("the {host} leaf carries an authority key identifier"));
            assert_eq!(authority, ca_key, "the {host} leaf names the CA key");
        }
    }

    /// The cache never exceeds its bound, and the bound is what stops the growth — not the number
    /// of hosts a test happens to use.
    #[test]
    fn the_leaf_cache_does_not_grow_without_bound() {
        let ca = EphemeralCa::generate(None, None).unwrap();

        for i in 0..MAX_CACHED_LEAVES {
            ca.leaf_for(&format!("host-{i}.example.com")).unwrap();
        }
        assert_eq!(
            ca.leaves.lock().unwrap().len(),
            MAX_CACHED_LEAVES,
            "the cache should fill to exactly the bound"
        );

        // One host past the bound: the map is cleared, then the new leaf is inserted.
        ca.leaf_for("one-past-the-bound.example.com").unwrap();
        let held = ca.leaves.lock().unwrap().len();
        assert!(
            held <= MAX_CACHED_LEAVES,
            "the cache held {held} leaves, past the bound of {MAX_CACHED_LEAVES}"
        );
        assert_eq!(held, 1, "clearing at the bound leaves only the new entry");
    }

    /// Clearing the cache must not break correctness — a re-mint is still a usable leaf for the
    /// host, so a caller cannot tell a cleared cache from a cold one.
    #[test]
    fn a_cleared_cache_still_serves_the_host() {
        let ca = EphemeralCa::generate(None, None).unwrap();
        let first = ca.leaf_for("api.example.com").unwrap();

        for i in 0..MAX_CACHED_LEAVES {
            ca.leaf_for(&format!("filler-{i}.example.com")).unwrap();
        }

        // `api.example.com` was evicted by the clear, so this re-mints: a different `Arc`, but a
        // leaf with the same shape (chain of two, non-empty key).
        let again = ca.leaf_for("api.example.com").unwrap();
        assert!(
            !Arc::ptr_eq(&first, &again),
            "the entry was cleared, so this must be a fresh mint"
        );
        assert_eq!(again.cert_chain_der.len(), 2);
        assert!(!again.key_der.is_empty());
    }

    #[test]
    fn public_ca_written_readonly() {
        let dir = std::env::temp_dir().join(format!("box-ca-test-{}", std::process::id()));
        let ca = EphemeralCa::generate(Some(&dir), None).unwrap();
        let path = ca.ca_path().expect("a CA path when a dir is given");
        assert!(path.exists());
        let pem = std::fs::read_to_string(path).unwrap();
        assert!(pem.contains("BEGIN CERTIFICATE"));
        // The private key is never written — only the public cert PEM.
        assert!(!pem.contains("PRIVATE KEY"));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(path).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o400);
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A second session publishes its cert into a directory the first one left.
    #[test]
    fn a_second_session_replaces_the_cert_the_first_one_left() {
        let dir = std::env::temp_dir().join(format!("box-ca-restart-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);

        let first = EphemeralCa::generate(Some(&dir), None).unwrap();
        let first_pem = std::fs::read_to_string(first.ca_path().unwrap()).unwrap();

        let second =
            EphemeralCa::generate(Some(&dir), None).expect("a restart must be able to republish");
        let path = second.ca_path().expect("a CA path when a dir is given");
        let second_pem = std::fs::read_to_string(path).unwrap();

        assert_eq!(
            second_pem,
            second.ca_cert_pem(),
            "the published cert must be the CA now signing leaves, not the previous one"
        );
        assert_ne!(
            first_pem, second_pem,
            "each session mints its own CA, so the file must have changed"
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(path).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o400, "the replacement is read-only too");
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn an_opened_ca_file_survives_a_directory_path_swap() {
        let parent = std::env::temp_dir().join(format!("box-ca-opened-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&parent);
        std::fs::create_dir(&parent).expect("CA parent");
        let directory = parent.join("trust");
        let moved = parent.join("moved-trust");
        std::fs::create_dir(&directory).expect("trust directory");
        let path = directory.join("cert.pem");
        let file = std::fs::File::create(&path).expect("CA descriptor");
        std::fs::rename(&directory, &moved).expect("move trust directory");
        std::fs::create_dir(&directory).expect("replacement trust directory");

        let ca =
            EphemeralCa::generate(Some(&directory), Some(&file)).expect("CA writes through file");

        assert!(
            std::fs::read_to_string(moved.join("cert.pem"))
                .expect("opened CA reads")
                .contains("BEGIN CERTIFICATE")
        );
        assert!(
            !directory.join("cert.pem").exists(),
            "the replacement directory must receive no certificate"
        );
        assert_eq!(ca.ca_path(), Some(directory.join("cert.pem").as_path()));
        let _ = std::fs::remove_dir_all(parent);
    }
}

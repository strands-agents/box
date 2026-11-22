use std::collections::{BTreeMap, BTreeSet};
use std::sync::LazyLock;

use sha2::{Digest, Sha256};

include!(concat!(env!("OUT_DIR"), "/builtin_packs.rs"));

type Fingerprint = ([u8; 32], Option<[u8; 32]>);

pub(crate) static CATALOG: LazyLock<BTreeMap<&'static str, Fingerprint>> =
    LazyLock::new(|| BUILTIN_PACKS.iter().copied().collect());

/// A loaded pack's bytes and source evidence.
#[derive(Debug, Clone, Copy)]
pub struct Pack<'a> {
    /// The catalog candidate ID, or `None` for an operator pack.
    pub id: Option<&'a str>,
    /// The original bytes read by the pack loader.
    pub bytes: &'a [u8],
    /// The original optional `grammar.toml` bytes.
    pub grammar: Option<&'a [u8]>,
    /// Whether the loader verified the catalog source location.
    pub bundled_location: Option<bool>,
}

pub(crate) fn classify<'a>(
    packs: impl IntoIterator<Item = Pack<'a>>,
) -> (Option<Vec<String>>, Option<bool>) {
    let mut builtin = BTreeSet::new();
    let mut custom = false;
    for pack in packs {
        let Some((id, expected)) = pack.id.and_then(|id| CATALOG.get_key_value(id)) else {
            custom = true;
            continue;
        };
        let actual: Fingerprint = (
            Sha256::digest(pack.bytes).into(),
            pack.grammar.map(|bytes| Sha256::digest(bytes).into()),
        );
        if actual != *expected || pack.bundled_location == Some(false) {
            custom = true;
            continue;
        }
        if pack.bundled_location.is_none() {
            return (None, None);
        }
        builtin.insert((*id).to_string());
    }
    (Some(builtin.into_iter().collect()), Some(custom))
}

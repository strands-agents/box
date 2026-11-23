use std::time::{SystemTime, UNIX_EPOCH};

use sha2::{Digest, Sha256};

use super::banner::clean;

pub(super) const HISTORY_LIMIT: usize = 1000;

#[derive(Clone, Copy, Default, Debug, PartialEq)]
pub(super) enum ActivityView {
    #[default]
    TopDenials,
    LatestDenials,
    AllOperations,
}

impl ActivityView {
    pub(super) fn title(self) -> &'static str {
        match self {
            Self::TopDenials => "Top Denials",
            Self::LatestDenials => "Latest Denials",
            Self::AllOperations => "All Operations",
        }
    }

    pub(super) fn next(self) -> Self {
        match self {
            Self::TopDenials => Self::LatestDenials,
            Self::LatestDenials => Self::AllOperations,
            Self::AllOperations => Self::TopDenials,
        }
    }
}

pub(super) struct Operation {
    pub(super) id: u64,
    pub(super) permitted: bool,
    pub(super) time: String,
    pub(super) action: String,
    pub(super) resource: String,
    pub(super) reason: String,
    pub(super) kind: [u8; 32],
}

pub(super) struct ActivityEntry<'a> {
    pub(super) operation: &'a Operation,
    pub(super) count: usize,
}

impl Operation {
    /// An operation that `time` records.
    pub(super) fn at(
        id: u64,
        permitted: bool,
        action: &str,
        resource: &str,
        reason: Option<&str>,
        rule: &str,
        time: SystemTime,
    ) -> Self {
        let action = action
            .strip_prefix("Box::Action::\"")
            .and_then(|action| action.strip_suffix('"'))
            .unwrap_or(action);
        // Top Denials groups a refused HTTP request by its `host:port`, not by each URL path.
        let grouped = if action == "http:request" {
            resource.split_once('/').map_or(resource, |(host, _)| host)
        } else {
            resource
        };
        let mut kind = Sha256::new();
        for field in [action, grouped, rule] {
            kind.update((field.len() as u64).to_le_bytes());
            kind.update(field.as_bytes());
        }
        Self {
            id,
            permitted,
            time: local_time(time),
            action: clean(action),
            resource: clean(resource),
            reason: clean(reason.unwrap_or(if permitted {
                "the request was approved"
            } else {
                "the request was refused"
            })),
            kind: kind.finalize().into(),
        }
    }
}

fn local_time(time: SystemTime) -> String {
    let seconds = time
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as nix::libc::time_t;
    let mut time = std::mem::MaybeUninit::<nix::libc::tm>::uninit();
    // SAFETY: localtime_r receives valid pointers and initializes time on success.
    unsafe {
        if nix::libc::localtime_r(&seconds, time.as_mut_ptr()).is_null() {
            return "--:--:--".into();
        }
        let time = time.assume_init();
        format!("{:02}:{:02}:{:02}", time.tm_hour, time.tm_min, time.tm_sec)
    }
}

//! `[containment]`: how a box's contained processes see the host. One field today.

use containment::ProcessInfoMode;
use serde::{Deserialize, Serialize};

/// The `[containment]` table.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ContainmentSpec {
    /// Whether each contained process gets its own `/proc`. `false` is the operator's trust grant
    /// for hosts that mask `/proc` (Kata pods, non-privileged containers), where the kernel refuses
    /// a private procfs: the workload then lists the container's processes and reads their
    /// `cmdline`, `stat`, and `status`, and still cannot signal, trace, or inspect any of them.
    #[serde(default = "private_proc_default")]
    pub(crate) private_proc: bool,
}

fn private_proc_default() -> bool {
    true
}

impl Default for ContainmentSpec {
    fn default() -> Self {
        Self { private_proc: true }
    }
}

impl ContainmentSpec {
    pub(crate) fn is_default(&self) -> bool {
        *self == Self::default()
    }

    /// What every leaf's containment request carries.
    pub(crate) fn process_info_mode(&self) -> ProcessInfoMode {
        if self.private_proc {
            ProcessInfoMode::Isolated
        } else {
            ProcessInfoMode::AllowAll
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug, serde::Deserialize)]
    struct Holder {
        #[serde(default)]
        containment: ContainmentSpec,
    }

    #[test]
    fn absent_table_and_absent_field_both_mean_a_private_proc() {
        for text in ["", "[containment]\n"] {
            let holder: Holder = toml::from_str(text).expect(text);
            assert!(holder.containment.private_proc, "{text:?}");
            assert_eq!(
                holder.containment.process_info_mode(),
                ProcessInfoMode::Isolated
            );
        }
    }

    #[test]
    fn false_shares_the_container_proc() {
        let holder: Holder = toml::from_str("[containment]\nprivate_proc = false\n").unwrap();
        assert_eq!(
            holder.containment.process_info_mode(),
            ProcessInfoMode::AllowAll
        );
        assert!(!holder.containment.is_default());
    }

    #[test]
    fn an_unknown_field_or_a_non_boolean_is_refused() {
        for text in [
            "[containment]\nwat = 1\n",
            "[containment]\nprivate_proc = \"no\"\n",
        ] {
            assert!(toml::from_str::<Holder>(text).is_err(), "{text:?}");
        }
    }
}

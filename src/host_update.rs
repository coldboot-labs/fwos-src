//! Files the Host update program and netd exchange in shared `/var` when a
//! Host update is rolled back. Both sides are the *previous* Release's code:
//! the Release that preserved the network before the update restores it.
use serde::{Deserialize, Serialize};

/// Written by the Host update program on the previous Release, before netd
/// starts, when this boot is a return from an update boot that was never
/// accepted. netd consumes it: it restores the pre-update Accepted revision
/// it preserved at staging, writes [`NETWORK_RESTORATION`], then removes it.
pub const RESTORE_PRE_UPDATE: &str = "/var/lib/fwos/restore-pre-update";

/// netd's [`NetworkRestoration`] for the last rollback. The Host update
/// program reports it with that rollback's outcome; netd removes it when it
/// preserves the network for a new update.
pub const NETWORK_RESTORATION: &str = "/var/lib/fwos/pre-update-network-restoration.json";

/// How netd dealt with the pre-update network after a Host image rollback.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "outcome")]
pub enum NetworkRestoration {
    /// The preserved network is live again as a new Accepted revision.
    Restored { revision: u64 },
    /// The failed Release left the preserved network Accepted.
    Unchanged { revision: u64 },
    /// The preserved network could not be restored; `error` says why.
    Failed { error: String },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn restoration_outcome_wire_format() {
        let restored = serde_json::to_value(NetworkRestoration::Restored { revision: 7 }).unwrap();
        assert_eq!(
            restored,
            serde_json::json!({"outcome": "restored", "revision": 7})
        );
        let failed: NetworkRestoration =
            serde_json::from_value(serde_json::json!({"outcome": "failed", "error": "x"})).unwrap();
        assert_eq!(failed, NetworkRestoration::Failed { error: "x".into() });
    }
}

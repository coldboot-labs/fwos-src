//! The complete Desired state exchanged as JSON with netd and stored as TOML.
use serde::{Deserialize, Serialize};

fn initial_revision() -> u64 {
    1
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DesiredState {
    #[serde(default = "initial_revision")]
    pub revision: u64,
    #[serde(default)]
    pub interfaces: Vec<Iface>,
    #[serde(default)]
    pub wireguard: Vec<Wg>,
    #[serde(default)]
    pub routes: Vec<StaticRoute>,
    #[serde(default)]
    pub nft_extra: Vec<String>,
    #[serde(default)]
    pub qdiscs: Vec<Qdisc>,
    #[serde(default)]
    pub hostname: Option<String>,
    #[serde(default)]
    pub lan_prefix: Option<String>,
    #[serde(default)]
    pub dhcp_pool: Option<String>,
    #[serde(default)]
    pub wan_pd: Option<String>,
    #[serde(default)]
    pub ui_exposure: Vec<String>,
}

impl Default for DesiredState {
    fn default() -> Self {
        Self {
            revision: initial_revision(),
            interfaces: Vec::new(),
            wireguard: Vec::new(),
            routes: Vec::new(),
            nft_extra: Vec::new(),
            qdiscs: Vec::new(),
            hostname: None,
            lan_prefix: None,
            dhcp_pool: None,
            wan_pd: None,
            ui_exposure: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Iface {
    pub name: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub placement: String,
    #[serde(default)]
    pub role: Option<String>,
    #[serde(default)]
    pub addresses: Vec<String>,
    #[serde(default)]
    pub vlan: Option<u16>,
    #[serde(default)]
    pub parent: Option<String>,
    #[serde(default)]
    pub dhcp: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Wg {
    pub name: String,
    pub private_key: String,
    #[serde(default)]
    pub listen_port: Option<u16>,
    #[serde(default)]
    pub addresses: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StaticRoute {
    pub to: String,
    pub via: String,
    #[serde(default)]
    pub dev: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Qdisc {
    pub dev: String,
    pub kind: String,
}

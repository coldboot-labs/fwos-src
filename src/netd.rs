use std::fs::{self, File};
use std::io::{Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{chown, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;
use std::process::{self, Command};
use std::thread;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

const SOCK: &str = "/var/lib/fwos/netd.sock";
const DESIRED: &str = "/var/lib/fwos/desired.toml";
const OPT_FILE: &str = "/var/lib/fwos/first-boot-opt.json";
const BOOTSTRAPPED: &str = "/var/lib/fwos/bootstrapped";
const HOST_NS: &str = "/run/host-netns";
const MGMT_NS: &str = "/run/netns/mgmt";
const HOST_VETH: &str = "h0mgmt";
const MGMT_VETH: &str = "m0mgmt";
const HOST_VETH_ADDR: &str = "169.254.127.1/30";
const MGMT_VETH_ADDR: &str = "169.254.127.2/30";
const HOST_VETH_GW: &str = "169.254.127.2";
const FWD_MGMT_VETH: &str = "f0mgmt";
const MGMT_FWD_VETH: &str = "m1mgmt";
const FWD_MGMT_ADDR: &str = "169.254.127.5/30";
const MGMT_FWD_ADDR: &str = "169.254.127.6/30";
const FWD_MGMT_GW: &str = "169.254.127.5";
const MGMT_FWD_IP: &str = "169.254.127.6";
const FWD_MGMT_ADDR6: &str = "fd53:1:1::5/64";
const MGMT_FWD_ADDR6: &str = "fd53:1:1::6/64";
const MGMT_FWD_IP6: &str = "fd53:1:1::6";
const CGNAT: [u8; 2] = [100, 64];

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct DesiredState {
    #[serde(default)]
    interfaces: Vec<Iface>,
    #[serde(default)]
    wireguard: Vec<Wg>,
    #[serde(default)]
    routes: Vec<StaticRoute>,
    #[serde(default)]
    nft_extra: Vec<String>,
    #[serde(default)]
    qdiscs: Vec<Qdisc>,
    #[serde(default)]
    hostname: Option<String>,
    #[serde(default)]
    lan_prefix: Option<String>,
    #[serde(default)]
    dhcp_pool: Option<String>,
    #[serde(default)]
    wan_pd: Option<String>,
    #[serde(default)]
    ui_exposure: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Iface {
    name: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    placement: String,
    #[serde(default)]
    role: Option<String>,
    #[serde(default)]
    addresses: Vec<String>,
    #[serde(default)]
    vlan: Option<u16>,
    #[serde(default)]
    parent: Option<String>,
    #[serde(default)]
    dhcp: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Wg {
    name: String,
    private_key: String,
    #[serde(default)]
    listen_port: Option<u16>,
    #[serde(default)]
    addresses: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct StaticRoute {
    to: String,
    via: String,
    #[serde(default)]
    dev: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Qdisc {
    dev: String,
    kind: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct FirstBootOpt {
    nic: String,
    mode: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    cidr: Option<String>,
}

fn main() {
    if let Err(err) = run() {
        eprintln!("netd: {err}");
        process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let path = Path::new(SOCK);
    if let Some(dir) = path.parent() {
        fs::create_dir_all(dir).map_err(|e| format!("create {}: {e}", dir.display()))?;
    }
    let _ = fs::remove_file(path);
    let listener = UnixListener::bind(path).map_err(|e| format!("bind {SOCK}: {e}"))?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o660))
        .map_err(|e| format!("chmod {SOCK}: {e}"))?;
    let gid = wheel_gid().unwrap_or(10);
    chown(path, Some(0), Some(gid)).map_err(|e| format!("chown {SOCK}: {e}"))?;
    setup_plumbing()?;
    claim_traffic_nics()?;
    if Path::new(DESIRED).exists() {
        let raw = fs::read_to_string(DESIRED).map_err(|e| format!("read {DESIRED}: {e}"))?;
        let mut state: DesiredState =
            toml::from_str(&raw).map_err(|e| format!("parse {DESIRED}: {e}"))?;
        apply(&mut state)?;
        persist(&state)?;
    } else if let Some(opt) = load_opt() {
        apply_opt(&opt)?;
    }
    loop {
        let (stream, _) = listener
            .accept()
            .map_err(|e| format!("accept {SOCK}: {e}"))?;
        if let Err(err) = handle_client(stream) {
            eprintln!("netd: {err}");
        }
    }
}

fn handle_client(mut stream: UnixStream) -> Result<(), String> {
    let mut buf = Vec::new();
    stream
        .read_to_end(&mut buf)
        .map_err(|e| format!("read socket: {e}"))?;
    let reply = match serde_json::from_slice::<Value>(&buf) {
        Ok(v) if v.get("op").and_then(Value::as_str).is_some() => handle_cmd(&v),
        Ok(v) => match serde_json::from_value::<DesiredState>(v) {
            Ok(mut state) => match apply(&mut state) {
                Ok(()) => {
                    if let Err(err) = persist(&state) {
                        json!({"ok": false, "error": err}).to_string()
                    } else {
                        json!({"ok": true}).to_string()
                    }
                }
                Err(err) => json!({"ok": false, "error": err}).to_string(),
            },
            Err(err) => json!({"ok": false, "error": err.to_string()}).to_string(),
        },
        Err(err) => json!({"ok": false, "error": err.to_string()}).to_string(),
    };
    stream
        .write_all(reply.as_bytes())
        .and_then(|_| stream.write_all(b"\n"))
        .map_err(|e| format!("write socket: {e}"))?;
    Ok(())
}

fn handle_cmd(v: &Value) -> String {
    match v.get("op").and_then(Value::as_str).unwrap_or("") {
        "list" => list_nics_reply(),
        "opt" => match parse_opt(v).and_then(apply_and_persist_opt) {
            Ok(()) => json!({"ok": true}).to_string(),
            Err(err) => json!({"ok": false, "error": err}).to_string(),
        },
        other => json!({"ok": false, "error": format!("unknown op {other}")}).to_string(),
    }
}

fn parse_opt(v: &Value) -> Result<FirstBootOpt, String> {
    let nic = v
        .get("nic")
        .and_then(Value::as_str)
        .unwrap_or("")
        .trim()
        .to_string();
    let mode = v
        .get("mode")
        .and_then(Value::as_str)
        .unwrap_or("")
        .trim()
        .to_string();
    if nic.is_empty() {
        return Err("missing nic".into());
    }
    if mode != "static" && mode != "dhcp" && mode != "slaac" {
        return Err("mode must be static, dhcp, or slaac".into());
    }
    let cidr = v
        .get("cidr")
        .and_then(Value::as_str)
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());
    if mode == "static" && cidr.is_none() {
        return Err("static opt needs a cidr".into());
    }
    Ok(FirstBootOpt { nic, mode, cidr })
}

fn persist(state: &DesiredState) -> Result<(), String> {
    let raw = toml::to_string_pretty(state).map_err(|e| format!("encode TOML: {e}"))?;
    fs::write(DESIRED, raw).map_err(|e| format!("write {DESIRED}: {e}"))
}

fn validate(state: &DesiredState) -> Result<(), String> {
    for iface in &state.interfaces {
        if iface.placement == "mgmt" {
            return Err("placement=mgmt is not a contract; use roles and ui_exposure".into());
        }
        if let Some(role) = iface.role.as_deref() {
            if !matches!(role, "wan" | "lan" | "unused" | "stick") {
                return Err(format!("unknown role {role}"));
            }
        }
    }
    let wans: Vec<&Iface> = state
        .interfaces
        .iter()
        .filter(|i| i.role.as_deref() == Some("wan"))
        .collect();
    let lans: Vec<&Iface> = state
        .interfaces
        .iter()
        .filter(|i| i.role.as_deref() == Some("lan"))
        .collect();
    if wans.is_empty() {
        return Err("need at least one WAN".into());
    }
    if lans.is_empty() {
        return Err("need at least one LAN".into());
    }
    for wan in &wans {
        for lan in &lans {
            if l2_key(wan) == l2_key(lan) {
                return Err("WAN and LAN must not share the same parent and tag".into());
            }
        }
    }
    if state.ui_exposure.is_empty() {
        return Err("ui_exposure must not be empty".into());
    }
    for name in &state.ui_exposure {
        let Some(iface) = state.interfaces.iter().find(|i| i.name == *name) else {
            return Err(format!("ui_exposure {name} is not an interface"));
        };
        if iface.role.as_deref() == Some("wan") {
            return Err("ui_exposure cannot include a WAN".into());
        }
    }
    Ok(())
}

fn l2_key(iface: &Iface) -> (String, Option<u16>) {
    let parent = iface.parent.clone().unwrap_or_else(|| {
        if iface.vlan.is_some() {
            iface
                .name
                .rsplit_once('.')
                .map(|(p, _)| p.to_string())
                .unwrap_or_else(|| iface.name.clone())
        } else {
            iface.name.clone()
        }
    });
    (parent, iface.vlan)
}

fn exposes_ui(state: &DesiredState, name: &str) -> bool {
    state.ui_exposure.iter().any(|n| n == name)
}

fn lan_l2(state: &DesiredState) -> Option<&Iface> {
    state
        .interfaces
        .iter()
        .find(|i| i.role.as_deref() == Some("lan"))
}

fn merge_lan_prefix_addr(state: &mut DesiredState) {
    let Some(prefix) = state
        .lan_prefix
        .clone()
        .or_else(|| state.dhcp_pool.as_deref().and_then(prefix_from_pool))
    else {
        return;
    };
    let Some(lan_v4) = first_v4_host(&prefix) else {
        return;
    };
    let plen = prefix.split('/').nth(1).unwrap_or("24");
    let cidr = format!("{lan_v4}/{plen}");
    if let Some(iface) = state
        .interfaces
        .iter_mut()
        .find(|i| i.role.as_deref() == Some("lan"))
    {
        if !iface
            .addresses
            .iter()
            .any(|a| a == &cidr || a.starts_with(&format!("{lan_v4}/")))
        {
            iface.addresses.push(cidr);
        }
    }
}

fn apply(state: &mut DesiredState) -> Result<(), String> {
    validate(state)?;
    // Capture UI-exposure / LAN addresses before tearing down the first-boot
    // opt so HTTPS stays at the LAN interface address after apply.
    let capture_names: Vec<String> = state
        .interfaces
        .iter()
        .filter(|i| {
            i.vlan.is_none() && (exposes_ui(state, &i.name) || i.role.as_deref() == Some("lan"))
        })
        .map(|i| i.name.clone())
        .collect();
    let mut saved: Vec<(String, Vec<String>)> = Vec::new();
    for iface in &mut state.interfaces {
        if !capture_names.iter().any(|n| n == &iface.name) {
            continue;
        }
        let Ok((mut addrs, _)) = capture_ipv4(&iface.name) else {
            continue;
        };
        if addrs.is_empty() {
            addrs = iface.addresses.clone();
        } else if iface.addresses.is_empty() {
            iface.addresses = addrs.clone();
        }
        saved.push((iface.name.clone(), addrs));
    }
    merge_lan_prefix_addr(state);
    discard_opt()?;
    setup_plumbing()?;
    for iface in &state.interfaces {
        if iface.vlan.is_none() {
            ensure_in_fwd(&iface.name)?;
            run_ip(&["link", "set", &iface.name, "up"])?;
            let extra = saved
                .iter()
                .find(|(n, _)| n == &iface.name)
                .map(|(_, a)| a.clone())
                .unwrap_or_default();
            for addr in extra.iter().chain(iface.addresses.iter()) {
                add_addr(&iface.name, addr)?;
            }
        }
    }
    program_vlans(state)?;
    host_default_via_mgmt()?;
    program_wg(state)?;
    program_routes(state)?;
    program_qdiscs(state)?;
    program_lan_services(state)?;
    persist(state)?;
    program_nft(state)
}

fn ensure_in_fwd(name: &str) -> Result<(), String> {
    if link_exists(name)? {
        return Ok(());
    }
    let fwd = File::open("/proc/self/ns/net").map_err(|e| format!("open fwd netns: {e}"))?;
    let host = File::open(HOST_NS).map_err(|e| format!("open host netns: {e}"))?;
    setns_net(host.as_raw_fd()).map_err(|e| format!("setns host: {e}"))?;
    let ns_path = format!("/proc/{}/fd/{}", process::id(), fwd.as_raw_fd());
    let moved = run_ip(&["link", "set", name, "netns", &ns_path]);
    let back = setns_net(fwd.as_raw_fd());
    moved?;
    back.map_err(|e| format!("setns fwd: {e}"))?;
    Ok(())
}

fn with_netns<T>(ns_path: &str, f: impl FnOnce() -> Result<T, String>) -> Result<T, String> {
    let cur = File::open("/proc/self/ns/net").map_err(|e| format!("open current netns: {e}"))?;
    let ns = File::open(ns_path).map_err(|e| format!("open {ns_path}: {e}"))?;
    setns_net(ns.as_raw_fd()).map_err(|e| format!("setns {ns_path}: {e}"))?;
    let r = f();
    let back = setns_net(cur.as_raw_fd()).map_err(|e| format!("setns back: {e}"));
    match (r, back) {
        (Ok(v), Ok(())) => Ok(v),
        (Err(e), _) => Err(e),
        (Ok(_), Err(e)) => Err(e),
    }
}

fn with_host_net<T>(f: impl FnOnce() -> Result<T, String>) -> Result<T, String> {
    with_netns(HOST_NS, f)
}

fn with_mgmt_net<T>(f: impl FnOnce() -> Result<T, String>) -> Result<T, String> {
    with_netns(MGMT_NS, f)
}

fn capture_host_ipv4(name: &str) -> Result<(Vec<String>, Option<String>), String> {
    with_host_net(|| {
        let addr_out = ip_cmd()
            .args(["-o", "addr", "show", "dev", name])
            .output()
            .map_err(|e| format!("ip addr show {name}: {e}"))?;
        let mut addrs = Vec::new();
        for word in String::from_utf8_lossy(&addr_out.stdout).split_whitespace() {
            if word.contains('/') && word.contains('.') {
                addrs.push(word.to_string());
            }
        }
        let route_out = ip_cmd()
            .args(["-o", "route", "show", "default"])
            .output()
            .map_err(|e| format!("ip route: {e}"))?;
        let route = String::from_utf8_lossy(&route_out.stdout);
        let gw = if route.contains(name) {
            route
                .split_whitespace()
                .skip_while(|w| *w != "via")
                .nth(1)
                .map(str::to_string)
        } else {
            None
        };
        Ok((addrs, gw))
    })
}

fn ensure_host_mgmt_veth() -> Result<(), String> {
    with_host_net(|| {
        let status = ip_cmd()
            .args(["link", "show", "dev", HOST_VETH])
            .status()
            .map_err(|e| format!("ip link show {HOST_VETH}: {e}"))?;
        if status.success() {
            return Ok(());
        }
        run_ip(&[
            "link", "add", HOST_VETH, "type", "veth", "peer", "name", MGMT_VETH,
        ])?;
        run_ip(&["link", "set", MGMT_VETH, "netns", MGMT_NS])?;
        Ok(())
    })?;
    with_host_net(|| {
        add_addr(HOST_VETH, HOST_VETH_ADDR)?;
        run_ip(&["link", "set", HOST_VETH, "up"])?;
        Ok(())
    })?;
    with_mgmt_net(|| {
        add_addr(MGMT_VETH, MGMT_VETH_ADDR)?;
        run_ip(&["link", "set", MGMT_VETH, "up"])?;
        Ok(())
    })?;
    Ok(())
}

fn host_default_via_mgmt() -> Result<(), String> {
    with_host_net(|| run_ip(&["route", "replace", "default", "via", HOST_VETH_GW]))
}

fn ensure_fwd_mgmt_veth() -> Result<(), String> {
    if !link_exists(FWD_MGMT_VETH)? {
        run_ip(&[
            "link",
            "add",
            FWD_MGMT_VETH,
            "type",
            "veth",
            "peer",
            "name",
            MGMT_FWD_VETH,
        ])?;
        run_ip(&["link", "set", MGMT_FWD_VETH, "netns", MGMT_NS])?;
    }
    add_addr(FWD_MGMT_VETH, FWD_MGMT_ADDR)?;
    add_addr(FWD_MGMT_VETH, FWD_MGMT_ADDR6)?;
    run_ip(&["link", "set", FWD_MGMT_VETH, "up"])?;
    with_mgmt_net(|| {
        add_addr(MGMT_FWD_VETH, MGMT_FWD_ADDR)?;
        add_addr(MGMT_FWD_VETH, MGMT_FWD_ADDR6)?;
        run_ip(&["link", "set", MGMT_FWD_VETH, "up"])?;
        Ok(())
    })?;
    Ok(())
}

fn program_vlans(state: &DesiredState) -> Result<(), String> {
    for iface in &state.interfaces {
        let Some(vid) = iface.vlan else {
            continue;
        };
        let parent = iface.parent.clone().unwrap_or_else(|| {
            iface
                .name
                .rsplit_once('.')
                .map(|(p, _)| p.to_string())
                .unwrap_or_else(|| iface.name.clone())
        });
        if !link_exists(&iface.name)? {
            run_ip(&[
                "link",
                "add",
                "link",
                &parent,
                "name",
                &iface.name,
                "type",
                "vlan",
                "id",
                &vid.to_string(),
            ])?;
        }
        run_ip(&["link", "set", &iface.name, "up"])?;
        for addr in &iface.addresses {
            add_addr(&iface.name, addr)?;
        }
    }
    Ok(())
}

fn link_exists(name: &str) -> Result<bool, String> {
    let status = ip_cmd()
        .args(["link", "show", "dev", name])
        .status()
        .map_err(|e| format!("ip link show {name}: {e}"))?;
    Ok(status.success())
}

fn add_addr(dev: &str, cidr: &str) -> Result<(), String> {
    let output = ip_cmd()
        .args(["addr", "add", cidr, "dev", dev])
        .output()
        .map_err(|e| format!("ip addr add {cidr} dev {dev}: {e}"))?;
    if output.status.success() {
        return Ok(());
    }
    let err = String::from_utf8_lossy(&output.stderr);
    if err.contains("File exists") || err.contains("already assigned") {
        Ok(())
    } else {
        Err(format!(
            "ip addr add {cidr} dev {dev} failed: {}",
            err.trim()
        ))
    }
}

fn program_lan_services(state: &DesiredState) -> Result<(), String> {
    let Some(lan) = lan_l2(state) else {
        return Ok(());
    };
    let prefix = state
        .lan_prefix
        .clone()
        .or_else(|| state.dhcp_pool.as_deref().and_then(prefix_from_pool));
    let Some(prefix) = prefix else {
        return Ok(());
    };
    let lan_v4 = first_v4_host(&prefix).ok_or_else(|| "lan_prefix has no v4 host".to_string())?;
    let plen = prefix.split('/').nth(1).unwrap_or("24");
    add_addr(&lan.name, &format!("{lan_v4}/{plen}"))?;
    if let Some(pd) = state.wan_pd.as_deref() {
        if let Some(v6) = pd_lan_addr(pd) {
            add_addr(&lan.name, &v6)?;
        }
    }
    let Some(pool) = state.dhcp_pool.as_deref() else {
        return Ok(());
    };
    fs::create_dir_all("/var/lib/fwos/kea").map_err(|e| format!("mkdir kea: {e}"))?;
    fs::create_dir_all("/var/lib/fwos/unbound").map_err(|e| format!("mkdir unbound: {e}"))?;
    let (p1, p2) = split_pool(pool);
    let kea4 = kea_dhcp4_conf(&lan.name, &prefix, &p1, &p2, &lan_v4);
    fs::write("/var/lib/fwos/kea/kea-dhcp4.conf", kea4)
        .map_err(|e| format!("write kea-dhcp4: {e}"))?;
    if let Some(pd) = state.wan_pd.as_deref() {
        if let (Some(v6_sub), Some((v6p1, v6p2))) = (pd_subnet64(pd), pd_pool(pd)) {
            let kea6 = kea_dhcp6_conf(&lan.name, &v6_sub, &v6p1, &v6p2);
            fs::write("/var/lib/fwos/kea/kea-dhcp6.conf", kea6)
                .map_err(|e| format!("write kea-dhcp6: {e}"))?;
        }
    }
    let unbound = unbound_conf(&lan_v4, &prefix);
    fs::write("/var/lib/fwos/unbound/unbound.conf", unbound)
        .map_err(|e| format!("write unbound: {e}"))?;
    Ok(())
}

fn kea_dhcp4_conf(dev: &str, prefix: &str, p1: &str, p2: &str, lan_v4: &str) -> String {
    format!(
        r#"{{
  "Dhcp4": {{
    "interfaces-config": {{ "interfaces": [ "{dev}" ], "re-detect": true }},
    "lease-database": {{ "type": "memfile", "persist": false, "name": "/tmp/dhcp4.leases" }},
    "valid-lifetime": 3600,
    "subnet4": [ {{
      "id": 1,
      "subnet": "{prefix}",
      "interface": "{dev}",
      "pools": [ {{ "pool": "{p1} - {p2}" }} ],
      "option-data": [
        {{ "name": "routers", "data": "{lan_v4}" }},
        {{ "name": "domain-name-servers", "data": "{lan_v4}" }}
      ]
    }} ],
    "loggers": [ {{ "name": "kea-dhcp4", "severity": "INFO", "output-options": [ {{ "output": "stdout" }} ] }} ]
  }}
}}
"#
    )
}

fn kea_dhcp6_conf(dev: &str, subnet: &str, p1: &str, p2: &str) -> String {
    format!(
        r#"{{
  "Dhcp6": {{
    "interfaces-config": {{ "interfaces": [ "{dev}" ], "re-detect": true }},
    "lease-database": {{ "type": "memfile", "persist": false, "name": "/tmp/dhcp6.leases" }},
    "server-id": {{ "type": "LLT", "persist": false }},
    "subnet6": [ {{
      "id": 1,
      "subnet": "{subnet}",
      "interface": "{dev}",
      "pools": [ {{ "pool": "{p1} - {p2}" }} ]
    }} ],
    "loggers": [ {{ "name": "kea-dhcp6", "severity": "INFO", "output-options": [ {{ "output": "stdout" }} ] }} ]
  }}
}}
"#
    )
}

fn unbound_conf(lan_v4: &str, prefix: &str) -> String {
    format!(
        "server:\n  interface: {lan_v4}\n  port: 53\n  access-control: {prefix} allow\n  access-control: 127.0.0.0/8 allow\n  do-daemonize: no\n  username: \"\"\n  chroot: \"\"\n  directory: \"/tmp\"\n  pidfile: \"/tmp/unbound.pid\"\n  use-syslog: no\n  logfile: /dev/null\n"
    )
}

fn split_pool(pool: &str) -> (String, String) {
    let p = pool.replace(' ', "");
    match p.split_once('-') {
        Some((a, b)) => (a.to_string(), b.to_string()),
        None => (p.clone(), p),
    }
}

fn prefix_from_pool(pool: &str) -> Option<String> {
    let (start, _) = split_pool(pool);
    let mut o: Vec<u8> = start.split('.').filter_map(|s| s.parse().ok()).collect();
    if o.len() != 4 {
        return None;
    }
    o[3] = 0;
    Some(format!("{}.{}.{}.{}/24", o[0], o[1], o[2], o[3]))
}

fn first_v4_host(cidr: &str) -> Option<String> {
    let ip = cidr.split('/').next()?;
    let mut o: Vec<u8> = ip.split('.').filter_map(|s| s.parse().ok()).collect();
    if o.len() != 4 {
        return None;
    }
    if o[3] == 0 {
        o[3] = 1;
    }
    Some(format!("{}.{}.{}.{}", o[0], o[1], o[2], o[3]))
}

fn pd_lan_addr(pd: &str) -> Option<String> {
    let base = pd.split('/').next()?.trim_end_matches(':');
    Some(format!("{base}::1/64"))
}

fn pd_subnet64(pd: &str) -> Option<String> {
    let base = pd.split('/').next()?.trim_end_matches(':');
    Some(format!("{base}::/64"))
}

fn pd_pool(pd: &str) -> Option<(String, String)> {
    let base = pd.split('/').next()?.trim_end_matches(':');
    Some((format!("{base}::100"), format!("{base}::1ff")))
}

fn program_nft(state: &DesiredState) -> Result<(), String> {
    let wans: Vec<&str> = state
        .interfaces
        .iter()
        .filter(|i| i.role.as_deref() == Some("wan"))
        .map(|i| i.name.as_str())
        .collect();
    let v4_wan = state
        .interfaces
        .iter()
        .any(|i| i.role.as_deref() == Some("wan") && i.addresses.iter().any(|a| a.contains('.')));
    let exposure = ui_exposure(state);
    let mut rules = String::from("flush ruleset\n");
    rules.push_str(&host_pull_nft());
    rules.push_str("table inet fwos {\n");
    rules.push_str("  chain input {\n");
    rules.push_str("    type filter hook input priority filter; policy accept;\n");
    rules.push_str("    iifname \"lo\" accept\n");
    for extra in &state.nft_extra {
        rules.push_str(&format!("    {extra}\n"));
    }
    for wan in &wans {
        rules.push_str(&format!(
            "    iifname \"{wan}\" ct state established,related accept\n"
        ));
        rules.push_str(&format!("    iifname \"{wan}\" drop\n"));
    }
    rules.push_str("  }\n");
    rules.push_str("  chain forward {\n");
    rules.push_str("    type filter hook forward priority filter; policy drop;\n");
    rules.push_str("    ct state established,related accept\n");
    // Host-netns pulls and DNATed UI replies arrive from mgmt on this veth.
    rules.push_str(&format!("    iifname \"{FWD_MGMT_VETH}\" accept\n"));
    for (name, _) in &exposure {
        rules.push_str(&format!(
            "    iifname \"{name}\" oifname \"{FWD_MGMT_VETH}\" tcp dport 443 accept\n"
        ));
    }
    for wan in &wans {
        rules.push_str(&format!("    oifname \"{wan}\" accept\n"));
    }
    rules.push_str("  }\n");
    if !exposure.is_empty() {
        rules.push_str("  chain prerouting {\n");
        rules.push_str("    type nat hook prerouting priority dstnat; policy accept;\n");
        for (name, addrs) in &exposure {
            let ips = expose_ips(addrs);
            if ips.is_empty() {
                // LAN L2 with no address yet: DNAT only on that interface, never on a WAN.
                rules.push_str(&format!(
                    "    iifname \"{name}\" tcp dport 443 dnat ip to {MGMT_FWD_IP}\n"
                ));
                continue;
            }
            for ip in ips {
                if ip.contains(':') {
                    rules.push_str(&format!(
                        "    iifname \"{name}\" ip6 daddr {ip} tcp dport 443 dnat ip6 to {MGMT_FWD_IP6}\n"
                    ));
                } else {
                    rules.push_str(&format!(
                        "    iifname \"{name}\" ip daddr {ip} tcp dport 443 dnat ip to {MGMT_FWD_IP}\n"
                    ));
                }
            }
        }
        rules.push_str("  }\n");
    }
    if v4_wan {
        rules.push_str("  chain postrouting {\n");
        rules.push_str("    type nat hook postrouting priority srcnat; policy accept;\n");
        for wan in &wans {
            rules.push_str(&format!("    oifname \"{wan}\" masquerade\n"));
        }
        rules.push_str("  }\n");
    }
    rules.push_str("}\n");
    nft_apply(&rules)
}

fn nft_apply(rules: &str) -> Result<(), String> {
    let mut child = Command::new("nft")
        .env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin")
        .arg("-f")
        .arg("-")
        .stdin(std::process::Stdio::piped())
        .spawn()
        .map_err(|e| format!("nft: {e}"))?;
    child
        .stdin
        .as_mut()
        .ok_or_else(|| "nft stdin".to_string())?
        .write_all(rules.as_bytes())
        .map_err(|e| format!("nft write: {e}"))?;
    let status = child.wait().map_err(|e| format!("nft wait: {e}"))?;
    if status.success() {
        Ok(())
    } else {
        Err(format!("nft -f failed ({status})"))
    }
}

fn program_wg(state: &DesiredState) -> Result<(), String> {
    for wg in &state.wireguard {
        if !link_exists(&wg.name)? {
            run_ip(&["link", "add", &wg.name, "type", "wireguard"])?;
        }
        let mut args = vec!["set".to_string(), wg.name.clone()];
        args.push("private-key".into());
        args.push("/dev/stdin".into());
        if let Some(port) = wg.listen_port {
            args.push("listen-port".into());
            args.push(port.to_string());
        }
        let mut child = Command::new("wg")
            .env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin")
            .args(&args)
            .stdin(std::process::Stdio::piped())
            .spawn()
            .map_err(|e| format!("wg: {e}"))?;
        child
            .stdin
            .as_mut()
            .ok_or_else(|| "wg stdin".to_string())?
            .write_all(wg.private_key.as_bytes())
            .map_err(|e| format!("wg write: {e}"))?;
        let status = child.wait().map_err(|e| format!("wg wait: {e}"))?;
        if !status.success() {
            return Err(format!("wg set {} failed ({status})", wg.name));
        }
        run_ip(&["link", "set", &wg.name, "up"])?;
        for addr in &wg.addresses {
            add_addr(&wg.name, addr)?;
        }
    }
    Ok(())
}

fn program_routes(state: &DesiredState) -> Result<(), String> {
    for route in &state.routes {
        let mut args = vec!["route", "replace", &route.to, "via", &route.via];
        if let Some(dev) = route.dev.as_deref() {
            args.push("dev");
            args.push(dev);
        }
        run_ip(&args)?;
    }
    Ok(())
}

fn program_qdiscs(state: &DesiredState) -> Result<(), String> {
    for q in &state.qdiscs {
        let output = Command::new("tc")
            .env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin")
            .args(["qdisc", "replace", "dev", &q.dev, "root", &q.kind])
            .output()
            .map_err(|e| format!("tc qdisc: {e}"))?;
        if !output.status.success() {
            return Err(format!(
                "tc qdisc replace dev {} root {} failed: {}",
                q.dev,
                q.kind,
                String::from_utf8_lossy(&output.stderr).trim()
            ));
        }
    }
    Ok(())
}

fn run_ip(args: &[&str]) -> Result<(), String> {
    let output = ip_cmd()
        .args(args)
        .output()
        .map_err(|e| format!("ip {}: {e}", args.join(" ")))?;
    if output.status.success() {
        Ok(())
    } else {
        Err(format!(
            "ip {} failed: {}",
            args.join(" "),
            String::from_utf8_lossy(&output.stderr).trim()
        ))
    }
}

fn ip_cmd() -> Command {
    let mut cmd = Command::new("ip");
    cmd.env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin");
    cmd
}

fn setns_net(fd: i32) -> Result<(), String> {
    let rc = unsafe { libc::setns(fd, libc::CLONE_NEWNET) };
    if rc == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error().to_string())
    }
}

fn setup_plumbing() -> Result<(), String> {
    ensure_fwd_mgmt_veth()?;
    ensure_host_mgmt_veth()?;
    host_default_via_mgmt()?;
    with_mgmt_net(|| {
        let _ = run_ip(&["route", "replace", "default", "via", FWD_MGMT_GW]);
        let _ = fs::write("/proc/sys/net/ipv4/ip_forward", "1");
        Ok(())
    })?;
    let _ = fs::write("/proc/sys/net/ipv4/ip_forward", "1");
    write_sysctl("all", "ipv4", "rp_filter", "2");
    write_sysctl("default", "ipv4", "rp_filter", "2");
    write_sysctl(FWD_MGMT_VETH, "ipv4", "rp_filter", "2");
    // Host-netns pull sources live on h0mgmt (169.254.127.0/30), not on the
    // fwd↔mgmt /30. Return traffic after masquerade un-SNAT needs this route.
    let _ = run_ip(&[
        "route",
        "replace",
        "169.254.127.0/30",
        "via",
        MGMT_FWD_IP,
        "dev",
        FWD_MGMT_VETH,
    ]);
    let _ = nft_apply("destroy table ip fwos-pull\n");
    let _ = nft_apply(&host_pull_nft());
    Ok(())
}

fn host_pull_nft() -> String {
    String::from(
        "table ip fwos-pull {\n  chain postrouting {\n    type nat hook postrouting priority srcnat; policy accept;\n    ip saddr 169.254.127.0/30 masquerade\n  }\n}\n",
    )
}

fn claim_traffic_nics() -> Result<(), String> {
    let names = host_netns_ethernet()?;
    for name in names {
        ensure_in_fwd(&name)?;
        lock_unopted(&name)?;
        let _ = run_ip(&["link", "set", &name, "up"]);
    }
    Ok(())
}

fn host_netns_ethernet() -> Result<Vec<String>, String> {
    with_host_net(|| {
        let out = ip_cmd()
            .args(["-o", "link", "show"])
            .output()
            .map_err(|e| format!("ip link show: {e}"))?;
        let mut names = Vec::new();
        for line in String::from_utf8_lossy(&out.stdout).lines() {
            let name = link_name(line);
            if is_ethernet(&name) {
                names.push(name);
            }
        }
        Ok(names)
    })
}

fn link_name(line: &str) -> String {
    let name = line.split(':').nth(1).unwrap_or("").trim();
    name.split('@').next().unwrap_or(name).to_string()
}

fn addr_dev(line: &str) -> String {
    line.split_whitespace()
        .nth(1)
        .unwrap_or("")
        .split('@')
        .next()
        .unwrap_or("")
        .to_string()
}

fn is_ethernet(name: &str) -> bool {
    name.starts_with("enp")
        || name.starts_with("eth")
        || name.starts_with("ens")
        || name.starts_with("eno")
}

fn lock_unopted(nic: &str) -> Result<(), String> {
    write_sysctl(nic, "ipv6", "accept_ra", "0");
    write_sysctl(nic, "ipv6", "autoconf", "0");
    write_sysctl(nic, "ipv4", "rp_filter", "2");
    let _ = run_ip(&["addr", "flush", "dev", nic]);
    Ok(())
}

fn write_sysctl(nic: &str, fam: &str, key: &str, val: &str) {
    let path = format!("/proc/sys/net/{fam}/conf/{nic}/{key}");
    let _ = fs::write(&path, val);
}

fn load_opt() -> Option<FirstBootOpt> {
    let raw = fs::read_to_string(OPT_FILE).ok()?;
    serde_json::from_str(&raw).ok()
}

fn persist_opt(opt: &FirstBootOpt) -> Result<(), String> {
    let raw = serde_json::to_string_pretty(opt).map_err(|e| format!("encode opt: {e}"))?;
    if let Some(dir) = Path::new(OPT_FILE).parent() {
        fs::create_dir_all(dir).map_err(|e| format!("mkdir {}: {e}", dir.display()))?;
    }
    fs::write(OPT_FILE, raw).map_err(|e| format!("write {OPT_FILE}: {e}"))?;
    // Hard reset (QEMU system_reset / power loss) must still see the opt.
    if let Ok(f) = File::open(OPT_FILE) {
        let _ = f.sync_all();
    }
    if let Ok(dir) = File::open("/var/lib/fwos") {
        let _ = dir.sync_all();
    }
    unsafe {
        libc::sync();
    }
    Ok(())
}

fn apply_and_persist_opt(opt: FirstBootOpt) -> Result<(), String> {
    if Path::new(BOOTSTRAPPED).exists() {
        return Err("already bootstrapped".into());
    }
    apply_opt(&opt)?;
    persist_opt(&opt)
}

fn apply_opt(opt: &FirstBootOpt) -> Result<(), String> {
    if let Some(prev) = load_opt() {
        if prev.nic != opt.nic || prev.mode != opt.mode || prev.cidr != opt.cidr {
            teardown_opt(&prev)?;
        }
    }
    setup_plumbing()?;
    ensure_in_fwd(&opt.nic)?;
    run_ip(&["link", "set", &opt.nic, "up"])?;
    match opt.mode.as_str() {
        "static" => {
            let cidr = opt.cidr.as_deref().ok_or("static opt needs a cidr")?;
            add_addr(&opt.nic, cidr)?;
        }
        "dhcp" => ephemeral_dhcp(&opt.nic)?,
        "slaac" => {
            // fwd has IPv6 forwarding on (Host pull / DNAT). Kernel ignores
            // accept_ra=1 on a forwarding interface; 2 still learns RAs.
            write_sysctl(&opt.nic, "ipv6", "accept_ra", "2");
            write_sysctl(&opt.nic, "ipv6", "autoconf", "1");
        }
        other => return Err(format!("unknown opt mode {other}")),
    }
    let addrs = match opt.mode.as_str() {
        "slaac" => wait_expose_cidrs(&opt.nic)?,
        _ => iface_cidrs(&opt.nic)?,
    };
    program_first_boot_nft(&opt.nic, &addrs)
}

fn wait_expose_cidrs(nic: &str) -> Result<Vec<String>, String> {
    let deadline = Instant::now() + Duration::from_secs(8);
    loop {
        let addrs = iface_cidrs(nic)?;
        if !expose_ips(&addrs).is_empty() || Instant::now() >= deadline {
            return Ok(addrs);
        }
        thread::sleep(Duration::from_millis(200));
    }
}

fn teardown_opt(opt: &FirstBootOpt) -> Result<(), String> {
    stop_dhclient();
    if opt.mode == "slaac" {
        write_sysctl(&opt.nic, "ipv6", "accept_ra", "0");
        write_sysctl(&opt.nic, "ipv6", "autoconf", "0");
    }
    if link_exists(&opt.nic)? {
        lock_unopted(&opt.nic)?;
        let _ = run_ip(&["link", "set", &opt.nic, "up"]);
    }
    let _ = nft_apply("destroy table ip fwos-first-boot\ndestroy table ip6 fwos-first-boot\n");
    Ok(())
}

fn discard_opt() -> Result<(), String> {
    if let Some(opt) = load_opt() {
        teardown_opt(&opt)?;
    }
    let _ = fs::remove_file(OPT_FILE);
    Ok(())
}

fn ephemeral_dhcp(nic: &str) -> Result<(), String> {
    stop_dhclient();
    write_dhclient_script()?;
    let output = Command::new("dhclient")
        .env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin")
        .args([
            "-1",
            "-sf",
            "/var/lib/fwos/dhclient-script",
            "-lf",
            "/var/lib/fwos/dhclient.leases",
            "-pf",
            "/var/lib/fwos/dhclient.pid",
            nic,
        ])
        .output()
        .map_err(|e| format!("dhclient: {e}"))?;
    if output.status.success() {
        Ok(())
    } else {
        Err(format!(
            "dhcp on {nic} failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ))
    }
}

fn write_dhclient_script() -> Result<(), String> {
    let script = r#"#!/bin/sh
case "${reason}" in
BOUND|RENEW|REBIND|REBOOT)
  pfx="${new_prefix}"
  if [ -z "${pfx}" ]; then
    pfx=24
  fi
  ip addr replace "${new_ip_address}/${pfx}" dev "${interface}"
  if [ -n "${new_routers}" ]; then
    gw=$(echo "${new_routers}" | awk '{print $1}')
    ip route replace default via "${gw}" dev "${interface}"
  fi
  ;;
esac
exit 0
"#;
    fs::write("/var/lib/fwos/dhclient-script", script)
        .map_err(|e| format!("write dhclient-script: {e}"))?;
    let mut perms = fs::metadata("/var/lib/fwos/dhclient-script")
        .map_err(|e| format!("stat dhclient-script: {e}"))?
        .permissions();
    perms.set_mode(0o755);
    fs::set_permissions("/var/lib/fwos/dhclient-script", perms)
        .map_err(|e| format!("chmod dhclient-script: {e}"))
}

fn stop_dhclient() {
    if let Ok(pid) = fs::read_to_string("/var/lib/fwos/dhclient.pid") {
        let pid = pid.trim();
        if !pid.is_empty() {
            let _ = Command::new("kill")
                .env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin")
                .args(["-TERM", pid])
                .status();
        }
    }
    let _ = fs::remove_file("/var/lib/fwos/dhclient.pid");
}

fn program_first_boot_nft(nic: &str, cidrs: &[String]) -> Result<(), String> {
    let ips = expose_ips(cidrs);
    let _ = nft_apply("destroy table ip fwos-first-boot\ndestroy table ip6 fwos-first-boot\n");
    let rules = first_boot_nft(nic, &ips);
    if rules.trim().is_empty() {
        Ok(())
    } else {
        nft_apply(&rules)
    }
}

fn first_boot_nft(nic: &str, ips: &[String]) -> String {
    let mut rules = String::new();
    let v4: Vec<&str> = ips
        .iter()
        .map(|s| s.as_str())
        .filter(|s| !s.contains(':'))
        .collect();
    let v6: Vec<&str> = ips
        .iter()
        .map(|s| s.as_str())
        .filter(|s| s.contains(':'))
        .collect();
    if !v4.is_empty() {
        rules.push_str("table ip fwos-first-boot {\n");
        rules.push_str("  chain prerouting {\n");
        rules.push_str("    type nat hook prerouting priority dstnat; policy accept;\n");
        for ip in &v4 {
            rules.push_str(&format!(
                "    iifname \"{nic}\" ip daddr {ip} tcp dport 443 dnat ip to {MGMT_FWD_IP}\n"
            ));
        }
        rules.push_str("  }\n");
        rules.push_str("  chain forward {\n");
        rules.push_str("    type filter hook forward priority filter; policy accept;\n");
        rules.push_str(&format!(
            "    iifname \"{nic}\" oifname \"{FWD_MGMT_VETH}\" tcp dport 443 accept\n"
        ));
        rules.push_str("  }\n");
        rules.push_str("}\n");
    }
    if !v6.is_empty() {
        rules.push_str("table ip6 fwos-first-boot {\n");
        rules.push_str("  chain prerouting {\n");
        rules.push_str("    type nat hook prerouting priority dstnat; policy accept;\n");
        for ip in &v6 {
            rules.push_str(&format!(
                "    iifname \"{nic}\" ip6 daddr {ip} tcp dport 443 dnat ip6 to {MGMT_FWD_IP6}\n"
            ));
        }
        rules.push_str("  }\n");
        rules.push_str("  chain forward {\n");
        rules.push_str("    type filter hook forward priority filter; policy accept;\n");
        rules.push_str(&format!(
            "    iifname \"{nic}\" oifname \"{FWD_MGMT_VETH}\" tcp dport 443 accept\n"
        ));
        rules.push_str("  }\n");
        rules.push_str("}\n");
    }
    rules
}

fn ui_exposure(state: &DesiredState) -> Vec<(String, Vec<String>)> {
    state
        .ui_exposure
        .iter()
        .filter_map(|name| {
            state
                .interfaces
                .iter()
                .find(|i| i.name == *name && i.role.as_deref() != Some("wan"))
        })
        .map(|i| (i.name.clone(), i.addresses.clone()))
        .collect()
}

fn expose_ips(cidrs: &[String]) -> Vec<String> {
    let mut out = Vec::new();
    for cidr in cidrs {
        let ip = cidr.split('/').next().unwrap_or(cidr);
        if expose_allowed(ip) && !out.iter().any(|e| e == ip) {
            out.push(ip.to_string());
        }
    }
    out
}

fn expose_allowed(ip: &str) -> bool {
    if let Ok(v4) = ip.parse::<std::net::Ipv4Addr>() {
        if v4.is_loopback() {
            return false;
        }
        let o = v4.octets();
        if o[0] == CGNAT[0] && (64..=127).contains(&o[1]) {
            return false;
        }
        // Host↔mgmt plumbing is not operator reachability.
        if o[0] == 169 && o[1] == 254 && o[2] == 127 {
            return false;
        }
        return v4.is_private() || v4.is_link_local();
    }
    if let Ok(v6) = ip.parse::<std::net::Ipv6Addr>() {
        if v6.is_loopback() {
            return false;
        }
        return v6.is_unicast_link_local() || (v6.octets()[0] & 0xfe) == 0xfc;
    }
    false
}

fn list_nics_reply() -> String {
    let nics = list_ethernet_json();
    let opt = load_opt();
    json!({"ok": true, "nics": nics, "opt": opt}).to_string()
}

fn list_ethernet_json() -> Vec<Value> {
    let Ok(out) = ip_cmd().args(["-o", "link", "show"]).output() else {
        return Vec::new();
    };
    let mut nics: Vec<(String, Vec<String>)> = Vec::new();
    for line in String::from_utf8_lossy(&out.stdout).lines() {
        let name = link_name(line);
        if is_ethernet(&name) {
            nics.push((name, Vec::new()));
        }
    }
    if let Ok(addrs) = ip_cmd().args(["-o", "addr", "show"]).output() {
        for line in String::from_utf8_lossy(&addrs.stdout).lines() {
            let name = addr_dev(line);
            let Some((_, addrs)) = nics.iter_mut().find(|(n, _)| n == &name) else {
                continue;
            };
            if let Some(cidr) = addr_cidr(line) {
                if !addrs.contains(&cidr) {
                    addrs.push(cidr);
                }
            }
        }
    }
    nics.into_iter()
        .map(|(name, addresses)| json!({"name": name, "addresses": addresses}))
        .collect()
}

fn addr_cidr(line: &str) -> Option<String> {
    let mut toks = line.split_whitespace();
    while let Some(tok) = toks.next() {
        if tok == "inet" || tok == "inet6" {
            return toks.next().map(str::to_string);
        }
    }
    None
}

fn iface_cidrs(name: &str) -> Result<Vec<String>, String> {
    let out = ip_cmd()
        .args(["-o", "addr", "show", "dev", name])
        .output()
        .map_err(|e| format!("ip addr show {name}: {e}"))?;
    let mut addrs = Vec::new();
    for line in String::from_utf8_lossy(&out.stdout).lines() {
        if let Some(cidr) = addr_cidr(line) {
            if !addrs.contains(&cidr) {
                addrs.push(cidr);
            }
        }
    }
    Ok(addrs)
}

fn capture_ipv4(name: &str) -> Result<(Vec<String>, Option<String>), String> {
    if link_exists(name)? {
        return capture_ipv4_here(name);
    }
    capture_host_ipv4(name)
}

fn capture_ipv4_here(name: &str) -> Result<(Vec<String>, Option<String>), String> {
    let addr_out = ip_cmd()
        .args(["-o", "addr", "show", "dev", name])
        .output()
        .map_err(|e| format!("ip addr show {name}: {e}"))?;
    let mut addrs = Vec::new();
    for word in String::from_utf8_lossy(&addr_out.stdout).split_whitespace() {
        if word.contains('/') && word.contains('.') {
            addrs.push(word.to_string());
        }
    }
    let route_out = ip_cmd()
        .args(["-o", "route", "show", "default"])
        .output()
        .map_err(|e| format!("ip route: {e}"))?;
    let route = String::from_utf8_lossy(&route_out.stdout);
    let gw = if route.contains(name) {
        route
            .split_whitespace()
            .skip_while(|w| *w != "via")
            .nth(1)
            .map(str::to_string)
    } else {
        None
    };
    Ok((addrs, gw))
}

fn wheel_gid() -> Option<u32> {
    let group = fs::read_to_string("/etc/group").ok()?;
    for line in group.lines() {
        let mut parts = line.split(':');
        if parts.next()? != "wheel" {
            continue;
        }
        parts.next()?;
        return parts.next()?.parse().ok();
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cmd_json_is_not_empty_desired() {
        let v: Value = serde_json::from_str(r#"{"op":"list"}"#).unwrap();
        assert!(v.get("op").and_then(Value::as_str).is_some());
        let desired = serde_json::from_value::<DesiredState>(v.clone());
        assert!(desired.unwrap().interfaces.is_empty());
    }

    #[test]
    fn parse_opt_requires_cidr_for_static() {
        let v: Value =
            serde_json::from_str(r#"{"op":"opt","nic":"enp1s0","mode":"static"}"#).unwrap();
        assert!(parse_opt(&v).is_err());
        let v: Value = serde_json::from_str(
            r#"{"op":"opt","nic":"enp1s0","mode":"static","cidr":"10.0.2.15/24"}"#,
        )
        .unwrap();
        let opt = parse_opt(&v).unwrap();
        assert_eq!(opt.nic, "enp1s0");
        assert_eq!(opt.cidr.as_deref(), Some("10.0.2.15/24"));
    }

    #[test]
    fn first_boot_nft_dnats_https_on_the_opted_nic() {
        let rules = first_boot_nft("enp1s0", &["10.0.2.15".into()]);
        assert!(rules.contains("iifname \"enp1s0\""));
        assert!(rules.contains("ip daddr 10.0.2.15 tcp dport 443 dnat ip to 169.254.127.6"));
        assert!(!rules.contains("flush ruleset"));
        let v6 = first_boot_nft("enp1s0", &["fe80::1".into(), "fd53:1:1::9".into()]);
        assert!(v6.contains("ip6 daddr fe80::1 tcp dport 443 dnat ip6 to fd53:1:1::6"));
        assert!(v6.contains("chain forward"));
        assert!(!v6.contains("dnat to fd53"));
    }

    #[test]
    fn expose_allowed_is_non_global() {
        assert!(expose_allowed("10.0.2.15"));
        assert!(expose_allowed("192.168.1.1"));
        assert!(expose_allowed("169.254.1.1"));
        assert!(!expose_allowed("169.254.127.6"));
        assert!(!expose_allowed("8.8.8.8"));
        assert!(!expose_allowed("100.64.0.1"));
        assert!(!expose_allowed("2001:db8::1"));
        assert!(expose_allowed("fd53:1:1::9"));
        assert!(expose_allowed("fe80::1"));
    }

    fn iface(name: &str, role: &str, addrs: &[&str]) -> Iface {
        Iface {
            name: name.into(),
            placement: String::new(),
            role: Some(role.into()),
            addresses: addrs.iter().map(|s| (*s).to_string()).collect(),
            vlan: None,
            parent: None,
            dhcp: false,
        }
    }

    fn vlan_iface(name: &str, role: &str, parent: &str, vid: u16, addrs: &[&str]) -> Iface {
        Iface {
            name: name.into(),
            placement: String::new(),
            role: Some(role.into()),
            addresses: addrs.iter().map(|s| (*s).to_string()).collect(),
            vlan: Some(vid),
            parent: Some(parent.into()),
            dhcp: false,
        }
    }

    fn wan_lan() -> DesiredState {
        DesiredState {
            interfaces: vec![
                iface("enp1s0", "lan", &["10.0.2.15/24", "192.168.1.1/24"]),
                iface("enp2s0", "wan", &["192.0.2.1/24"]),
            ],
            ui_exposure: vec!["enp1s0".into()],
            lan_prefix: Some("192.168.1.0/24".into()),
            dhcp_pool: Some("192.168.1.100-192.168.1.200".into()),
            ..DesiredState::default()
        }
    }

    #[test]
    fn ui_exposure_is_lan_not_wan() {
        let state = wan_lan();
        let exp = ui_exposure(&state);
        assert_eq!(exp.len(), 1);
        assert_eq!(exp[0].0, "enp1s0");
        assert!(!exp.iter().any(|(n, _)| n == "enp2s0"));
        assert!(validate(&state).is_ok());
    }

    #[test]
    fn reject_placement_mgmt() {
        let mut state = wan_lan();
        state.interfaces[0].placement = "mgmt".into();
        let err = validate(&state).unwrap_err();
        assert!(err.contains("placement=mgmt"), "{err}");
    }

    #[test]
    fn reject_empty_ui_exposure() {
        let mut state = wan_lan();
        state.ui_exposure.clear();
        let err = validate(&state).unwrap_err();
        assert!(err.contains("ui_exposure"), "{err}");
    }

    #[test]
    fn reject_wan_in_ui_exposure() {
        let mut state = wan_lan();
        state.ui_exposure = vec!["enp2s0".into()];
        let err = validate(&state).unwrap_err();
        assert!(err.contains("WAN"), "{err}");
    }

    #[test]
    fn require_wan_and_lan() {
        let mut state = wan_lan();
        state
            .interfaces
            .retain(|i| i.role.as_deref() != Some("lan"));
        let err = validate(&state).unwrap_err();
        assert!(err.to_ascii_lowercase().contains("lan"), "{err}");
        let mut state = wan_lan();
        state
            .interfaces
            .retain(|i| i.role.as_deref() != Some("wan"));
        let err = validate(&state).unwrap_err();
        assert!(err.to_ascii_lowercase().contains("wan"), "{err}");
    }

    #[test]
    fn reject_wan_and_lan_same_parent_and_tag() {
        let state = DesiredState {
            interfaces: vec![
                iface("enp1s0", "wan", &["192.0.2.1/24"]),
                iface("enp1s0", "lan", &["192.168.1.1/24"]),
            ],
            ui_exposure: vec!["enp1s0".into()],
            ..DesiredState::default()
        };
        let err = validate(&state).unwrap_err();
        assert!(err.contains("parent") && err.contains("tag"), "{err}");

        let ok = DesiredState {
            interfaces: vec![
                vlan_iface("enp1s0.10", "wan", "enp1s0", 10, &["192.0.2.1/24"]),
                vlan_iface("enp1s0.20", "lan", "enp1s0", 20, &["192.168.1.1/24"]),
            ],
            ui_exposure: vec!["enp1s0.20".into()],
            ..DesiredState::default()
        };
        assert!(validate(&ok).is_ok());

        let mixed = DesiredState {
            interfaces: vec![
                iface("enp1s0", "wan", &["192.0.2.1/24"]),
                vlan_iface("enp1s0.20", "lan", "enp1s0", 20, &["192.168.1.1/24"]),
            ],
            ui_exposure: vec!["enp1s0.20".into()],
            ..DesiredState::default()
        };
        assert!(validate(&mixed).is_ok());
    }

    #[test]
    fn extra_unused_nics_are_not_wans() {
        let state = DesiredState {
            interfaces: vec![
                iface("enp1s0", "lan", &["192.168.1.1/24"]),
                iface("enp2s0", "wan", &["192.0.2.1/24"]),
                iface("enp3s0", "unused", &[]),
            ],
            ui_exposure: vec!["enp1s0".into()],
            ..DesiredState::default()
        };
        assert!(validate(&state).is_ok());
        let wans: Vec<_> = state
            .interfaces
            .iter()
            .filter(|i| i.role.as_deref() == Some("wan"))
            .map(|i| i.name.as_str())
            .collect();
        assert_eq!(wans, vec!["enp2s0"]);
        let exp = ui_exposure(&state);
        assert!(!exp.iter().any(|(n, _)| n == "enp3s0"));
    }

    #[test]
    fn kea_and_unbound_bind_the_lan_l2_not_dummy() {
        let state = wan_lan();
        let lan = lan_l2(&state).unwrap();
        assert_eq!(lan.name, "enp1s0");
        assert_ne!(lan.name, "lan0");
        let kea4 = kea_dhcp4_conf(
            &lan.name,
            "192.168.1.0/24",
            "192.168.1.100",
            "192.168.1.200",
            "192.168.1.1",
        );
        assert!(kea4.contains("\"interfaces\": [ \"enp1s0\" ]"), "{kea4}");
        assert!(kea4.contains("\"interface\": \"enp1s0\""), "{kea4}");
        assert!(!kea4.contains("lan0"), "{kea4}");
        let kea6 = kea_dhcp6_conf(&lan.name, "2001:db8::/64", "2001:db8::100", "2001:db8::1ff");
        assert!(kea6.contains("enp1s0"), "{kea6}");
        assert!(!kea6.contains("lan0"), "{kea6}");
        let unbound = unbound_conf("192.168.1.1", "192.168.1.0/24");
        assert!(unbound.contains("interface: 192.168.1.1"), "{unbound}");
    }

    #[test]
    fn stick_json_with_ui_exposure_on_lan_vlan_is_valid() {
        let state = DesiredState {
            interfaces: vec![
                iface("enp1s0", "stick", &[]),
                vlan_iface("enp1s0.10", "wan", "enp1s0", 10, &["192.0.2.1/24"]),
                vlan_iface("enp1s0.20", "lan", "enp1s0", 20, &["192.168.1.1/24"]),
            ],
            ui_exposure: vec!["enp1s0.20".into()],
            lan_prefix: Some("192.168.1.0/24".into()),
            dhcp_pool: Some("192.168.1.100-192.168.1.200".into()),
            ..DesiredState::default()
        };
        assert!(validate(&state).is_ok());
        let exp = ui_exposure(&state);
        assert_eq!(exp[0].0, "enp1s0.20");
        let kea4 = kea_dhcp4_conf(
            "enp1s0.20",
            "192.168.1.0/24",
            "192.168.1.100",
            "192.168.1.200",
            "192.168.1.1",
        );
        assert!(kea4.contains("enp1s0.20"));
        assert!(!kea4.contains("lan0"));
    }
}

use std::fs::{self, File};
use std::io::{Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{chown, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;
use std::process::{self, Command};

use serde::{Deserialize, Serialize};

const SOCK: &str = "/var/lib/fwos/netd.sock";
const DESIRED: &str = "/var/lib/fwos/desired.toml";
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
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Iface {
    name: String,
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
    if Path::new(DESIRED).exists() {
        let raw = fs::read_to_string(DESIRED).map_err(|e| format!("read {DESIRED}: {e}"))?;
        let mut state: DesiredState =
            toml::from_str(&raw).map_err(|e| format!("parse {DESIRED}: {e}"))?;
        apply(&mut state)?;
        persist(&state)?;
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
    let reply = match serde_json::from_slice::<DesiredState>(&buf) {
        Ok(mut state) => match apply(&mut state) {
            Ok(()) => {
                if let Err(err) = persist(&state) {
                    serde_json::json!({"ok": false, "error": err}).to_string()
                } else {
                    serde_json::json!({"ok": true}).to_string()
                }
            }
            Err(err) => serde_json::json!({"ok": false, "error": err}).to_string(),
        },
        Err(err) => serde_json::json!({"ok": false, "error": err.to_string()}).to_string(),
    };
    stream
        .write_all(reply.as_bytes())
        .and_then(|_| stream.write_all(b"\n"))
        .map_err(|e| format!("write socket: {e}"))?;
    Ok(())
}

fn persist(state: &DesiredState) -> Result<(), String> {
    let raw = toml::to_string_pretty(state).map_err(|e| format!("encode TOML: {e}"))?;
    fs::write(DESIRED, raw).map_err(|e| format!("write {DESIRED}: {e}"))
}

fn apply(state: &mut DesiredState) -> Result<(), String> {
    // Capture Management NIC addresses while they still live in the Host netns,
    // before the veth replaces the host default route. `ip -n` / `ip netns exec`
    // hang in this container's mount ns (named-netns bind), so all mgmt work
    // uses setns instead. Persist whatever we captured so reboot does not
    // depend on DHCP racing netd.
    let mut mgmt_saved: Vec<(String, Vec<String>, Option<String>)> = Vec::new();
    for iface in &mut state.interfaces {
        if iface.placement == "mgmt" || iface.role.as_deref() == Some("stick") {
            let (mut addrs, gw) = capture_host_ipv4(&iface.name)?;
            if addrs.is_empty() {
                addrs = iface.addresses.clone();
            } else if iface.addresses.is_empty() {
                iface.addresses = addrs.clone();
            }
            mgmt_saved.push((iface.name.clone(), addrs, gw));
        }
    }
    if has_mgmt_path(state) {
        ensure_host_mgmt_veth()?;
    }
    if is_stick(state) {
        ensure_fwd_mgmt_veth()?;
        with_mgmt_net(|| {
            let _ = run_ip(&["route", "replace", "default", "via", FWD_MGMT_GW]);
            Ok(())
        })?;
        persist(state)?;
        program_nft(state)?;
    }
    for iface in &state.interfaces {
        if iface.placement == "fwd" && iface.vlan.is_none() {
            ensure_in_ns(&iface.name, "fwd")?;
            run_ip(&["link", "set", &iface.name, "up"])?;
            let extra = mgmt_saved
                .iter()
                .find(|(n, _, _)| n == &iface.name)
                .map(|(_, a, _)| a.clone())
                .unwrap_or_default();
            for addr in extra.iter().chain(iface.addresses.iter()) {
                add_addr(&iface.name, addr)?;
            }
        }
    }
    program_vlans(state)?;
    for iface in &state.interfaces {
        if iface.placement == "mgmt" {
            let (addrs, gw) = mgmt_saved
                .iter()
                .find(|(n, _, _)| n == &iface.name)
                .map(|(_, a, g)| (a.clone(), g.clone()))
                .unwrap_or_default();
            ensure_in_ns(&iface.name, "mgmt")?;
            with_mgmt_net(|| {
                run_ip(&["link", "set", &iface.name, "up"])?;
                for addr in addrs.iter().chain(iface.addresses.iter()) {
                    add_addr(&iface.name, addr)?;
                }
                if let Some(gw) = gw {
                    let _ = run_ip(&[
                        "route",
                        "replace",
                        "default",
                        "via",
                        &gw,
                        "dev",
                        &iface.name,
                    ]);
                }
                Ok(())
            })?;
        }
    }
    if has_mgmt_path(state) {
        host_default_via_mgmt()?;
        program_host_pull_nat()?;
    }
    program_wg(state)?;
    program_routes(state)?;
    program_qdiscs(state)?;
    program_lan_services(state)?;
    persist(state)?;
    program_nft(state)
}

fn has_mgmt(state: &DesiredState) -> bool {
    state.interfaces.iter().any(|i| i.placement == "mgmt")
}

fn is_stick(state: &DesiredState) -> bool {
    state
        .interfaces
        .iter()
        .any(|i| i.role.as_deref() == Some("stick"))
}

fn has_mgmt_path(state: &DesiredState) -> bool {
    has_mgmt(state) || is_stick(state)
}

fn stick_parent(state: &DesiredState) -> Option<&Iface> {
    state
        .interfaces
        .iter()
        .find(|i| i.role.as_deref() == Some("stick"))
}

fn ensure_in_ns(name: &str, ns: &str) -> Result<(), String> {
    if ns_has_link(ns, name)? {
        return Ok(());
    }
    if ns == "fwd" {
        return ensure_in_fwd(name);
    }
    with_host_net(|| {
        let _ = run_ip(&["link", "set", name, "down"]);
        run_ip(&["link", "set", name, "netns", &format!("/run/netns/{ns}")])
    })
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

fn ns_has_link(ns: &str, name: &str) -> Result<bool, String> {
    match ns {
        "fwd" => link_exists(name),
        "mgmt" => with_mgmt_net(|| link_exists(name)),
        _ => Err(format!("unknown netns {ns}")),
    }
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

fn program_host_pull_nat() -> Result<(), String> {
    // Host-netns pulls (bootc) leave via the mgmt veth; masquerade so they
    // can reach a Workstation-local registry on the Management NIC.
    let rules = format!(
        "destroy table ip fwos-host-pull\ntable ip fwos-host-pull {{\n  chain postrouting {{\n    type nat hook postrouting priority srcnat; policy accept;\n    ip saddr {HOST_VETH_ADDR} masquerade\n  }}\n}}\n"
    );
    with_mgmt_net(|| nft_apply(&rules))
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
    run_ip(&["link", "set", FWD_MGMT_VETH, "up"])?;
    with_mgmt_net(|| {
        add_addr(MGMT_FWD_VETH, MGMT_FWD_ADDR)?;
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
    let Some(pool) = state.dhcp_pool.as_deref() else {
        return Ok(());
    };
    let prefix = state
        .lan_prefix
        .clone()
        .or_else(|| prefix_from_pool(pool))
        .ok_or_else(|| "lan_prefix or a parseable dhcp_pool is required".to_string())?;
    let lan_v4 = first_v4_host(&prefix).ok_or_else(|| "lan_prefix has no v4 host".to_string())?;
    ensure_lan_dev(
        "lan0",
        &format!("{lan_v4}/{}", prefix.split('/').nth(1).unwrap_or("24")),
    )?;
    if let Some(pd) = state.wan_pd.as_deref() {
        if let Some(v6) = pd_lan_addr(pd) {
            add_addr("lan0", &v6)?;
        }
    }
    fs::create_dir_all("/var/lib/fwos/kea").map_err(|e| format!("mkdir kea: {e}"))?;
    fs::create_dir_all("/var/lib/fwos/unbound").map_err(|e| format!("mkdir unbound: {e}"))?;
    let (p1, p2) = split_pool(pool);
    let kea4 = format!(
        r#"{{
  "Dhcp4": {{
    "interfaces-config": {{ "interfaces": [ "lan0" ], "re-detect": true }},
    "lease-database": {{ "type": "memfile", "persist": false, "name": "/tmp/dhcp4.leases" }},
    "valid-lifetime": 3600,
    "subnet4": [ {{
      "id": 1,
      "subnet": "{prefix}",
      "interface": "lan0",
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
    );
    fs::write("/var/lib/fwos/kea/kea-dhcp4.conf", kea4)
        .map_err(|e| format!("write kea-dhcp4: {e}"))?;
    if let Some(pd) = state.wan_pd.as_deref() {
        if let (Some(v6_sub), Some((v6p1, v6p2))) = (pd_subnet64(pd), pd_pool(pd)) {
            let kea6 = format!(
                r#"{{
  "Dhcp6": {{
    "interfaces-config": {{ "interfaces": [ "lan0" ], "re-detect": true }},
    "lease-database": {{ "type": "memfile", "persist": false, "name": "/tmp/dhcp6.leases" }},
    "server-id": {{ "type": "LLT", "persist": false }},
    "subnet6": [ {{
      "id": 1,
      "subnet": "{v6_sub}",
      "interface": "lan0",
      "pools": [ {{ "pool": "{v6p1} - {v6p2}" }} ]
    }} ],
    "loggers": [ {{ "name": "kea-dhcp6", "severity": "INFO", "output-options": [ {{ "output": "stdout" }} ] }} ]
  }}
}}
"#
            );
            fs::write("/var/lib/fwos/kea/kea-dhcp6.conf", kea6)
                .map_err(|e| format!("write kea-dhcp6: {e}"))?;
        }
    }
    let unbound = format!(
        "server:\n  interface: {lan_v4}\n  port: 53\n  access-control: {prefix} allow\n  access-control: 127.0.0.0/8 allow\n  do-daemonize: no\n  username: \"\"\n  chroot: \"\"\n  directory: \"/tmp\"\n  pidfile: \"/tmp/unbound.pid\"\n  use-syslog: no\n  logfile: /dev/null\n"
    );
    fs::write("/var/lib/fwos/unbound/unbound.conf", unbound)
        .map_err(|e| format!("write unbound: {e}"))?;
    Ok(())
}

fn ensure_lan_dev(name: &str, cidr: &str) -> Result<(), String> {
    if !link_exists(name)? {
        run_ip(&["link", "add", name, "type", "dummy"])?;
    }
    run_ip(&["link", "set", name, "up"])?;
    add_addr(name, cidr)
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
        .filter(|i| i.placement == "fwd" && i.role.as_deref() == Some("wan"))
        .map(|i| i.name.as_str())
        .collect();
    let v4_wan = state.interfaces.iter().any(|i| {
        i.placement == "fwd"
            && i.role.as_deref() == Some("wan")
            && i.addresses.iter().any(|a| a.contains('.'))
    });
    let stick = stick_parent(state);
    let stick_ip = stick.and_then(|s| {
        s.addresses
            .iter()
            .find(|a| a.contains('.'))
            .and_then(|a| a.split('/').next())
            .map(str::to_string)
    });
    let mut rules = String::from("flush ruleset\n");
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
    if let Some(parent) = stick {
        rules.push_str(&format!(
            "    iifname \"{}\" oifname \"{FWD_MGMT_VETH}\" tcp dport 443 accept\n",
            parent.name
        ));
    }
    for wan in &wans {
        rules.push_str(&format!("    oifname \"{wan}\" accept\n"));
    }
    rules.push_str("  }\n");
    if stick.is_some() {
        rules.push_str("  chain prerouting {\n");
        rules.push_str("    type nat hook prerouting priority dstnat; policy accept;\n");
        match stick_ip.as_deref() {
            Some(ip) => rules.push_str(&format!(
                "    ip daddr {ip} tcp dport 443 dnat ip to {MGMT_FWD_IP}\n"
            )),
            None => rules.push_str(&format!("    tcp dport 443 dnat ip to {MGMT_FWD_IP}\n")),
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

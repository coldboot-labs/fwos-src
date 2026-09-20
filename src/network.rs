use std::fs;
use std::process::Command;

use serde::Deserialize;

pub(crate) const FWD_MGMT_VETH: &str = "f0mgmt";
pub(crate) const MGMT_FWD_IP: &str = "169.254.127.6";
pub(crate) const MGMT_FWD_IP6: &str = "fd53:1:1::6";

pub(crate) fn link_exists(name: &str) -> Result<bool, String> {
    let status = ip_cmd()
        .args(["link", "show", "dev", name])
        .status()
        .map_err(|e| format!("ip link show {name}: {e}"))?;
    Ok(status.success())
}

pub(crate) fn add_addr(dev: &str, cidr: &str) -> Result<(), String> {
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

pub(crate) fn run_ip(args: &[&str]) -> Result<(), String> {
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

pub(crate) fn ip_cmd() -> Command {
    let mut cmd = Command::new("ip");
    cmd.env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin");
    cmd
}

#[derive(Deserialize)]
struct Link {
    ifname: String,
    link_type: String,
    #[serde(default)]
    linkinfo: LinkInfo,
}

#[derive(Default, Deserialize)]
struct LinkInfo {
    info_kind: Option<String>,
}

pub(crate) fn traffic_nic_names() -> Result<Vec<String>, String> {
    let output = ip_cmd()
        .args(["-j", "-d", "link", "show"])
        .output()
        .map_err(|e| format!("list Traffic NICs: {e}"))?;
    if !output.status.success() {
        return Err(format!(
            "list Traffic NICs: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    let links: Vec<Link> = serde_json::from_slice(&output.stdout)
        .map_err(|e| format!("parse Traffic NIC metadata: {e}"))?;
    Ok(links
        .into_iter()
        // Physical, virtio and VF interfaces have Ethernet framing but no
        // virtual link kind. This also excludes our fixed veth plumbing.
        .filter(|link| link.link_type == "ether" && link.linkinfo.info_kind.is_none())
        .map(|link| link.ifname)
        .collect())
}

pub(crate) fn lock_unopted(nic: &str) -> Result<(), String> {
    write_sysctl(nic, "ipv6", "accept_ra", "0")?;
    write_sysctl(nic, "ipv6", "autoconf", "0")?;
    write_sysctl(nic, "ipv4", "rp_filter", "2")?;
    run_ip(&["addr", "flush", "dev", nic])
}

pub(crate) fn write_sysctl(nic: &str, fam: &str, key: &str, val: &str) -> Result<(), String> {
    let path = format!("/proc/sys/net/{fam}/conf/{nic}/{key}");
    fs::write(&path, val).map_err(|e| format!("write {path}: {e}"))
}

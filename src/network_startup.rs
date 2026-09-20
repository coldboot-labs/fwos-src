use std::fs::{self, File};
use std::os::fd::AsRawFd;
use std::process;

use super::network::{
    add_addr, ip_cmd, is_ethernet, link_exists, link_name, lock_unopted, run_ip, write_sysctl,
};
use super::network::{FWD_MGMT_VETH, MGMT_FWD_IP, MGMT_FWD_IP6};

const HOST_NS: &str = "/proc/1/ns/net";
const FWD_NS: &str = "/run/netns/fwd";
const MGMT_NS: &str = "/run/netns/mgmt";
const HOST_VETH: &str = "h0mgmt";
const MGMT_VETH: &str = "m0mgmt";
const HOST_VETH_ADDR: &str = "169.254.127.1/30";
const MGMT_VETH_ADDR: &str = "169.254.127.2/30";
const HOST_VETH_GW: &str = "169.254.127.2";
const MGMT_FWD_VETH: &str = "m1mgmt";
const FWD_MGMT_ADDR: &str = "169.254.127.5/30";
const MGMT_FWD_ADDR: &str = "169.254.127.6/30";
const FWD_MGMT_GW: &str = "169.254.127.5";
const FWD_MGMT_ADDR6: &str = "fd53:1:1::5/64";

pub(super) fn prepare() -> Result<(), String> {
    with_netns(FWD_NS, || {
        setup_plumbing()?;
        claim_traffic_nics()
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
        add_addr(MGMT_FWD_VETH, &format!("{MGMT_FWD_IP6}/64"))?;
        run_ip(&["link", "set", MGMT_FWD_VETH, "up"])?;
        Ok(())
    })?;
    Ok(())
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
        run_ip(&["route", "replace", "default", "via", FWD_MGMT_GW])?;
        fs::write("/proc/sys/net/ipv4/ip_forward", "1")
            .map_err(|e| format!("enable forwarding in mgmt: {e}"))?;
        Ok(())
    })?;
    fs::write("/proc/sys/net/ipv4/ip_forward", "1")
        .map_err(|e| format!("enable forwarding in fwd: {e}"))?;
    write_sysctl("all", "ipv4", "rp_filter", "2")?;
    write_sysctl("default", "ipv4", "rp_filter", "2")?;
    write_sysctl(FWD_MGMT_VETH, "ipv4", "rp_filter", "2")?;
    // Host-netns pull sources live on h0mgmt (169.254.127.0/30), not on the
    // fwd↔mgmt /30. Return traffic after masquerade un-SNAT needs this route.
    run_ip(&[
        "route",
        "replace",
        "169.254.127.0/30",
        "via",
        MGMT_FWD_IP,
        "dev",
        FWD_MGMT_VETH,
    ])?;
    Ok(())
}

fn claim_traffic_nics() -> Result<(), String> {
    let names = host_netns_ethernet()?;
    for name in names {
        ensure_in_fwd(&name)?;
        lock_unopted(&name)?;
        run_ip(&["link", "set", &name, "up"])?;
    }
    Ok(())
}

fn host_netns_ethernet() -> Result<Vec<String>, String> {
    with_host_net(|| {
        let out = ip_cmd()
            .args(["-o", "link", "show"])
            .output()
            .map_err(|e| format!("ip link show: {e}"))?;
        if !out.status.success() {
            return Err(format!(
                "list Host Traffic NICs: {}",
                String::from_utf8_lossy(&out.stderr).trim()
            ));
        }
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

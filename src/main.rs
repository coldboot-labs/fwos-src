use std::path::Path;
use std::process::{self, Command};

fn main() {
    if let Err(err) = run() {
        eprintln!("fwos-fwd-setup: {err}");
        process::exit(1);
    }
}

fn run() -> Result<(), String> {
    for name in ["fwd", "mgmt"] {
        ensure_netns(name)?;
        up_lo(name)?;
        enable_v4_forward(name)?;
        lock_autoconf(name)?;
    }
    Ok(())
}

fn lock_autoconf(name: &str) -> Result<(), String> {
    let script = "echo 0 > /proc/sys/net/ipv6/conf/all/accept_ra; echo 0 > /proc/sys/net/ipv6/conf/default/accept_ra; echo 0 > /proc/sys/net/ipv6/conf/all/autoconf; echo 0 > /proc/sys/net/ipv6/conf/default/autoconf; echo 2 > /proc/sys/net/ipv4/conf/all/rp_filter; echo 2 > /proc/sys/net/ipv4/conf/default/rp_filter";
    let status = Command::new("ip")
        .args(["netns", "exec", name, "sh", "-c", script])
        .status()
        .map_err(|e| format!("lock autoconf in {name}: {e}"))?;
    if status.success() {
        Ok(())
    } else {
        Err(format!("lock autoconf in {name} failed ({status})"))
    }
}

fn ensure_netns(name: &str) -> Result<(), String> {
    let path = Path::new("/run/netns").join(name);
    if path.exists() {
        return Ok(());
    }
    let status = Command::new("ip")
        .args(["netns", "add", name])
        .status()
        .map_err(|e| format!("ip netns add {name}: {e}"))?;
    if status.success() || path.exists() {
        Ok(())
    } else {
        Err(format!("ip netns add {name} failed ({status})"))
    }
}

fn up_lo(name: &str) -> Result<(), String> {
    let status = Command::new("ip")
        .args(["netns", "exec", name, "ip", "link", "set", "lo", "up"])
        .status()
        .map_err(|e| format!("bring up lo in {name}: {e}"))?;
    if status.success() {
        Ok(())
    } else {
        Err(format!("ip link set lo up in {name} failed ({status})"))
    }
}

fn enable_v4_forward(name: &str) -> Result<(), String> {
    let status = Command::new("ip")
        .args([
            "netns",
            "exec",
            name,
            "sh",
            "-c",
            "echo 1 > /proc/sys/net/ipv4/ip_forward; echo 1 > /proc/sys/net/ipv6/conf/all/forwarding",
        ])
        .status()
        .map_err(|e| format!("ip_forward in {name}: {e}"))?;
    if status.success() {
        Ok(())
    } else {
        Err(format!("enable ip_forward in {name} failed ({status})"))
    }
}

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
    }
    Ok(())
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

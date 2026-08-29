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

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct DesiredState {
    #[serde(default)]
    interfaces: Vec<Iface>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Iface {
    name: String,
    placement: String,
    #[serde(default)]
    role: Option<String>,
    #[serde(default)]
    addresses: Vec<String>,
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
        let state: DesiredState =
            toml::from_str(&raw).map_err(|e| format!("parse {DESIRED}: {e}"))?;
        apply(&state)?;
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
        Ok(state) => match apply(&state) {
            Ok(()) => {
                persist(&state)?;
                serde_json::json!({"ok": true}).to_string()
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

fn apply(state: &DesiredState) -> Result<(), String> {
    for iface in &state.interfaces {
        if iface.placement == "fwd" {
            ensure_in_fwd(&iface.name)?;
            run_ip(&["link", "set", &iface.name, "up"])?;
            for addr in &iface.addresses {
                add_addr(&iface.name, addr)?;
            }
        }
    }
    program_nft(state)
}

fn ensure_in_fwd(name: &str) -> Result<(), String> {
    if link_exists(name)? {
        return Ok(());
    }
    let fwd = File::open("/proc/self/ns/net").map_err(|e| format!("open fwd netns: {e}"))?;
    let host = File::open("/run/host-netns").map_err(|e| format!("open host netns: {e}"))?;
    setns_net(host.as_raw_fd()).map_err(|e| format!("setns host: {e}"))?;
    let ns_path = format!("/proc/{}/fd/{}", process::id(), fwd.as_raw_fd());
    let moved = run_ip(&["link", "set", name, "netns", &ns_path]);
    let back = setns_net(fwd.as_raw_fd());
    moved?;
    back.map_err(|e| format!("setns fwd: {e}"))?;
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
    let mut rules = String::from("flush ruleset\n");
    rules.push_str("table inet fwos {\n");
    rules.push_str("  chain input {\n");
    rules.push_str("    type filter hook input priority filter; policy accept;\n");
    rules.push_str("    iifname \"lo\" accept\n");
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
    for wan in &wans {
        rules.push_str(&format!("    oifname \"{wan}\" accept\n"));
    }
    rules.push_str("  }\n");
    if v4_wan {
        rules.push_str("  chain postrouting {\n");
        rules.push_str("    type nat hook postrouting priority srcnat; policy accept;\n");
        for wan in &wans {
            rules.push_str(&format!("    oifname \"{wan}\" masquerade\n"));
        }
        rules.push_str("  }\n");
    }
    rules.push_str("}\n");
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

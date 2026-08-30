use std::io::{self, BufRead, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::process::Command;

const CGNAT: Ipv4Addr = Ipv4Addr::new(100, 64, 0, 0);

pub fn run() -> Result<(), String> {
    let mut stdout = io::stdout();
    let stdin = io::stdin();
    print_status(&mut stdout)?;
    loop {
        write!(stdout, "> ").map_err(|e| e.to_string())?;
        stdout.flush().map_err(|e| e.to_string())?;
        let mut line = String::new();
        let n = stdin
            .lock()
            .read_line(&mut line)
            .map_err(|e| format!("read console: {e}"))?;
        if n == 0 {
            return Ok(());
        }
        if let Err(err) = handle(&mut stdout, line.trim()) {
            writeln!(stdout, "{err}").map_err(|e| e.to_string())?;
            stdout.flush().map_err(|e| e.to_string())?;
        }
    }
}

fn handle(out: &mut impl Write, line: &str) -> Result<(), String> {
    let mut parts = line.split_whitespace();
    match parts.next() {
        None | Some("status") => print_status(out),
        Some("help") => print_help(out),
        Some("static") => {
            let nic = parts.next().ok_or("usage: static <nic> <cidr>")?;
            let cidr = parts.next().ok_or("usage: static <nic> <cidr>")?;
            ephemeral_static(nic, cidr)?;
            print_status(out)
        }
        Some("dhcp") => {
            let nic = parts.next().ok_or("usage: dhcp <nic>")?;
            ephemeral_dhcp(nic)?;
            print_status(out)
        }
        Some("slaac") => {
            let nic = parts.next().ok_or("usage: slaac <nic>")?;
            ephemeral_slaac(nic)?;
            print_status(out)
        }
        Some("apply") => {
            Err("Bootstrap console sets ephemeral addressing, not Desired state".into())
        }
        Some(_) => {
            writeln!(out, "unknown command").map_err(|e| e.to_string())?;
            out.flush().map_err(|e| e.to_string())?;
            Ok(())
        }
    }
}

fn print_help(out: &mut impl Write) -> Result<(), String> {
    writeln!(
        out,
        "static <nic> <cidr>  ephemeral IPv4/IPv6\ndhcp <nic>            ephemeral DHCPv4\nslaac <nic>           ephemeral IPv6 RA\nstatus"
    )
    .map_err(|e| e.to_string())?;
    out.flush().map_err(|e| e.to_string())
}

fn print_status(out: &mut impl Write) -> Result<(), String> {
    writeln!(out, "FWOS Bootstrap console").map_err(|e| e.to_string())?;
    let nics = host_nics()?;
    writeln!(out, "NICs:").map_err(|e| e.to_string())?;
    if nics.is_empty() {
        writeln!(out, "  (none)").map_err(|e| e.to_string())?;
    }
    for nic in &nics {
        let addrs = nic
            .addrs
            .iter()
            .map(|a| a.to_string())
            .collect::<Vec<_>>()
            .join(" ");
        if addrs.is_empty() {
            writeln!(out, "  {}", nic.name).map_err(|e| e.to_string())?;
        } else {
            writeln!(out, "  {}  {addrs}", nic.name).map_err(|e| e.to_string())?;
        }
    }
    writeln!(out, "Reach the UI:").map_err(|e| e.to_string())?;
    let mut urls = 0;
    for nic in &nics {
        for addr in &nic.addrs {
            if let Some(url) = ui_url(&nic.name, *addr) {
                writeln!(out, "  {url}").map_err(|e| e.to_string())?;
                urls += 1;
            }
        }
    }
    if urls == 0 {
        writeln!(out, "  (set ephemeral addressing: static, dhcp, or slaac)")
            .map_err(|e| e.to_string())?;
    }
    out.flush().map_err(|e| e.to_string())
}

struct Nic {
    name: String,
    addrs: Vec<IpAddr>,
}

fn host_nics() -> Result<Vec<Nic>, String> {
    let links = ip_output(&["-o", "link", "show"])?;
    let mut nics = Vec::new();
    for line in links.lines() {
        let name = link_name(line);
        if !is_ethernet(&name) {
            continue;
        }
        nics.push(Nic {
            name,
            addrs: Vec::new(),
        });
    }
    let addrs = ip_output(&["-o", "addr", "show"])?;
    for line in addrs.lines() {
        let name = addr_dev(line);
        let Some(nic) = nics.iter_mut().find(|n| n.name == name) else {
            continue;
        };
        if let Some(ip) = addr_ip(line) {
            if !nic.addrs.contains(&ip) {
                nic.addrs.push(ip);
            }
        }
    }
    Ok(nics)
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

fn addr_ip(line: &str) -> Option<IpAddr> {
    let mut toks = line.split_whitespace();
    while let Some(tok) = toks.next() {
        if tok == "inet" || tok == "inet6" {
            let cidr = toks.next()?;
            let ip = cidr.split('/').next()?;
            return ip.parse().ok();
        }
    }
    None
}

fn is_ethernet(name: &str) -> bool {
    name.starts_with("enp")
        || name.starts_with("eth")
        || name.starts_with("ens")
        || name.starts_with("eno")
}

fn ui_url(nic: &str, addr: IpAddr) -> Option<String> {
    if !ui_reachable(addr) {
        return None;
    }
    match addr {
        IpAddr::V4(v4) => Some(format!("https://{v4}/")),
        IpAddr::V6(v6) if v6.is_unicast_link_local() => Some(format!("https://[{v6}%{nic}]/")),
        IpAddr::V6(v6) => Some(format!("https://[{v6}]/")),
    }
}

fn ui_reachable(addr: IpAddr) -> bool {
    match addr {
        IpAddr::V4(v4) => {
            if v4.is_loopback() {
                return false;
            }
            let oct = v4.octets();
            if oct[0] == CGNAT.octets()[0] && oct[1] >= 64 && oct[1] <= 127 {
                return false;
            }
            v4.is_private() || v4.is_link_local()
        }
        IpAddr::V6(v6) => {
            if v6.is_loopback() {
                return false;
            }
            v6.is_unicast_link_local() || is_ula(v6)
        }
    }
}

fn is_ula(addr: Ipv6Addr) -> bool {
    let b = addr.octets()[0];
    (b & 0xfe) == 0xfc
}

fn ephemeral_static(nic: &str, cidr: &str) -> Result<(), String> {
    ip_ok(&["link", "set", "dev", nic, "up"])?;
    ip_add(nic, cidr)
}

fn ephemeral_dhcp(nic: &str) -> Result<(), String> {
    ip_ok(&["link", "set", "dev", nic, "up"])?;
    if cmd_ok("nmcli", &["device", "connect", nic]) {
        return Ok(());
    }
    if cmd_ok("dhclient", &["-1", nic]) {
        return Ok(());
    }
    Err(format!("dhcp on {nic} failed"))
}

fn ephemeral_slaac(nic: &str) -> Result<(), String> {
    ip_ok(&["link", "set", "dev", nic, "up"])?;
    let key = format!("net.ipv6.conf.{nic}.accept_ra=1");
    if !cmd_ok("sysctl", &["-w", &key]) {
        return Err(format!("slaac on {nic} failed"));
    }
    Ok(())
}

fn ip_add(nic: &str, cidr: &str) -> Result<(), String> {
    let output = Command::new("ip")
        .args(["addr", "add", cidr, "dev", nic])
        .output()
        .map_err(|e| format!("ip addr add: {e}"))?;
    if output.status.success() {
        return Ok(());
    }
    let err = String::from_utf8_lossy(&output.stderr);
    if err.contains("File exists") {
        Ok(())
    } else {
        Err(format!("ip addr add {cidr} dev {nic}: {}", err.trim()))
    }
}

fn ip_ok(args: &[&str]) -> Result<(), String> {
    let output = Command::new("ip")
        .args(args)
        .output()
        .map_err(|e| format!("ip: {e}"))?;
    if output.status.success() {
        Ok(())
    } else {
        Err(format!(
            "ip {}: {}",
            args.join(" "),
            String::from_utf8_lossy(&output.stderr).trim()
        ))
    }
}

fn ip_output(args: &[&str]) -> Result<String, String> {
    let output = Command::new("ip")
        .args(args)
        .output()
        .map_err(|e| format!("ip: {e}"))?;
    if output.status.success() {
        String::from_utf8(output.stdout).map_err(|_| "ip output was not UTF-8".into())
    } else {
        Err(format!(
            "ip {}: {}",
            args.join(" "),
            String::from_utf8_lossy(&output.stderr).trim()
        ))
    }
}

fn cmd_ok(bin: &str, args: &[&str]) -> bool {
    Command::new(bin)
        .args(args)
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

use std::fs;
use std::io::{self, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::os::fd::AsRawFd;
use std::path::Path;
use std::process::Command;
use std::sync::Mutex;

const CGNAT: Ipv4Addr = Ipv4Addr::new(100, 64, 0, 0);
const BOOTSTRAPPED: &str = "/var/lib/fwos/bootstrapped";
const DESIRED: &str = "/var/lib/fwos/desired.toml";
const HOSTNAME_FILE: &str = "/var/lib/fwos/hostname";

// libxcrypt; Fedora shadow hashes are yescrypt (`$y$`).
#[link(name = "crypt")]
extern "C" {
    fn crypt(key: *const libc::c_char, salt: *const libc::c_char) -> *mut libc::c_char;
}

pub fn run() -> Result<(), String> {
    if bootstrapped() {
        admin_run()
    } else {
        bootstrap_run()
    }
}

fn bootstrapped() -> bool {
    Path::new(BOOTSTRAPPED).exists()
}

fn bootstrap_run() -> Result<(), String> {
    let mut stdout = io::stdout();
    let fd = io::stdin().as_raw_fd();
    let mut acc = Vec::new();
    print_status(&mut stdout)?;
    loop {
        if bootstrapped() {
            return switch_to_admin(&mut stdout);
        }
        write!(stdout, "> ").map_err(|e| e.to_string())?;
        stdout.flush().map_err(|e| e.to_string())?;
        match read_line_poll(fd, &mut acc, 500)? {
            Input::Timeout => continue,
            Input::Eof => return Ok(()),
            Input::Line(line) => {
                if bootstrapped() {
                    return switch_to_admin(&mut stdout);
                }
                if let Err(err) = handle(&mut stdout, line.trim()) {
                    writeln!(stdout, "{err}").map_err(|e| e.to_string())?;
                    stdout.flush().map_err(|e| e.to_string())?;
                }
            }
        }
    }
}

fn switch_to_admin(out: &mut impl Write) -> Result<(), String> {
    writeln!(out, "Bootstrap complete.").map_err(|e| e.to_string())?;
    out.flush().map_err(|e| e.to_string())?;
    admin_run()
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

fn admin_run() -> Result<(), String> {
    let mut stdout = io::stdout();
    let fd = io::stdin().as_raw_fd();
    let mut acc = Vec::new();
    writeln!(stdout, "FWOS Appliance CLI").map_err(|e| e.to_string())?;
    stdout.flush().map_err(|e| e.to_string())?;
    loop {
        write!(stdout, "admin: ").map_err(|e| e.to_string())?;
        stdout.flush().map_err(|e| e.to_string())?;
        let user = match read_line_poll(fd, &mut acc, -1)? {
            Input::Eof => return Ok(()),
            Input::Timeout => continue,
            Input::Line(line) => line.trim().to_string(),
        };
        if user.is_empty() {
            continue;
        }
        write!(stdout, "password: ").map_err(|e| e.to_string())?;
        stdout.flush().map_err(|e| e.to_string())?;
        let password = match read_line_poll(fd, &mut acc, -1)? {
            Input::Eof => return Ok(()),
            Input::Timeout => continue,
            Input::Line(line) => line.trim_end_matches(['\r', '\n']).to_string(),
        };
        if verify_admin(&user, &password) {
            admin_session(&mut stdout, fd, &mut acc)?;
        } else {
            writeln!(stdout, "login failed").map_err(|e| e.to_string())?;
            stdout.flush().map_err(|e| e.to_string())?;
        }
    }
}

fn admin_session(out: &mut impl Write, fd: i32, acc: &mut Vec<u8>) -> Result<(), String> {
    print_admin_status(out)?;
    loop {
        write!(out, "fwos> ").map_err(|e| e.to_string())?;
        out.flush().map_err(|e| e.to_string())?;
        let line = match read_line_poll(fd, acc, -1)? {
            Input::Eof => return Ok(()),
            Input::Timeout => continue,
            Input::Line(line) => line,
        };
        match admin_handle(out, line.trim())? {
            AdminAct::Continue => {}
            AdminAct::Logout => return Ok(()),
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
enum AdminAct {
    Continue,
    Logout,
}

fn admin_handle(out: &mut impl Write, line: &str) -> Result<AdminAct, String> {
    let mut parts = line.split_whitespace();
    match parts.next() {
        None | Some("status") => {
            print_admin_status(out)?;
            Ok(AdminAct::Continue)
        }
        Some("help") => {
            print_admin_help(out)?;
            Ok(AdminAct::Continue)
        }
        Some("logout") => Ok(AdminAct::Logout),
        Some(_) => {
            writeln!(out, "unknown command").map_err(|e| e.to_string())?;
            out.flush().map_err(|e| e.to_string())?;
            Ok(AdminAct::Continue)
        }
    }
}

fn print_admin_help(out: &mut impl Write) -> Result<(), String> {
    writeln!(out, "status\nhelp\nlogout").map_err(|e| e.to_string())?;
    out.flush().map_err(|e| e.to_string())
}

fn print_admin_status(out: &mut impl Write) -> Result<(), String> {
    writeln!(out, "FWOS Appliance CLI").map_err(|e| e.to_string())?;
    let desired = fs::read_to_string(DESIRED)
        .ok()
        .and_then(|raw| raw.parse::<toml::Value>().ok());
    let hostname = fs::read_to_string(HOSTNAME_FILE)
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .or_else(|| {
            desired
                .as_ref()
                .and_then(|v| v.get("hostname"))
                .and_then(|x| x.as_str())
                .map(str::to_string)
        });
    if let Some(hn) = hostname {
        writeln!(out, "hostname: {hn}").map_err(|e| e.to_string())?;
    }
    if bootstrapped() {
        writeln!(out, "bootstrapped").map_err(|e| e.to_string())?;
    }
    if let Some(ifaces) = desired
        .as_ref()
        .and_then(|v| v.get("interfaces"))
        .and_then(|x| x.as_array())
    {
        writeln!(out, "NICs:").map_err(|e| e.to_string())?;
        for iface in ifaces {
            let name = iface.get("name").and_then(|x| x.as_str()).unwrap_or("?");
            let place = iface
                .get("placement")
                .and_then(|x| x.as_str())
                .unwrap_or("");
            let role = iface.get("role").and_then(|x| x.as_str()).unwrap_or("");
            let extra = format!("{place} {role}").trim().to_string();
            if extra.is_empty() {
                writeln!(out, "  {name}").map_err(|e| e.to_string())?;
            } else {
                writeln!(out, "  {name}  {extra}").map_err(|e| e.to_string())?;
            }
        }
    }
    out.flush().map_err(|e| e.to_string())
}

fn verify_admin(name: &str, password: &str) -> bool {
    if name == "root" || name.is_empty() || password.is_empty() {
        return false;
    }
    if !user_is_admin(name) {
        return false;
    }
    let Some(hash) = shadow_hash(name) else {
        return false;
    };
    crypt_ok(password, &hash)
}

fn user_is_admin(name: &str) -> bool {
    let Ok(group) = fs::read_to_string("/etc/group") else {
        return false;
    };
    for line in group.lines() {
        let Some(rest) = line.strip_prefix("wheel:") else {
            continue;
        };
        let members = rest.rsplit(':').next().unwrap_or("");
        return members.split(',').any(|m| m == name);
    }
    false
}

fn shadow_hash(name: &str) -> Option<String> {
    let raw = fs::read_to_string("/etc/shadow").ok()?;
    for line in raw.lines() {
        let mut parts = line.split(':');
        if parts.next()? != name {
            continue;
        }
        let hash = parts.next()?.to_string();
        if hash.is_empty() || hash == "*" || hash == "!" || hash.starts_with('!') {
            return None;
        }
        return Some(hash);
    }
    None
}

fn crypt_ok(password: &str, setting: &str) -> bool {
    let Ok(pw) = std::ffi::CString::new(password) else {
        return false;
    };
    let Ok(salt) = std::ffi::CString::new(setting) else {
        return false;
    };
    static LOCK: Mutex<()> = Mutex::new(());
    let _g = LOCK.lock().unwrap_or_else(|p| p.into_inner());
    let enc = unsafe { crypt(pw.as_ptr(), salt.as_ptr()) };
    if enc.is_null() {
        return false;
    }
    let got = unsafe { std::ffi::CStr::from_ptr(enc) };
    eq_ct(got.to_bytes(), setting.as_bytes())
}

fn eq_ct(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut x = 0u8;
    for (p, q) in a.iter().zip(b) {
        x |= p ^ q;
    }
    x == 0
}

enum Input {
    Line(String),
    Eof,
    Timeout,
}

fn take_line(acc: &mut Vec<u8>) -> Option<String> {
    let pos = acc.iter().position(|&b| b == b'\n' || b == b'\r')?;
    let line = String::from_utf8_lossy(&acc[..pos]).into_owned();
    let mut skip = pos + 1;
    if acc[pos] == b'\r' && acc.get(pos + 1) == Some(&b'\n') {
        skip += 1;
    }
    acc.drain(..skip);
    Some(line)
}

fn read_line_poll(fd: i32, acc: &mut Vec<u8>, timeout_ms: i32) -> Result<Input, String> {
    if let Some(line) = take_line(acc) {
        return Ok(Input::Line(line));
    }
    let mut pfd = libc::pollfd {
        fd,
        events: libc::POLLIN,
        revents: 0,
    };
    let n = unsafe { libc::poll(&mut pfd, 1, timeout_ms) };
    if n < 0 {
        return Err(format!("poll console: {}", io::Error::last_os_error()));
    }
    if n == 0 {
        return Ok(Input::Timeout);
    }
    if pfd.revents & libc::POLLIN == 0 {
        if pfd.revents & (libc::POLLHUP | libc::POLLERR) != 0 {
            return Ok(Input::Eof);
        }
        return Ok(Input::Timeout);
    }
    let mut tmp = [0u8; 512];
    let r = unsafe { libc::read(fd, tmp.as_mut_ptr() as *mut libc::c_void, tmp.len()) };
    if r < 0 {
        return Err(format!("read console: {}", io::Error::last_os_error()));
    }
    if r == 0 {
        return Ok(Input::Eof);
    }
    acc.extend_from_slice(&tmp[..r as usize]);
    if let Some(line) = take_line(acc) {
        Ok(Input::Line(line))
    } else {
        Ok(Input::Timeout)
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bootstrap_help_lists_ephemeral() {
        let mut out = Vec::new();
        print_help(&mut out).unwrap();
        let s = String::from_utf8(out).unwrap();
        assert!(s.contains("static"));
        assert!(s.contains("dhcp"));
        assert!(s.contains("slaac"));
    }

    #[test]
    fn admin_rejects_shell_and_ephemeral() {
        let mut out = Vec::new();
        assert_eq!(
            admin_handle(&mut out, "echo SHELL_RAN").unwrap(),
            AdminAct::Continue
        );
        let s = String::from_utf8(out).unwrap();
        assert!(s.contains("unknown command"));
        assert!(!s.lines().any(|l| l.trim() == "SHELL_RAN"));

        let mut out = Vec::new();
        admin_handle(&mut out, "static enp0s2 192.168.9.9/24").unwrap();
        let s = String::from_utf8(out).unwrap();
        assert!(s.contains("unknown command"));
        assert!(!s.contains("192.168.9.9"));
    }

    #[test]
    fn admin_status_is_not_bootstrap_console() {
        let mut out = Vec::new();
        print_admin_status(&mut out).unwrap();
        let s = String::from_utf8(out).unwrap();
        assert!(s.contains("FWOS Appliance CLI"));
        assert!(!s.contains("FWOS Bootstrap console"));
        assert!(!s.contains("ephemeral"));
        assert!(!s.contains("Reach the UI"));
    }

    #[test]
    fn admin_logout_leaves_session() {
        let mut out = Vec::new();
        assert_eq!(admin_handle(&mut out, "logout").unwrap(), AdminAct::Logout);
    }

    #[test]
    fn eq_ct_matches_only_same_bytes() {
        assert!(eq_ct(b"abc", b"abc"));
        assert!(!eq_ct(b"abc", b"abd"));
        assert!(!eq_ct(b"ab", b"abc"));
    }
}

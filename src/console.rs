use std::fs;
use std::io::{self, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::os::fd::AsRawFd;
use std::os::unix::net::UnixStream;
use std::path::Path;

use fwos_fwd_setup::identity::{self, Authentication, AuthenticationResult};

const CGNAT: Ipv4Addr = Ipv4Addr::new(100, 64, 0, 0);
const BOOTSTRAPPED: &str = "/var/lib/fwos/bootstrapped";
const DESIRED: &str = "/var/lib/fwos/desired.toml";
const HOSTNAME_FILE: &str = "/var/lib/fwos/hostname";

pub fn run() -> Result<(), String> {
    if bootstrapped() {
        admin_run()
    } else {
        bootstrap_run()
    }
}

fn clear_tty(out: &mut impl Write) -> Result<(), String> {
    write!(out, "\x1b[2J\x1b[H").map_err(|e| e.to_string())?;
    out.flush().map_err(|e| e.to_string())
}

fn write_prompt(out: &mut impl Write) -> Result<(), String> {
    write!(out, "> ").map_err(|e| e.to_string())?;
    out.flush().map_err(|e| e.to_string())
}

fn nics_key(nics: &[Nic]) -> String {
    nics.iter()
        .map(|n| {
            let addrs = n
                .addrs
                .iter()
                .map(|a| a.to_string())
                .collect::<Vec<_>>()
                .join(",");
            format!("{}={addrs}", n.name)
        })
        .collect::<Vec<_>>()
        .join(";")
}

fn bootstrapped() -> bool {
    Path::new(BOOTSTRAPPED).exists()
}

fn bootstrap_run() -> Result<(), String> {
    let mut stdout = io::stdout();
    let fd = io::stdin().as_raw_fd();
    let mut acc = Vec::new();
    clear_tty(&mut stdout)?;
    print_status(&mut stdout)?;
    write_prompt(&mut stdout)?;
    let mut key = nics_key(&traffic_nics().unwrap_or_default());
    loop {
        if bootstrapped() {
            return switch_to_admin(&mut stdout);
        }
        match read_line_poll(fd, &mut acc, 500)? {
            Input::Timeout => {
                if bootstrapped() {
                    return switch_to_admin(&mut stdout);
                }
                let now = nics_key(&traffic_nics().unwrap_or_default());
                if now != key {
                    // NIC list going empty is placement, not a status to show.
                    let skip = now.is_empty() && !key.is_empty();
                    key = now;
                    if !skip {
                        print_status(&mut stdout)?;
                        write_prompt(&mut stdout)?;
                    }
                }
            }
            Input::Eof => return Ok(()),
            Input::Line(line) => {
                if bootstrapped() {
                    return switch_to_admin(&mut stdout);
                }
                if let Err(err) = handle(&mut stdout, line.trim()) {
                    writeln!(stdout, "{err}").map_err(|e| e.to_string())?;
                    stdout.flush().map_err(|e| e.to_string())?;
                }
                write_prompt(&mut stdout)?;
                key = nics_key(&traffic_nics().unwrap_or_default());
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
        Some("update") => {
            let image = parts.next().unwrap_or("");
            write_cmd(out, super::update_client(image))?;
            Ok(())
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
        "static <nic> <cidr>  ephemeral IPv4/IPv6\ndhcp <nic>            ephemeral DHCPv4\nslaac <nic>           ephemeral IPv6 RA\nupdate <image>\nstatus"
    )
    .map_err(|e| e.to_string())?;
    out.flush().map_err(|e| e.to_string())
}

fn print_status(out: &mut impl Write) -> Result<(), String> {
    writeln!(out, "FWOS Bootstrap console").map_err(|e| e.to_string())?;
    let list = list_from_netd();
    writeln!(out, "NICs:").map_err(|e| e.to_string())?;
    if list.nics.is_empty() {
        writeln!(out, "  (none)").map_err(|e| e.to_string())?;
    }
    for nic in &list.nics {
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
    for nic in &list.nics {
        if list.opted.as_deref() != Some(nic.name.as_str()) {
            continue;
        }
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
    clear_tty(&mut stdout)?;
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
        let Some(password) = read_password(&mut stdout, fd, &mut acc)? else {
            return Ok(());
        };
        let authentication = identity::authenticate(identity::LOCAL_SOURCE, &user, &password);
        drop(password);
        match authentication {
            AuthenticationResult::Authenticated(authentication)
                if identity::authorize_administrator(&authentication) =>
            {
                admin_session(&mut stdout, fd, &mut acc, &authentication)?;
            }
            AuthenticationResult::Challenge(_) => {
                writeln!(
                    stdout,
                    "additional authentication required; console login unavailable"
                )
                .map_err(|e| e.to_string())?;
            }
            _ => {
                writeln!(stdout, "login failed").map_err(|e| e.to_string())?;
            }
        }
        stdout.flush().map_err(|e| e.to_string())?;
    }
}

/// Restore terminal settings even if password input fails or the console exits.
struct HiddenInput {
    fd: i32,
    previous: libc::termios,
}

impl HiddenInput {
    fn new(fd: i32) -> Result<Self, String> {
        let mut previous = unsafe { std::mem::zeroed::<libc::termios>() };
        if unsafe { libc::tcgetattr(fd, &mut previous) } != 0 {
            return Err(format!(
                "read console terminal settings: {}",
                io::Error::last_os_error()
            ));
        }
        let mut hidden = previous;
        hidden.c_lflag &= !(libc::ECHO | libc::ECHONL);
        if unsafe { libc::tcsetattr(fd, libc::TCSANOW, &hidden) } != 0 {
            return Err(format!(
                "hide console input: {}",
                io::Error::last_os_error()
            ));
        }
        Ok(Self { fd, previous })
    }
}

impl Drop for HiddenInput {
    fn drop(&mut self) {
        unsafe { libc::tcsetattr(self.fd, libc::TCSANOW, &self.previous) };
    }
}

fn read_password(
    out: &mut impl Write,
    fd: i32,
    acc: &mut Vec<u8>,
) -> Result<Option<String>, String> {
    // Hide input before exposing the prompt, including to very fast serial clients.
    let hidden = HiddenInput::new(fd)?;
    write!(out, "password: ").map_err(|e| e.to_string())?;
    out.flush().map_err(|e| e.to_string())?;
    let password = loop {
        match read_line_poll(fd, acc, -1)? {
            Input::Eof => break None,
            Input::Timeout => continue,
            Input::Line(line) => break Some(line),
        }
    };
    drop(hidden);
    writeln!(out).map_err(|e| e.to_string())?;
    Ok(password)
}

fn admin_session(
    out: &mut impl Write,
    fd: i32,
    acc: &mut Vec<u8>,
    authentication: &Authentication,
) -> Result<(), String> {
    print_admin_status(out)?;
    loop {
        if !identity::authorize_administrator(authentication) {
            writeln!(out, "session authorization expired").map_err(|e| e.to_string())?;
            return Ok(());
        }
        write!(out, "fwos> ").map_err(|e| e.to_string())?;
        out.flush().map_err(|e| e.to_string())?;
        let line = match read_line_poll(fd, acc, -1)? {
            Input::Eof => return Ok(()),
            Input::Timeout => continue,
            Input::Line(line) => line,
        };
        // An account can be changed while this console is waiting for input.
        if !identity::authorize_administrator(authentication) {
            writeln!(out, "session authorization expired").map_err(|e| e.to_string())?;
            return Ok(());
        }
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
    let line = line.trim();
    let (cmd, rest) = match line.split_once(char::is_whitespace) {
        Some((cmd, rest)) => (cmd, rest.trim()),
        None => (line, ""),
    };
    match cmd {
        "" | "status" => {
            print_admin_status(out)?;
            Ok(AdminAct::Continue)
        }
        "help" => {
            print_admin_help(out)?;
            Ok(AdminAct::Continue)
        }
        "logout" => Ok(AdminAct::Logout),
        "show" => {
            write_cmd(out, super::show_desired())?;
            Ok(AdminAct::Continue)
        }
        "apply" => {
            if rest.is_empty() {
                writeln!(out, "usage: apply <json|toml|path>").map_err(|e| e.to_string())?;
                out.flush().map_err(|e| e.to_string())?;
                return Ok(AdminAct::Continue);
            }
            write_cmd(
                out,
                super::apply_source(rest).and_then(|raw| super::apply_desired(&raw)),
            )?;
            Ok(AdminAct::Continue)
        }
        "update" => {
            write_cmd(out, super::update_client(rest))?;
            Ok(AdminAct::Continue)
        }
        "reboot" => {
            write_cmd(out, super::reboot_client())?;
            Ok(AdminAct::Continue)
        }
        "rollback" => {
            write_cmd(out, super::rollback_client())?;
            Ok(AdminAct::Continue)
        }
        _ => {
            writeln!(out, "unknown command").map_err(|e| e.to_string())?;
            out.flush().map_err(|e| e.to_string())?;
            Ok(AdminAct::Continue)
        }
    }
}

fn write_cmd(out: &mut impl Write, result: Result<String, String>) -> Result<(), String> {
    match result {
        Ok(reply) => {
            write!(out, "{reply}").map_err(|e| e.to_string())?;
            if !reply.ends_with('\n') {
                writeln!(out).map_err(|e| e.to_string())?;
            }
        }
        Err(err) => writeln!(out, "{err}").map_err(|e| e.to_string())?,
    }
    out.flush().map_err(|e| e.to_string())
}

fn print_admin_help(out: &mut impl Write) -> Result<(), String> {
    writeln!(
        out,
        "status\nshow\napply <json|toml|path>\nupdate <image>\nreboot\nrollback\nhelp\nlogout"
    )
    .map_err(|e| e.to_string())?;
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
            let role = iface.get("role").and_then(|x| x.as_str()).unwrap_or("");
            if role.is_empty() {
                writeln!(out, "  {name}").map_err(|e| e.to_string())?;
            } else {
                writeln!(out, "  {name}  {role}").map_err(|e| e.to_string())?;
            }
        }
    }
    if let Some(exp) = desired
        .as_ref()
        .and_then(|v| v.get("ui_exposure"))
        .and_then(|x| x.as_array())
    {
        let names: Vec<&str> = exp.iter().filter_map(|x| x.as_str()).collect();
        if !names.is_empty() {
            writeln!(out, "UI exposure: {}", names.join(" ")).map_err(|e| e.to_string())?;
        }
    }
    writeln!(
        out,
        "fwd: {}",
        if netns_exists("fwd") { "yes" } else { "no" }
    )
    .map_err(|e| e.to_string())?;
    writeln!(
        out,
        "mgmt: {}",
        if netns_exists("mgmt") { "yes" } else { "no" }
    )
    .map_err(|e| e.to_string())?;
    writeln!(
        out,
        "netd: {}",
        if netd_running() { "running" } else { "down" }
    )
    .map_err(|e| e.to_string())?;
    if let Ok(raw) = super::update_status() {
        if let Ok(v) = serde_json::from_str::<serde_json::Value>(&raw) {
            for key in ["booted", "staged", "rollback"] {
                if let Some(s) = v
                    .get(key)
                    .and_then(|x| x.as_str())
                    .filter(|s| !s.is_empty())
                {
                    writeln!(out, "{key}: {s}").map_err(|e| e.to_string())?;
                }
            }
        }
    }
    out.flush().map_err(|e| e.to_string())
}

fn netns_exists(name: &str) -> bool {
    Path::new("/run/netns").join(name).exists()
}

fn netd_running() -> bool {
    UnixStream::connect("/var/lib/fwos/netd.sock").is_ok()
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

fn traffic_nics() -> Result<Vec<Nic>, String> {
    Ok(list_from_netd().nics)
}

struct NicList {
    nics: Vec<Nic>,
    opted: Option<String>,
}

fn list_from_netd() -> NicList {
    match super::netd_json(&serde_json::json!({"op": "list"})) {
        Ok(v) if v.get("ok").and_then(|x| x.as_bool()) != Some(false) => parse_nic_list(&v),
        _ => NicList {
            nics: Vec::new(),
            opted: None,
        },
    }
}

fn parse_nic_list(v: &serde_json::Value) -> NicList {
    let mut nics = Vec::new();
    if let Some(arr) = v.get("nics").and_then(|x| x.as_array()) {
        for nic in arr {
            let Some(name) = nic.get("name").and_then(|x| x.as_str()) else {
                continue;
            };
            let mut addrs = Vec::new();
            if let Some(list) = nic.get("addresses").and_then(|x| x.as_array()) {
                for a in list {
                    if let Some(s) = a.as_str() {
                        if let Some(ip) = s.split('/').next().and_then(|p| p.parse().ok()) {
                            if !addrs.contains(&ip) {
                                addrs.push(ip);
                            }
                        }
                    }
                }
            }
            nics.push(Nic {
                name: name.to_string(),
                addrs,
            });
        }
    }
    let opted = v
        .get("opt")
        .and_then(|o| o.get("nic"))
        .and_then(|x| x.as_str())
        .map(str::to_string);
    NicList { nics, opted }
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
    netd_opt("static", nic, Some(cidr))
}

fn ephemeral_dhcp(nic: &str) -> Result<(), String> {
    netd_opt("dhcp", nic, None)
}

fn ephemeral_slaac(nic: &str) -> Result<(), String> {
    netd_opt("slaac", nic, None)
}

fn netd_opt(mode: &str, nic: &str, cidr: Option<&str>) -> Result<(), String> {
    let mut body = serde_json::json!({"op": "opt", "nic": nic, "mode": mode});
    if let Some(cidr) = cidr {
        body["cidr"] = serde_json::json!(cidr);
    }
    let reply = super::netd_json(&body)?;
    if reply.get("ok").and_then(|x| x.as_bool()) == Some(true) {
        Ok(())
    } else {
        Err(reply
            .get("error")
            .and_then(|x| x.as_str())
            .unwrap_or("opt failed")
            .to_string())
    }
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
    fn admin_help_lists_apply_show_update() {
        let mut out = Vec::new();
        print_admin_help(&mut out).unwrap();
        let s = String::from_utf8(out).unwrap();
        assert!(s.contains("apply"));
        assert!(s.contains("show"));
        assert!(s.contains("update <image>"));
        assert!(s.contains("reboot"));
        assert!(s.contains("rollback"));
    }

    #[test]
    fn admin_status_reports_fwd_mgmt_netd() {
        let mut out = Vec::new();
        print_admin_status(&mut out).unwrap();
        let s = String::from_utf8(out).unwrap();
        assert!(s.contains("fwd:"));
        assert!(s.contains("mgmt:"));
        assert!(s.contains("netd:"));
    }

    #[test]
    fn admin_reboot_is_a_host_update_socket_client() {
        let mut out = Vec::new();
        assert_eq!(
            admin_handle(&mut out, "reboot").unwrap(),
            AdminAct::Continue
        );
        let s = String::from_utf8(out).unwrap();
        assert!(!s.contains("unknown command"));
        assert!(s.contains("update.sock"));
    }

    #[test]
    fn admin_rollback_is_a_host_update_socket_client() {
        let mut out = Vec::new();
        assert_eq!(
            admin_handle(&mut out, "rollback").unwrap(),
            AdminAct::Continue
        );
        let s = String::from_utf8(out).unwrap();
        assert!(!s.contains("unknown command"));
        assert!(s.contains("update.sock"));
    }

    #[test]
    fn admin_update_without_image_prints_usage() {
        let mut out = Vec::new();
        assert_eq!(
            admin_handle(&mut out, "update").unwrap(),
            AdminAct::Continue
        );
        let s = String::from_utf8(out).unwrap();
        assert!(s.contains("usage: update <image>"));
        assert!(!s.contains("update.sock"));
    }

    #[test]
    fn admin_apply_is_a_netd_client() {
        let mut out = Vec::new();
        assert_eq!(
            admin_handle(&mut out, r#"apply {"wireguard":[]}"#).unwrap(),
            AdminAct::Continue
        );
        let s = String::from_utf8(out).unwrap();
        assert!(!s.contains("unknown command"));
        assert!(s.contains("netd.sock"));
    }

    #[test]
    fn admin_show_round_trips_toml_on_var() {
        let mut out = Vec::new();
        assert_eq!(admin_handle(&mut out, "show").unwrap(), AdminAct::Continue);
        let s = String::from_utf8(out).unwrap();
        assert!(!s.contains("unknown command"));
        assert!(s.contains("/var/lib/fwos/desired.toml"));
    }

    #[test]
    fn admin_update_is_a_host_update_socket_client() {
        let mut out = Vec::new();
        assert_eq!(
            admin_handle(&mut out, "update 10.0.2.2:5000/fwos:next").unwrap(),
            AdminAct::Continue
        );
        let s = String::from_utf8(out).unwrap();
        assert!(!s.contains("unknown command"));
        assert!(s.contains("update.sock"));
    }

    #[test]
    fn bootstrap_update_hits_the_host_update_socket() {
        let mut out = Vec::new();
        handle(&mut out, "update 10.0.2.2:5000/fwos:next").unwrap();
        let s = String::from_utf8(out).unwrap();
        assert!(!s.contains("unknown command"));
        assert!(s.contains("update.sock"));
    }

    #[test]
    fn nics_key_changes_when_addresses_change() {
        let a = vec![Nic {
            name: "enp0s2".into(),
            addrs: vec!["10.0.2.15".parse().unwrap()],
        }];
        let b = vec![Nic {
            name: "enp0s2".into(),
            addrs: vec![
                "10.0.2.15".parse().unwrap(),
                "192.168.200.50".parse().unwrap(),
            ],
        }];
        assert_eq!(nics_key(&a), nics_key(&a));
        assert_ne!(nics_key(&a), nics_key(&b));
        assert!(nics_key(&[]).is_empty());
    }
}

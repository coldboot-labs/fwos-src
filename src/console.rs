//! The Appliance console Host program on VGA and serial: the Bootstrap
//! console before ownership, then the authenticated v1 recovery menu. It is
//! neither the full Appliance CLI (deferred to v2) nor a Host shell; routine
//! configuration and Host update belong to the UI.

use std::env;
use std::fs;
use std::io::{self, Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::os::fd::AsRawFd;
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::process;
use std::time::Duration;

use fwos_fwd_setup::desired::DesiredState;
use fwos_fwd_setup::identity::{self, Authentication, AuthenticationResult, Principal};

#[cfg(not(test))]
const NETD_SOCK: &str = "/var/lib/fwos/netd.sock";
#[cfg(not(test))]
const UPDATE_SOCK: &str = "/var/lib/fwos/update.sock";
// Unit tests exercise the real clients against sockets that never exist, so
// they cannot restore, reboot, or roll back a host that runs FWOS.
#[cfg(test)]
const NETD_SOCK: &str = "/nonexistent/fwos-unit-test/netd.sock";
#[cfg(test)]
const UPDATE_SOCK: &str = "/nonexistent/fwos-unit-test/update.sock";
const CGNAT: Ipv4Addr = Ipv4Addr::new(100, 64, 0, 0);
const BOOTSTRAPPED: &str = "/var/lib/fwos/bootstrapped";
const DESIRED: &str = "/var/lib/fwos/desired.toml";
const APPLY_OPERATION: &str = "/var/lib/fwos/apply-operation.json";
const APPLY_PREVIOUS: &str = "/var/lib/fwos/apply-previous.toml";
const PREVIOUS_ACCEPTED: &str = "/var/lib/fwos/previous-accepted.toml";
const HOSTNAME_FILE: &str = "/var/lib/fwos/hostname";
/// Shown when the authenticated recovery mode starts and atop its status.
const RECOVERY_BANNER: &str = "FWOS Appliance console: authenticated recovery";

fn main() {
    let result = no_arguments(env::args().skip(1)).and_then(|()| run());
    if let Err(err) = result {
        eprintln!("fwos-console: {err}");
        process::exit(1);
    }
}

/// The console is the tty's program, not a command-line client: it has no
/// subcommands to apply, stage, or roll back from a shell.
fn no_arguments(mut args: impl Iterator<Item = String>) -> Result<(), String> {
    match args.next() {
        None => Ok(()),
        Some(arg) => Err(format!(
            "unexpected argument {arg}: the Appliance console takes no arguments; \
             configure the appliance and update its Host image in the UI"
        )),
    }
}

fn run() -> Result<(), String> {
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
    writeln!(stdout, "{RECOVERY_BANNER}").map_err(|e| e.to_string())?;
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
        write!(out, "recovery> ").map_err(|e| e.to_string())?;
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
        match admin_handle_with_principal(out, line.trim(), Some(&authentication.principal))? {
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

#[cfg(test)]
fn admin_handle(out: &mut impl Write, line: &str) -> Result<AdminAct, String> {
    admin_handle_with_principal(out, line, None)
}

fn admin_handle_with_principal(
    out: &mut impl Write,
    line: &str,
    principal: Option<&identity::Principal>,
) -> Result<AdminAct, String> {
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
        "restore-previous" => {
            if !rest.is_empty() {
                writeln!(out, "usage: restore-previous").map_err(|e| e.to_string())?;
                out.flush().map_err(|e| e.to_string())?;
                return Ok(AdminAct::Continue);
            }
            write_cmd(out, restore_previous_client(principal))?;
            Ok(AdminAct::Continue)
        }
        "rollback-image" => {
            if !rest.is_empty() {
                writeln!(out, "usage: rollback-image").map_err(|e| e.to_string())?;
                out.flush().map_err(|e| e.to_string())?;
                return Ok(AdminAct::Continue);
            }
            write!(out, "{}", describe_image_rollback(update_op("rollback")))
                .map_err(|e| e.to_string())?;
            out.flush().map_err(|e| e.to_string())?;
            Ok(AdminAct::Continue)
        }
        "reboot" => {
            write_cmd(out, update_op("reboot"))?;
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
    write!(
        out,
        "\
status            appliance, Accepted Desired state, and Host image status
restore-previous  restore the previous Accepted Desired state (network revision); the Host image is unchanged
rollback-image    boot the previous Host image at the next reboot; the Accepted Desired state is unchanged.
                  Entering it again before rebooting cancels the queued rollback
reboot            reboot, activating a staged Host update or a queued Host image rollback
help
logout
Configure the appliance and update its Host image in the UI.
"
    )
    .map_err(|e| e.to_string())?;
    out.flush().map_err(|e| e.to_string())
}

/// The outcome of a manual Host image rollback request to the Host update
/// program, and the explicit reboot it needs. The rollback changes only the
/// bootc deployment: network revisions and Identity configuration stay.
fn describe_image_rollback(result: Result<String, String>) -> String {
    let reply = match result.and_then(|raw| {
        serde_json::from_str::<serde_json::Value>(&raw)
            .map_err(|e| format!("unreadable Host update program reply: {e}"))
    }) {
        Ok(reply) => reply,
        Err(err) => {
            return format!(
                "Host image rollback failed: {err}\nThe running Host image and Accepted Desired state are unchanged.\n"
            )
        }
    };
    let image = |key: &str| reply[key].as_str().unwrap_or_default().to_string();
    if reply["ok"] != true {
        let error = reply["error"]
            .as_str()
            .unwrap_or("refused by the Host update program");
        return format!(
            "Host image rollback refused: {error}\nThe running Host image and Accepted Desired state are unchanged.\n"
        );
    }
    if reply["rollback_queued"] != true {
        return format!(
            "Host image rollback cancelled: the next boot runs the current Host image {}.\nNo reboot is required.\n",
            image("booted")
        );
    }
    let mut s = format!(
        "Host image rollback queued: the next boot runs the previous Host image {}.\n\
         The current Host image {} stays active until then; enter rollback-image again before rebooting to cancel.\n",
        image("rollback"),
        image("booted")
    );
    if let Some(discarded) = reply["discarded_staged"].as_str() {
        s.push_str(&format!(
            "The staged Host update {discarded} was discarded.\n"
        ));
    }
    s.push_str("Reboot required: enter reboot to boot the previous Host image.\n");
    if reply["restores_pre_update_network"] == true {
        s.push_str(
            "This Host update was never accepted: the previous Host image restores the network preserved before it.\n",
        );
    } else {
        s.push_str(
            "The Accepted Desired state is unchanged; restore-previous restores the previous network revision separately.\n",
        );
    }
    s.push_str("Current administrator accounts and passwords stay in effect.\n");
    s
}

/// Host image lines of the recovery status, from the Host update program.
fn write_host_image_status(out: &mut impl Write, v: &serde_json::Value) -> Result<(), String> {
    let deployment = |key: &str| {
        v[key]
            .as_str()
            .filter(|s| !s.is_empty())
            .map(str::to_string)
    };
    let mut s = String::from("Host image (bootc deployments):\n");
    for key in ["booted", "staged", "rollback"] {
        if let Some(image) = deployment(key) {
            s.push_str(&format!("  {key}: {image}\n"));
        }
    }
    match (deployment("rollback"), v["rollback_queued"] == true) {
        (Some(previous), true) => s.push_str(&format!(
            "Host image rollback queued: the next boot runs {previous}\n"
        )),
        (Some(previous), false) => s.push_str(&format!(
            "Previous Host image available for rollback-image: {previous}\n"
        )),
        (None, _) => s.push_str("No previous Host image is available for rollback-image\n"),
    }
    if let (Some(staged), false) = (deployment("staged"), v["rollback_queued"] == true) {
        s.push_str(&format!(
            "Host update staged: the next boot runs {staged}\n"
        ));
    }
    if v["reboot_required"] == true {
        s.push_str("Reboot required: enter reboot to activate it\n");
    }
    if let Some(line) = last_host_image_change(&v["last_update"]) {
        s.push_str(&line);
        s.push('\n');
    }
    write!(out, "{s}").map_err(|e| e.to_string())
}

/// The last Host update health decision or manual Host image rollback.
fn last_host_image_change(last: &serde_json::Value) -> Option<String> {
    let release = last["release"].as_str()?;
    let network = &last["network"];
    let network = match network["outcome"].as_str() {
        Some("restored") => format!(
            "; pre-update network restored as Accepted Desired state revision {}",
            network["revision"]
        ),
        Some("unchanged") => format!(
            "; pre-update network remained the Accepted Desired state (revision {})",
            network["revision"]
        ),
        Some("failed") => format!(
            "; pre-update network not restored: {}",
            network["error"].as_str().unwrap_or("unknown error")
        ),
        _ => String::new(),
    };
    if let Some(to) = last["manual"]["to"].as_str() {
        return Some(format!(
            "Last Host image change: manually rolled back from {release} to {to}{network}"
        ));
    }
    let outcome = match last["outcome"].as_str() {
        Some("accepted") => "accepted".to_string(),
        Some("rolled_back") => format!(
            "rolled back ({})",
            last["reason"].as_str().unwrap_or("no reason recorded")
        ),
        other => other.unwrap_or("unknown").to_string(),
    };
    Some(format!("Last Host update: {release} {outcome}{network}"))
}

fn print_admin_status(out: &mut impl Write) -> Result<(), String> {
    writeln!(out, "{RECOVERY_BANNER}").map_err(|e| e.to_string())?;
    let operation = fs::read_to_string(APPLY_OPERATION)
        .ok()
        .and_then(|raw| serde_json::from_str::<serde_json::Value>(&raw).ok());
    let accepted_phase = operation
        .as_ref()
        .and_then(|value| value.get("phase"))
        .and_then(|phase| phase.as_str())
        == Some("accepted");
    let pending_phase = operation
        .as_ref()
        .and_then(|value| value.get("phase"))
        .and_then(|phase| phase.as_str())
        == Some("pending_confirmation");
    let netd_recovery_required = matches!(
        netd_json(&serde_json::json!({"op": "get_desired"})),
        Ok(reply) if reply["outcome"] == "recovery_required"
    );
    let indeterminate = accepted_phase && netd_recovery_required;
    let recovery_required = Path::new(APPLY_PREVIOUS).exists()
        || (Path::new(APPLY_OPERATION).exists() && !accepted_phase && !pending_phase)
        || (!accepted_phase && netd_recovery_required);
    let desired = fs::read_to_string(DESIRED)
        .ok()
        .and_then(|raw| raw.parse::<toml::Value>().ok());
    let recovery_target = operation
        .as_ref()
        .and_then(|operation| operation.get("accepted").cloned())
        .and_then(|accepted| serde_json::from_value::<DesiredState>(accepted).ok())
        .and_then(|accepted| toml::Value::try_from(accepted).ok())
        .or_else(|| {
            fs::read_to_string(APPLY_PREVIOUS)
                .ok()
                .and_then(|raw| raw.parse::<toml::Value>().ok())
        })
        .or_else(|| {
            // After a post-unlink completion failure, A is already durable
            // and netd still guards forwarding. It remains the retry target.
            if recovery_required && !Path::new(APPLY_OPERATION).exists() {
                desired.clone()
            } else {
                None
            }
        });
    let shown = if indeterminate {
        None
    } else if recovery_required {
        recovery_target.as_ref()
    } else {
        desired.as_ref()
    };
    let hostname = fs::read_to_string(HOSTNAME_FILE)
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .or_else(|| {
            shown
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
    if recovery_required {
        writeln!(out, "Recovery required: interrupted Desired state apply")
            .map_err(|e| e.to_string())?;
    } else if pending_phase {
        let revision = operation
            .as_ref()
            .and_then(|value| value.get("proposed"))
            .and_then(|value| value.get("revision"))
            .and_then(|value| value.as_u64());
        writeln!(
            out,
            "Apply confirmation pending for network revision {}",
            revision.unwrap_or(0)
        )
        .map_err(|e| e.to_string())?;
    } else if indeterminate {
        writeln!(
            out,
            "Apply outcome indeterminate: reboot to resolve Accepted state"
        )
        .map_err(|e| e.to_string())?;
    }
    if let Some(revision) = shown
        .and_then(|v| v.get("revision"))
        .and_then(|v| v.as_integer())
    {
        if recovery_required {
            writeln!(out, "Recovery target Accepted network revision: {revision}")
                .map_err(|e| e.to_string())?;
        } else {
            writeln!(out, "Accepted network revision: {revision}").map_err(|e| e.to_string())?;
        }
    }
    let predecessor = if recovery_required && Path::new(APPLY_OPERATION).exists() {
        operation
            .as_ref()
            .and_then(|operation| operation.get("previous_accepted").cloned())
            .and_then(|bytes| {
                serde_json::from_value::<Option<Vec<u8>>>(bytes)
                    .ok()
                    .flatten()
            })
            .and_then(|bytes| String::from_utf8(bytes).ok())
            .and_then(|raw| raw.parse::<toml::Value>().ok())
            .and_then(|v| v.get("revision").and_then(|revision| revision.as_integer()))
    } else {
        fs::read_to_string(PREVIOUS_ACCEPTED)
            .ok()
            .and_then(|raw| raw.parse::<toml::Value>().ok())
            .and_then(|v| v.get("revision").and_then(|revision| revision.as_integer()))
    };
    match (indeterminate, predecessor) {
        (true, _) => writeln!(out, "Previous accepted network revision: (indeterminate)"),
        (false, Some(revision)) => writeln!(out, "Previous accepted network revision: {revision}"),
        (false, None) => writeln!(out, "Previous accepted network revision: (none)"),
    }
    .map_err(|e| e.to_string())?;
    if let Some(ifaces) = shown
        .and_then(|v| v.get("interfaces"))
        .and_then(|x| x.as_array())
    {
        writeln!(out, "NICs:").map_err(|e| e.to_string())?;
        for iface in ifaces {
            writeln!(out, "{}", interface_line(iface)).map_err(|e| e.to_string())?;
        }
    }
    if let Some(exp) = shown
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
    if let Ok(raw) = update_op("status") {
        if let Ok(v) = serde_json::from_str::<serde_json::Value>(&raw) {
            write_host_image_status(out, &v)?;
        }
    }
    out.flush().map_err(|e| e.to_string())
}

/// One Accepted Desired state interface in recovery status: its name, role,
/// and VLAN tag and parent when it is a VLAN.
fn interface_line(iface: &toml::Value) -> String {
    let field = |key: &str| iface.get(key).and_then(|x| x.as_str()).unwrap_or("");
    let mut line = format!(
        "  {}",
        iface.get("name").and_then(|x| x.as_str()).unwrap_or("?")
    );
    if !field("role").is_empty() {
        line.push_str(&format!("  {}", field("role")));
    }
    if let Some(vlan) = iface.get("vlan").and_then(|x| x.as_integer()) {
        line.push_str(&format!("  vlan {vlan}"));
        if !field("parent").is_empty() {
            line.push_str(&format!(" on {}", field("parent")));
        }
    }
    line
}

fn netns_exists(name: &str) -> bool {
    Path::new("/run/netns").join(name).exists()
}

fn netd_running() -> bool {
    UnixStream::connect(NETD_SOCK).is_ok()
}

fn netd_json(body: &serde_json::Value) -> Result<serde_json::Value, String> {
    let raw = serde_json::to_vec(body).map_err(|e| format!("encode netd cmd: {e}"))?;
    let reply = socket_roundtrip(NETD_SOCK, &raw)?;
    serde_json::from_str(&reply).map_err(|e| format!("parse netd reply: {e}"))
}

fn restore_previous_client(applying: Option<&Principal>) -> Result<String, String> {
    let body = serde_json::json!({"op": "restore_previous", "applying": applying}).to_string();
    // Manual recovery uses the same bounded Host activation and rollback as
    // a normal Desired state apply; keep the socket open for its outcome.
    socket_roundtrip_for(NETD_SOCK, body.as_bytes(), Duration::from_secs(120))
}

/// A Host update program operation: `status`, `reboot`, or `rollback`.
fn update_op(op: &str) -> Result<String, String> {
    let body = serde_json::json!({"op": op}).to_string();
    socket_roundtrip(UPDATE_SOCK, body.as_bytes())
}

fn socket_roundtrip(sock: &str, body: &[u8]) -> Result<String, String> {
    socket_roundtrip_for(sock, body, Duration::from_secs(60))
}

fn socket_roundtrip_for(sock: &str, body: &[u8], timeout: Duration) -> Result<String, String> {
    let mut stream = UnixStream::connect(sock).map_err(|e| format!("connect {sock}: {e}"))?;
    let _ = stream.set_read_timeout(Some(timeout));
    let _ = stream.set_write_timeout(Some(timeout));
    stream
        .write_all(body)
        .map_err(|e| format!("write socket: {e}"))?;
    stream
        .shutdown(std::net::Shutdown::Write)
        .map_err(|e| format!("shutdown socket: {e}"))?;
    let mut reply = String::new();
    stream
        .read_to_string(&mut reply)
        .map_err(|e| format!("read socket: {e}"))?;
    Ok(reply)
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
    match netd_json(&serde_json::json!({"op": "list"})) {
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
            v4.is_private()
        }
        IpAddr::V6(v6) => {
            if v6.is_loopback() {
                return false;
            }
            is_ula(v6)
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
    let reply = netd_json(&body)?;
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
        assert!(s.contains(RECOVERY_BANNER), "{s}");
        assert!(!s.contains("CLI"), "{s}");
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
    fn admin_help_offers_limited_recovery_without_full_configuration_cli() {
        let mut out = Vec::new();
        print_admin_help(&mut out).unwrap();
        let s = String::from_utf8(out).unwrap();
        assert!(s.contains("status"));
        assert!(s.contains("restore-previous"));
        assert!(s.contains("reboot"));
        assert!(!s.contains("apply <"));
        assert!(!s.contains("show"));
        assert!(!s.contains("update <image>"));
        assert!(!s.lines().any(|l| l.trim() == "rollback"));
    }

    #[test]
    fn admin_help_distinguishes_network_restoration_from_image_rollback() {
        let mut out = Vec::new();
        print_admin_help(&mut out).unwrap();
        let s = String::from_utf8(out).unwrap();
        let line = |cmd: &str| {
            s.lines()
                .find(|l| l.split_whitespace().next() == Some(cmd))
                .unwrap_or_else(|| panic!("{cmd} missing from help: {s}"))
                .to_string()
        };
        let restore = line("restore-previous");
        assert!(restore.contains("Accepted Desired state"), "{restore}");
        assert!(restore.contains("Host image is unchanged"), "{restore}");
        let rollback = line("rollback-image");
        assert!(rollback.contains("previous Host image"), "{rollback}");
        assert!(
            rollback.contains("Accepted Desired state is unchanged"),
            "{rollback}"
        );
        assert!(
            s.contains("again before rebooting cancels the queued rollback"),
            "{s}"
        );
        assert!(line("reboot").contains("Host image rollback"));
        // The retired JSON adapter is not a menu entry.
        assert!(!s.lines().any(|l| l.trim() == "rollback"), "{s}");
    }

    #[test]
    fn image_rollback_outcome_names_the_next_boot_and_the_required_reboot() {
        let queued = serde_json::json!({"ok": true, "reboot_required": true,
            "rollback_queued": true, "booted": "reg/fwos:next", "staged": "",
            "rollback": "localhost/fwos:dev"});
        let s = describe_image_rollback(Ok(queued.to_string()));
        assert!(s.contains("Host image rollback queued"), "{s}");
        assert!(s.contains("localhost/fwos:dev"), "{s}");
        assert!(s.contains("reg/fwos:next"), "{s}");
        assert!(s.contains("Reboot required: enter reboot"), "{s}");
        assert!(s.contains("Accepted Desired state is unchanged"), "{s}");
        assert!(s.contains("restore-previous"), "{s}");
        assert!(s.contains("again before rebooting to cancel"), "{s}");
        assert!(s.contains("administrator"), "{s}");
        assert!(!s.contains("discarded"), "{s}");

        let unaccepted = serde_json::json!({"ok": true, "reboot_required": true,
            "rollback_queued": true, "booted": "reg/fwos:next", "staged": "",
            "rollback": "localhost/fwos:dev", "restores_pre_update_network": true});
        let s = describe_image_rollback(Ok(unaccepted.to_string()));
        assert!(
            s.contains("restores the network preserved before it"),
            "{s}"
        );
        assert!(!s.contains("Accepted Desired state is unchanged"), "{s}");

        let discarded = serde_json::json!({"ok": true, "reboot_required": true,
            "rollback_queued": true, "booted": "a:2", "staged": "",
            "rollback": "a:1", "discarded_staged": "a:3"});
        let s = describe_image_rollback(Ok(discarded.to_string()));
        assert!(s.contains("staged Host update a:3 was discarded"), "{s}");

        // bootc rollback on a queued rollback puts the booted image first again.
        let cancelled = serde_json::json!({"ok": true, "reboot_required": false,
            "rollback_queued": false, "booted": "a:2", "staged": "", "rollback": "a:1"});
        let s = describe_image_rollback(Ok(cancelled.to_string()));
        assert!(s.contains("Host image rollback cancelled"), "{s}");
        assert!(s.contains("No reboot is required"), "{s}");

        let refused = serde_json::json!({"ok": false, "error": "no rollback deployment"});
        let s = describe_image_rollback(Ok(refused.to_string()));
        assert!(
            s.contains("Host image rollback refused: no rollback deployment"),
            "{s}"
        );
        assert!(s.contains("unchanged"), "{s}");

        let s = describe_image_rollback(Err("connect /var/lib/fwos/update.sock: x".into()));
        assert!(s.contains("Host image rollback failed"), "{s}");
        assert!(s.contains("update.sock"), "{s}");
    }

    #[test]
    fn admin_rollback_image_is_a_host_update_socket_client_not_network_restoration() {
        let mut out = Vec::new();
        assert_eq!(
            admin_handle(&mut out, "rollback-image").unwrap(),
            AdminAct::Continue
        );
        let s = String::from_utf8(out).unwrap();
        assert!(!s.contains("unknown command"), "{s}");
        assert!(s.contains("Host image rollback"), "{s}");
        assert!(s.contains("update.sock"), "{s}");
        assert!(!s.contains("netd.sock"), "{s}");

        let mut out = Vec::new();
        admin_handle(&mut out, "rollback-image now").unwrap();
        let s = String::from_utf8(out).unwrap();
        assert!(s.contains("usage: rollback-image"), "{s}");
        assert!(!s.contains("update.sock"), "{s}");
    }

    #[test]
    fn host_image_status_shows_the_rollback_target_and_what_the_next_boot_runs() {
        let render = |v: serde_json::Value| {
            let mut out = Vec::new();
            write_host_image_status(&mut out, &v).unwrap();
            String::from_utf8(out).unwrap()
        };
        let s = render(
            serde_json::json!({"ok": true, "booted": "a:2", "staged": "",
            "rollback": "a:1", "rollback_queued": false, "reboot_required": false,
            "last_update": {"release": "a:2", "outcome": "accepted", "network": null}}),
        );
        // Legacy status lines stay parseable.
        assert!(s.lines().any(|l| l.trim() == "booted: a:2"), "{s}");
        assert!(s.lines().any(|l| l.trim() == "rollback: a:1"), "{s}");
        assert!(
            s.contains("Previous Host image available for rollback-image: a:1"),
            "{s}"
        );
        assert!(s.contains("Last Host update: a:2 accepted"), "{s}");
        assert!(!s.contains("Reboot required"), "{s}");

        let s = render(
            serde_json::json!({"ok": true, "booted": "a:2", "staged": "",
            "rollback": "a:1", "rollback_queued": true, "reboot_required": true}),
        );
        assert!(
            s.contains("Host image rollback queued: the next boot runs a:1"),
            "{s}"
        );
        assert!(s.contains("Reboot required"), "{s}");

        let s = render(
            serde_json::json!({"ok": true, "booted": "a:1", "staged": "",
            "rollback": "a:2", "rollback_queued": false, "reboot_required": false,
            "last_update": {"release": "a:2", "outcome": "rolled_back",
                "reason": "netd not running",
                "network": {"outcome": "restored", "revision": 5}}}),
        );
        assert!(
            s.contains("Last Host update: a:2 rolled back (netd not running); pre-update network restored as Accepted Desired state revision 5"),
            "{s}"
        );

        let s = render(
            serde_json::json!({"ok": true, "booted": "a:1", "staged": "",
            "rollback": "a:2", "rollback_queued": false, "reboot_required": false,
            "last_update": {"release": "a:2", "outcome": "rolled_back",
                "reason": "manual rollback",
                "manual": {"to": "a:1", "pre_update_network": false}, "network": null}}),
        );
        assert!(
            s.contains("Last Host image change: manually rolled back from a:2 to a:1\n"),
            "{s}"
        );

        let s = render(
            serde_json::json!({"ok": true, "booted": "a:1", "staged": "a:2",
            "rollback": "", "rollback_queued": false, "reboot_required": true}),
        );
        assert!(
            s.contains("Host update staged: the next boot runs a:2"),
            "{s}"
        );
        assert!(s.contains("No previous Host image"), "{s}");
    }

    #[test]
    fn admin_restore_previous_is_a_netd_client_not_host_image_rollback() {
        let mut out = Vec::new();
        assert_eq!(
            admin_handle(&mut out, "restore-previous").unwrap(),
            AdminAct::Continue
        );
        let s = String::from_utf8(out).unwrap();
        assert!(!s.contains("unknown command"));
        assert!(
            s.contains("netd.sock"),
            "network recovery must go through netd: {s}"
        );
        assert!(
            !s.contains("update.sock"),
            "Host-image rollback is distinct: {s}"
        );
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
    fn console_takes_no_arguments() {
        let args = |list: &[&str]| list.iter().map(|a| a.to_string()).collect::<Vec<_>>();
        assert!(no_arguments(args(&[]).into_iter()).is_ok());
        for retired in [
            &["apply", "/var/lib/fwos/desired.toml"][..],
            &["update", "reg/fwos:next"],
            &["reboot"],
            &["rollback"],
            &["console"],
        ] {
            let err = no_arguments(args(retired).into_iter()).unwrap_err();
            assert!(err.contains("takes no arguments"), "{err}");
            assert!(err.contains("UI"), "{err}");
        }
    }

    #[test]
    fn recovery_menu_refuses_retired_full_cli_commands_without_calling_netd_or_host_update() {
        for retired in [
            "show",
            r#"apply {"wireguard":[]}"#,
            "apply /var/lib/fwos/desired.toml",
            "apply",
            "update 10.0.2.2:5000/fwos:next",
            "update",
            "rollback",
            "stage 10.0.2.2:5000/fwos:next",
            "confirm",
        ] {
            let mut out = Vec::new();
            assert_eq!(
                admin_handle(&mut out, retired).unwrap(),
                AdminAct::Continue,
                "{retired}"
            );
            let s = String::from_utf8(out).unwrap();
            assert!(s.contains("unknown command"), "{retired}: {s}");
            assert!(!s.contains(".sock"), "{retired} reached a socket: {s}");
            assert!(
                !s.contains("desired.toml"),
                "{retired} read Desired state: {s}"
            );
        }
    }

    #[test]
    fn bootstrap_console_refuses_host_update_and_desired_state_commands() {
        for retired in [
            "update 10.0.2.2:5000/fwos:next",
            "update",
            "apply {}",
            "show",
            "rollback",
        ] {
            let mut out = Vec::new();
            handle(&mut out, retired).unwrap();
            let s = String::from_utf8(out).unwrap();
            assert!(s.contains("unknown command"), "{retired}: {s}");
            assert!(!s.contains(".sock"), "{retired} reached a socket: {s}");
        }
        let mut out = Vec::new();
        print_help(&mut out).unwrap();
        let help = String::from_utf8(out).unwrap();
        assert!(!help.contains("update"), "{help}");
    }

    #[test]
    fn recovery_help_lists_only_recovery_commands_and_points_to_the_ui() {
        let mut out = Vec::new();
        print_admin_help(&mut out).unwrap();
        let s = String::from_utf8(out).unwrap();
        let (commands, prose): (Vec<&str>, Vec<&str>) =
            s.lines().filter(|l| !l.starts_with(' ')).partition(|l| {
                l.split_whitespace()
                    .next()
                    .is_some_and(|w| w.chars().all(|c| c.is_ascii_lowercase() || c == '-'))
            });
        let commands: Vec<&str> = commands
            .iter()
            .filter_map(|l| l.split_whitespace().next())
            .collect();
        assert_eq!(
            commands,
            [
                "status",
                "restore-previous",
                "rollback-image",
                "reboot",
                "help",
                "logout"
            ],
            "{s}"
        );
        assert_eq!(
            prose,
            ["Configure the appliance and update its Host image in the UI."],
            "{s}"
        );
    }

    #[test]
    fn interface_status_line_shows_role_and_vlan_from_desired_state() {
        let iface = |raw: &str| raw.parse::<toml::Table>().unwrap().into();
        assert_eq!(
            interface_line(&iface(
                r#"name = "enp1s0"
role = "wan""#
            )),
            "  enp1s0  wan"
        );
        assert_eq!(
            interface_line(&iface(
                r#"name = "enp1s0.42"
role = "lan"
parent = "enp1s0"
vlan = 42"#
            )),
            "  enp1s0.42  lan  vlan 42 on enp1s0"
        );
        assert_eq!(interface_line(&iface(r#"name = "enp2s0""#)), "  enp2s0");
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

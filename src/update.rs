use std::fs;
use std::io::{Read, Write};
use std::net::IpAddr;
use std::os::unix::fs::{chown, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;
use std::process::{self, Command, Stdio};

use serde::Deserialize;
use serde_json::{json, Value};

const SOCK: &str = "/var/lib/fwos/update.sock";
const BOOTSTRAPPED: &str = "/var/lib/fwos/bootstrapped";
const REGISTRIES_DROPIN: &str = "/etc/containers/registries.conf.d/fwos-update.conf";

#[derive(Debug, Deserialize)]
struct Request {
    op: String,
    #[serde(default)]
    image: String,
}

fn main() {
    if let Err(err) = run() {
        eprintln!("fwos-update: {err}");
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
    loop {
        let (stream, _) = listener
            .accept()
            .map_err(|e| format!("accept {SOCK}: {e}"))?;
        if let Err(err) = handle_client(stream) {
            eprintln!("fwos-update: {err}");
        }
    }
}

fn handle_client(mut stream: UnixStream) -> Result<(), String> {
    let mut buf = Vec::new();
    stream
        .read_to_end(&mut buf)
        .map_err(|e| format!("read socket: {e}"))?;
    let (reply, reboot) = match serde_json::from_slice::<Request>(&buf) {
        Ok(req) => {
            let reboot = req.op == "reboot";
            (handle_request(req), reboot)
        }
        Err(err) => (
            json!({"ok": false, "error": err.to_string()}).to_string(),
            false,
        ),
    };
    stream
        .write_all(reply.as_bytes())
        .and_then(|_| stream.write_all(b"\n"))
        .map_err(|e| format!("write socket: {e}"))?;
    if reboot && reply_ok(&reply) {
        request_reboot();
    }
    Ok(())
}

fn reply_ok(reply: &str) -> bool {
    serde_json::from_str::<Value>(reply)
        .ok()
        .and_then(|v| v.get("ok").and_then(Value::as_bool))
        == Some(true)
}

fn request_reboot() {
    // Reply is already on the socket. Reboot is the operator step, not staging.
    let _ = Command::new("systemctl")
        .args(["reboot", "--no-block"])
        .env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin")
        .stdin(Stdio::null())
        .status();
}

fn handle_request(req: Request) -> String {
    match req.op.as_str() {
        "status" => {
            let (booted, staged, rollback) = bootc_images();
            json!({
                "ok": true,
                "reboot_required": !staged.is_empty(),
                "booted": booted,
                "staged": staged,
                "rollback": rollback,
            })
            .to_string()
        }
        "reboot" => {
            if !admin_exists() {
                return json!({"ok": false, "error": "Host update refused until an admin exists"})
                    .to_string();
            }
            json!({"ok": true, "rebooting": true}).to_string()
        }
        "stage" => stage_request(&req.image),
        other => json!({"ok": false, "error": format!("unknown op {other}")}).to_string(),
    }
}

fn stage_request(image: &str) -> String {
    if !admin_exists() {
        return json!({"ok": false, "error": "Host update refused until an admin exists"})
            .to_string();
    }
    if image.is_empty() {
        return json!({"ok": false, "error": "Host image required"}).to_string();
    }
    match bootc_switch(image) {
        Ok(()) => {
            let (booted, staged, rollback) = bootc_images();
            json!({
                "ok": true,
                "reboot_required": true,
                "booted": booted,
                "staged": staged,
                "rollback": rollback,
            })
            .to_string()
        }
        Err(err) => json!({"ok": false, "error": err}).to_string(),
    }
}

fn admin_exists() -> bool {
    Path::new(BOOTSTRAPPED).is_file()
}

fn bootc_switch(image: &str) -> Result<(), String> {
    allow_insecure_local_registry(image)?;
    // Stage only. Never pass --apply: reboot is a later operator step.
    let output = Command::new("bootc")
        .args(["switch", "--quiet", image])
        .env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin")
        .stdin(Stdio::null())
        .output()
        .map_err(|e| format!("bootc switch: {e}"))?;
    if output.status.success() {
        Ok(())
    } else {
        Err(format!(
            "bootc switch failed: {} {}",
            String::from_utf8_lossy(&output.stdout).trim(),
            String::from_utf8_lossy(&output.stderr).trim()
        ))
    }
}

fn allow_insecure_local_registry(image: &str) -> Result<(), String> {
    let Some(host) = local_registry_host(image) else {
        return Ok(());
    };
    if let Some(dir) = Path::new(REGISTRIES_DROPIN).parent() {
        fs::create_dir_all(dir).map_err(|e| format!("create {}: {e}", dir.display()))?;
    }
    let body = format!("[[registry]]\nlocation = \"{host}\"\ninsecure = true\n");
    fs::write(REGISTRIES_DROPIN, body).map_err(|e| format!("write {REGISTRIES_DROPIN}: {e}"))
}

fn local_registry_host(image: &str) -> Option<String> {
    let rest = image.strip_prefix("docker://").unwrap_or(image);
    let host = rest.split('/').next().unwrap_or("");
    if host.is_empty() {
        return None;
    }
    let name = host.rsplit_once(':').map(|(h, _)| h).unwrap_or(host);
    let name = name.trim_start_matches('[').trim_end_matches(']');
    if name == "localhost" || name.parse::<IpAddr>().is_ok() {
        Some(host.to_string())
    } else {
        None
    }
}

fn bootc_images() -> (String, String, String) {
    let output = Command::new("bootc")
        .args(["status", "--format", "json"])
        .env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin")
        .output();
    let Ok(output) = output else {
        return (String::new(), String::new(), String::new());
    };
    let v: Value = serde_json::from_slice(&output.stdout).unwrap_or(Value::Null);
    (
        image_ref(&v, "booted"),
        image_ref(&v, "staged"),
        image_ref(&v, "rollback"),
    )
}

fn image_ref(status: &Value, which: &str) -> String {
    let paths = [
        &["status", which, "image", "image", "image"][..],
        &["status", which, "image", "image"][..],
        &[which, "image", "image", "image"][..],
        &[which, "image", "image"][..],
    ];
    for p in paths {
        let mut cur = status;
        for key in p {
            cur = &cur[*key];
        }
        if let Some(s) = cur.as_str() {
            if !s.is_empty() {
                return s.to_string();
            }
        }
    }
    String::new()
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn local_ip_registry_is_marked_insecure() {
        assert_eq!(
            local_registry_host("10.0.2.2:46481/fwos:next").as_deref(),
            Some("10.0.2.2:46481")
        );
        assert_eq!(
            local_registry_host("localhost:5000/fwos:next").as_deref(),
            Some("localhost:5000")
        );
        assert_eq!(local_registry_host("quay.io/fwos:next"), None);
    }

    #[test]
    fn status_op_reports_bootc_deployments() {
        let s = handle_request(Request {
            op: "status".into(),
            image: String::new(),
        });
        assert!(s.contains("\"ok\":true") || s.contains("\"ok\": true"));
        assert!(s.contains("booted"));
        assert!(s.contains("staged"));
        assert!(s.contains("rollback"));
        assert!(!s.contains("unknown op"));
    }

    #[test]
    fn reboot_op_without_admin_is_refused() {
        let s = handle_request(Request {
            op: "reboot".into(),
            image: String::new(),
        });
        assert!(!s.contains("unknown op"));
        let l = s.to_ascii_lowercase();
        assert!(l.contains("admin") || l.contains("refus"));
        assert!(!s.contains("\"ok\":true") && !s.contains("\"ok\": true"));
    }
}

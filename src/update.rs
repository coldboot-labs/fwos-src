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
    let reply = match serde_json::from_slice::<Request>(&buf) {
        Ok(req) => handle_request(req),
        Err(err) => json!({"ok": false, "error": err.to_string()}).to_string(),
    };
    stream
        .write_all(reply.as_bytes())
        .and_then(|_| stream.write_all(b"\n"))
        .map_err(|e| format!("write socket: {e}"))?;
    Ok(())
}

fn handle_request(req: Request) -> String {
    if req.op != "stage" {
        return json!({"ok": false, "error": format!("unknown op {}", req.op)}).to_string();
    }
    if !admin_exists() {
        return json!({"ok": false, "error": "Host update refused until an admin exists"})
            .to_string();
    }
    if req.image.is_empty() {
        return json!({"ok": false, "error": "Host image required"}).to_string();
    }
    match bootc_switch(&req.image) {
        Ok(()) => {
            let (booted, staged) = bootc_images();
            json!({
                "ok": true,
                "reboot_required": true,
                "booted": booted,
                "staged": staged,
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

fn bootc_images() -> (String, String) {
    let output = Command::new("bootc")
        .args(["status", "--format", "json"])
        .env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin")
        .output();
    let Ok(output) = output else {
        return (String::new(), String::new());
    };
    let v: Value = serde_json::from_slice(&output.stdout).unwrap_or(Value::Null);
    (image_ref(&v, "booted"), image_ref(&v, "staged"))
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
}

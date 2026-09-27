use std::env;
use std::fs;
use std::io::{Read, Write};
use std::net::IpAddr;
use std::os::unix::fs::{chown, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;
use std::process::{self, Command, Stdio};
use std::sync::{Mutex, MutexGuard};
use std::thread;
use std::time::{Duration, Instant};

use fwos_fwd_setup::host_image;
use serde::Deserialize;
use serde_json::{json, Value};

const SOCK: &str = "/var/lib/fwos/update.sock";
const BOOTSTRAPPED: &str = "/var/lib/fwos/bootstrapped";
const PENDING: &str = "/var/lib/fwos/health-pending";
const NETD_SOCK: &str = "/var/lib/fwos/netd.sock";
const REGISTRIES_DROPIN: &str = "/etc/containers/registries.conf.d/fwos-update.conf";
const HEALTH_TIMEOUT: Duration = Duration::from_secs(180);

#[derive(Debug, Deserialize)]
struct Request {
    op: String,
    #[serde(default)]
    image: String,
}

fn main() {
    match env::args().nth(1).as_deref() {
        Some("health") => {
            if let Err(err) = run_health() {
                eprintln!("fwos-update: {err}");
                process::exit(1);
            }
        }
        Some(other) => {
            eprintln!("fwos-update: unknown command {other}");
            process::exit(1);
        }
        None => {
            if let Err(err) = run() {
                eprintln!("fwos-update: {err}");
                process::exit(1);
            }
        }
    }
}

fn run() -> Result<(), String> {
    record_staged_for_health();
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
        // A legacy synchronous stage can take minutes; status and reboot must
        // still answer while it runs.
        thread::spawn(move || {
            if let Err(err) = handle_client(stream) {
                eprintln!("fwos-update: {err}");
            }
        });
    }
}

// A crash between `bootc switch` and writing the health-pending record would
// leave a staged deployment that boots without post-update health checking.
fn record_staged_for_health() {
    let staged = bootc_images().staged;
    if let Some(image) = missing_pending_record(&read_pending(), &staged) {
        if let Err(err) = write_pending(&image) {
            eprintln!("fwos-update: {err}");
        }
    }
}

fn missing_pending_record(pending: &str, staged: &str) -> Option<String> {
    (pending.is_empty() && !staged.is_empty()).then(|| staged.to_string())
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

#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct Deployments {
    booted: String,
    staged: String,
    rollback: String,
    /// `bootc rollback` makes the rollback deployment the next boot.
    rollback_queued: bool,
}

/// The Host update operation this controller is running or last failed.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Operation {
    Idle,
    /// Deployments as they were when staging began; `bootc status` may wait
    /// on the sysroot lock while `bootc switch` holds it.
    Staging {
        image: String,
        before: Deployments,
    },
    Failed {
        image: String,
        error: String,
    },
}

impl Operation {
    fn before_staging(&self) -> Option<&Deployments> {
        match self {
            Self::Staging { before, .. } => Some(before),
            _ => None,
        }
    }
}

static OPERATION: Mutex<Operation> = Mutex::new(Operation::Idle);

fn lock_operation() -> MutexGuard<'static, Operation> {
    OPERATION.lock().unwrap_or_else(|p| p.into_inner())
}

/// Reboot, rollback, and another stage wait until a running stage finishes.
fn idle(op: &Operation) -> Result<(), String> {
    match op {
        Operation::Staging { image, .. } => Err(format!(
            "Host update staging of {image} is already in progress"
        )),
        _ => Ok(()),
    }
}

fn begin_staging(op: &mut Operation, image: &str, before: Deployments) -> Result<(), String> {
    idle(op)?;
    *op = Operation::Staging {
        image: image.to_string(),
        before,
    };
    Ok(())
}

fn finish_staging(op: &mut Operation, image: &str, result: Result<(), String>) {
    *op = match result {
        Ok(()) => Operation::Idle,
        Err(error) => Operation::Failed {
            image: image.to_string(),
            error,
        },
    };
}

fn operation_json(op: &Operation) -> Value {
    match op {
        Operation::Idle => json!({"state": "idle"}),
        Operation::Staging { image, .. } => json!({"state": "staging", "image": image}),
        Operation::Failed { image, error } => {
            json!({"state": "failed", "image": image, "error": error})
        }
    }
}

fn status_reply(deployments: &Deployments, op: &Operation) -> Value {
    json!({
        "ok": true,
        "reboot_required": !deployments.staged.is_empty() || deployments.rollback_queued,
        "booted": deployments.booted,
        "staged": deployments.staged,
        "rollback": deployments.rollback,
        "operation": operation_json(op),
    })
}

fn current_status() -> Value {
    let op = lock_operation().clone();
    let deployments = match op.before_staging() {
        Some(before) => before.clone(),
        None => match bootc_status() {
            Ok(deployments) => deployments,
            Err(error) => return json!({"ok": false, "error": error}),
        },
    };
    status_reply(&deployments, &op)
}

const NOT_BOOTSTRAPPED: &str = "Host update refused until Bootstrap has completed";

fn handle_request(req: Request) -> String {
    match req.op.as_str() {
        "status" => current_status().to_string(),
        "reboot" => {
            if !bootstrap_completed() {
                return json!({"ok": false, "error": NOT_BOOTSTRAPPED}).to_string();
            }
            if let Err(err) = idle(&lock_operation()) {
                return json!({"ok": false, "error": err}).to_string();
            }
            json!({"ok": true, "rebooting": true}).to_string()
        }
        "rollback" => rollback_request(),
        "stage" => stage_request(&req.image),
        "start_stage" => start_stage_request(&req.image),
        other => json!({"ok": false, "error": format!("unknown op {other}")}).to_string(),
    }
}

fn rollback_request() -> String {
    if !bootstrap_completed() {
        return json!({"ok": false, "error": NOT_BOOTSTRAPPED}).to_string();
    }
    if let Err(err) = idle(&lock_operation()) {
        return json!({"ok": false, "error": err}).to_string();
    }
    match bootc_rollback() {
        Ok(()) => {
            clear_pending();
            current_status().to_string()
        }
        Err(err) => json!({"ok": false, "error": err}).to_string(),
    }
}

fn claim_staging(image: &str) -> Result<(), String> {
    if !bootstrap_completed() {
        return Err(NOT_BOOTSTRAPPED.into());
    }
    if !host_image::valid_reference(image) {
        return Err("one Release image reference required".into());
    }
    begin_staging(&mut lock_operation(), image, bootc_images())
}

/// Legacy synchronous stage: the reply waits for the staged deployment.
fn stage_request(image: &str) -> String {
    if let Err(err) = claim_staging(image) {
        return json!({"ok": false, "error": err}).to_string();
    }
    let result = stage(image);
    let reply = match &result {
        Ok(()) => None,
        Err(err) => Some(json!({"ok": false, "error": err}).to_string()),
    };
    finish_staging(&mut lock_operation(), image, result);
    reply.unwrap_or_else(|| current_status().to_string())
}

/// UI stage: accept the request, then pull and stage in the background.
fn start_stage_request(image: &str) -> String {
    if let Err(err) = claim_staging(image) {
        return json!({"ok": false, "error": err}).to_string();
    }
    let owned = image.to_string();
    thread::spawn(move || {
        let result = stage(&owned);
        if let Err(err) = &result {
            eprintln!("fwos-update: staging {owned} failed: {err}");
        }
        finish_staging(&mut lock_operation(), &owned, result);
    });
    let mut reply = current_status();
    reply["staging"] = json!(true);
    reply.to_string()
}

// Pull and stage without touching the running deployment or networking. The
// health-pending record is written only once a deployment is staged, so a registry or
// download failure never makes the next boot look like a Host update boot.
fn stage(image: &str) -> Result<(), String> {
    bootc_switch(image)?;
    let staged = bootc_status()?.staged;
    if staged.is_empty() {
        // `bootc switch` to the booted image reference stages nothing.
        return Err(format!(
            "no deployment was staged; {image} may already be active"
        ));
    }
    write_pending(&staged)
}

fn bootstrap_completed() -> bool {
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

fn bootc_images() -> Deployments {
    bootc_status().unwrap_or_default()
}

// Every bootc system has a booted deployment; an answer without one is a
// transient `bootc status` failure (seen right after a failed switch), not an
// appliance with no Release.
fn bootc_status() -> Result<Deployments, String> {
    let mut last = String::new();
    for _ in 0..10 {
        match Command::new("bootc")
            .args(["status", "--format", "json"])
            .env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin")
            .output()
        {
            Ok(output) => {
                let found =
                    deployments(&serde_json::from_slice(&output.stdout).unwrap_or(Value::Null));
                if !found.booted.is_empty() {
                    return Ok(found);
                }
                last = String::from_utf8_lossy(&output.stderr).trim().to_string();
            }
            Err(err) => last = err.to_string(),
        }
        thread::sleep(Duration::from_millis(500));
    }
    Err(format!("bootc status unavailable: {last}"))
}

fn deployments(status: &Value) -> Deployments {
    Deployments {
        booted: image_ref(status, "booted"),
        staged: image_ref(status, "staged"),
        rollback: image_ref(status, "rollback"),
        rollback_queued: status["status"]["rollbackQueued"] == true,
    }
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ApplianceHealth {
    Ok,
    DefaultTargetNotReached,
    FwdMissing,
    MgmtMissing,
    NetdNotRunning,
}

impl ApplianceHealth {
    fn as_str(self) -> &'static str {
        match self {
            Self::Ok => "ok",
            Self::DefaultTargetNotReached => "default target not reached",
            Self::FwdMissing => "fwd missing",
            Self::MgmtMissing => "mgmt missing",
            Self::NetdNotRunning => "netd not running",
        }
    }
}

fn assess_health(default_target: bool, fwd: bool, mgmt: bool, netd: bool) -> ApplianceHealth {
    if !default_target {
        ApplianceHealth::DefaultTargetNotReached
    } else if !fwd {
        ApplianceHealth::FwdMissing
    } else if !mgmt {
        ApplianceHealth::MgmtMissing
    } else if !netd {
        ApplianceHealth::NetdNotRunning
    } else {
        ApplianceHealth::Ok
    }
}

fn should_auto_rollback(
    pending_this_boot: bool,
    has_rollback: bool,
    health: ApplianceHealth,
) -> bool {
    pending_this_boot && has_rollback && health != ApplianceHealth::Ok
}

fn pending_is_this_boot(pending: &str, booted: &str) -> bool {
    fn norm(s: &str) -> &str {
        let s = s.strip_prefix("docker://").unwrap_or(s);
        s.split('@').next().unwrap_or(s)
    }
    let pending = norm(pending);
    let booted = norm(booted);
    !pending.is_empty() && !booted.is_empty() && pending == booted
}

fn write_pending(image: &str) -> Result<(), String> {
    if let Some(dir) = Path::new(PENDING).parent() {
        fs::create_dir_all(dir).map_err(|e| format!("create {}: {e}", dir.display()))?;
    }
    fs::write(PENDING, format!("{image}\n")).map_err(|e| format!("write {PENDING}: {e}"))
}

fn read_pending() -> String {
    fs::read_to_string(PENDING)
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_default()
}

fn clear_pending() {
    let _ = fs::remove_file(PENDING);
}

fn bootc_rollback() -> Result<(), String> {
    let output = Command::new("bootc")
        .args(["rollback"])
        .env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin")
        .stdin(Stdio::null())
        .output()
        .map_err(|e| format!("bootc rollback: {e}"))?;
    if output.status.success() {
        Ok(())
    } else {
        Err(format!(
            "bootc rollback failed: {} {}",
            String::from_utf8_lossy(&output.stdout).trim(),
            String::from_utf8_lossy(&output.stderr).trim()
        ))
    }
}

fn run_health() -> Result<(), String> {
    let pending = read_pending();
    if pending.is_empty() {
        return Ok(());
    }
    let deadline = Instant::now() + HEALTH_TIMEOUT;
    loop {
        let Deployments {
            booted, rollback, ..
        } = bootc_images();
        if !booted.is_empty() && !pending_is_this_boot(&pending, &booted) {
            return Ok(());
        }
        let this_boot = pending_is_this_boot(&pending, &booted);
        let has_rollback = !rollback.is_empty();
        let health = assess_health(
            default_target_reached(),
            netns_exists("fwd"),
            netns_exists("mgmt"),
            netd_running(),
        );
        if this_boot && health == ApplianceHealth::Ok {
            clear_pending();
            console_log("appliance health ok");
            return Ok(());
        }
        if Instant::now() >= deadline {
            if should_auto_rollback(this_boot, has_rollback, health) {
                console_log(&format!(
                    "appliance health failed ({}); rolling back",
                    health.as_str()
                ));
                bootc_rollback()?;
                clear_pending();
                request_reboot();
            } else if this_boot {
                clear_pending();
            }
            return Ok(());
        }
        thread::sleep(Duration::from_secs(1));
    }
}

fn default_target_reached() -> bool {
    Command::new("systemctl")
        .args(["is-active", "--quiet", "default.target"])
        .env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin")
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

fn netns_exists(name: &str) -> bool {
    Path::new("/run/netns").join(name).exists()
}

fn netd_running() -> bool {
    UnixStream::connect(NETD_SOCK).is_ok()
}

fn console_log(msg: &str) {
    let line = format!("fwos-update: {msg}\n");
    eprint!("{line}");
    if let Ok(mut f) = fs::OpenOptions::new().write(true).open("/dev/console") {
        let _ = f.write_all(line.as_bytes());
    }
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
        let reply = status_reply(
            &Deployments {
                booted: "a:1".into(),
                rollback: "a:0".into(),
                ..Deployments::default()
            },
            &Operation::Idle,
        );
        assert_eq!(reply["ok"], true);
        assert_eq!(reply["booted"], "a:1");
        assert_eq!(reply["staged"], "");
        assert_eq!(reply["rollback"], "a:0");
        assert_eq!(reply["operation"]["state"], "idle");
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

    #[test]
    fn rollback_op_without_admin_is_refused() {
        let s = handle_request(Request {
            op: "rollback".into(),
            image: String::new(),
        });
        assert!(!s.contains("unknown op"));
        let l = s.to_ascii_lowercase();
        assert!(l.contains("admin") || l.contains("refus"));
        assert!(!s.contains("\"ok\":true") && !s.contains("\"ok\": true"));
    }

    #[test]
    fn start_stage_without_completed_bootstrap_is_refused() {
        let s = handle_request(Request {
            op: "start_stage".into(),
            image: "10.0.2.2:5000/fwos:next".into(),
        });
        assert!(!s.contains("unknown op"));
        assert!(s.contains("Bootstrap"));
        assert!(!s.contains("\"ok\":true"));
    }

    #[test]
    fn only_one_staging_operation_runs_at_a_time() {
        let before = Deployments {
            booted: "localhost/fwos:dev".into(),
            ..Deployments::default()
        };
        let mut op = Operation::Idle;
        begin_staging(&mut op, "10.0.2.2:5000/fwos:next", before.clone()).unwrap();
        let busy = begin_staging(&mut op, "10.0.2.2:5000/fwos:other", before.clone());
        assert!(busy.unwrap_err().contains("in progress"));
        let json = operation_json(&op);
        assert_eq!(json["state"], "staging");
        assert_eq!(json["image"], "10.0.2.2:5000/fwos:next");
        assert_eq!(op.before_staging(), Some(&before));

        finish_staging(
            &mut op,
            "10.0.2.2:5000/fwos:next",
            Err("registry unreachable".into()),
        );
        let json = operation_json(&op);
        assert_eq!(json["state"], "failed");
        assert_eq!(json["error"], "registry unreachable");
        assert_eq!(op.before_staging(), None);

        begin_staging(&mut op, "10.0.2.2:5000/fwos:next", before).unwrap();
        finish_staging(&mut op, "10.0.2.2:5000/fwos:next", Ok(()));
        assert_eq!(operation_json(&op)["state"], "idle");
    }

    #[test]
    fn staged_or_queued_rollback_deployments_require_a_reboot() {
        let idle = Operation::Idle;
        let status = |v: Value| status_reply(&deployments(&v), &idle)["reboot_required"].clone();
        let booted = json!({"status": {"booted": {"image": {"image": {"image": "a:1"}}}}});
        assert_eq!(status(booted), false);
        let staged = json!({"status": {"staged": {"image": {"image": {"image": "a:2"}}}}});
        assert_eq!(status(staged), true);
        let queued = json!({"status": {"rollbackQueued": true,
            "rollback": {"image": {"image": {"image": "a:0"}}}}});
        assert_eq!(status(queued), true);
    }

    #[test]
    fn reboot_and_rollback_wait_for_a_running_stage() {
        assert!(idle(&Operation::Idle).is_ok());
        let failed = Operation::Failed {
            image: "a:2".into(),
            error: "registry unreachable".into(),
        };
        assert!(idle(&failed).is_ok());
        let staging = Operation::Staging {
            image: "a:2".into(),
            before: Deployments::default(),
        };
        assert!(idle(&staging).unwrap_err().contains("in progress"));
    }

    #[test]
    fn a_staged_deployment_without_a_health_record_gets_one() {
        assert_eq!(
            missing_pending_record("", "10.0.2.2:5000/fwos:next").as_deref(),
            Some("10.0.2.2:5000/fwos:next")
        );
        assert_eq!(
            missing_pending_record("10.0.2.2:5000/fwos:next", "10.0.2.2:5000/fwos:next"),
            None
        );
        assert_eq!(missing_pending_record("", ""), None);
    }

    #[test]
    fn appliance_health_is_target_netns_and_netd_not_desired_state() {
        assert_eq!(assess_health(true, true, true, true), ApplianceHealth::Ok);
        assert_eq!(
            assess_health(false, true, true, true),
            ApplianceHealth::DefaultTargetNotReached
        );
        assert_eq!(
            assess_health(true, false, true, true),
            ApplianceHealth::FwdMissing
        );
        assert_eq!(
            assess_health(true, true, false, true),
            ApplianceHealth::MgmtMissing
        );
        assert_eq!(
            assess_health(true, true, true, false),
            ApplianceHealth::NetdNotRunning
        );
    }

    #[test]
    fn auto_rollback_only_after_host_update_boot_with_a_rollback_target() {
        assert!(!should_auto_rollback(
            false,
            true,
            ApplianceHealth::NetdNotRunning
        ));
        assert!(!should_auto_rollback(
            true,
            false,
            ApplianceHealth::NetdNotRunning
        ));
        assert!(!should_auto_rollback(true, true, ApplianceHealth::Ok));
        assert!(should_auto_rollback(
            true,
            true,
            ApplianceHealth::NetdNotRunning
        ));
        assert!(should_auto_rollback(
            true,
            true,
            ApplianceHealth::FwdMissing
        ));
        assert!(should_auto_rollback(
            true,
            true,
            ApplianceHealth::DefaultTargetNotReached
        ));
    }

    #[test]
    fn pending_matches_booted_image_refs() {
        assert!(pending_is_this_boot(
            "10.0.2.2:5000/fwos:next",
            "10.0.2.2:5000/fwos:next"
        ));
        assert!(pending_is_this_boot(
            "docker://10.0.2.2:5000/fwos:next",
            "10.0.2.2:5000/fwos:next"
        ));
        assert!(pending_is_this_boot(
            "10.0.2.2:5000/fwos:next",
            "10.0.2.2:5000/fwos:next@sha256:abc"
        ));
        assert!(!pending_is_this_boot(
            "10.0.2.2:5000/fwos:next",
            "10.0.2.2:5000/fwos:dev"
        ));
        assert!(!pending_is_this_boot("", "10.0.2.2:5000/fwos:next"));
        assert!(!pending_is_this_boot("10.0.2.2:5000/fwos:next", ""));
    }
}

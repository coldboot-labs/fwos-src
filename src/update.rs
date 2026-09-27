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

use fwos_fwd_setup::durable;
use fwos_fwd_setup::host_image;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

const SOCK: &str = "/var/lib/fwos/update.sock";
const BOOTSTRAPPED: &str = "/var/lib/fwos/bootstrapped";
const PENDING: &str = "/var/lib/fwos/health-pending";
/// The deployments of a staged Host update, kept until its boot is accepted.
const UPDATE_RECORD: &str = "/var/lib/fwos/host-update.json";
/// The last post-update health outcome, for status.
const UPDATE_OUTCOME: &str = "/var/lib/fwos/host-update-outcome.json";
/// Asks netd to restore the pre-update Accepted revision (netd owns it).
const RESTORE_PRE_UPDATE: &str = "/var/lib/fwos/restore-pre-update";
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
        Some("restore-check") => {
            if let Err(err) = run_restore_check() {
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
    booted_digest: String,
    staged_digest: String,
    rollback_digest: String,
    /// `bootc rollback` makes the rollback deployment the next boot.
    rollback_queued: bool,
}

/// One bootc deployment: its image reference and, when bootc reports it, the
/// image digest that distinguishes two pulls of the same tag.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
struct DeploymentId {
    image: String,
    #[serde(default)]
    digest: String,
}

impl DeploymentId {
    fn matches(&self, image: &str, digest: &str) -> bool {
        if !self.digest.is_empty() && !digest.is_empty() {
            return self.digest == digest;
        }
        pending_is_this_boot(&self.image, image)
    }
}

/// A staged Host update: the Release it replaces and the Release it stages.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct UpdateRecord {
    previous: DeploymentId,
    update: DeploymentId,
}

/// After `bootc rollback` from the update boot, the previous Release is booted
/// and the update is its rollback deployment. A staged update that was never
/// activated leaves an older rollback deployment instead.
fn returned_from_update(record: &UpdateRecord, deployments: &Deployments) -> bool {
    record
        .previous
        .matches(&deployments.booted, &deployments.booted_digest)
        && record
            .update
            .matches(&deployments.rollback, &deployments.rollback_digest)
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

fn status_reply(deployments: &Deployments, op: &Operation, last_update: Option<Value>) -> Value {
    json!({
        "ok": true,
        "reboot_required": !deployments.staged.is_empty() || deployments.rollback_queued,
        "booted": deployments.booted,
        "staged": deployments.staged,
        "rollback": deployments.rollback,
        "operation": operation_json(op),
        "last_update": last_update,
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
    status_reply(&deployments, &op, read_outcome())
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
            refresh_pre_update();
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
    // The previous Release restores this revision if the update boot fails.
    preserve_pre_update()?;
    let before = bootc_status()?;
    bootc_switch(image)?;
    let after = bootc_status()?;
    if after.staged.is_empty() {
        // `bootc switch` to the booted image reference stages nothing.
        return Err(format!(
            "no deployment was staged; {image} may already be active"
        ));
    }
    write_update_record(&UpdateRecord {
        previous: DeploymentId {
            image: before.booted,
            digest: before.booted_digest,
        },
        update: DeploymentId {
            image: after.staged.clone(),
            digest: after.staged_digest,
        },
    })?;
    write_pending(&after.staged)
}

fn preserve_pre_update() -> Result<(), String> {
    match netd_cmd(&json!({"op": "preserve_pre_update"})) {
        Ok(reply) if reply["ok"] == true => Ok(()),
        Ok(reply) => Err(format!(
            "could not preserve the Accepted network before the update: {}",
            reply["error"].as_str().unwrap_or("netd refused")
        )),
        Err(err) => Err(format!(
            "could not preserve the Accepted network before the update: {err}"
        )),
    }
}

/// Reboot activates a staged update: preserve the Accepted revision as of now,
/// not as of staging. A failure keeps the revision preserved at staging.
fn refresh_pre_update() {
    if bootc_images().staged.is_empty() {
        return;
    }
    if let Err(err) = preserve_pre_update() {
        eprintln!("fwos-update: {err}; keeping the revision preserved at staging");
    }
}

fn netd_cmd(body: &Value) -> Result<Value, String> {
    let mut stream = UnixStream::connect(NETD_SOCK).map_err(|e| format!("connect netd: {e}"))?;
    stream
        .set_read_timeout(Some(Duration::from_secs(30)))
        .map_err(|e| format!("netd timeout: {e}"))?;
    stream
        .write_all(body.to_string().as_bytes())
        .and_then(|_| stream.shutdown(std::net::Shutdown::Write))
        .map_err(|e| format!("write netd: {e}"))?;
    let mut reply = Vec::new();
    stream
        .read_to_end(&mut reply)
        .map_err(|e| format!("read netd: {e}"))?;
    serde_json::from_slice(&reply).map_err(|e| format!("parse netd reply: {e}"))
}

fn write_update_record(record: &UpdateRecord) -> Result<(), String> {
    let raw = serde_json::to_vec(record).map_err(|e| format!("encode Host update record: {e}"))?;
    durable::write(Path::new(UPDATE_RECORD), &raw)
}

fn read_update_record() -> Option<UpdateRecord> {
    fs::read(UPDATE_RECORD)
        .ok()
        .and_then(|raw| serde_json::from_slice(&raw).ok())
}

fn write_outcome(release: &str, outcome: &str, reason: Option<&str>) {
    let record = json!({"release": release, "outcome": outcome, "reason": reason});
    if let Err(err) = durable::write(Path::new(UPDATE_OUTCOME), record.to_string().as_bytes()) {
        eprintln!("fwos-update: record Host update outcome: {err}");
    }
}

fn read_outcome() -> Option<Value> {
    fs::read(UPDATE_OUTCOME)
        .ok()
        .and_then(|raw| serde_json::from_slice(&raw).ok())
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
        booted_digest: image_digest(status, "booted"),
        staged_digest: image_digest(status, "staged"),
        rollback_digest: image_digest(status, "rollback"),
        rollback_queued: status["status"]["rollbackQueued"] == true,
    }
}

fn image_digest(status: &Value, which: &str) -> String {
    status["status"][which]["image"]["imageDigest"]
        .as_str()
        .unwrap_or_default()
        .to_string()
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

#[derive(Debug, Clone, PartialEq, Eq)]
enum ApplianceHealth {
    Ok,
    DefaultTargetNotReached,
    FwdMissing,
    MgmtMissing,
    NetdNotRunning,
    DesiredStateNotRestored(String),
    UiNotRunning,
}

impl ApplianceHealth {
    fn describe(&self) -> String {
        match self {
            Self::Ok => "ok".into(),
            Self::DefaultTargetNotReached => "default target not reached".into(),
            Self::FwdMissing => "fwd missing".into(),
            Self::MgmtMissing => "mgmt missing".into(),
            Self::NetdNotRunning => "netd not running".into(),
            Self::DesiredStateNotRestored(reason) => {
                format!("Desired state not restored: {reason}")
            }
            Self::UiNotRunning => "UI not running".into(),
        }
    }
}

/// What netd reports about restoring Accepted Desired state on this boot.
#[derive(Debug, Clone, PartialEq, Eq)]
enum NetdRestoration {
    NotRunning,
    Unrestored(String),
    Restored,
}

fn netd_restoration(reply: Result<Value, String>) -> NetdRestoration {
    match reply {
        Err(_) => NetdRestoration::NotRunning,
        Ok(reply) if reply["ok"] == true && reply["restored"] == true => NetdRestoration::Restored,
        Ok(reply) => NetdRestoration::Unrestored(
            reply["reason"]
                .as_str()
                .or_else(|| reply["error"].as_str())
                .unwrap_or("netd did not report restoration")
                .to_string(),
        ),
    }
}

/// Upstream reachability is deliberately absent: an unplugged WAN or an ISP
/// outage is not a failed Release.
struct HealthChecks {
    default_target: bool,
    fwd: bool,
    mgmt: bool,
    netd: NetdRestoration,
    ui: bool,
}

fn assess_health(checks: &HealthChecks) -> ApplianceHealth {
    if !checks.default_target {
        return ApplianceHealth::DefaultTargetNotReached;
    }
    if !checks.fwd {
        return ApplianceHealth::FwdMissing;
    }
    if !checks.mgmt {
        return ApplianceHealth::MgmtMissing;
    }
    match &checks.netd {
        NetdRestoration::NotRunning => return ApplianceHealth::NetdNotRunning,
        NetdRestoration::Unrestored(reason) => {
            return ApplianceHealth::DesiredStateNotRestored(reason.clone())
        }
        NetdRestoration::Restored => (),
    }
    if !checks.ui {
        return ApplianceHealth::UiNotRunning;
    }
    ApplianceHealth::Ok
}

fn should_auto_rollback(
    pending_this_boot: bool,
    has_rollback: bool,
    health: &ApplianceHealth,
) -> bool {
    pending_this_boot && has_rollback && *health != ApplianceHealth::Ok
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
        let health = assess_health(&HealthChecks {
            default_target: default_target_reached(),
            fwd: netns_exists("fwd"),
            mgmt: netns_exists("mgmt"),
            netd: netd_restoration(netd_cmd(&json!({"op": "restoration_status"}))),
            ui: unit_active("fwos-ui-mgmt.service"),
        });
        if this_boot && health == ApplianceHealth::Ok {
            accept_update(&booted);
            clear_pending();
            console_log("appliance health ok");
            return Ok(());
        }
        if Instant::now() >= deadline {
            if should_auto_rollback(this_boot, has_rollback, &health) {
                let reason = health.describe();
                console_log(&format!("appliance health failed ({reason}); rolling back"));
                write_outcome(&booted, "rolled_back", Some(&reason));
                // The previous Release restores the preserved network itself,
                // from the Host update record this boot leaves in place.
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

/// The update boot is a working appliance: the pre-update network is no longer
/// a rollback restoration target.
fn accept_update(booted: &str) {
    if let Err(err) = netd_cmd(&json!({"op": "discard_pre_update"})) {
        eprintln!("fwos-update: discard pre-update network: {err}");
    }
    if let Err(err) = durable::remove(Path::new(UPDATE_RECORD)) {
        eprintln!("fwos-update: {err}");
    }
    write_outcome(booted, "accepted", None);
}

/// Before netd starts: on the previous Release after a rollback from the
/// update boot, ask netd to restore the network preserved before the update.
fn run_restore_check() -> Result<(), String> {
    let Some(record) = read_update_record() else {
        return Ok(());
    };
    let deployments = bootc_status()?;
    if !returned_from_update(&record, &deployments) {
        return Ok(());
    }
    durable::write(
        Path::new(RESTORE_PRE_UPDATE),
        record.update.image.as_bytes(),
    )?;
    durable::remove(Path::new(UPDATE_RECORD))?;
    console_log(&format!(
        "Host update to {} was rolled back; restoring the pre-update network",
        record.update.image
    ));
    Ok(())
}

fn default_target_reached() -> bool {
    unit_active("default.target")
}

fn unit_active(unit: &str) -> bool {
    Command::new("systemctl")
        .args(["is-active", "--quiet", unit])
        .env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin")
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

fn netns_exists(name: &str) -> bool {
    Path::new("/run/netns").join(name).exists()
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
            None,
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
        let status =
            |v: Value| status_reply(&deployments(&v), &idle, None)["reboot_required"].clone();
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

    fn checks() -> HealthChecks {
        HealthChecks {
            default_target: true,
            fwd: true,
            mgmt: true,
            netd: NetdRestoration::Restored,
            ui: true,
        }
    }

    #[test]
    fn appliance_health_requires_restored_desired_state_and_local_services() {
        assert_eq!(assess_health(&checks()), ApplianceHealth::Ok);
        let failed = |change: fn(&mut HealthChecks)| {
            let mut checks = checks();
            change(&mut checks);
            assess_health(&checks)
        };
        assert_eq!(
            failed(|c| c.default_target = false),
            ApplianceHealth::DefaultTargetNotReached
        );
        assert_eq!(failed(|c| c.fwd = false), ApplianceHealth::FwdMissing);
        assert_eq!(failed(|c| c.mgmt = false), ApplianceHealth::MgmtMissing);
        assert_eq!(
            failed(|c| c.netd = NetdRestoration::NotRunning),
            ApplianceHealth::NetdNotRunning
        );
        // A running netd that has not restored the network and its LAN
        // services is not a working appliance.
        assert_eq!(
            failed(|c| c.netd = NetdRestoration::Unrestored("LAN services failed".into())),
            ApplianceHealth::DesiredStateNotRestored("LAN services failed".into())
        );
        assert_eq!(failed(|c| c.ui = false), ApplianceHealth::UiNotRunning);
    }

    #[test]
    fn netd_restoration_reply_is_read_strictly() {
        let restored = json!({"ok": true, "restored": true, "revision": 3});
        assert_eq!(netd_restoration(Ok(restored)), NetdRestoration::Restored);
        let unrestored =
            json!({"ok": true, "restored": false, "reason": "LAN services are starting"});
        assert_eq!(
            netd_restoration(Ok(unrestored)),
            NetdRestoration::Unrestored("LAN services are starting".into())
        );
        let unknown = json!({"ok": false, "error": "unknown op restoration_status"});
        assert!(matches!(
            netd_restoration(Ok(unknown)),
            NetdRestoration::Unrestored(_)
        ));
        assert_eq!(
            netd_restoration(Err("connect: refused".into())),
            NetdRestoration::NotRunning
        );
    }

    fn id(image: &str, digest: &str) -> DeploymentId {
        DeploymentId {
            image: image.into(),
            digest: digest.into(),
        }
    }

    #[test]
    fn a_rollback_from_the_update_boot_is_recognized_on_the_previous_release() {
        let record = UpdateRecord {
            previous: id("localhost/fwos:dev", "sha256:a"),
            update: id("10.0.2.2:5000/fwos:next", "sha256:b"),
        };
        let back = Deployments {
            booted: "localhost/fwos:dev".into(),
            booted_digest: "sha256:a".into(),
            rollback: "10.0.2.2:5000/fwos:next".into(),
            rollback_digest: "sha256:b".into(),
            ..Deployments::default()
        };
        assert!(returned_from_update(&record, &back));
        // The update boot itself, and a previous Release whose staged update
        // was never activated, are not a return from the update.
        let update_boot = Deployments {
            booted: "10.0.2.2:5000/fwos:next".into(),
            booted_digest: "sha256:b".into(),
            rollback: "localhost/fwos:dev".into(),
            rollback_digest: "sha256:a".into(),
            ..Deployments::default()
        };
        assert!(!returned_from_update(&record, &update_boot));
        let never_activated = Deployments {
            rollback: "10.0.2.2:5000/fwos:next".into(),
            rollback_digest: "sha256:older".into(),
            ..back.clone()
        };
        assert!(!returned_from_update(&record, &never_activated));
        // Without digests, image references decide.
        let refs = UpdateRecord {
            previous: id("localhost/fwos:dev", ""),
            update: id("docker://10.0.2.2:5000/fwos:next", ""),
        };
        assert!(returned_from_update(&refs, &back));
    }

    #[test]
    fn host_update_outcome_is_reported_in_status() {
        let outcome = json!({"release": "10.0.2.2:5000/fwos:next", "outcome": "rolled_back",
            "reason": "Desired state not restored: LAN services failed"});
        let reply = status_reply(
            &Deployments::default(),
            &Operation::Idle,
            Some(outcome.clone()),
        );
        assert_eq!(reply["last_update"], outcome);
        let reply = status_reply(&Deployments::default(), &Operation::Idle, None);
        assert_eq!(reply["last_update"], Value::Null);
    }

    #[test]
    fn bootc_status_reports_deployment_digests() {
        let status = json!({"status": {
            "booted": {"image": {"image": {"image": "localhost/fwos:dev"}, "imageDigest": "sha256:a"}},
            "rollback": {"image": {"image": {"image": "localhost/fwos:old"}, "imageDigest": "sha256:0"}}
        }});
        let found = deployments(&status);
        assert_eq!(found.booted_digest, "sha256:a");
        assert_eq!(found.rollback_digest, "sha256:0");
        assert_eq!(found.staged_digest, "");
    }

    #[test]
    fn auto_rollback_only_after_host_update_boot_with_a_rollback_target() {
        assert!(!should_auto_rollback(
            false,
            true,
            &ApplianceHealth::NetdNotRunning
        ));
        assert!(!should_auto_rollback(
            true,
            false,
            &ApplianceHealth::NetdNotRunning
        ));
        assert!(!should_auto_rollback(true, true, &ApplianceHealth::Ok));
        assert!(should_auto_rollback(
            true,
            true,
            &ApplianceHealth::NetdNotRunning
        ));
        assert!(should_auto_rollback(
            true,
            true,
            &ApplianceHealth::FwdMissing
        ));
        assert!(should_auto_rollback(
            true,
            true,
            &ApplianceHealth::DesiredStateNotRestored("LAN services failed".into())
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

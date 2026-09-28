use std::env;
use std::ffi::CString;
use std::fs;
use std::io::{Read, Write};
use std::net::IpAddr;
use std::os::fd::AsRawFd;
use std::os::unix::fs::{chown, MetadataExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::{self, Command, Stdio};
use std::sync::{Mutex, MutexGuard};
use std::thread;
use std::time::{Duration, Instant};

use fwos_fwd_setup::durable;
use fwos_fwd_setup::{fwd_resolvers, host_image};
use fwos_fwd_setup::host_update::{NetworkRestoration, NETWORK_RESTORATION, RESTORE_PRE_UPDATE};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

const SOCK: &str = "/var/lib/fwos/update.sock";
const BOOTSTRAPPED: &str = "/var/lib/fwos/bootstrapped";
const PENDING: &str = "/var/lib/fwos/health-pending";
/// The deployments of a staged Host update, kept until its boot is accepted.
const UPDATE_RECORD: &str = "/var/lib/fwos/host-update.json";
/// The last post-update health outcome, for status.
const UPDATE_OUTCOME: &str = "/var/lib/fwos/host-update-outcome.json";
const NETD_SOCK: &str = "/var/lib/fwos/netd.sock";
const REGISTRIES_DROPIN: &str = "/etc/containers/registries.conf.d/fwos-update.conf";
const FWD_NETNS: &str = "/run/netns/fwd";
const WORKER_RESOLVER_DIR: &str = "/run/systemd/resolve";
const RESOLV_CONF: &str = "/etc/resolv.conf";
const HEALTH_TIMEOUT: Duration = Duration::from_secs(180);
/// Runs `fwos-update health` on every boot and exits once it has decided.
const HEALTH_UNIT: &str = "fwos-health.service";
/// A queued manual Host image rollback, until the next boot.
const MANUAL_ROLLBACK: &str = "/var/lib/fwos/host-image-rollback.json";

#[derive(Debug, Deserialize)]
struct Request {
    op: String,
    #[serde(default)]
    image: String,
}

fn main() {
    match env::args().nth(1).as_deref() {
        Some("worker") => {
            let program: Vec<String> = env::args().skip(2).collect();
            if let Err(err) = run_worker(&program) {
                eprintln!("fwos-update worker: {err}");
            }
            process::exit(1);
        }
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
    let staged = bootc_images().staged.image;
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
    booted: DeploymentId,
    staged: DeploymentId,
    rollback: DeploymentId,
    /// `bootc rollback` makes the rollback deployment the next boot.
    rollback_queued: bool,
}

/// One bootc deployment: its image reference and, when bootc reports it, the
/// image digest that distinguishes two pulls of the same tag. An empty image
/// means there is no such deployment.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
struct DeploymentId {
    image: String,
    #[serde(default)]
    digest: String,
}

impl DeploymentId {
    fn matches(&self, other: &DeploymentId) -> bool {
        if !self.digest.is_empty() && !other.digest.is_empty() {
            return self.digest == other.digest;
        }
        pending_is_this_boot(&self.image, &other.image)
    }

    fn is_empty(&self) -> bool {
        self.image.is_empty()
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
    record.previous.matches(&deployments.booted) && record.update.matches(&deployments.rollback)
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
        // The next boot runs the rollback deployment, not the booted one.
        "rollback_queued": deployments.rollback_queued,
        "booted": deployments.booted.image,
        "staged": deployments.staged.image,
        "rollback": deployments.rollback.image,
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
    let mut reply = status_reply(&deployments, &op, last_update());
    // Evidence of ADR-0060 placement: the controller in the Host netns, the
    // last download worker in `fwd`.
    reply["worker_network"] = LAST_WORKER
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .clone()
        .unwrap_or(Value::Null);
    reply
}

const NOT_BOOTSTRAPPED: &str = "Host update refused until Bootstrap has completed";

fn handle_request(req: Request) -> String {
    match req.op.as_str() {
        "status" => current_status().to_string(),
        "reboot" => {
            if !bootstrap_completed() {
                return json!({"ok": false, "error": NOT_BOOTSTRAPPED}).to_string();
            }
            // Hold the operation until the reply: no stage may start between
            // preserving the network and the reboot.
            let op = lock_operation();
            if let Err(err) = idle(&op) {
                return json!({"ok": false, "error": err}).to_string();
            }
            refresh_pre_update();
            drop(op);
            json!({"ok": true, "rebooting": true}).to_string()
        }
        "rollback" => rollback_request(),
        "stage" => stage_request(&req.image),
        "start_stage" => start_stage_request(&req.image),
        other => json!({"ok": false, "error": format!("unknown op {other}")}).to_string(),
    }
}

/// What a manual Host image rollback returns from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ManualRollback {
    /// An accepted Release, or one that was never a Host update boot. Only
    /// the bootc deployment changes: the Accepted Desired state stays.
    Image,
    /// An update boot whose appliance health check finished without accepting
    /// it. Returning from it is a rejected update: the previous Release
    /// restores the network preserved before the update, as after an
    /// automatic rollback.
    UnacceptedUpdate,
}

/// Until appliance health has finished on an update boot, it owns the
/// rollback: a manual rollback before or while it runs could be undone by
/// its own `bootc rollback`.
fn manual_rollback(
    update_boot_pending: bool,
    health_finished: bool,
) -> Result<ManualRollback, String> {
    match (update_boot_pending, health_finished) {
        (true, false) => Err(format!(
            "appliance health has not finished checking this Host update boot and rolls it \
             back automatically if it fails; try again when it has finished (within {} seconds)",
            HEALTH_TIMEOUT.as_secs()
        )),
        (true, true) => Ok(ManualRollback::UnacceptedUpdate),
        (false, _) => Ok(ManualRollback::Image),
    }
}

/// A queued manual rollback, kept until the next boot shows whether it
/// happened. Cancelling it before the reboot removes it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct ManualRollbackRecord {
    from: DeploymentId,
    to: DeploymentId,
}

/// The boot order a manual rollback changes; `bootc` on the appliance.
trait BootOrder {
    fn status(&mut self) -> Result<Deployments, String>;
    fn rollback(&mut self) -> Result<(), String>;
}

struct Bootc;

impl BootOrder for Bootc {
    fn status(&mut self) -> Result<Deployments, String> {
        bootc_status()
    }

    fn rollback(&mut self) -> Result<(), String> {
        bootc_rollback()
    }
}

/// Files a manual rollback keeps: its record, and the health-pending record
/// of an update boot.
struct ManualRollbackFiles<'a> {
    record: &'a Path,
    pending: &'a Path,
}

/// Queue the rollback deployment for the next boot, or cancel a queued manual
/// rollback (`bootc rollback` swaps the order back). Nothing else is written:
/// the outcome is recorded once the previous Release has booted, so a
/// cancelled or never-activated rollback leaves no trace. Returns the
/// deployments as they were before, and whether the queued rollback returns
/// from an unaccepted update.
fn manual_rollback_step(
    bootc: &mut impl BootOrder,
    files: &ManualRollbackFiles<'_>,
    health_finished: impl Fn() -> bool,
) -> Result<(Deployments, bool), String> {
    let before = bootc.status()?;
    let pending = read_pending_at(files.pending);
    let kind = manual_rollback(
        pending_is_this_boot(&pending, &before.booted.image),
        health_finished(),
    )?;
    if before.rollback_queued {
        if !files.record.exists() {
            return Err(
                "the queued Host image rollback was not requested manually and cannot be cancelled"
                    .into(),
            );
        }
        bootc.rollback()?;
        durable::remove(files.record)?;
        return Ok((before, false));
    }
    let record = ManualRollbackRecord {
        from: before.booted.clone(),
        to: before.rollback.clone(),
    };
    let raw = serde_json::to_vec(&record).map_err(|e| format!("encode rollback record: {e}"))?;
    durable::write(files.record, &raw)?;
    if let Err(err) = bootc.rollback() {
        let _ = durable::remove(files.record);
        return Err(err);
    }
    // An unaccepted update keeps its health-pending record, so a cancelled
    // rollback leaves it checked again on its next boot. Otherwise the only
    // pending record is that of a staged update, which `bootc rollback`
    // discarded.
    if kind == ManualRollback::Image {
        let _ = fs::remove_file(files.pending);
    }
    Ok((before, kind == ManualRollback::UnacceptedUpdate))
}

/// Manual Host image rollback: queue the previous bootc deployment for the
/// next boot, or cancel a queued one. Reboot is the operator's separate step,
/// as after staging. Identity configuration in shared `/var` is untouched,
/// and restoring a previous network revision is netd's separate operation.
fn rollback_request() -> String {
    if !bootstrap_completed() {
        return json!({"ok": false, "error": NOT_BOOTSTRAPPED}).to_string();
    }
    // Hold the operation so no stage starts while the boot order changes.
    let op = lock_operation();
    if let Err(err) = idle(&op) {
        return json!({"ok": false, "error": err}).to_string();
    }
    let files = ManualRollbackFiles {
        record: Path::new(MANUAL_ROLLBACK),
        pending: Path::new(PENDING),
    };
    let (before, pre_update_network) =
        match manual_rollback_step(&mut Bootc, &files, health_finished) {
            Ok(step) => step,
            Err(err) => return json!({"ok": false, "error": err}).to_string(),
        };
    drop(op);
    rollback_reply(&before, pre_update_network, current_status()).to_string()
}

/// At boot: the outcome of a manual rollback that actually took effect.
/// `pre_update_network` is whether this boot returns from an unaccepted
/// update, whose preserved network the previous Release restores.
fn manual_rollback_outcome(
    record: &ManualRollbackRecord,
    deployments: &Deployments,
    pre_update_network: bool,
) -> Option<UpdateOutcome> {
    (record.to.matches(&deployments.booted) && record.from.matches(&deployments.rollback)).then(
        || UpdateOutcome {
            release: record.from.image.clone(),
            outcome: Outcome::RolledBack,
            reason: Some("manual rollback".into()),
            manual: Some(ManualOutcome {
                to: record.to.image.clone(),
                pre_update_network,
            }),
        },
    )
}

/// `bootc rollback` discards a staged, never-activated update; say so, and
/// whether the previous Release restores the pre-update network.
fn rollback_reply(before: &Deployments, pre_update_network: bool, mut status: Value) -> Value {
    if status["ok"] != true {
        return status;
    }
    if !before.staged.is_empty() && status["staged"] == "" {
        status["discarded_staged"] = json!(before.staged.image);
    }
    status["restores_pre_update_network"] =
        json!(pre_update_network && status["rollback_queued"] == true);
    status
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
    resolvable(image, fs::read_to_string(fwd_resolvers::PATH).ok().as_deref())?;
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
    let staged = after.staged.image.clone();
    write_update_record(&UpdateRecord {
        previous: before.booted,
        update: after.staged,
    })?;
    write_pending(&staged)
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum Outcome {
    Accepted,
    RolledBack,
}

/// The post-update health decision on an update boot.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct UpdateOutcome {
    release: String,
    outcome: Outcome,
    #[serde(default)]
    reason: Option<String>,
    /// Set when an administrator rolled the Host image back, rather than
    /// appliance health. Omitted otherwise; an older Release ignores it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    manual: Option<ManualOutcome>,
}

/// A manual Host image rollback from `release` to `to`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct ManualOutcome {
    to: String,
    /// The rollback left an unaccepted update, so the previous Release
    /// restores the pre-update network. Otherwise the Accepted Desired state
    /// was kept and no restoration belongs to this rollback.
    pre_update_network: bool,
}

fn write_outcome(outcome: &UpdateOutcome) {
    let written = serde_json::to_vec(outcome)
        .map_err(|e| format!("encode Host update outcome: {e}"))
        .and_then(|raw| durable::write(Path::new(UPDATE_OUTCOME), &raw));
    if let Err(err) = written {
        eprintln!("fwos-update: record Host update outcome: {err}");
    }
}

fn read_json<T: serde::de::DeserializeOwned>(path: &str) -> Option<T> {
    fs::read(path)
        .ok()
        .and_then(|raw| serde_json::from_slice(&raw).ok())
}

fn last_update() -> Option<Value> {
    last_update_json(read_json(UPDATE_OUTCOME), read_json(NETWORK_RESTORATION))
}

/// A rollback's outcome carries how the previous Release restored the
/// pre-update network, once netd has reported it.
fn last_update_json(
    outcome: Option<UpdateOutcome>,
    network: Option<NetworkRestoration>,
) -> Option<Value> {
    let outcome = outcome?;
    let restores_network = outcome.outcome == Outcome::RolledBack
        && outcome
            .manual
            .as_ref()
            .is_none_or(|manual| manual.pre_update_network);
    let network = network.filter(|_| restores_network);
    let mut json = serde_json::to_value(&outcome).ok()?;
    json["network"] = serde_json::to_value(network).ok()?;
    Some(json)
}

fn bootstrap_completed() -> bool {
    Path::new(BOOTSTRAPPED).is_file()
}

/// The registry host of an image reference; Docker Hub when it names none.
fn registry_host(image: &str) -> &str {
    let rest = image.strip_prefix("docker://").unwrap_or(image);
    match rest.split_once('/') {
        Some((host, _)) if host.contains(['.', ':']) || host == "localhost" => host,
        _ => "docker.io",
    }
}

/// A registry name resolves only through the resolvers `fwd` learned from
/// its WANs; say so plainly instead of letting the download fail on DNS.
fn resolvable(image: &str, published: Option<&str>) -> Result<(), String> {
    let host = registry_host(image);
    if local_registry_host(image).is_some() || published.is_some_and(fwd_resolvers::has_resolver) {
        return Ok(());
    }
    Err(format!(
        "no DNS resolver learned from any WAN, so the registry name {host} cannot be resolved"
    ))
}

/// Where the last worker's download ran, from its netns marker.
static LAST_WORKER: Mutex<Option<Value>> = Mutex::new(None);

fn worker_netns(stderr: &str) -> Option<u64> {
    stderr
        .lines()
        .find_map(|line| line.strip_prefix(WORKER_NETNS_MARKER))
        .and_then(|inode| inode.trim().parse().ok())
}

fn placement(worker: Option<u64>, fwd: Option<u64>, controller: Option<u64>, host: Option<u64>) -> Value {
    let controller = if controller.is_some() && controller == host { "host" } else { "other" };
    let worker = match worker {
        None => "not started",
        Some(inode) if Some(inode) == fwd => "fwd",
        Some(_) => "other",
    };
    json!({"controller": controller, "worker": worker})
}

fn bootc_switch(image: &str) -> Result<(), String> {
    allow_insecure_local_registry(image)?;
    let output = switch_command(image)
        .env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin")
        .stdin(Stdio::null())
        .output()
        .map_err(|e| format!("bootc switch: {e}"))?;
    *LAST_WORKER.lock().unwrap_or_else(|p| p.into_inner()) = Some(placement(
        worker_netns(&String::from_utf8_lossy(&output.stderr)),
        netns_inode(FWD_NETNS),
        netns_inode("/proc/self/ns/net"),
        netns_inode("/proc/1/ns/net"),
    ));
    if output.status.success() {
        Ok(())
    } else {
        Err(format!(
            "bootc switch failed: {} {}",
            String::from_utf8_lossy(&output.stdout).trim(),
            String::from_utf8_lossy(&output.stderr)
                .lines()
                .filter(|line| !line.starts_with(WORKER_NETNS_MARKER))
                .collect::<Vec<_>>()
                .join("\n")
                .trim()
        ))
    }
}

/// `bootc switch` and its download children run in a temporary worker with
/// `fwd` networking (ADR-0060); this controller stays in the Host netns.
/// Stage only. Never pass --apply: reboot is a later operator step.
fn switch_command(image: &str) -> Command {
    let mut command = Command::new(worker_program());
    command.args(["worker", "bootc", "switch", "--quiet", image]);
    command
}

fn worker_program() -> std::path::PathBuf {
    env::current_exe().unwrap_or_else(|_| "/usr/bin/fwos-update".into())
}

/// The worker: leave the Host netns for `fwd` and resolve names with the
/// resolvers `fwd` learned from its WANs, then become `program`. It keeps the
/// Host filesystem and deployment state, and it configures no interface,
/// route, or firewall policy.
fn run_worker(program: &[String]) -> Result<(), String> {
    let (name, args) = program
        .split_first()
        .ok_or("worker needs a program to run")?;
    enter_fwd_networking()?;
    let err = Command::new(name).args(args).exec();
    Err(format!("exec {name}: {err}"))
}

/// The worker announces the network namespace it joined on stderr, so the
/// controller can report where the download ran.
const WORKER_NETNS_MARKER: &str = "fwos-update worker netns ";

fn enter_fwd_networking() -> Result<(), String> {
    let fwd = fs::File::open(FWD_NETNS).map_err(|e| format!("open {FWD_NETNS}: {e}"))?;
    // A private mount namespace keeps the resolver mounts below to this worker.
    // bootc sees it is already unshared and remounts /sysroot in it as usual.
    syscall_ok(unsafe { libc::unshare(libc::CLONE_NEWNS) }, "unshare mount namespace")?;
    mount(None, "/", None, libc::MS_REC | libc::MS_SLAVE, None)?;
    syscall_ok(
        unsafe { libc::setns(fwd.as_raw_fd(), libc::CLONE_NEWNET) },
        "join the fwd network namespace",
    )?;
    if let Some(inode) = netns_inode("/proc/self/ns/net") {
        eprintln!("{WORKER_NETNS_MARKER}{inode}");
    }
    use_fwd_resolvers()
}

fn netns_inode(path: &str) -> Option<u64> {
    fs::metadata(path).ok().map(|meta| meta.ino())
}

/// systemd-resolved answers NSS lookups from the Host netns. Covering its
/// runtime directory (only inside this worker's mount namespace) hides that
/// socket, so lookups read /etc/resolv.conf, which the resolvers netd
/// published for `fwd` now cover. Without them, names do not resolve.
fn use_fwd_resolvers() -> Result<(), String> {
    let resolved_hidden = Path::new(WORKER_RESOLVER_DIR).is_dir();
    if resolved_hidden {
        mount(
            Some("tmpfs"),
            WORKER_RESOLVER_DIR,
            Some("tmpfs"),
            libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC,
            Some("mode=0755"),
        )?;
    }
    if !Path::new(fwd_resolvers::PATH).is_file() {
        eprintln!("fwos-update worker: no resolvers published for fwd");
        return Ok(());
    }
    let target = resolv_conf_target(fs::read_link(RESOLV_CONF).ok());
    if resolved_hidden && target.starts_with(WORKER_RESOLVER_DIR) {
        // Fedora links /etc/resolv.conf to a file in the hidden directory.
        fs::write(&target, "").map_err(|e| format!("create {}: {e}", target.display()))?;
    } else if !target.exists() {
        eprintln!("fwos-update worker: {RESOLV_CONF} is missing; names will not resolve");
        return Ok(());
    }
    mount(Some(fwd_resolvers::PATH), RESOLV_CONF, None, libc::MS_BIND, None)
}

/// The file /etc/resolv.conf names, given its symlink target if it is one.
fn resolv_conf_target(link: Option<std::path::PathBuf>) -> std::path::PathBuf {
    let Some(link) = link else {
        return RESOLV_CONF.into();
    };
    let mut target = std::path::PathBuf::from("/etc");
    for part in link.components() {
        match part {
            std::path::Component::RootDir => target = "/".into(),
            std::path::Component::ParentDir => {
                target.pop();
            }
            std::path::Component::Normal(name) => target.push(name),
            _ => {}
        }
    }
    target
}

fn mount(
    source: Option<&str>,
    target: &str,
    fstype: Option<&str>,
    flags: libc::c_ulong,
    data: Option<&str>,
) -> Result<(), String> {
    let cstr = |s: &str| CString::new(s).map_err(|_| format!("mount argument {s:?}"));
    let source = source.map(cstr).transpose()?;
    let target_c = cstr(target)?;
    let fstype = fstype.map(cstr).transpose()?;
    let data = data.map(cstr).transpose()?;
    let ptr = |s: &Option<CString>| s.as_ref().map_or(std::ptr::null(), |s| s.as_ptr());
    syscall_ok(
        unsafe {
            libc::mount(
                ptr(&source),
                target_c.as_ptr(),
                ptr(&fstype),
                flags,
                ptr(&data).cast(),
            )
        },
        &format!("mount {target}"),
    )
}

fn syscall_ok(rc: libc::c_int, what: &str) -> Result<(), String> {
    if rc == 0 {
        Ok(())
    } else {
        Err(format!("{what}: {}", std::io::Error::last_os_error()))
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
        booted: deployment_id(status, "booted"),
        staged: deployment_id(status, "staged"),
        rollback: deployment_id(status, "rollback"),
        rollback_queued: status["status"]["rollbackQueued"] == true,
    }
}

fn deployment_id(status: &Value, which: &str) -> DeploymentId {
    DeploymentId {
        image: image_ref(status, which),
        digest: status["status"][which]["image"]["imageDigest"]
            .as_str()
            .unwrap_or_default()
            .to_string(),
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
    read_pending_at(Path::new(PENDING))
}

fn read_pending_at(path: &Path) -> String {
    fs::read_to_string(path)
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
        let booted = booted.image;
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
                write_outcome(&UpdateOutcome {
                    release: booted.clone(),
                    outcome: Outcome::RolledBack,
                    reason: Some(reason),
                    manual: None,
                });
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
    let discarded = netd_cmd(&json!({"op": "discard_pre_update"})).and_then(|reply| {
        if reply["ok"] == true {
            Ok(())
        } else {
            Err(reply["error"]
                .as_str()
                .unwrap_or("netd refused")
                .to_string())
        }
    });
    if let Err(err) = discarded {
        // Harmless: the next stage preserves a new revision over it.
        eprintln!("fwos-update: discard pre-update network: {err}");
    }
    if let Err(err) = durable::remove(Path::new(UPDATE_RECORD)) {
        eprintln!("fwos-update: {err}");
    }
    write_outcome(&UpdateOutcome {
        release: booted.to_string(),
        outcome: Outcome::Accepted,
        reason: None,
        manual: None,
    });
}

/// Before netd starts: record a manual rollback that took effect, and, on the
/// previous Release after a rollback from the update boot, ask netd to restore
/// the network preserved before the update.
fn run_restore_check() -> Result<(), String> {
    let manual: Option<ManualRollbackRecord> = read_json(MANUAL_ROLLBACK);
    let record = read_update_record();
    if manual.is_none() && record.is_none() {
        return Ok(());
    }
    let deployments = bootc_status()?;
    let returned = record
        .as_ref()
        .is_some_and(|record| returned_from_update(record, &deployments));
    if let Some(manual) = manual {
        if let Some(outcome) = manual_rollback_outcome(&manual, &deployments, returned) {
            write_outcome(&outcome);
            console_log(&format!(
                "Host image manually rolled back from {} to {}",
                manual.from.image, manual.to.image
            ));
        }
        durable::remove(Path::new(MANUAL_ROLLBACK))?;
    }
    let Some(record) = record.filter(|_| returned) else {
        return Ok(());
    };
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

/// Whether `fwos-health.service` has run and exited on this boot.
fn health_finished() -> bool {
    Command::new("systemctl")
        .args([
            "show",
            "--property=ExecMainExitTimestampMonotonic",
            "--value",
            HEALTH_UNIT,
        ])
        .env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin")
        .output()
        .map(|output| exited_this_boot(&String::from_utf8_lossy(&output.stdout)))
        .unwrap_or(false)
}

/// systemd's exit timestamp of a unit's main process, 0 until it exits;
/// unit state does not survive a reboot.
fn exited_this_boot(exit_timestamp: &str) -> bool {
    exit_timestamp
        .trim()
        .parse::<u64>()
        .is_ok_and(|timestamp| timestamp > 0)
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
    fn registry_names_are_never_plain_http() {
        assert_eq!(local_registry_host("registry.fwos.test:5000/fwos:next"), None);
        assert_eq!(local_registry_host("quay.io/fwos:next"), None);
    }

    #[test]
    fn a_registry_name_needs_a_wan_resolver() {
        let none = fwd_resolvers::resolv_conf("");
        let some = fwd_resolvers::resolv_conf("nameserver 2001:db8::53\n");
        let err = resolvable("quay.io/coldboot-labs/fwos:next", Some(&none)).unwrap_err();
        assert!(err.contains("no DNS resolver learned from any WAN"), "{err}");
        assert!(resolvable("quay.io/coldboot-labs/fwos:next", None).is_err());
        assert!(resolvable("fedora/fedora-bootc:44", None).is_err(), "docker.io by default");
        assert!(resolvable("quay.io/coldboot-labs/fwos:next", Some(&some)).is_ok());
        assert!(resolvable("10.0.2.2:5000/fwos:next", None).is_ok());
        assert!(resolvable("localhost:5000/fwos:next", None).is_ok());
    }

    #[test]
    fn resolv_conf_link_targets_are_absolute() {
        assert_eq!(resolv_conf_target(None), Path::new("/etc/resolv.conf"));
        assert_eq!(
            resolv_conf_target(Some("../run/systemd/resolve/stub-resolv.conf".into())),
            Path::new("/run/systemd/resolve/stub-resolv.conf")
        );
        assert_eq!(
            resolv_conf_target(Some("/run/systemd/resolve/resolv.conf".into())),
            Path::new("/run/systemd/resolve/resolv.conf")
        );
    }

    #[test]
    fn worker_placement_is_read_from_its_netns_marker() {
        let stderr = format!("noise\n{WORKER_NETNS_MARKER}4026533451\nmore");
        assert_eq!(worker_netns(&stderr), Some(4026533451));
        assert_eq!(worker_netns("fwos-update worker: open /run/netns/fwd: gone"), None);
        assert_eq!(
            placement(Some(7), Some(7), Some(1), Some(1)),
            json!({"controller": "host", "worker": "fwd"})
        );
        assert_eq!(
            placement(None, Some(7), Some(2), Some(1)),
            json!({"controller": "other", "worker": "not started"})
        );
    }

    #[test]
    fn switch_downloads_in_a_fwd_worker() {
        let switch = switch_command("registry.fwos.test:5000/fwos:next");
        let args: Vec<_> = switch.get_args().map(|a| a.to_string_lossy().into_owned()).collect();
        assert_eq!(
            args,
            ["worker", "bootc", "switch", "--quiet", "registry.fwos.test:5000/fwos:next"]
        );
    }

    #[test]
    fn status_op_reports_bootc_deployments() {
        let reply = status_reply(
            &Deployments {
                booted: id("a:1", ""),
                rollback: id("a:0", ""),
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
            booted: id("localhost/fwos:dev", ""),
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
    fn status_reports_a_queued_image_rollback() {
        let queued = json!({"status": {"rollbackQueued": true,
            "booted": {"image": {"image": {"image": "a:2"}}},
            "rollback": {"image": {"image": {"image": "a:1"}}}}});
        let reply = status_reply(&deployments(&queued), &Operation::Idle, None);
        assert_eq!(reply["rollback_queued"], true);
        assert_eq!(reply["rollback"], "a:1");
        let not_queued = status_reply(&Deployments::default(), &Operation::Idle, None);
        assert_eq!(not_queued["rollback_queued"], false);
    }

    #[test]
    fn manual_rollback_waits_until_update_health_has_finished_on_this_boot() {
        // Appliance health owns the decision on an update boot until it has
        // run: a manual rollback before or while it runs could be undone by
        // its own rollback.
        let refused = manual_rollback(true, false).unwrap_err();
        assert!(refused.contains("appliance health"), "{refused}");
        // An accepted update, or no update at all, is a plain image rollback:
        // no network revision is restored.
        assert_eq!(manual_rollback(false, false), Ok(ManualRollback::Image));
        assert_eq!(manual_rollback(false, true), Ok(ManualRollback::Image));
        // An update boot whose health check finished without accepting it.
        assert_eq!(
            manual_rollback(true, true),
            Ok(ManualRollback::UnacceptedUpdate)
        );
    }

    #[test]
    fn health_has_finished_only_once_its_unit_exited_this_boot() {
        assert!(!exited_this_boot("0\n"), "not started or still running");
        assert!(!exited_this_boot(""));
        assert!(!exited_this_boot("[not set]"));
        assert!(exited_this_boot("48213377\n"));
    }

    /// `bootc rollback`: swaps the boot order and discards a staged update.
    struct FakeBootc(Deployments);

    impl BootOrder for FakeBootc {
        fn status(&mut self) -> Result<Deployments, String> {
            Ok(self.0.clone())
        }

        fn rollback(&mut self) -> Result<(), String> {
            if self.0.rollback.is_empty() {
                return Err("No rollback available".into());
            }
            self.0.staged = DeploymentId::default();
            self.0.rollback_queued = !self.0.rollback_queued;
            Ok(())
        }
    }

    fn scratch(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("fwos-update-test-{name}-{}", process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn a_cancelled_manual_rollback_of_an_unaccepted_update_leaves_nothing_behind() {
        let dir = scratch("cancel");
        let (record, pending) = (dir.join("rollback.json"), dir.join("health-pending"));
        let files = ManualRollbackFiles {
            record: &record,
            pending: &pending,
        };
        fs::write(&pending, "reg/fwos:next\n").unwrap();
        let update_boot = Deployments {
            booted: id("reg/fwos:next", "sha256:b"),
            rollback: id("localhost/fwos:dev", "sha256:a"),
            ..Deployments::default()
        };
        let mut bootc = FakeBootc(update_boot.clone());

        // Before or while appliance health runs: refused, nothing changes.
        let refused = manual_rollback_step(&mut bootc, &files, || false).unwrap_err();
        assert!(refused.contains("appliance health"), "{refused}");
        assert_eq!(bootc.0, update_boot);
        assert!(!record.exists());

        // Queued: only the rollback record is written; the update's
        // health-pending record stays.
        let (_, pre_update_network) = manual_rollback_step(&mut bootc, &files, || true).unwrap();
        assert!(pre_update_network);
        assert!(bootc.0.rollback_queued);
        let queued: ManualRollbackRecord =
            serde_json::from_slice(&fs::read(&record).unwrap()).unwrap();
        assert_eq!(queued.from, update_boot.booted);
        assert_eq!(queued.to, update_boot.rollback);
        assert_eq!(read_pending_at(&pending), "reg/fwos:next");

        // Cancelled before the reboot: everything is as it was.
        let (_, pre_update_network) = manual_rollback_step(&mut bootc, &files, || true).unwrap();
        assert!(!pre_update_network);
        assert_eq!(bootc.0, update_boot);
        assert!(!record.exists());
        assert_eq!(read_pending_at(&pending), "reg/fwos:next");
        // Rebooting then records no rollback outcome.
        assert_eq!(manual_rollback_outcome(&queued, &bootc.0, true), None);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_manual_rollback_takes_effect_only_when_the_previous_release_boots() {
        let dir = scratch("boot");
        let (record, pending) = (dir.join("rollback.json"), dir.join("health-pending"));
        let files = ManualRollbackFiles {
            record: &record,
            pending: &pending,
        };
        // An accepted update, with a newer update staged but not activated.
        fs::write(&pending, "reg/fwos:later\n").unwrap();
        let accepted = Deployments {
            booted: id("reg/fwos:next", "sha256:b"),
            staged: id("reg/fwos:later", "sha256:c"),
            rollback: id("localhost/fwos:dev", "sha256:a"),
            rollback_queued: false,
        };
        let mut bootc = FakeBootc(accepted.clone());
        let (before, pre_update_network) =
            manual_rollback_step(&mut bootc, &files, || false).unwrap();
        assert_eq!(before, accepted);
        assert!(!pre_update_network);
        // The discarded staged update is no longer awaiting a health check.
        assert_eq!(read_pending_at(&pending), "");
        let queued: ManualRollbackRecord =
            serde_json::from_slice(&fs::read(&record).unwrap()).unwrap();

        // Not rebooted yet: the next boot of the same deployment is no rollback.
        assert_eq!(manual_rollback_outcome(&queued, &accepted, false), None);
        let previous_booted = Deployments {
            booted: id("localhost/fwos:dev", "sha256:a"),
            rollback: id("reg/fwos:next", "sha256:b"),
            ..Deployments::default()
        };
        let outcome = manual_rollback_outcome(&queued, &previous_booted, false).unwrap();
        assert_eq!(outcome.release, "reg/fwos:next");
        assert_eq!(outcome.outcome, Outcome::RolledBack);
        assert_eq!(outcome.reason.as_deref(), Some("manual rollback"));
        assert_eq!(
            outcome.manual,
            Some(ManualOutcome {
                to: "localhost/fwos:dev".into(),
                pre_update_network: false
            })
        );
        // A plain image rollback owns no network restoration, even a stale one.
        let last = last_update_json(
            Some(outcome),
            Some(NetworkRestoration::Restored { revision: 3 }),
        )
        .unwrap();
        assert_eq!(
            last,
            json!({"release": "reg/fwos:next", "outcome": "rolled_back",
                "reason": "manual rollback",
                "manual": {"to": "localhost/fwos:dev", "pre_update_network": false},
                "network": null})
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn only_a_manually_queued_rollback_can_be_cancelled() {
        let dir = scratch("health-queued");
        let (record, pending) = (dir.join("rollback.json"), dir.join("health-pending"));
        let files = ManualRollbackFiles {
            record: &record,
            pending: &pending,
        };
        let queued_by_health = Deployments {
            booted: id("reg/fwos:next", "sha256:b"),
            rollback: id("localhost/fwos:dev", "sha256:a"),
            rollback_queued: true,
            ..Deployments::default()
        };
        let mut bootc = FakeBootc(queued_by_health.clone());
        let refused = manual_rollback_step(&mut bootc, &files, || true).unwrap_err();
        assert!(refused.contains("cannot be cancelled"), "{refused}");
        assert_eq!(bootc.0, queued_by_health);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn manual_rollback_reply_names_a_discarded_staged_update() {
        let before = Deployments {
            booted: id("a:2", ""),
            staged: id("a:3", ""),
            rollback: id("a:1", ""),
            rollback_queued: false,
        };
        let after = Deployments {
            staged: DeploymentId::default(),
            rollback_queued: true,
            ..before.clone()
        };
        let reply = rollback_reply(&before, false, status_reply(&after, &Operation::Idle, None));
        assert_eq!(reply["ok"], true);
        assert_eq!(reply["rollback_queued"], true);
        assert_eq!(reply["reboot_required"], true);
        assert_eq!(reply["discarded_staged"], "a:3");
        assert_eq!(reply["restores_pre_update_network"], false);
        let plain = rollback_reply(&after, true, status_reply(&after, &Operation::Idle, None));
        assert_eq!(plain["discarded_staged"], Value::Null);
        assert_eq!(plain["restores_pre_update_network"], true);
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
            booted: id("localhost/fwos:dev", "sha256:a"),
            rollback: id("10.0.2.2:5000/fwos:next", "sha256:b"),
            ..Deployments::default()
        };
        assert!(returned_from_update(&record, &back));
        // The update boot itself, and a previous Release whose staged update
        // was never activated, are not a return from the update.
        let update_boot = Deployments {
            booted: id("10.0.2.2:5000/fwos:next", "sha256:b"),
            rollback: id("localhost/fwos:dev", "sha256:a"),
            ..Deployments::default()
        };
        assert!(!returned_from_update(&record, &update_boot));
        let never_activated = Deployments {
            rollback: id("10.0.2.2:5000/fwos:next", "sha256:older"),
            ..back.clone()
        };
        assert!(!returned_from_update(&record, &never_activated));
        // Without digests, image references decide.
        let refs = UpdateRecord {
            previous: id("localhost/fwos:dev", ""),
            update: id("docker://10.0.2.2:5000/fwos:next", ""),
        };
        let back_without_digests = Deployments {
            booted: id("localhost/fwos:dev", ""),
            rollback: id("10.0.2.2:5000/fwos:next", ""),
            ..Deployments::default()
        };
        assert!(returned_from_update(&refs, &back_without_digests));
    }

    #[test]
    fn a_manual_rollback_outcome_stays_readable_by_the_previous_release() {
        let manual = UpdateOutcome {
            release: "reg/fwos:next".into(),
            outcome: Outcome::RolledBack,
            reason: Some("manual rollback".into()),
            manual: Some(ManualOutcome {
                to: "localhost/fwos:dev".into(),
                pre_update_network: true,
            }),
        };
        // Returning from an unaccepted update: netd's restoration belongs to it.
        let network = NetworkRestoration::Unchanged { revision: 4 };
        let last = last_update_json(Some(manual.clone()), Some(network)).unwrap();
        assert_eq!(last["outcome"], "rolled_back");
        assert_eq!(last["manual"]["to"], "localhost/fwos:dev");
        assert_eq!(last["network"]["outcome"], "unchanged");
        // An older Release reads it as a plain rollback outcome.
        #[derive(Deserialize)]
        struct OlderOutcome {
            release: String,
            outcome: Outcome,
            reason: Option<String>,
        }
        let older: OlderOutcome =
            serde_json::from_value(serde_json::to_value(&manual).unwrap()).unwrap();
        assert_eq!(older.release, "reg/fwos:next");
        assert_eq!(older.outcome, Outcome::RolledBack);
        assert_eq!(older.reason.as_deref(), Some("manual rollback"));
        // Written by a Release without the field: an automatic rollback.
        let automatic: UpdateOutcome = serde_json::from_value(
            json!({"release": "a:2", "outcome": "rolled_back", "reason": "netd not running"}),
        )
        .unwrap();
        assert_eq!(automatic.manual, None);
        assert_eq!(
            serde_json::to_value(&automatic).unwrap().get("manual"),
            None
        );
    }

    #[test]
    fn host_update_outcome_is_reported_in_status() {
        let rolled_back = UpdateOutcome {
            release: "10.0.2.2:5000/fwos:next".into(),
            outcome: Outcome::RolledBack,
            reason: Some("Desired state not restored: LAN services failed".into()),
            manual: None,
        };
        let network = NetworkRestoration::Restored { revision: 5 };
        let last = last_update_json(Some(rolled_back.clone()), Some(network.clone())).unwrap();
        assert_eq!(
            last,
            json!({"release": "10.0.2.2:5000/fwos:next", "outcome": "rolled_back",
                "reason": "Desired state not restored: LAN services failed",
                "network": {"outcome": "restored", "revision": 5}})
        );
        let reply = status_reply(
            &Deployments::default(),
            &Operation::Idle,
            Some(last.clone()),
        );
        assert_eq!(reply["last_update"], last);
        // netd has not reported yet on the previous Release.
        let pending = last_update_json(Some(rolled_back), None).unwrap();
        assert_eq!(pending["network"], Value::Null);
        // An accepted update restores nothing; a stale restoration is not its own.
        let accepted = UpdateOutcome {
            release: "10.0.2.2:5000/fwos:next".into(),
            outcome: Outcome::Accepted,
            reason: None,
            manual: None,
        };
        let last = last_update_json(Some(accepted), Some(network)).unwrap();
        assert_eq!(last["outcome"], "accepted");
        assert_eq!(last["network"], Value::Null);
        assert_eq!(last_update_json(None, None), None);
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
        assert_eq!(found.booted, id("localhost/fwos:dev", "sha256:a"));
        assert_eq!(found.rollback, id("localhost/fwos:old", "sha256:0"));
        assert!(found.staged.is_empty());
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

mod network;

use network::{
    add_addr, ip_cmd, link_exists, lock_unopted, run_ip, traffic_nic_names, write_sysctl,
    FWD_MGMT_VETH, MGMT_FWD_IP, MGMT_FWD_IP6,
};

use std::collections::HashSet;
use std::fs::{self, File};
use std::io::{Read, Write};
use std::net::IpAddr;
use std::os::fd::AsRawFd;
use std::os::unix::fs::{chown, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;
use std::process::{self, Command};
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::{Duration, Instant};

use base64::Engine;
use fwos_fwd_setup::desired::{DesiredState, Iface};
use fwos_fwd_setup::identity::Principal;
use fwos_fwd_setup::{bootstrap_values, durable, identity};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

const SOCK: &str = "/var/lib/fwos/netd.sock";
const DESIRED: &str = "/var/lib/fwos/desired.toml";
const APPLY_OPERATION: &str = "/var/lib/fwos/apply-operation.json";
const APPLY_PREVIOUS: &str = "/var/lib/fwos/apply-previous.toml";
const APPLY_ATTRIBUTION: &str = "/var/lib/fwos/apply-attribution.json";
const PREVIOUS_ACCEPTED: &str = "/var/lib/fwos/previous-accepted.toml";
const LAN_SERVICES_READY: &str = "/var/lib/fwos/lan-services-ready";
const LAN_SERVICES_RESULT: &str = "/var/lib/fwos/lan-services-result";
const OPT_FILE: &str = "/var/lib/fwos/first-boot-opt.json";
const BOOTSTRAPPED: &str = "/var/lib/fwos/bootstrapped";
const BOOTSTRAP_ATTEMPT: &str = "/var/lib/fwos/bootstrap-attempt.json";
const IDENTITY: &str = "/var/lib/fwos/identity.json";
const HOSTNAME: &str = "/var/lib/fwos/hostname";
const CGNAT: [u8; 2] = [100, 64];
static RECOVERY_REQUIRED: AtomicBool = AtomicBool::new(false);

fn recovery_pending() -> bool {
    RECOVERY_REQUIRED.load(Ordering::SeqCst)
        || operation_requires_recovery()
        || Path::new(APPLY_PREVIOUS).exists()
}

#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum ApplyPhase {
    Applying,
    PendingConfirmation,
    Accepted,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum ApplyIntent {
    Ordinary,
    RecoveryRestore,
}

impl Default for ApplyPhase {
    fn default() -> Self {
        Self::Applying
    }
}

#[derive(Serialize, Deserialize)]
struct ApplyOperation {
    #[serde(default)]
    phase: ApplyPhase,
    accepted: DesiredState,
    previous_accepted: Option<Vec<u8>>,
    #[serde(default)]
    previous_attribution: Option<Vec<u8>>,
    #[serde(default)]
    proposed: Option<DesiredState>,
    #[serde(default)]
    confirmation_id: Option<String>,
    #[serde(default)]
    applying: Option<Principal>,
    #[serde(default)]
    draft_version: Option<String>,
    #[serde(default)]
    deadline_boot_ns: Option<u64>,
    #[serde(default)]
    expires_at_unix_ms: Option<u64>,
}

#[derive(Serialize, Deserialize)]
struct ApplyAttribution {
    revision: u64,
    applying: Option<Principal>,
    confirming: Option<Principal>,
    #[serde(default)]
    draft_version: Option<String>,
}

fn boot_time_ns() -> Result<u64, String> {
    let mut time = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    if unsafe { libc::clock_gettime(libc::CLOCK_BOOTTIME, &mut time) } != 0 {
        return Err(format!(
            "read monotonic Apply confirmation clock: {}",
            std::io::Error::last_os_error()
        ));
    }
    Ok((time.tv_sec as u64)
        .saturating_mul(1_000_000_000)
        .saturating_add(time.tv_nsec as u64))
}

fn pending_operation() -> Result<Option<ApplyOperation>, String> {
    let raw = match fs::read(APPLY_OPERATION) {
        Ok(raw) => raw,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(format!("read Apply confirmation: {error}")),
    };
    let operation: ApplyOperation = serde_json::from_slice(&raw)
        .map_err(|error| format!("parse Apply confirmation: {error}"))?;
    Ok((operation.phase == ApplyPhase::PendingConfirmation).then_some(operation))
}

fn apply_busy() -> bool {
    recovery_pending() || matches!(pending_operation(), Ok(Some(_)) | Err(_))
}

fn accepted_attribution(revision: u64) -> Option<ApplyAttribution> {
    fs::read(APPLY_ATTRIBUTION)
        .ok()
        .and_then(|raw| serde_json::from_slice::<ApplyAttribution>(&raw).ok())
        .filter(|record| record.revision == revision)
}

fn write_attribution(record: &ApplyAttribution) -> Result<(), String> {
    let raw =
        serde_json::to_vec(record).map_err(|error| format!("encode Apply actors: {error}"))?;
    durable::write(Path::new(APPLY_ATTRIBUTION), &raw)
}

fn restore_attribution(previous: Option<&[u8]>) -> Result<(), String> {
    match previous {
        Some(raw) => durable::write(Path::new(APPLY_ATTRIBUTION), raw),
        None => durable::remove(Path::new(APPLY_ATTRIBUTION)),
    }
}

fn operation_requires_recovery() -> bool {
    if !Path::new(APPLY_OPERATION).exists() {
        return false;
    }
    match fs::read(APPLY_OPERATION)
        .ok()
        .and_then(|raw| serde_json::from_slice::<ApplyOperation>(&raw).ok())
    {
        Some(operation) => operation.phase == ApplyPhase::Applying,
        None => true,
    }
}

struct RecoveryTarget {
    operation: ApplyOperation,
    marker: &'static str,
    restore_predecessor: bool,
}

fn read_recovery_target() -> Result<RecoveryTarget, String> {
    if Path::new(APPLY_OPERATION).exists() {
        let raw = fs::read(APPLY_OPERATION)
            .map_err(|error| format!("read in-flight apply operation: {error}"))?;
        let operation: ApplyOperation = serde_json::from_slice(&raw)
            .map_err(|error| format!("parse in-flight apply operation: {error}"))?;
        if operation.phase == ApplyPhase::Accepted {
            return Err(
                "apply operation is already Accepted; reboot to finish an indeterminate commit"
                    .into(),
            );
        }
        return Ok(RecoveryTarget {
            operation,
            marker: APPLY_OPERATION,
            restore_predecessor: true,
        });
    }
    let raw = fs::read_to_string(APPLY_PREVIOUS)
        .map_err(|error| format!("read legacy in-flight Accepted recovery target: {error}"))?;
    let accepted = toml::from_str(&raw)
        .map_err(|error| format!("parse legacy in-flight Accepted recovery target: {error}"))?;
    Ok(RecoveryTarget {
        operation: ApplyOperation {
            phase: ApplyPhase::Applying,
            accepted,
            previous_accepted: None,
            previous_attribution: None,
            proposed: None,
            confirmation_id: None,
            applying: None,
            draft_version: None,
            deadline_boot_ns: None,
            expires_at_unix_ms: None,
        },
        marker: APPLY_PREVIOUS,
        restore_predecessor: false,
    })
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct FirstBootOpt {
    nic: String,
    mode: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    cidr: Option<String>,
}

#[derive(Serialize, Deserialize)]
struct BootstrapAttempt {
    vlan_links: Vec<String>,
}

enum BootstrapFailure {
    Incomplete(String),
    Owned(String),
    Indeterminate(String),
}

impl From<String> for BootstrapFailure {
    fn from(error: String) -> Self {
        Self::Incomplete(error)
    }
}

impl From<&str> for BootstrapFailure {
    fn from(error: &str) -> Self {
        Self::Incomplete(error.to_string())
    }
}

fn main() {
    if let Err(err) = run() {
        eprintln!("netd: {err}");
        process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let interrupted = Path::new(BOOTSTRAPPED).exists()
        && (operation_requires_recovery()
            || matches!(pending_operation(), Ok(Some(_)) | Err(_))
            || Path::new(APPLY_PREVIOUS).exists());
    if interrupted {
        require_recovery_guard()?;
    }
    program_host_pull()?;
    if !Path::new(BOOTSTRAPPED).exists() {
        recover_incomplete_bootstrap()?;
    }
    if interrupted {
        if let Err(error) = recover_interrupted_apply() {
            eprintln!(
                "netd: interrupted Desired state apply needs authenticated recovery: {error}"
            );
        }
    } else if Path::new(DESIRED).exists() {
        let raw = fs::read_to_string(DESIRED).map_err(|e| format!("read {DESIRED}: {e}"))?;
        let mut state: DesiredState =
            toml::from_str(&raw).map_err(|e| format!("parse {DESIRED}: {e}"))?;
        apply(&mut state)?;
        persist(&state)?;
        if Path::new(BOOTSTRAPPED).exists() && !recovery_pending() {
            set_lan_services_ready(true)?;
        }
        if Path::new(APPLY_OPERATION).exists() && !operation_requires_recovery() {
            if let Err(error) = durable::remove(Path::new(APPLY_OPERATION)) {
                eprintln!("netd: remove completed apply journal after restart: {error}");
            }
        }
    } else {
        program_first_boot_nft("", &[])?;
        if let Some(opt) = load_opt() {
            apply_opt(&opt)?;
        }
    }
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
    let mut observed_exposure = None;
    let mut refresh_at = Instant::now();
    loop {
        expire_pending_confirmation();
        if Instant::now() >= refresh_at {
            refresh_bootstrap_exposure(&mut observed_exposure)?;
            refresh_at = Instant::now() + Duration::from_secs(1);
        }
        // Keep command application and address observation on the same thread:
        // an old observation must never republish a replaced selection.
        let mut ready = libc::pollfd {
            fd: listener.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        let result = unsafe { libc::poll(&mut ready, 1, 1000) };
        if result < 0 {
            let error = std::io::Error::last_os_error();
            if error.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            return Err(format!("poll {SOCK}: {error}"));
        }
        if result == 0 {
            continue;
        }
        let (stream, _) = listener
            .accept()
            .map_err(|e| format!("accept {SOCK}: {e}"))?;
        if let Err(err) = handle_client(stream) {
            eprintln!("netd: {err}");
        }
    }
}

fn refresh_bootstrap_exposure(observed: &mut Option<(String, Vec<String>)>) -> Result<(), String> {
    if Path::new(DESIRED).exists() || Path::new(BOOTSTRAPPED).exists() {
        *observed = None;
        return Ok(());
    }
    let Some(opt) = load_opt() else {
        *observed = None;
        return Ok(());
    };
    let mut addresses = bootstrap_expose_ips(&iface_cidrs(&opt.nic)?);
    addresses.sort_unstable();
    let current = (opt.nic, addresses);
    if observed.as_ref() != Some(&current) {
        program_first_boot_nft(&current.0, &current.1)?;
        *observed = Some(current);
    }
    Ok(())
}

fn handle_client(mut stream: UnixStream) -> Result<(), String> {
    let mut buf = Vec::new();
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err("socket request read timed out".into());
        }
        stream
            .set_read_timeout(Some(remaining))
            .map_err(|e| format!("bound socket request read: {e}"))?;
        let mut chunk = [0u8; 8192];
        match stream.read(&mut chunk) {
            Ok(0) => break,
            Ok(count) => buf.extend_from_slice(&chunk[..count]),
            Err(error) => return Err(format!("read socket: {error}")),
        }
    }
    expire_pending_confirmation();
    if buf.is_empty() {
        return Ok(());
    }
    let reply = match serde_json::from_slice::<Value>(&buf) {
        Ok(v) if v.get("op").and_then(Value::as_str).is_some() => handle_cmd(&v),
        // Older console and socket clients send bare complete Desired JSON.
        // Their base is the current Accepted revision at receipt, on this
        // single-threaded socket loop; they use the same validation and apply.
        Ok(v) if Path::new(BOOTSTRAPPED).exists() => {
            apply_desired_request(&v, None, None, None, ApplyIntent::Ordinary).to_string()
        }
        Ok(_) => json!({"ok": false, "error": "complete Bootstrap before applying Desired state"})
            .to_string(),
        Err(err) => json!({"ok": false, "error": err.to_string()}).to_string(),
    };
    stream
        .write_all(reply.as_bytes())
        .and_then(|_| stream.write_all(b"\n"))
        .map_err(|e| format!("write socket: {e}"))?;
    Ok(())
}

fn handle_cmd(v: &Value) -> String {
    match v.get("op").and_then(Value::as_str).unwrap_or("") {
        "list" => list_nics_reply(),
        "opt" => match parse_opt(v).and_then(apply_and_persist_opt) {
            Ok(()) => json!({"ok": true}).to_string(),
            Err(err) => json!({"ok": false, "error": err}).to_string(),
        },
        "bootstrap_apply" => match bootstrap_apply(v) {
            Ok(()) => json!({"ok": true}).to_string(),
            Err(BootstrapFailure::Owned(err)) => json!({
                "ok": false,
                "bootstrapped": true,
                "error": err,
                "next_action": "sign in to review and repair configuration"
            })
            .to_string(),
            Err(BootstrapFailure::Indeterminate(err)) => json!({
                "ok": false,
                "bootstrapped": Value::Null,
                "outcome": "indeterminate",
                "error": err,
                "next_action": "do not retry; reboot and check Appliance status or console"
            })
            .to_string(),
            Err(BootstrapFailure::Incomplete(err)) => {
                json!({"ok": false, "bootstrapped": false, "error": err}).to_string()
            }
        },
        "get_desired" if recovery_pending() => json!({
            "ok": false,
            "outcome": "recovery_required",
            "error": "the previous Desired state apply needs recovery before Accepted state is available"
        })
        .to_string(),
        "get_desired" => match accepted_desired() {
            Ok(desired) => {
                json!({"ok": true, "desired": desired, "revision": desired.revision}).to_string()
            }
            Err(error) => json!({"ok": false, "error": error}).to_string(),
        },
        "get_apply_confirmation" => apply_confirmation_status().to_string(),
        "was_draft_accepted" => was_draft_accepted(v).to_string(),
        "confirm_apply" => confirm_apply(v).to_string(),
        "restore_previous" => {
            let actor = v.get("applying").cloned()
                .and_then(|value| serde_json::from_value::<Principal>(value).ok());
            restore_previous_request(actor).to_string()
        }
        "apply_desired" => {
            if !Path::new(BOOTSTRAPPED).exists() {
                return json!({"ok": false, "outcome": "rejected", "error": "complete Bootstrap before applying Desired state"}).to_string();
            }
            let Some(base) = v.get("base_revision").and_then(Value::as_u64) else {
                return json!({"ok": false, "outcome": "rejected", "error": "base_revision is required"}).to_string();
            };
            let actor = v.get("applying").cloned().and_then(|actor| serde_json::from_value::<Principal>(actor).ok());
            let draft_version = v.get("draft_version").and_then(Value::as_str).map(str::to_owned);
            apply_desired_request(v.get("desired").unwrap_or(&Value::Null), Some(base), actor, draft_version, ApplyIntent::Ordinary).to_string()
        }
        other => json!({"ok": false, "error": format!("unknown op {other}")}).to_string(),
    }
}

fn accepted_desired() -> Result<DesiredState, String> {
    let raw =
        fs::read_to_string(DESIRED).map_err(|e| format!("read Accepted Desired state: {e}"))?;
    let mut state: DesiredState =
        toml::from_str(&raw).map_err(|e| format!("parse Accepted Desired state: {e}"))?;
    if state.revision == 0 {
        state.revision = 1;
    }
    Ok(state)
}

fn review_projection(state: &DesiredState) -> Value {
    json!({
        "apply_confirmation": state.apply_confirmation,
        "hostname": state.hostname,
        "interfaces": state.interfaces,
        "routes": state.routes,
        "ui_exposure": state.ui_exposure,
        "lan_prefix": state.lan_prefix,
        "dhcp_pool": state.dhcp_pool,
        "wan_pd": state.wan_pd,
        "nft_extra": state.nft_extra,
        "qdiscs": state.qdiscs,
        "wireguard": state.wireguard.iter().map(|tunnel| json!({
            "name": tunnel.name,
            "listen_port": tunnel.listen_port,
            "addresses": tunnel.addresses,
        })).collect::<Vec<_>>(),
    })
}

fn apply_confirmation_status() -> Value {
    let accepted = match accepted_desired() {
        Ok(accepted) => accepted,
        Err(error) => return json!({"ok": false, "error": error}),
    };
    let pending = match pending_operation() {
        Ok(Some(operation)) => {
            let Some(proposed) = operation.proposed else {
                return json!({"ok": false, "error": "pending Apply revision is missing"});
            };
            json!({
                "revision": proposed.revision,
                "confirmation_id": operation.confirmation_id,
                "base_revision": operation.accepted.revision,
                "routes": proposed.routes,
                "applying": operation.applying,
                "expires_at_unix_ms": operation.expires_at_unix_ms,
                "accepted_review": review_projection(&operation.accepted),
                "proposed_review": review_projection(&proposed),
            })
        }
        Ok(None) => Value::Null,
        Err(error) => return json!({"ok": false, "error": error}),
    };
    let last_accepted = accepted_attribution(accepted.revision).map(|record| {
        json!({
            "revision": record.revision,
            "applying": record.applying,
            "confirming": record.confirming,
        })
    });
    json!({"ok": true, "enabled": accepted.apply_confirmation, "accepted_revision": accepted.revision,
        "pending": pending, "last_accepted": last_accepted})
}

fn was_draft_accepted(request: &Value) -> Value {
    if recovery_pending() {
        return json!({"ok": false, "error": "Accepted Desired state is unavailable during recovery"});
    }
    let Some(revision) = request.get("revision").and_then(Value::as_u64) else {
        return json!({"ok": false, "error": "Accepted revision is required"});
    };
    let Some(version) = request.get("draft_version").and_then(Value::as_str) else {
        return json!({"ok": false, "error": "draft version is required"});
    };
    let Some(owner) = request
        .get("owner")
        .cloned()
        .and_then(|value| serde_json::from_value::<Principal>(value).ok())
    else {
        return json!({"ok": false, "error": "draft owner is required"});
    };
    let accepted = match accepted_desired() {
        Ok(accepted) => accepted,
        Err(error) => return json!({"ok": false, "error": error}),
    };
    let matches = accepted.revision == revision
        && accepted_attribution(revision).is_some_and(|record| {
            record.draft_version.as_deref() == Some(version)
                && record.applying.as_ref().is_some_and(|actor| {
                    actor.source == owner.source && actor.subject == owner.subject
                })
        });
    json!({"ok": true, "accepted": matches})
}

fn pending_expired(operation: &ApplyOperation) -> Result<bool, String> {
    let deadline = operation
        .deadline_boot_ns
        .ok_or("pending Apply deadline is missing")?;
    Ok(boot_time_ns()? >= deadline)
}

fn expire_pending_confirmation() {
    let pending = match pending_operation() {
        Ok(pending) => pending,
        Err(error) => {
            eprintln!("netd: inspect pending Apply confirmation: {error}");
            let _ = require_recovery_guard();
            return;
        }
    };
    if let Some(operation) = pending {
        if pending_expired(&operation).unwrap_or(true) {
            if let Err(error) = recover_interrupted_apply() {
                eprintln!("netd: expired Apply confirmation recovery failed: {error}");
            }
        }
    }
}

fn confirm_apply(request: &Value) -> Value {
    let Some(revision) = request.get("revision").and_then(Value::as_u64) else {
        return json!({"ok": false, "outcome": "rejected", "error": "pending revision is required"});
    };
    let Some(confirmation_id) = request.get("confirmation_id").and_then(Value::as_str) else {
        return json!({"ok": false, "outcome": "rejected", "error": "Apply confirmation ID is required"});
    };
    let Some(confirming) = request
        .get("confirming")
        .cloned()
        .and_then(|value| serde_json::from_value::<Principal>(value).ok())
    else {
        return json!({"ok": false, "outcome": "rejected", "error": "current administrator identity is required"});
    };
    if recovery_pending() {
        return json!({"ok": false, "outcome": "rejected", "error": "Apply recovery is in progress"});
    }
    let operation = match pending_operation() {
        Ok(Some(operation)) => operation,
        Ok(None) => {
            return json!({"ok": false, "outcome": "rejected", "error": "no Apply confirmation is pending"})
        }
        Err(error) => return json!({"ok": false, "outcome": "failed", "error": error}),
    };
    let Some(proposed) = operation.proposed.as_ref() else {
        let _ = require_recovery_guard();
        return json!({"ok": false, "outcome": "failed", "error": "pending Apply revision is missing"});
    };
    if revision != proposed.revision
        || operation.confirmation_id.as_deref() != Some(confirmation_id)
    {
        return json!({"ok": false, "outcome": "rejected", "error": "pending Apply operation changed"});
    }
    if pending_expired(&operation).unwrap_or(true) {
        let recovered = recover_interrupted_apply();
        return json!({"ok": false, "outcome": "rejected", "error": "Apply confirmation expired", "restoration": if recovered.is_ok() {"restored"} else {"required"}});
    }
    let result = (|| {
        write_attribution(&ApplyAttribution {
            revision,
            applying: operation.applying.clone(),
            confirming: Some(confirming.clone()),
            draft_version: operation.draft_version.clone(),
        })?;
        persist(proposed)?;
        persist_at(Path::new(PREVIOUS_ACCEPTED), &operation.accepted)?;
        let accepted_journal = ApplyOperation {
            phase: ApplyPhase::Accepted,
            accepted: operation.accepted.clone(),
            previous_accepted: operation.previous_accepted.clone(),
            previous_attribution: operation.previous_attribution.clone(),
            proposed: None,
            confirmation_id: None,
            applying: operation.applying.clone(),
            draft_version: operation.draft_version.clone(),
            deadline_boot_ns: None,
            expires_at_unix_ms: None,
        };
        let raw = serde_json::to_vec(&accepted_journal)
            .map_err(|error| format!("encode accepted Apply: {error}"))?;
        durable::write(Path::new(APPLY_OPERATION), &raw)?;
        Ok::<(), String>(())
    })();
    if let Err(error) = result {
        let recovery = recover_interrupted_apply();
        return json!({"ok": false, "outcome": "failed", "error": error,
            "restoration": if recovery.is_ok() {"restored"} else {"required"},
            "recovery_error": recovery.err()});
    }
    if let Err(error) = durable::remove(Path::new(APPLY_OPERATION)) {
        eprintln!("netd: remove confirmed Apply journal: {error}");
    }
    json!({"ok": true, "outcome": "accepted", "status": "accepted", "revision": revision,
        "applying": operation.applying, "confirming": confirming})
}

fn restore_previous_request(actor: Option<Principal>) -> Value {
    if !Path::new(BOOTSTRAPPED).exists() {
        return json!({"ok": false, "outcome": "rejected", "error": "complete Bootstrap before restoring Desired state"});
    }
    if recovery_pending() {
        return match recover_interrupted_apply() {
            Ok(revision) => {
                json!({"ok": true, "outcome": "restored", "restoration": "restored", "revision": revision})
            }
            Err(error) => {
                json!({"ok": false, "outcome": "failed", "restoration": "required", "error": error})
            }
        };
    }
    if matches!(pending_operation(), Ok(Some(_)) | Err(_)) {
        return json!({"ok": false, "outcome": "rejected", "error": "Apply confirmation is pending"});
    }
    let current = match accepted_desired() {
        Ok(state) => state,
        Err(error) => return json!({"ok": false, "outcome": "failed", "error": error}),
    };
    let raw = match fs::read_to_string(PREVIOUS_ACCEPTED) {
        Ok(raw) => raw,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return json!({"ok": false, "outcome": "rejected", "revision": current.revision, "error": "no previous Accepted network revision is available"});
        }
        Err(error) => {
            return json!({"ok": false, "outcome": "failed", "revision": current.revision, "error": format!("read previous Accepted network revision: {error}")});
        }
    };
    let previous: DesiredState = match toml::from_str(&raw) {
        Ok(state) => state,
        Err(error) => {
            return json!({"ok": false, "outcome": "failed", "revision": current.revision, "error": format!("parse previous Accepted network revision: {error}")});
        }
    };
    if previous.revision == 0 || previous.revision >= current.revision {
        return json!({"ok": false, "outcome": "failed", "revision": current.revision, "error": "previous Accepted network revision is not older than the current revision"});
    }
    let input = match serde_json::to_value(previous) {
        Ok(input) => input,
        Err(error) => {
            return json!({"ok": false, "outcome": "failed", "revision": current.revision, "error": format!("encode previous Accepted network revision: {error}")});
        }
    };
    // A manual restoration is a new Accepted revision, not a file copy. The
    // normal apply transaction retains the displaced current state as its
    // predecessor and restores that state if this attempt fails.
    apply_desired_request(
        &input,
        Some(current.revision),
        actor,
        None,
        ApplyIntent::RecoveryRestore,
    )
}

fn apply_desired_request(
    input: &Value,
    base_revision: Option<u64>,
    actor: Option<Principal>,
    draft_version: Option<String>,
    intent: ApplyIntent,
) -> Value {
    if apply_busy() {
        return json!({"ok": false, "outcome": "busy", "error": "another Desired state apply or recovery is in progress"});
    }
    let current = match accepted_desired() {
        Ok(state) => state,
        Err(error) => return json!({"ok": false, "outcome": "failed", "error": error}),
    };
    let base = base_revision.unwrap_or(current.revision);
    if base != current.revision {
        return json!({"ok": false, "outcome": "rejected", "revision": current.revision, "error": "Accepted Desired state changed; reload before applying"});
    }
    let mut proposed: DesiredState = match serde_json::from_value(input.clone()) {
        Ok(state) => state,
        Err(error) => {
            return json!({"ok": false, "outcome": "rejected", "revision": current.revision, "error": format!("invalid complete Desired state: {error}")})
        }
    };
    if let Err(error) = validate(&proposed) {
        return json!({"ok": false, "outcome": "rejected", "revision": current.revision, "error": error});
    }
    if let Err(error) = nft_check(&nft_rules(&proposed)) {
        return json!({"ok": false, "outcome": "rejected", "revision": current.revision, "error": error});
    }
    let Some(next_revision) = current.revision.checked_add(1) else {
        return json!({"ok": false, "outcome": "rejected", "error": "revision limit reached"});
    };
    proposed.revision = next_revision;
    let footprint = match RollbackFootprint::capture(&current, &proposed) {
        Ok(footprint) => footprint,
        Err(error) => {
            return json!({"ok": false, "outcome": "failed", "restoration": "unchanged", "revision": current.revision, "error": format!("could not inspect live network before apply: {error}")})
        }
    };
    let old_predecessor = match fs::read(PREVIOUS_ACCEPTED) {
        Ok(bytes) => Some(bytes),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
        Err(error) => {
            return json!({"ok": false, "outcome": "failed", "revision": current.revision, "error": format!("read retained predecessor: {error}")});
        }
    };
    let old_attribution = match fs::read(APPLY_ATTRIBUTION) {
        Ok(bytes) => Some(bytes),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
        Err(error) => {
            return json!({"ok": false, "outcome": "failed", "error": format!("read prior Apply actors: {error}")})
        }
    };
    let lan_ready_before = Path::new(LAN_SERVICES_READY).exists();
    // One atomic operation record retains both the recovery target and its
    // manual predecessor. B may overwrite either durable file before the
    // operation is accepted; a restart must be able to restore both.
    let operation = ApplyOperation {
        phase: ApplyPhase::Applying,
        accepted: current.clone(),
        previous_accepted: old_predecessor.clone(),
        previous_attribution: old_attribution.clone(),
        proposed: None,
        confirmation_id: None,
        applying: actor.clone(),
        draft_version: draft_version.clone(),
        deadline_boot_ns: None,
        expires_at_unix_ms: None,
    };
    let journal = match serde_json::to_vec(&operation) {
        Ok(bytes) => bytes,
        Err(error) => {
            return json!({"ok": false, "outcome": "failed", "restoration": "unchanged", "revision": current.revision, "error": format!("encode apply operation: {error}")})
        }
    };
    if let Err(error) = durable::write(Path::new(APPLY_OPERATION), &journal) {
        if operation_requires_recovery() {
            let guard = require_recovery_guard();
            return json!({"ok": false, "outcome": "failed", "restoration": "required", "revision": current.revision, "error": format!("could not retain Accepted Desired state before apply: {error}"), "recovery_error": format!("forwarding guard: {guard:?}")});
        }
        return json!({"ok": false, "outcome": "failed", "restoration": "unchanged", "revision": current.revision, "error": format!("could not retain Accepted Desired state before apply: {error}")});
    }
    // Host path units and service start conditions both require this marker.
    // Tentative Kea/Unbound files may be written during apply, but cannot
    // launch a new service until the replacement is accepted below.
    if let Err(error) = set_lan_services_ready(false) {
        let mut failures = Vec::new();
        if let Err(cause) = set_lan_services_ready(lan_ready_before) {
            failures.push(format!("restore LAN service readiness: {cause}"));
        }
        if failures.is_empty() {
            if let Err(cause) = durable::remove(Path::new(APPLY_OPERATION)) {
                if operation_requires_recovery() {
                    failures.push(format!("clear in-flight operation: {cause}"));
                } else {
                    return json!({"ok": false, "outcome": "failed", "restoration": "unchanged", "revision": current.revision, "error": format!("could not suspend LAN service activation: {error}"), "cleanup_error": cause});
                }
            }
            if failures.is_empty() {
                return json!({"ok": false, "outcome": "failed", "restoration": "unchanged", "revision": current.revision, "error": format!("could not suspend LAN service activation: {error}")});
            }
        }
        if let Err(cause) = require_recovery_guard() {
            failures.push(format!("block forwarding: {cause}"));
        }
        return json!({"ok": false, "outcome": "failed", "restoration": "required", "revision": current.revision, "error": format!("could not suspend LAN service activation: {error}"), "recovery_error": failures.join("; ")});
    }
    let result = (|| {
        apply(&mut proposed)?;
        remove_stale_routes(&current, &proposed)?;
        let generation =
            set_lan_services_ready(true)?.ok_or("LAN service generation was not published")?;
        wait_lan_services(&generation)?;
        if !current.apply_confirmation || intent == ApplyIntent::RecoveryRestore {
            persist(&proposed)?;
            persist_at(Path::new(PREVIOUS_ACCEPTED), &current)?;
            write_attribution(&ApplyAttribution {
                revision: proposed.revision,
                applying: actor.clone(),
                confirming: None,
                draft_version: draft_version.clone(),
            })?;
        }
        Ok::<(), String>(())
    })();
    if let Err(error) = result {
        return restore_failed_apply(
            &current,
            &proposed,
            &footprint,
            lan_ready_before,
            old_predecessor.as_deref(),
            old_attribution.as_deref(),
            error,
        );
    }
    if current.apply_confirmation && intent == ApplyIntent::Ordinary {
        let confirmation_id = match identity::random_token() {
            Ok(id) => id,
            Err(error) => {
                return restore_failed_apply(
                    &current,
                    &proposed,
                    &footprint,
                    lan_ready_before,
                    old_predecessor.as_deref(),
                    old_attribution.as_deref(),
                    error,
                )
            }
        };
        let now_boot = match boot_time_ns() {
            Ok(now) => now,
            Err(error) => {
                return restore_failed_apply(
                    &current,
                    &proposed,
                    &footprint,
                    lan_ready_before,
                    old_predecessor.as_deref(),
                    old_attribution.as_deref(),
                    error,
                )
            }
        };
        let expires_at_unix_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis()
            .saturating_add(120_000) as u64;
        let pending = ApplyOperation {
            phase: ApplyPhase::PendingConfirmation,
            accepted: current.clone(),
            previous_accepted: old_predecessor,
            previous_attribution: old_attribution,
            proposed: Some(proposed.clone()),
            confirmation_id: Some(confirmation_id),
            applying: actor.clone(),
            draft_version: draft_version.clone(),
            deadline_boot_ns: Some(now_boot.saturating_add(120_000_000_000)),
            expires_at_unix_ms: Some(expires_at_unix_ms),
        };
        let result = serde_json::to_vec(&pending)
            .map_err(|error| format!("encode pending Apply confirmation: {error}"))
            .and_then(|raw| durable::write(Path::new(APPLY_OPERATION), &raw));
        if let Err(error) = result {
            // B is live but not Accepted. The Applying journal still retains
            // A, and even an ambiguous pending-journal write must attempt an
            // immediate rollback before requiring serial recovery.
            return restore_failed_apply(
                &current,
                &proposed,
                &footprint,
                lan_ready_before,
                pending.previous_accepted.as_deref(),
                pending.previous_attribution.as_deref(),
                format!("retain pending Apply confirmation: {error}"),
            );
        }
        return json!({"ok": true, "outcome": "pending_confirmation", "status": "pending_confirmation", "applied": true, "accepted": false, "revision": proposed.revision, "base_revision": base, "applying": actor, "expires_at_unix_ms": expires_at_unix_ms});
    }
    let accepted_journal = match serde_json::to_vec(&ApplyOperation {
        phase: ApplyPhase::Accepted,
        accepted: current.clone(),
        previous_accepted: old_predecessor,
        previous_attribution: old_attribution,
        proposed: None,
        confirmation_id: None,
        applying: actor.clone(),
        draft_version,
        deadline_boot_ns: None,
        expires_at_unix_ms: None,
    }) {
        Ok(bytes) => bytes,
        Err(error) => {
            let guard = require_recovery_guard();
            return json!({"ok": false, "outcome": "indeterminate", "restoration": "required", "error": format!("encode Accepted apply operation: {error}"), "recovery_error": format!("forwarding guard: {guard:?}")});
        }
    };
    if let Err(error) = durable::write(Path::new(APPLY_OPERATION), &accepted_journal) {
        let guard = require_recovery_guard();
        return json!({"ok": false, "outcome": "indeterminate", "restoration": "required", "error": format!("durably accept Desired state: {error}; reboot to resolve the operation"), "recovery_error": format!("forwarding guard: {guard:?}")});
    }
    // The accepted phase is durable. Unlink is only cleanup; either outcome
    // leaves B Accepted and its predecessor A durable across a power loss.
    if let Err(error) = durable::remove(Path::new(APPLY_OPERATION)) {
        eprintln!("netd: remove completed apply journal: {error}");
    }
    json!({"ok": true, "outcome": "accepted", "status": "accepted", "applied": true, "accepted": true, "revision": proposed.revision, "base_revision": base, "predecessor_revision": current.revision, "applying": actor})
}

fn require_recovery_guard() -> Result<(), String> {
    RECOVERY_REQUIRED.store(true, Ordering::SeqCst);
    // Retain the prior Accepted input policy while the unconditional forward
    // drop in nft_rules blocks v4 and v6 transit. A forwarding-only fallback
    // would open WAN input after the ruleset flush.
    if let Ok(target) = read_recovery_target() {
        if nft_apply(&nft_rules(&target.operation.accepted)).is_ok() {
            return Ok(());
        }
    }
    // A missing, unreadable, or indeterminate journal cannot authorize any
    // network input. Serial authentication remains available for recovery.
    nft_apply(&format!(
        "flush ruleset\n{}table inet fwos-recovery {{\n  chain input {{\n    type filter hook input priority filter; policy drop;\n    iifname \"lo\" accept\n  }}\n  chain forward {{\n    type filter hook forward priority filter; policy drop;\n  }}\n}}\n",
        host_pull_nft()
    ))
}

fn recover_interrupted_apply() -> Result<u64, String> {
    // The marker may have been unlinked before its parent fsync failed, or
    // reopening forwarding may have failed after a durable unlink. A/P and
    // Host services were already restored; retry only the guarded final step.
    if RECOVERY_REQUIRED.load(Ordering::SeqCst)
        && !Path::new(APPLY_OPERATION).exists()
        && !Path::new(APPLY_PREVIOUS).exists()
    {
        let previous = accepted_desired()?;
        reopen_restored_forwarding(&previous)?;
        return Ok(previous.revision);
    }
    require_recovery_guard()?;
    let target = read_recovery_target()?;
    let mut previous = target.operation.accepted;
    let tentative = target
        .operation
        .proposed
        .or_else(|| accepted_desired().ok());
    set_lan_services_ready(false)?;
    apply(&mut previous)?;
    if let Some(tentative) = tentative.as_ref() {
        remove_stale_routes(tentative, &previous)?;
    }
    persist(&previous)?;
    if target.restore_predecessor {
        match target.operation.previous_accepted.as_deref() {
            Some(bytes) => durable::write(Path::new(PREVIOUS_ACCEPTED), bytes)?,
            None => durable::remove(Path::new(PREVIOUS_ACCEPTED))?,
        }
        restore_attribution(target.operation.previous_attribution.as_deref())?;
    }
    let generation = set_lan_services_ready(true)?
        .ok_or("LAN service generation was not published during recovery")?;
    wait_lan_services(&generation)?;
    finish_recovery(&previous, target.marker)?;
    Ok(previous.revision)
}

fn finish_recovery(previous: &DesiredState, marker: &str) -> Result<(), String> {
    // A/P and Host services are live and durable. Keep the physical guard
    // until the in-flight marker is durably gone, so a failed completion has
    // never forwarded traffic. A crash after unlink boots durable A normally.
    if let Err(error) = durable::remove(Path::new(marker)) {
        let guard = require_recovery_guard();
        return Err(format!(
            "complete interrupted apply recovery: {error}; guard: {guard:?}"
        ));
    }
    reopen_restored_forwarding(previous)?;
    Ok(())
}

fn reopen_restored_forwarding(previous: &DesiredState) -> Result<(), String> {
    // Keep other applies excluded until nft atomically installs the unguarded
    // Accepted policy. A failure leaves the runtime guard set for serial retry.
    if let Err(error) = nft_apply(&nft_rules_with_recovery_guard(previous, false)) {
        let guard = require_recovery_guard();
        return Err(format!(
            "reopen restored forwarding: {error}; guard: {guard:?}"
        ));
    }
    RECOVERY_REQUIRED.store(false, Ordering::SeqCst);
    Ok(())
}

fn restore_failed_apply(
    current: &DesiredState,
    proposed: &DesiredState,
    footprint: &RollbackFootprint,
    lan_ready_before: bool,
    old_predecessor: Option<&[u8]>,
    old_attribution: Option<&[u8]>,
    error: String,
) -> Value {
    let mut failures = Vec::new();
    if let Err(cause) = require_recovery_guard() {
        failures.push(format!("block forwarding during recovery: {cause}"));
    }
    if let Err(cause) = set_lan_services_ready(false) {
        failures.push(format!("suspend tentative LAN services: {cause}"));
    }
    let mut previous = current.clone();
    if let Err(cause) = apply(&mut previous) {
        failures.push(format!("restore live Accepted state: {cause}"));
    }
    if let Err(cause) = remove_stale_routes(proposed, current) {
        failures.push(format!("remove tentative routes: {cause}"));
    }
    failures.extend(footprint.remove_tentative_state());
    if let Err(cause) = persist(current) {
        failures.push(format!("restore durable Accepted state: {cause}"));
    }
    let predecessor_result = match old_predecessor {
        Some(bytes) => durable::write(Path::new(PREVIOUS_ACCEPTED), bytes),
        None => durable::remove(Path::new(PREVIOUS_ACCEPTED)),
    };
    if let Err(cause) = predecessor_result {
        failures.push(format!("restore retained predecessor: {cause}"));
    }
    if let Err(cause) = restore_attribution(old_attribution) {
        failures.push(format!("restore prior Apply actors: {cause}"));
    }
    if failures.is_empty() {
        match set_lan_services_ready(lan_ready_before) {
            Ok(Some(generation)) => {
                if let Err(cause) = wait_lan_services(&generation) {
                    failures.push(format!("restore Host LAN services: {cause}"));
                }
            }
            Ok(None) => (),
            Err(cause) => failures.push(format!("restore LAN service readiness: {cause}")),
        }
    }
    if failures.is_empty() {
        if let Err(cause) = finish_recovery(current, APPLY_OPERATION) {
            failures.push(format!("complete recovery: {cause}"));
        }
    }
    if failures.is_empty() {
        json!({"ok": false, "outcome": "failed", "status": "restored", "restoration": "restored", "applied": false, "accepted": false, "revision": current.revision, "error": error})
    } else {
        RECOVERY_REQUIRED.store(true, Ordering::SeqCst);
        json!({"ok": false, "outcome": "failed", "status": "recovery_required", "restoration": "failed", "applied": false, "accepted": false, "revision": current.revision, "error": error, "recovery_error": failures.join("; ")})
    }
}

fn set_lan_services_ready(ready: bool) -> Result<Option<String>, String> {
    let path = Path::new(LAN_SERVICES_READY);
    let generation = if ready {
        Some(identity::random_token()?)
    } else {
        None
    };
    let result = match &generation {
        Some(generation) => durable::write(path, generation.as_bytes()),
        None => durable::remove(path),
    };
    // A parent-directory fsync can fail after the rename/unlink. Verify the
    // exact generation, not just existence: an earlier marker might remain.
    let observed = match fs::read_to_string(path) {
        Ok(contents) => Some(contents),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
        Err(error) => return Err(format!("inspect LAN service readiness: {error}")),
    };
    if observed.as_deref() == generation.as_deref() {
        Ok(generation)
    } else {
        Err(result
            .err()
            .unwrap_or_else(|| "LAN service readiness did not reach requested state".into()))
    }
}

fn wait_lan_services(generation: &str) -> Result<(), String> {
    wait_lan_services_at(
        Path::new(LAN_SERVICES_RESULT),
        generation,
        Duration::from_secs(24),
    )
}

fn wait_lan_services_at(path: &Path, generation: &str, timeout: Duration) -> Result<(), String> {
    let deadline = Instant::now() + timeout;
    loop {
        match fs::read_to_string(path) {
            Ok(result) => {
                if let Some(outcome) = parse_lan_services_result(&result, generation) {
                    return outcome;
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => (),
            Err(error) => return Err(format!("read Host LAN service result: {error}")),
        }
        if Instant::now() >= deadline {
            return Err("Host LAN service reconciliation timed out".into());
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

fn parse_lan_services_result(result: &str, generation: &str) -> Option<Result<(), String>> {
    let (observed, status) = result.trim().split_once(' ')?;
    if observed != generation {
        return None;
    }
    Some(if status == "ok" {
        Ok(())
    } else {
        Err(format!("Host LAN service reconciliation failed: {status}"))
    })
}

struct RollbackFootprint {
    // Only additions that were absent before the attempt are ours to undo.
    addresses: Vec<(String, String)>,
    links: Vec<String>,
    qdiscs: Vec<(String, Option<RootQdisc>, bool)>,
    wireguard_ports: Vec<(String, u16)>,
    lan_files: Vec<(&'static str, Option<Vec<u8>>)>,
}

impl RollbackFootprint {
    fn capture(current: &DesiredState, proposed: &DesiredState) -> Result<Self, String> {
        let mut old = current.clone();
        let mut next = proposed.clone();
        merge_lan_prefix_addr(&mut old);
        merge_lan_prefix_addr(&mut next);
        let old_addresses = desired_addresses(&old);
        let mut addresses = Vec::new();
        for (dev, cidr) in desired_addresses(&next) {
            if old_addresses.contains(&(dev.clone(), cidr.clone())) {
                continue;
            }
            if link_exists(&dev)? && !live_address(&dev, &cidr)? {
                addresses.push((dev, cidr));
            }
        }
        let mut links = Vec::new();
        for iface in &next.interfaces {
            if iface.vlan.is_some() && !link_exists(&iface.name)? {
                links.push(iface.name.clone());
            }
        }
        for wg in &next.wireguard {
            if !link_exists(&wg.name)? {
                links.push(wg.name.clone());
            }
        }
        let mut wireguard_ports = Vec::new();
        for wg in &old.wireguard {
            if link_exists(&wg.name)? {
                wireguard_ports.push((wg.name.clone(), wireguard_listen_port(&wg.name)?));
            }
        }
        let mut qdiscs = Vec::new();
        for qdisc in &next.qdiscs {
            if link_exists(&qdisc.dev)? {
                let configured_before = old.qdiscs.iter().any(|previous| previous.dev == qdisc.dev);
                qdiscs.push((
                    qdisc.dev.clone(),
                    root_qdisc(&qdisc.dev)?,
                    !configured_before,
                ));
            }
        }
        let mut lan_files = Vec::new();
        for path in [
            "/var/lib/fwos/kea/kea-dhcp4.conf",
            "/var/lib/fwos/kea/kea-dhcp6.conf",
            "/var/lib/fwos/unbound/unbound.conf",
        ] {
            let contents = match fs::read(path) {
                Ok(contents) => Some(contents),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
                Err(error) => return Err(format!("inspect LAN service configuration: {error}")),
            };
            lan_files.push((path, contents));
        }
        Ok(Self {
            addresses,
            links,
            qdiscs,
            wireguard_ports,
            lan_files,
        })
    }

    fn remove_tentative_state(&self) -> Vec<String> {
        let mut failures = Vec::new();
        for (dev, cidr) in &self.addresses {
            match live_address(dev, cidr) {
                Ok(true) => {
                    if let Err(error) = run_ip(&["addr", "del", cidr, "dev", dev]) {
                        failures.push(format!("remove tentative address on {dev}: {error}"));
                    }
                }
                Ok(false) => (),
                Err(error) => failures.push(format!("inspect tentative address on {dev}: {error}")),
            }
        }
        for name in &self.links {
            match link_exists(name) {
                Ok(true) => {
                    if let Err(error) = run_ip(&["link", "delete", "dev", name]) {
                        failures.push(format!("remove tentative link {name}: {error}"));
                    }
                }
                Ok(false) => (),
                Err(error) => failures.push(format!("inspect tentative link {name}: {error}")),
            }
        }
        for (name, prior_port) in &self.wireguard_ports {
            match wireguard_listen_port(name) {
                Ok(port) if port == *prior_port => (),
                Ok(_) => {
                    let output = Command::new("wg")
                        .env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin")
                        .args(["set", name, "listen-port", &prior_port.to_string()])
                        .output();
                    match output {
                        Ok(output) if output.status.success() => (),
                        Ok(output) => failures.push(format!(
                            "restore WireGuard listen port on {name}: {}",
                            String::from_utf8_lossy(&output.stderr).trim()
                        )),
                        Err(error) => failures
                            .push(format!("restore WireGuard listen port on {name}: {error}")),
                    }
                    match wireguard_listen_port(name) {
                        Ok(restored) if restored == *prior_port => (),
                        Ok(_) => failures
                            .push(format!("WireGuard listen port on {name} was not restored")),
                        Err(error) => failures
                            .push(format!("verify WireGuard listen port on {name}: {error}")),
                    }
                }
                Err(error) => {
                    failures.push(format!("inspect WireGuard listen port on {name}: {error}"))
                }
            }
        }
        for (dev, prior, restore_unconfigured) in &self.qdiscs {
            let now = match root_qdisc(dev) {
                Ok(qdisc) => qdisc,
                Err(error) => {
                    failures.push(format!("inspect tentative qdisc on {dev}: {error}"));
                    continue;
                }
            };
            if &now == prior {
                continue;
            }
            if *restore_unconfigured {
                let mut command = Command::new("tc");
                command.env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin");
                match prior {
                    Some(qdisc) if qdisc.kind != "noqueue" && qdisc.kind != "mq" => {
                        command.args(["qdisc", "replace", "dev", dev, "root", &qdisc.kind]);
                    }
                    _ => {
                        command.args(["qdisc", "delete", "dev", dev, "root"]);
                    }
                }
                match command.output() {
                    Ok(output) if output.status.success() => (),
                    Ok(output) => failures.push(format!(
                        "restore qdisc on {dev}: {}",
                        String::from_utf8_lossy(&output.stderr).trim()
                    )),
                    Err(error) => failures.push(format!("restore qdisc on {dev}: {error}")),
                }
            }
            match root_qdisc(dev) {
                Ok(restored) if &restored == prior => (),
                Ok(_) => failures.push(format!("qdisc options on {dev} were not restored")),
                Err(error) => failures.push(format!("verify restored qdisc on {dev}: {error}")),
            }
        }
        for (path, contents) in &self.lan_files {
            let result = match contents {
                Some(contents) => fs::write(path, contents)
                    .map_err(|error| format!("restore LAN service configuration: {error}")),
                None => durable::remove(Path::new(path)),
            };
            if let Err(error) = result {
                failures.push(error);
            }
        }
        failures
    }
}

fn wireguard_listen_port(name: &str) -> Result<u16, String> {
    let output = Command::new("wg")
        .env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin")
        .args(["show", name, "listen-port"])
        .output()
        .map_err(|error| format!("inspect WireGuard listen port on {name}: {error}"))?;
    if !output.status.success() {
        return Err(format!("inspect WireGuard listen port on {name} failed"));
    }
    String::from_utf8_lossy(&output.stdout)
        .trim()
        .parse()
        .map_err(|error| format!("decode WireGuard listen port on {name}: {error}"))
}

#[derive(PartialEq)]
struct RootQdisc {
    kind: String,
    options: Value,
}

fn root_qdisc(dev: &str) -> Result<Option<RootQdisc>, String> {
    let output = Command::new("tc")
        .env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin")
        .args(["-j", "qdisc", "show", "dev", dev])
        .output()
        .map_err(|error| format!("inspect qdisc on {dev}: {error}"))?;
    if !output.status.success() {
        return Err(format!("inspect qdisc on {dev} failed"));
    }
    let qdiscs: Value = serde_json::from_slice(&output.stdout)
        .map_err(|error| format!("decode qdisc on {dev}: {error}"))?;
    Ok(qdiscs.as_array().and_then(|qdiscs| {
        qdiscs
            .iter()
            .find(|qdisc| qdisc["root"] == true)
            .and_then(|qdisc| {
                qdisc["kind"].as_str().map(|kind| RootQdisc {
                    kind: kind.to_owned(),
                    options: qdisc["options"].clone(),
                })
            })
    }))
}

fn desired_addresses(state: &DesiredState) -> Vec<(String, String)> {
    let mut addresses: Vec<(String, String)> = state
        .interfaces
        .iter()
        .flat_map(|iface| {
            iface
                .addresses
                .iter()
                .map(|cidr| (iface.name.clone(), cidr.clone()))
        })
        .chain(state.wireguard.iter().flat_map(|wg| {
            wg.addresses
                .iter()
                .map(|cidr| (wg.name.clone(), cidr.clone()))
        }))
        .collect();
    if let Some(lan) = lan_l2(state) {
        if let Some(pd) = state.wan_pd.as_deref().and_then(pd_lan_addr) {
            addresses.push((lan.name.clone(), pd));
        }
    }
    addresses
}

fn live_address(dev: &str, cidr: &str) -> Result<bool, String> {
    let (address, bits) = cidr
        .split_once('/')
        .ok_or_else(|| format!("invalid address prefix on {dev}"))?;
    let address: IpAddr = address
        .parse()
        .map_err(|_| format!("invalid address prefix on {dev}"))?;
    let bits: u8 = bits
        .parse()
        .map_err(|_| format!("invalid address prefix on {dev}"))?;
    let output = ip_cmd()
        .args(["-j", "address", "show", "dev", dev])
        .output()
        .map_err(|error| format!("inspect addresses on {dev}: {error}"))?;
    if !output.status.success() {
        return Err(format!("inspect addresses on {dev} failed"));
    }
    let links: Value = serde_json::from_slice(&output.stdout)
        .map_err(|error| format!("decode addresses on {dev}: {error}"))?;
    Ok(links.as_array().is_some_and(|links| {
        links.iter().any(|link| {
            link["addr_info"].as_array().is_some_and(|addresses| {
                addresses.iter().any(|live| {
                    live["local"]
                        .as_str()
                        .and_then(|local| local.parse::<IpAddr>().ok())
                        == Some(address)
                        && live["prefixlen"].as_u64() == Some(u64::from(bits))
                })
            })
        })
    }))
}

fn remove_stale_routes(previous: &DesiredState, proposed: &DesiredState) -> Result<(), String> {
    for old in &previous.routes {
        if !proposed.routes.iter().any(|new| new.to == old.to) {
            let family = if old.to.contains(':') { "-6" } else { "-4" };
            let mut args = vec![family, "route", "del", &old.to, "via", &old.via];
            if let Some(dev) = old.dev.as_deref() {
                args.push("dev");
                args.push(dev);
            }
            if let Err(error) = run_ip(&args) {
                // A failed apply may stop before a later proposed route was
                // installed. Only that exact route is ours to remove.
                if !error.contains("No such process") {
                    return Err(error);
                }
            }
        }
    }
    Ok(())
}

fn parse_opt(v: &Value) -> Result<FirstBootOpt, String> {
    let nic = v
        .get("nic")
        .and_then(Value::as_str)
        .unwrap_or("")
        .trim()
        .to_string();
    let mode = v
        .get("mode")
        .and_then(Value::as_str)
        .unwrap_or("")
        .trim()
        .to_string();
    if nic.is_empty() {
        return Err("missing nic".into());
    }
    if mode != "static" && mode != "dhcp" && mode != "slaac" {
        return Err("mode must be static, dhcp, or slaac".into());
    }
    let cidr = v
        .get("cidr")
        .and_then(Value::as_str)
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());
    if mode == "static" && cidr.is_none() {
        return Err("static opt needs a cidr".into());
    }
    Ok(FirstBootOpt { nic, mode, cidr })
}

fn persist(state: &DesiredState) -> Result<(), String> {
    persist_at(Path::new(DESIRED), state)
}

fn persist_at(path: &Path, state: &DesiredState) -> Result<(), String> {
    let raw = toml::to_string_pretty(state).map_err(|e| format!("encode TOML: {e}"))?;
    durable::write(path, raw.as_bytes())
}

fn bootstrap_apply(request: &Value) -> Result<(), BootstrapFailure> {
    if Path::new(BOOTSTRAPPED).exists() {
        return Err(BootstrapFailure::Owned("already bootstrapped".into()));
    }
    match bootstrap_apply_inner(request) {
        Ok(()) => Ok(()),
        Err(BootstrapFailure::Incomplete(error)) if Path::new(BOOTSTRAPPED).exists() => Err(
            BootstrapFailure::Owned(format!("Bootstrap ownership is recorded; {error}")),
        ),
        Err(BootstrapFailure::Incomplete(error)) => {
            Err(BootstrapFailure::Incomplete(fail_bootstrap_attempt(error)))
        }
        Err(other) => Err(other),
    }
}

fn bootstrap_apply_inner(request: &Value) -> Result<(), BootstrapFailure> {
    let admin_subject = request
        .get("admin_subject")
        .and_then(Value::as_str)
        .ok_or("missing Bootstrap administrator binding")?;
    let mut state: DesiredState = serde_json::from_value(
        request
            .get("desired")
            .cloned()
            .ok_or("missing Bootstrap Desired state")?,
    )
    .map_err(|error| format!("invalid Bootstrap Desired state: {error}"))?;
    validate(&state)?;
    for iface in &state.interfaces {
        bootstrap_values::interface(
            &iface.name,
            iface.parent.as_deref(),
            iface.vlan,
            &iface.addresses,
        )?;
    }
    bootstrap_values::addressing(
        state.lan_prefix.as_deref(),
        state.dhcp_pool.as_deref(),
        state.wan_pd.as_deref(),
    )?;
    if identity::tentative_first_administrator_subject().as_deref() != Some(admin_subject) {
        return Err("Bootstrap administrator changed before apply".into());
    }
    let hostname = state.hostname.clone().ok_or("missing Bootstrap hostname")?;
    if fs::read_to_string(HOSTNAME)
        .map(|name| name.trim().to_string())
        .ok()
        .as_deref()
        != Some(hostname.as_str())
    {
        return Err("Bootstrap hostname is not durable".into());
    }
    let attempt = BootstrapAttempt {
        vlan_links: state
            .interfaces
            .iter()
            .filter(|iface| iface.vlan.is_some())
            .map(|iface| iface.name.clone())
            .collect(),
    };
    let raw = serde_json::to_vec(&attempt)
        .map_err(|error| format!("encode Bootstrap attempt: {error}"))?;
    durable::write(Path::new(BOOTSTRAP_ATTEMPT), &raw)?;
    apply(&mut state)?;
    persist(&state)?;
    if identity::tentative_first_administrator_subject().as_deref() != Some(admin_subject) {
        return Err("Bootstrap administrator changed during apply".into());
    }
    if fs::read_to_string(HOSTNAME)
        .map(|name| name.trim().to_string())
        .ok()
        .as_deref()
        != Some(hostname.as_str())
    {
        return Err("Bootstrap hostname changed during apply".into());
    }
    commit_bootstrap_marker()?;
    // Host path units watch the readiness marker, and services require both
    // that marker and their config file. Incomplete attempts must not start
    // LAN services; next boot replays Desired if publication fails.
    program_lan_services(&state, true)?;
    set_lan_services_ready(true)?;
    for file in [OPT_FILE, BOOTSTRAP_ATTEMPT] {
        if let Err(error) = durable::remove(Path::new(file)) {
            eprintln!("netd: completed Bootstrap cleanup: {error}");
        }
    }
    Ok(())
}

fn commit_bootstrap_marker() -> Result<(), BootstrapFailure> {
    let marker = Path::new(BOOTSTRAPPED);
    let Err(error) = durable::write(marker, b"ok\n") else {
        return Ok(());
    };
    // A failed directory fsync can follow a successful rename. Confirm it on
    // retry if possible; otherwise durably remove the visible marker before
    // considering this attempt incomplete.
    if marker.exists()
        && marker
            .parent()
            .and_then(|parent| File::open(parent).ok())
            .is_some_and(|directory| directory.sync_all().is_ok())
    {
        return Ok(());
    }
    match durable::remove(marker) {
        Ok(()) => Err(BootstrapFailure::Incomplete(format!(
            "Bootstrap marker was not durable: {error}"
        ))),
        Err(cleanup) => Err(BootstrapFailure::Indeterminate(format!(
            "Bootstrap marker durability is uncertain: {error}; cleanup: {cleanup}"
        ))),
    }
}

fn fail_bootstrap_attempt(error: String) -> String {
    match recover_incomplete_bootstrap() {
        Ok(()) => error,
        Err(recovery) => format!("{error}; Bootstrap recovery failed: {recovery}"),
    }
}

fn recover_incomplete_bootstrap() -> Result<(), String> {
    if Path::new(BOOTSTRAPPED).exists() {
        return Ok(());
    }
    let attempt = match fs::read(BOOTSTRAP_ATTEMPT) {
        Ok(raw) => Some(
            serde_json::from_slice::<BootstrapAttempt>(&raw)
                .map_err(|error| format!("parse Bootstrap attempt: {error}"))?,
        ),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
        Err(error) => return Err(format!("read Bootstrap attempt: {error}")),
    };
    if let Some(attempt) = &attempt {
        stop_dhclient();
        for name in &attempt.vlan_links {
            if link_exists(name)? {
                run_ip(&["link", "delete", "dev", name])?;
            }
        }
        for nic in traffic_nic_names()? {
            lock_unopted(&nic)?;
            run_ip(&["link", "set", &nic, "up"])?;
        }
        nft_apply("flush ruleset\n")?;
        nft_apply(&host_pull_nft())?;
    }
    for file in [
        DESIRED,
        IDENTITY,
        HOSTNAME,
        "/var/lib/fwos/kea/kea-dhcp4.conf",
        "/var/lib/fwos/kea/kea-dhcp6.conf",
        "/var/lib/fwos/unbound/unbound.conf",
        BOOTSTRAP_ATTEMPT,
    ] {
        durable::remove(Path::new(file))?;
    }
    if attempt.is_some() {
        if let Some(opt) = load_opt() {
            apply_opt(&opt)?;
        } else {
            program_first_boot_nft("", &[])?;
        }
    }
    Ok(())
}

fn validate(state: &DesiredState) -> Result<(), String> {
    for iface in &state.interfaces {
        bootstrap_values::interface(
            &iface.name,
            iface.parent.as_deref(),
            iface.vlan,
            &iface.addresses,
        )?;
    }
    bootstrap_values::addressing(
        state.lan_prefix.as_deref(),
        state.dhcp_pool.as_deref(),
        state.wan_pd.as_deref(),
    )?;
    for wg in &state.wireguard {
        bootstrap_values::interface(&wg.name, None, None, &wg.addresses)?;
        let key = base64::engine::general_purpose::STANDARD
            .decode(&wg.private_key)
            .map_err(|_| format!("WireGuard {} has an invalid private key", wg.name))?;
        if key.len() != 32 {
            return Err(format!("WireGuard {} has an invalid private key", wg.name));
        }
    }
    for qdisc in &state.qdiscs {
        let known_dev = state.interfaces.iter().any(|iface| iface.name == qdisc.dev)
            || state.wireguard.iter().any(|wg| wg.name == qdisc.dev);
        if !known_dev
            || !matches!(
                qdisc.kind.as_str(),
                "fq_codel" | "fq" | "pfifo" | "bfifo" | "sfq" | "cake"
            )
        {
            return Err(format!("unsupported qdisc {} on {}", qdisc.kind, qdisc.dev));
        }
    }
    let mut destinations = HashSet::new();
    for route in &state.routes {
        let (address, prefix) = route
            .to
            .split_once('/')
            .ok_or_else(|| format!("route destination {} must be a CIDR prefix", route.to))?;
        let destination: IpAddr = address
            .parse()
            .map_err(|_| format!("invalid route destination {}", route.to))?;
        let bits: u8 = prefix
            .parse()
            .map_err(|_| format!("invalid route destination {}", route.to))?;
        let max = if destination.is_ipv4() { 32 } else { 128 };
        if bits > max {
            return Err(format!("invalid route destination {}", route.to));
        }
        let canonical = match destination {
            IpAddr::V4(ip) => {
                let mask = if bits == 0 {
                    0
                } else {
                    u32::MAX << (32 - bits)
                };
                u32::from(ip) & mask == u32::from(ip)
            }
            IpAddr::V6(ip) => {
                let mask = if bits == 0 {
                    0
                } else {
                    u128::MAX << (128 - bits)
                };
                u128::from(ip) & mask == u128::from(ip)
            }
        };
        if !canonical || !destinations.insert((destination, bits)) {
            return Err(format!(
                "invalid or duplicate route destination {}",
                route.to
            ));
        }
        let gateway: IpAddr = route
            .via
            .parse()
            .map_err(|_| format!("invalid route next hop {}", route.via))?;
        if destination.is_ipv4() != gateway.is_ipv4()
            || gateway.is_unspecified()
            || gateway.is_multicast()
        {
            return Err(format!(
                "route {} needs a usable next hop of the same IP family",
                route.to
            ));
        }
        if matches!(gateway, IpAddr::V6(address) if address.is_unicast_link_local())
            && route.dev.is_none()
        {
            return Err(format!(
                "route {} needs an interface for a link-local next hop",
                route.to
            ));
        }
        if let Some(dev) = route.dev.as_deref() {
            if !state.interfaces.iter().any(|iface| iface.name == dev) {
                return Err(format!("route {} uses unknown interface {dev}", route.to));
            }
        }
        if !route_next_hop_on_link(state, gateway, route.dev.as_deref()) {
            return Err(format!(
                "route {} next hop {} needs a configured on-link interface address",
                route.to, route.via
            ));
        }
    }
    for iface in &state.interfaces {
        if iface.placement == "mgmt" {
            return Err("placement=mgmt is not a contract; use roles and ui_exposure".into());
        }
        if let Some(role) = iface.role.as_deref() {
            if !matches!(role, "wan" | "lan" | "unused" | "stick" | "mgmt") {
                return Err(format!("unknown role {role}"));
            }
        }
        if iface.role.as_deref() == Some("mgmt") {
            validate_mgmt_iface(iface)?;
        }
    }
    let wans: Vec<&Iface> = state
        .interfaces
        .iter()
        .filter(|i| i.role.as_deref() == Some("wan"))
        .collect();
    let lans: Vec<&Iface> = state
        .interfaces
        .iter()
        .filter(|i| i.role.as_deref() == Some("lan"))
        .collect();
    let mgmts: Vec<&Iface> = state
        .interfaces
        .iter()
        .filter(|i| i.role.as_deref() == Some("mgmt"))
        .collect();
    if wans.is_empty() {
        return Err("need at least one WAN".into());
    }
    if lans.is_empty() {
        return Err("need at least one LAN".into());
    }
    for wan in &wans {
        for lan in &lans {
            if l2_key(wan) == l2_key(lan) {
                return Err("WAN and LAN must not share the same parent and tag".into());
            }
        }
    }
    let mgmt_parents: Vec<String> = mgmts.iter().map(|i| l2_key(i).0).collect();
    for iface in wans.iter().chain(lans.iter()) {
        if mgmt_parents.iter().any(|p| p == &l2_key(iface).0) {
            return Err("WAN or LAN must not share a parent with a Management NIC".into());
        }
    }
    if state.ui_exposure.is_empty() {
        return Err("ui_exposure must not be empty".into());
    }
    for name in &state.ui_exposure {
        let Some(iface) = state.interfaces.iter().find(|i| i.name == *name) else {
            return Err(format!("ui_exposure {name} is not an interface"));
        };
        if iface.role.as_deref() == Some("wan") {
            return Err("ui_exposure cannot include a WAN".into());
        }
    }
    for mgmt in &mgmts {
        if !state.ui_exposure.iter().any(|n| n == &mgmt.name) {
            return Err("Management NIC must be in ui_exposure".into());
        }
    }
    Ok(())
}

fn route_next_hop_on_link(state: &DesiredState, gateway: IpAddr, device: Option<&str>) -> bool {
    let first_lan = state
        .interfaces
        .iter()
        .find(|iface| iface.role.as_deref() == Some("lan"));
    for iface in &state.interfaces {
        if device.is_some_and(|name| name != iface.name) || iface.role.as_deref() == Some("mgmt") {
            continue;
        }
        let mut addresses = iface.addresses.clone();
        if first_lan.is_some_and(|lan| lan.name == iface.name) {
            if let Some(prefix) = state.lan_prefix.as_deref() {
                if let Some(host) = first_v4_host(prefix) {
                    if let Some((_, bits)) = prefix.split_once('/') {
                        addresses.push(format!("{host}/{bits}"));
                    }
                }
            }
        }
        if addresses
            .iter()
            .any(|address| gateway_in_cidr(gateway, address))
        {
            return true;
        }
    }
    false
}

fn gateway_in_cidr(gateway: IpAddr, cidr: &str) -> bool {
    let Some((address, bits)) = cidr.split_once('/') else {
        return false;
    };
    let (Ok(address), Ok(bits)) = (address.parse::<IpAddr>(), bits.parse::<u8>()) else {
        return false;
    };
    if gateway == address {
        return false;
    }
    match (gateway, address) {
        (IpAddr::V4(gateway), IpAddr::V4(address)) if bits <= 32 => {
            let mask = if bits == 0 {
                0
            } else {
                u32::MAX << (32 - bits)
            };
            u32::from(gateway) & mask == u32::from(address) & mask
        }
        (IpAddr::V6(gateway), IpAddr::V6(address)) if bits <= 128 => {
            let mask = if bits == 0 {
                0
            } else {
                u128::MAX << (128 - bits)
            };
            u128::from(gateway) & mask == u128::from(address) & mask
        }
        _ => false,
    }
}

fn validate_mgmt_iface(iface: &Iface) -> Result<(), String> {
    if iface.vlan.is_some() || iface.parent.is_some() {
        return Err("Management NIC owns the whole parent".into());
    }
    if iface.dhcp {
        return Err("Management NIC is on-link static; no DHCP".into());
    }
    if iface.addresses.is_empty() {
        return Err("Management NIC needs an on-link static prefix".into());
    }
    Ok(())
}

fn l2_key(iface: &Iface) -> (String, Option<u16>) {
    let parent = iface.parent.clone().unwrap_or_else(|| {
        if iface.vlan.is_some() {
            iface
                .name
                .rsplit_once('.')
                .map(|(p, _)| p.to_string())
                .unwrap_or_else(|| iface.name.clone())
        } else {
            iface.name.clone()
        }
    });
    (parent, iface.vlan)
}

fn exposes_ui(state: &DesiredState, name: &str) -> bool {
    state.ui_exposure.iter().any(|n| n == name)
}

fn lan_l2(state: &DesiredState) -> Option<&Iface> {
    state
        .interfaces
        .iter()
        .find(|i| i.role.as_deref() == Some("lan"))
}

fn merge_lan_prefix_addr(state: &mut DesiredState) {
    let Some(prefix) = state
        .lan_prefix
        .clone()
        .or_else(|| state.dhcp_pool.as_deref().and_then(prefix_from_pool))
    else {
        return;
    };
    let Some(lan_v4) = first_v4_host(&prefix) else {
        return;
    };
    let plen = prefix.split('/').nth(1).unwrap_or("24");
    let cidr = format!("{lan_v4}/{plen}");
    if let Some(iface) = state
        .interfaces
        .iter_mut()
        .find(|i| i.role.as_deref() == Some("lan"))
    {
        if !iface
            .addresses
            .iter()
            .any(|a| a == &cidr || a.starts_with(&format!("{lan_v4}/")))
        {
            iface.addresses.push(cidr);
        }
    }
}

fn apply(state: &mut DesiredState) -> Result<(), String> {
    validate(state)?;
    // Capture UI-exposure / LAN addresses before tearing down the first-boot
    // opt so HTTPS stays at the LAN interface address after apply.
    let capture_names: Vec<String> = state
        .interfaces
        .iter()
        .filter(|i| {
            i.vlan.is_none() && (exposes_ui(state, &i.name) || i.role.as_deref() == Some("lan"))
        })
        .map(|i| i.name.clone())
        .collect();
    let mut saved: Vec<(String, Vec<String>)> = Vec::new();
    for iface in &mut state.interfaces {
        if !capture_names.iter().any(|n| n == &iface.name) {
            continue;
        }
        let Ok((mut addrs, _)) = capture_ipv4(&iface.name) else {
            continue;
        };
        if addrs.is_empty() {
            addrs = iface.addresses.clone();
        } else if iface.addresses.is_empty() {
            iface.addresses = addrs.clone();
        }
        saved.push((iface.name.clone(), addrs));
    }
    merge_lan_prefix_addr(state);
    if Path::new(BOOTSTRAPPED).exists() {
        discard_opt()?;
    } else {
        suspend_opt()?;
    }
    for iface in &state.interfaces {
        if iface.vlan.is_none() {
            require_in_fwd(&iface.name)?;
            run_ip(&["link", "set", &iface.name, "up"])?;
            let extra = saved
                .iter()
                .find(|(n, _)| n == &iface.name)
                .map(|(_, a)| a.clone())
                .unwrap_or_default();
            for addr in extra.iter().chain(iface.addresses.iter()) {
                add_addr(&iface.name, addr)?;
            }
        }
    }
    program_vlans(state)?;
    program_wg(state)?;
    program_routes(state)?;
    program_qdiscs(state)?;
    program_lan_services(state, Path::new(BOOTSTRAPPED).exists())?;
    program_nft(state)
}

fn require_in_fwd(name: &str) -> Result<(), String> {
    if link_exists(name)? {
        Ok(())
    } else {
        Err(format!(
            "Traffic NIC {name} is missing from fwd; Network startup preparation is incomplete"
        ))
    }
}

fn program_vlans(state: &DesiredState) -> Result<(), String> {
    for iface in &state.interfaces {
        let Some(vid) = iface.vlan else {
            continue;
        };
        let parent = iface.parent.clone().unwrap_or_else(|| {
            iface
                .name
                .rsplit_once('.')
                .map(|(p, _)| p.to_string())
                .unwrap_or_else(|| iface.name.clone())
        });
        if !link_exists(&iface.name)? {
            run_ip(&[
                "link",
                "add",
                "link",
                &parent,
                "name",
                &iface.name,
                "type",
                "vlan",
                "id",
                &vid.to_string(),
            ])?;
        }
        run_ip(&["link", "set", &iface.name, "up"])?;
        for addr in &iface.addresses {
            add_addr(&iface.name, addr)?;
        }
    }
    Ok(())
}

fn program_lan_services(state: &DesiredState, publish: bool) -> Result<(), String> {
    let Some(lan) = lan_l2(state) else {
        if publish {
            remove_lan_service_configs()?;
        }
        return Ok(());
    };
    let prefix = state
        .lan_prefix
        .clone()
        .or_else(|| state.dhcp_pool.as_deref().and_then(prefix_from_pool));
    let Some(prefix) = prefix else {
        if publish {
            remove_lan_service_configs()?;
        }
        return Ok(());
    };
    let lan_v4 = first_v4_host(&prefix).ok_or_else(|| "lan_prefix has no v4 host".to_string())?;
    let plen = prefix.split('/').nth(1).unwrap_or("24");
    add_addr(&lan.name, &format!("{lan_v4}/{plen}"))?;
    if let Some(pd) = state.wan_pd.as_deref() {
        if let Some(v6) = pd_lan_addr(pd) {
            add_addr(&lan.name, &v6)?;
        }
    }
    if !publish {
        return Ok(());
    }
    let Some(pool) = state.dhcp_pool.as_deref() else {
        remove_lan_service_configs()?;
        return Ok(());
    };
    fs::create_dir_all("/var/lib/fwos/kea").map_err(|e| format!("mkdir kea: {e}"))?;
    fs::create_dir_all("/var/lib/fwos/unbound").map_err(|e| format!("mkdir unbound: {e}"))?;
    let (p1, p2) = split_pool(pool);
    let kea4 = kea_dhcp4_conf(&lan.name, &prefix, &p1, &p2, &lan_v4);
    fs::write("/var/lib/fwos/kea/kea-dhcp4.conf", kea4)
        .map_err(|e| format!("write kea-dhcp4: {e}"))?;
    if let Some(pd) = state.wan_pd.as_deref() {
        if let (Some(v6_sub), Some((v6p1, v6p2))) = (pd_subnet64(pd), pd_pool(pd)) {
            let kea6 = kea_dhcp6_conf(&lan.name, &v6_sub, &v6p1, &v6p2);
            fs::write("/var/lib/fwos/kea/kea-dhcp6.conf", kea6)
                .map_err(|e| format!("write kea-dhcp6: {e}"))?;
        } else {
            durable::remove(Path::new("/var/lib/fwos/kea/kea-dhcp6.conf"))?;
        }
    } else {
        durable::remove(Path::new("/var/lib/fwos/kea/kea-dhcp6.conf"))?;
    }
    let unbound = unbound_conf(&lan_v4, &prefix);
    fs::write("/var/lib/fwos/unbound/unbound.conf", unbound)
        .map_err(|e| format!("write unbound: {e}"))?;
    Ok(())
}

fn remove_lan_service_configs() -> Result<(), String> {
    for path in [
        "/var/lib/fwos/kea/kea-dhcp4.conf",
        "/var/lib/fwos/kea/kea-dhcp6.conf",
        "/var/lib/fwos/unbound/unbound.conf",
    ] {
        durable::remove(Path::new(path))?;
    }
    Ok(())
}

fn kea_dhcp4_conf(dev: &str, prefix: &str, p1: &str, p2: &str, lan_v4: &str) -> String {
    format!(
        r#"{{
  "Dhcp4": {{
    "interfaces-config": {{ "interfaces": [ "{dev}" ], "re-detect": true, "service-sockets-require-all": true }},
    "lease-database": {{ "type": "memfile", "persist": false, "name": "/tmp/dhcp4.leases" }},
    "valid-lifetime": 3600,
    "subnet4": [ {{
      "id": 1,
      "subnet": "{prefix}",
      "interface": "{dev}",
      "pools": [ {{ "pool": "{p1} - {p2}" }} ],
      "option-data": [
        {{ "name": "routers", "data": "{lan_v4}" }},
        {{ "name": "domain-name-servers", "data": "{lan_v4}" }}
      ]
    }} ],
    "loggers": [ {{ "name": "kea-dhcp4", "severity": "INFO", "output-options": [ {{ "output": "stdout" }} ] }} ]
  }}
}}
"#
    )
}

fn kea_dhcp6_conf(dev: &str, subnet: &str, p1: &str, p2: &str) -> String {
    format!(
        r#"{{
  "Dhcp6": {{
    "interfaces-config": {{ "interfaces": [ "{dev}" ], "re-detect": true, "service-sockets-require-all": true }},
    "lease-database": {{ "type": "memfile", "persist": false, "name": "/tmp/dhcp6.leases" }},
    "server-id": {{ "type": "LLT", "persist": false }},
    "subnet6": [ {{
      "id": 1,
      "subnet": "{subnet}",
      "interface": "{dev}",
      "pools": [ {{ "pool": "{p1} - {p2}" }} ]
    }} ],
    "loggers": [ {{ "name": "kea-dhcp6", "severity": "INFO", "output-options": [ {{ "output": "stdout" }} ] }} ]
  }}
}}
"#
    )
}

fn unbound_conf(lan_v4: &str, prefix: &str) -> String {
    format!(
        "server:\n  interface: {lan_v4}\n  port: 53\n  access-control: {prefix} allow\n  access-control: 127.0.0.0/8 allow\n  do-daemonize: no\n  username: \"\"\n  chroot: \"\"\n  directory: \"/tmp\"\n  pidfile: \"/tmp/unbound.pid\"\n  use-syslog: no\n  logfile: /dev/null\n"
    )
}

fn split_pool(pool: &str) -> (String, String) {
    let p = pool.replace(' ', "");
    match p.split_once('-') {
        Some((a, b)) => (a.to_string(), b.to_string()),
        None => (p.clone(), p),
    }
}

fn prefix_from_pool(pool: &str) -> Option<String> {
    let (start, _) = split_pool(pool);
    let mut o: Vec<u8> = start.split('.').filter_map(|s| s.parse().ok()).collect();
    if o.len() != 4 {
        return None;
    }
    o[3] = 0;
    Some(format!("{}.{}.{}.{}/24", o[0], o[1], o[2], o[3]))
}

fn first_v4_host(cidr: &str) -> Option<String> {
    let ip = cidr.split('/').next()?;
    let mut o: Vec<u8> = ip.split('.').filter_map(|s| s.parse().ok()).collect();
    if o.len() != 4 {
        return None;
    }
    if o[3] == 0 {
        o[3] = 1;
    }
    Some(format!("{}.{}.{}.{}", o[0], o[1], o[2], o[3]))
}

fn pd_lan_addr(pd: &str) -> Option<String> {
    Some(bootstrap_values::delegated_lan(pd)?.address_cidr)
}

fn pd_subnet64(pd: &str) -> Option<String> {
    Some(bootstrap_values::delegated_lan(pd)?.subnet_cidr)
}

fn pd_pool(pd: &str) -> Option<(String, String)> {
    let lan = bootstrap_values::delegated_lan(pd)?;
    Some((lan.pool_start, lan.pool_end))
}

fn program_nft(state: &DesiredState) -> Result<(), String> {
    nft_apply(&nft_rules(state))
}

fn nft_rules(state: &DesiredState) -> String {
    nft_rules_with_recovery_guard(state, RECOVERY_REQUIRED.load(Ordering::SeqCst))
}

fn nft_rules_with_recovery_guard(state: &DesiredState, recovery_required: bool) -> String {
    let wans: Vec<&str> = state
        .interfaces
        .iter()
        .filter(|i| i.role.as_deref() == Some("wan"))
        .map(|i| i.name.as_str())
        .collect();
    let v4_wan = state
        .interfaces
        .iter()
        .any(|i| i.role.as_deref() == Some("wan") && i.addresses.iter().any(|a| a.contains('.')));
    let exposure = ui_exposure(state);
    let mut rules = String::from("flush ruleset\n");
    rules.push_str(&host_pull_nft());
    rules.push_str("table inet fwos {\n");
    rules.push_str("  chain input {\n");
    rules.push_str("    type filter hook input priority filter; policy accept;\n");
    rules.push_str("    iifname \"lo\" accept\n");
    for extra in &state.nft_extra {
        rules.push_str(&format!("    {extra}\n"));
    }
    for wan in &wans {
        rules.push_str(&format!(
            "    iifname \"{wan}\" ct state established,related accept\n"
        ));
        rules.push_str(&format!("    iifname \"{wan}\" drop\n"));
    }
    rules.push_str("  }\n");
    rules.push_str("  chain forward {\n");
    rules.push_str("    type filter hook forward priority filter; policy drop;\n");
    if recovery_required {
        rules.push_str("    drop\n");
    }
    rules.push_str("    ct state established,related accept\n");
    // Host-netns pulls and DNATed UI replies arrive from mgmt on this veth.
    rules.push_str(&format!("    iifname \"{FWD_MGMT_VETH}\" accept\n"));
    for (name, _) in &exposure {
        rules.push_str(&format!(
            "    iifname \"{name}\" oifname \"{FWD_MGMT_VETH}\" tcp dport 443 accept\n"
        ));
    }
    let mgmts: Vec<&str> = state
        .interfaces
        .iter()
        .filter(|i| i.role.as_deref() == Some("mgmt"))
        .map(|i| i.name.as_str())
        .collect();
    for mgmt in &mgmts {
        rules.push_str(&format!("    iifname \"{mgmt}\" drop\n"));
        rules.push_str(&format!("    oifname \"{mgmt}\" drop\n"));
    }
    for wan in &wans {
        rules.push_str(&format!("    oifname \"{wan}\" accept\n"));
    }
    rules.push_str("  }\n");
    if !exposure.is_empty() {
        rules.push_str("  chain prerouting {\n");
        rules.push_str("    type nat hook prerouting priority dstnat; policy accept;\n");
        for (name, addrs) in &exposure {
            let ips = expose_ips(addrs);
            if ips.is_empty() {
                // LAN L2 with no address yet: DNAT only on that interface, never on a WAN.
                rules.push_str(&format!(
                    "    iifname \"{name}\" tcp dport 443 dnat ip to {MGMT_FWD_IP}\n"
                ));
                continue;
            }
            for ip in ips {
                if ip.contains(':') {
                    rules.push_str(&format!(
                        "    iifname \"{name}\" ip6 daddr {ip} tcp dport 443 dnat ip6 to {MGMT_FWD_IP6}\n"
                    ));
                } else {
                    rules.push_str(&format!(
                        "    iifname \"{name}\" ip daddr {ip} tcp dport 443 dnat ip to {MGMT_FWD_IP}\n"
                    ));
                }
            }
        }
        rules.push_str("  }\n");
    }
    if v4_wan {
        rules.push_str("  chain postrouting {\n");
        rules.push_str("    type nat hook postrouting priority srcnat; policy accept;\n");
        for wan in &wans {
            rules.push_str(&format!("    oifname \"{wan}\" masquerade\n"));
        }
        rules.push_str("  }\n");
    }
    rules.push_str("}\n");
    rules
}

fn nft_apply(rules: &str) -> Result<(), String> {
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

fn nft_check(rules: &str) -> Result<(), String> {
    let mut child = Command::new("nft")
        .env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin")
        .args(["-c", "-f", "-"])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .map_err(|e| format!("validate firewall rules: {e}"))?;
    child
        .stdin
        .as_mut()
        .ok_or("nft validation stdin")?
        .write_all(rules.as_bytes())
        .map_err(|e| format!("validate firewall rules: {e}"))?;
    if child
        .wait()
        .map_err(|e| format!("validate firewall rules: {e}"))?
        .success()
    {
        Ok(())
    } else {
        Err("invalid complete Desired state firewall rules".into())
    }
}

fn program_wg(state: &DesiredState) -> Result<(), String> {
    for wg in &state.wireguard {
        if !link_exists(&wg.name)? {
            run_ip(&["link", "add", &wg.name, "type", "wireguard"])?;
        }
        let mut args = vec!["set".to_string(), wg.name.clone()];
        args.push("private-key".into());
        args.push("/dev/stdin".into());
        if let Some(port) = wg.listen_port {
            args.push("listen-port".into());
            args.push(port.to_string());
        }
        let mut child = Command::new("wg")
            .env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin")
            .args(&args)
            .stdin(std::process::Stdio::piped())
            .spawn()
            .map_err(|e| format!("wg: {e}"))?;
        child
            .stdin
            .as_mut()
            .ok_or_else(|| "wg stdin".to_string())?
            .write_all(wg.private_key.as_bytes())
            .map_err(|e| format!("wg write: {e}"))?;
        let status = child.wait().map_err(|e| format!("wg wait: {e}"))?;
        if !status.success() {
            return Err(format!("wg set {} failed ({status})", wg.name));
        }
        run_ip(&["link", "set", &wg.name, "up"])?;
        for addr in &wg.addresses {
            add_addr(&wg.name, addr)?;
        }
    }
    Ok(())
}

fn program_routes(state: &DesiredState) -> Result<(), String> {
    for route in &state.routes {
        let family = if route.to.contains(':') { "-6" } else { "-4" };
        let mut args = vec![family, "route", "replace", &route.to, "via", &route.via];
        if let Some(dev) = route.dev.as_deref() {
            args.push("dev");
            args.push(dev);
        }
        run_ip(&args)?;
    }
    Ok(())
}

fn program_qdiscs(state: &DesiredState) -> Result<(), String> {
    for q in &state.qdiscs {
        let output = Command::new("tc")
            .env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin")
            .args(["qdisc", "replace", "dev", &q.dev, "root", &q.kind])
            .output()
            .map_err(|e| format!("tc qdisc: {e}"))?;
        if !output.status.success() {
            return Err(format!(
                "tc qdisc replace dev {} root {} failed: {}",
                q.dev,
                q.kind,
                String::from_utf8_lossy(&output.stderr).trim()
            ));
        }
    }
    Ok(())
}

fn program_host_pull() -> Result<(), String> {
    nft_apply("destroy table ip fwos-pull\n")?;
    nft_apply(&host_pull_nft())
}

fn host_pull_nft() -> String {
    String::from(
        "table ip fwos-pull {\n  chain postrouting {\n    type nat hook postrouting priority srcnat; policy accept;\n    ip saddr 169.254.127.0/30 masquerade\n  }\n}\n",
    )
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

fn load_opt() -> Option<FirstBootOpt> {
    let raw = fs::read_to_string(OPT_FILE).ok()?;
    serde_json::from_str(&raw).ok()
}

fn persist_opt(opt: &FirstBootOpt) -> Result<(), String> {
    let raw = serde_json::to_string_pretty(opt).map_err(|e| format!("encode opt: {e}"))?;
    if let Some(dir) = Path::new(OPT_FILE).parent() {
        fs::create_dir_all(dir).map_err(|e| format!("mkdir {}: {e}", dir.display()))?;
    }
    fs::write(OPT_FILE, raw).map_err(|e| format!("write {OPT_FILE}: {e}"))?;
    // Hard reset (QEMU system_reset / power loss) must still see the opt.
    if let Ok(f) = File::open(OPT_FILE) {
        let _ = f.sync_all();
    }
    if let Ok(dir) = File::open("/var/lib/fwos") {
        let _ = dir.sync_all();
    }
    unsafe {
        libc::sync();
    }
    Ok(())
}

fn apply_and_persist_opt(opt: FirstBootOpt) -> Result<(), String> {
    if Path::new(BOOTSTRAPPED).exists() {
        return Err("already bootstrapped".into());
    }
    apply_opt(&opt)?;
    persist_opt(&opt)
}

fn apply_opt(opt: &FirstBootOpt) -> Result<(), String> {
    // Validate the operator's target before removing the current selection.
    // Loopback, fixed plumbing and tagged/virtual links are not Traffic NICs.
    if !traffic_nic_names()?.iter().any(|name| name == &opt.nic) {
        return Err(format!("{} is not a Traffic NIC", opt.nic));
    }
    if let Some(prev) = load_opt() {
        if prev.nic != opt.nic || prev.mode != opt.mode || prev.cidr != opt.cidr {
            teardown_opt(&prev)?;
        }
    }
    require_in_fwd(&opt.nic)?;
    run_ip(&["link", "set", &opt.nic, "up"])?;
    match opt.mode.as_str() {
        "static" => {
            let cidr = opt.cidr.as_deref().ok_or("static opt needs a cidr")?;
            add_addr(&opt.nic, cidr)?;
        }
        "dhcp" => ephemeral_dhcp(&opt.nic)?,
        "slaac" => {
            // fwd has IPv6 forwarding on (Host pull / DNAT). Kernel ignores
            // accept_ra=1 on a forwarding interface; 2 still learns RAs.
            write_sysctl(&opt.nic, "ipv6", "accept_ra", "2")?;
            write_sysctl(&opt.nic, "ipv6", "autoconf", "1")?;
        }
        other => return Err(format!("unknown opt mode {other}")),
    }
    let addrs = match opt.mode.as_str() {
        "slaac" => wait_expose_cidrs(&opt.nic)?,
        _ => iface_cidrs(&opt.nic)?,
    };
    program_first_boot_nft(&opt.nic, &addrs)
}

fn wait_expose_cidrs(nic: &str) -> Result<Vec<String>, String> {
    let deadline = Instant::now() + Duration::from_secs(8);
    loop {
        let addrs = iface_cidrs(nic)?;
        if !bootstrap_expose_ips(&addrs).is_empty() || Instant::now() >= deadline {
            return Ok(addrs);
        }
        thread::sleep(Duration::from_millis(200));
    }
}

fn teardown_opt(opt: &FirstBootOpt) -> Result<(), String> {
    stop_dhclient();
    if opt.mode == "slaac" {
        write_sysctl(&opt.nic, "ipv6", "accept_ra", "0")?;
        write_sysctl(&opt.nic, "ipv6", "autoconf", "0")?;
    }
    if link_exists(&opt.nic)? {
        lock_unopted(&opt.nic)?;
        let _ = run_ip(&["link", "set", &opt.nic, "up"]);
    }
    // Keep the UI guarded while a selection is being replaced, including any
    // direct peer route to the internal Management namespace addresses.
    program_first_boot_nft("", &[])
}

fn suspend_opt() -> Result<(), String> {
    if let Some(opt) = load_opt() {
        teardown_opt(&opt)?;
    }
    nft_apply("destroy table inet fwos-first-boot\n")
}

fn discard_opt() -> Result<(), String> {
    suspend_opt()?;
    durable::remove(Path::new(OPT_FILE))
}

fn ephemeral_dhcp(nic: &str) -> Result<(), String> {
    stop_dhclient();
    write_dhclient_script()?;
    let output = Command::new("dhclient")
        .env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin")
        .args([
            "-1",
            "-sf",
            "/var/lib/fwos/dhclient-script",
            "-lf",
            "/var/lib/fwos/dhclient.leases",
            "-pf",
            "/var/lib/fwos/dhclient.pid",
            nic,
        ])
        .output()
        .map_err(|e| format!("dhclient: {e}"))?;
    if output.status.success() {
        Ok(())
    } else {
        Err(format!(
            "dhcp on {nic} failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ))
    }
}

fn write_dhclient_script() -> Result<(), String> {
    let script = r#"#!/bin/sh
case "${reason}" in
BOUND|RENEW|REBIND|REBOOT)
  ip addr replace "${new_ip_address}/${new_subnet_mask}" dev "${interface}"
  if [ -n "${new_routers}" ]; then
    gw=$(echo "${new_routers}" | awk '{print $1}')
    ip route replace default via "${gw}" dev "${interface}"
  fi
  ;;
esac
exit 0
"#;
    fs::write("/var/lib/fwos/dhclient-script", script)
        .map_err(|e| format!("write dhclient-script: {e}"))?;
    let mut perms = fs::metadata("/var/lib/fwos/dhclient-script")
        .map_err(|e| format!("stat dhclient-script: {e}"))?
        .permissions();
    perms.set_mode(0o755);
    fs::set_permissions("/var/lib/fwos/dhclient-script", perms)
        .map_err(|e| format!("chmod dhclient-script: {e}"))
}

fn stop_dhclient() {
    if let Ok(pid) = fs::read_to_string("/var/lib/fwos/dhclient.pid") {
        let pid = pid.trim();
        if !pid.is_empty() {
            let _ = Command::new("kill")
                .env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin")
                .args(["-TERM", pid])
                .status();
        }
    }
    let _ = fs::remove_file("/var/lib/fwos/dhclient.pid");
}

fn program_first_boot_nft(nic: &str, cidrs: &[String]) -> Result<(), String> {
    let ips = bootstrap_expose_ips(cidrs);
    // Replace NAT and its guard in one nft transaction, without an unguarded
    // interval between removing the previous selection and publishing the next.
    nft_apply(&format!(
        "destroy table ip fwos-first-boot\ndestroy table ip6 fwos-first-boot\ndestroy table inet fwos-first-boot\n{}",
        first_boot_nft(nic, &ips)
    ))
}

fn first_boot_nft(nic: &str, ips: &[String]) -> String {
    let mut rules = String::new();
    rules.push_str("table inet fwos-first-boot {\n  chain forward {\n    type filter hook forward priority filter; policy accept;\n");
    for ip in ips {
        let family = if ip.contains(':') { "ip6" } else { "ip" };
        rules.push_str(&format!(
            "    iifname \"{nic}\" oifname \"{FWD_MGMT_VETH}\" tcp dport 443 ct status dnat ct original {family} daddr {ip} accept\n"
        ));
    }
    rules.push_str(&format!(
        "    oifname \"{FWD_MGMT_VETH}\" tcp dport 443 drop\n  }}\n}}\n"
    ));
    let v4: Vec<&str> = ips
        .iter()
        .map(|s| s.as_str())
        .filter(|s| !s.contains(':'))
        .collect();
    let v6: Vec<&str> = ips
        .iter()
        .map(|s| s.as_str())
        .filter(|s| s.contains(':'))
        .collect();
    if !v4.is_empty() {
        rules.push_str("table ip fwos-first-boot {\n");
        rules.push_str("  chain prerouting {\n");
        rules.push_str("    type nat hook prerouting priority dstnat; policy accept;\n");
        for ip in &v4 {
            rules.push_str(&format!(
                "    iifname \"{nic}\" ip daddr {ip} tcp dport 443 dnat ip to {MGMT_FWD_IP}\n"
            ));
        }
        rules.push_str("  }\n");
        rules.push_str("  chain forward {\n");
        rules.push_str("    type filter hook forward priority filter; policy accept;\n");
        rules.push_str(&format!(
            "    iifname \"{nic}\" oifname \"{FWD_MGMT_VETH}\" tcp dport 443 accept\n"
        ));
        rules.push_str("  }\n");
        rules.push_str("}\n");
    }
    if !v6.is_empty() {
        rules.push_str("table ip6 fwos-first-boot {\n");
        rules.push_str("  chain prerouting {\n");
        rules.push_str("    type nat hook prerouting priority dstnat; policy accept;\n");
        for ip in &v6 {
            rules.push_str(&format!(
                "    iifname \"{nic}\" ip6 daddr {ip} tcp dport 443 dnat ip6 to {MGMT_FWD_IP6}\n"
            ));
        }
        rules.push_str("  }\n");
        rules.push_str("  chain forward {\n");
        rules.push_str("    type filter hook forward priority filter; policy accept;\n");
        rules.push_str(&format!(
            "    iifname \"{nic}\" oifname \"{FWD_MGMT_VETH}\" tcp dport 443 accept\n"
        ));
        rules.push_str("  }\n");
        rules.push_str("}\n");
    }
    rules
}

fn ui_exposure(state: &DesiredState) -> Vec<(String, Vec<String>)> {
    state
        .ui_exposure
        .iter()
        .filter_map(|name| {
            state
                .interfaces
                .iter()
                .find(|i| i.name == *name && i.role.as_deref() != Some("wan"))
        })
        .map(|i| (i.name.clone(), i.addresses.clone()))
        .collect()
}

fn expose_ips(cidrs: &[String]) -> Vec<String> {
    let mut out = Vec::new();
    for cidr in cidrs {
        let ip = cidr.split('/').next().unwrap_or(cidr);
        if expose_allowed(ip) && !out.iter().any(|e| e == ip) {
            out.push(ip.to_string());
        }
    }
    out
}

// Bootstrap deliberately excludes link-local HTTPS. Keep permanent Desired
// state exposure on its existing policy; it is a separate configuration path.
fn bootstrap_expose_ips(cidrs: &[String]) -> Vec<String> {
    expose_ips(cidrs)
        .into_iter()
        .filter(|ip| match ip.parse::<std::net::IpAddr>() {
            Ok(std::net::IpAddr::V4(address)) => address.is_private(),
            Ok(std::net::IpAddr::V6(address)) => address.octets()[0] & 0xfe == 0xfc,
            Err(_) => false,
        })
        .collect()
}

fn expose_allowed(ip: &str) -> bool {
    if let Ok(v4) = ip.parse::<std::net::Ipv4Addr>() {
        if v4.is_loopback() {
            return false;
        }
        let o = v4.octets();
        if o[0] == CGNAT[0] && (64..=127).contains(&o[1]) {
            return false;
        }
        // Host↔mgmt plumbing is not operator reachability.
        if o[0] == 169 && o[1] == 254 && o[2] == 127 {
            return false;
        }
        return v4.is_private() || v4.is_link_local();
    }
    if let Ok(v6) = ip.parse::<std::net::Ipv6Addr>() {
        if v6.is_loopback() {
            return false;
        }
        return v6.is_unicast_link_local() || (v6.octets()[0] & 0xfe) == 0xfc;
    }
    false
}

fn list_nics_reply() -> String {
    let nics = list_ethernet_json();
    let opt = load_opt();
    json!({"ok": true, "nics": nics, "opt": opt}).to_string()
}

fn list_ethernet_json() -> Vec<Value> {
    let Ok(names) = traffic_nic_names() else {
        return Vec::new();
    };
    let mut nics: Vec<(String, Vec<String>)> =
        names.into_iter().map(|name| (name, Vec::new())).collect();
    if let Ok(addrs) = ip_cmd().args(["-o", "addr", "show"]).output() {
        for line in String::from_utf8_lossy(&addrs.stdout).lines() {
            let name = addr_dev(line);
            let Some((_, addrs)) = nics.iter_mut().find(|(n, _)| n == &name) else {
                continue;
            };
            if let Some(cidr) = addr_cidr(line) {
                if !addrs.contains(&cidr) {
                    addrs.push(cidr);
                }
            }
        }
    }
    nics.into_iter()
        .map(|(name, addresses)| json!({"name": name, "addresses": addresses}))
        .collect()
}

fn addr_cidr(line: &str) -> Option<String> {
    let mut toks = line.split_whitespace();
    while let Some(tok) = toks.next() {
        if tok == "inet" || tok == "inet6" {
            return toks.next().map(str::to_string);
        }
    }
    None
}

fn iface_cidrs(name: &str) -> Result<Vec<String>, String> {
    let out = ip_cmd()
        .args(["-o", "addr", "show", "dev", name])
        .output()
        .map_err(|e| format!("ip addr show {name}: {e}"))?;
    let mut addrs = Vec::new();
    for line in String::from_utf8_lossy(&out.stdout).lines() {
        if let Some(cidr) = addr_cidr(line) {
            if !addrs.contains(&cidr) {
                addrs.push(cidr);
            }
        }
    }
    Ok(addrs)
}

fn capture_ipv4(name: &str) -> Result<(Vec<String>, Option<String>), String> {
    let addr_out = ip_cmd()
        .args(["-o", "addr", "show", "dev", name])
        .output()
        .map_err(|e| format!("ip addr show {name}: {e}"))?;
    let mut addrs = Vec::new();
    for word in String::from_utf8_lossy(&addr_out.stdout).split_whitespace() {
        if word.contains('/') && word.contains('.') {
            addrs.push(word.to_string());
        }
    }
    let route_out = ip_cmd()
        .args(["-o", "route", "show", "default"])
        .output()
        .map_err(|e| format!("ip route: {e}"))?;
    let route = String::from_utf8_lossy(&route_out.stdout);
    let gw = if route.contains(name) {
        route
            .split_whitespace()
            .skip_while(|w| *w != "via")
            .nth(1)
            .map(str::to_string)
    } else {
        None
    };
    Ok((addrs, gw))
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
    use fwos_fwd_setup::desired::{Qdisc, StaticRoute};

    #[test]
    fn network_restoration_is_a_netd_operation_and_requires_bootstrap() {
        let reply: Value = serde_json::from_str(&handle_cmd(&json!({"op": "restore_previous"})))
            .expect("netd response");
        assert_eq!(reply["outcome"], "rejected");
        assert_eq!(
            reply["error"],
            "complete Bootstrap before restoring Desired state"
        );
    }

    #[test]
    fn complete_desired_rejects_off_link_next_hop_before_apply() {
        let mut state = wan_lan();
        state.routes = vec![
            StaticRoute {
                to: "198.51.100.0/24".into(),
                via: "192.0.2.2".into(),
                dev: Some("enp2s0".into()),
            },
            StaticRoute {
                to: "203.0.113.0/24".into(),
                via: "192.0.3.2".into(),
                dev: Some("enp2s0".into()),
            },
        ];
        assert!(validate(&state).unwrap_err().contains("on-link"));
    }

    #[test]
    fn complete_desired_rejects_unsupported_qdisc_before_apply() {
        let mut state = wan_lan();
        state.routes.push(StaticRoute {
            to: "198.51.100.0/24".into(),
            via: "192.0.2.2".into(),
            dev: Some("enp2s0".into()),
        });
        state.qdiscs.push(Qdisc {
            dev: "enp2s0".into(),
            kind: "entirely_bogus".into(),
        });
        assert!(validate(&state).unwrap_err().contains("unsupported qdisc"));
    }

    #[test]
    fn complete_desired_accepts_supported_qdisc_and_on_link_next_hop() {
        let mut state = wan_lan();
        state.routes.push(StaticRoute {
            to: "198.51.100.0/24".into(),
            via: "192.0.2.2".into(),
            dev: Some("enp2s0".into()),
        });
        state.qdiscs.push(Qdisc {
            dev: "enp2s0".into(),
            kind: "fq_codel".into(),
        });
        assert!(validate(&state).is_ok());
    }

    #[test]
    fn complete_desired_requires_interface_for_ipv6_link_local_next_hop() {
        let mut state = wan_lan();
        state.interfaces[1].addresses.push("fe80::1/64".into());
        state.routes.push(StaticRoute {
            to: "2001:db8:100::/64".into(),
            via: "fe80::2".into(),
            dev: None,
        });
        assert!(validate(&state).unwrap_err().contains("interface"));
    }

    #[test]
    fn complete_desired_rejects_next_hop_reachable_only_by_live_dhcp_address() {
        let mut state = wan_lan();
        state.interfaces[1].name = "lo".into();
        state.interfaces[1].addresses.clear();
        state.interfaces[1].dhcp = true;
        state.routes.push(StaticRoute {
            to: "198.51.100.0/24".into(),
            via: "127.0.0.2".into(),
            dev: Some("lo".into()),
        });
        assert!(validate(&state).unwrap_err().contains("configured on-link"));
    }

    #[test]
    fn cmd_json_is_not_empty_desired() {
        let v: Value = serde_json::from_str(r#"{"op":"list"}"#).unwrap();
        assert!(v.get("op").and_then(Value::as_str).is_some());
        let desired = serde_json::from_value::<DesiredState>(v.clone());
        assert!(desired.is_err());
    }

    #[test]
    fn parse_opt_requires_cidr_for_static() {
        let v: Value =
            serde_json::from_str(r#"{"op":"opt","nic":"enp1s0","mode":"static"}"#).unwrap();
        assert!(parse_opt(&v).is_err());
        let v: Value = serde_json::from_str(
            r#"{"op":"opt","nic":"enp1s0","mode":"static","cidr":"10.0.2.15/24"}"#,
        )
        .unwrap();
        let opt = parse_opt(&v).unwrap();
        assert_eq!(opt.nic, "enp1s0");
        assert_eq!(opt.cidr.as_deref(), Some("10.0.2.15/24"));
    }

    #[test]
    fn first_boot_nft_dnats_https_on_the_opted_nic() {
        let rules = first_boot_nft("enp1s0", &["10.0.2.15".into()]);
        assert!(rules.contains("iifname \"enp1s0\""));
        assert!(rules.contains("ip daddr 10.0.2.15 tcp dport 443 dnat ip to 169.254.127.6"));
        assert!(!rules.contains("flush ruleset"));
        let v6 = first_boot_nft("enp1s0", &["fd53:1:1::9".into()]);
        assert!(v6.contains("ip6 daddr fd53:1:1::9 tcp dport 443 dnat ip6 to fd53:1:1::6"));
        assert!(v6.contains("chain forward"));
        assert!(!v6.contains("dnat to fd53"));
    }

    #[test]
    fn expose_allowed_is_private_or_link_local() {
        assert!(expose_allowed("10.0.2.15"));
        assert!(expose_allowed("192.168.1.1"));
        assert!(expose_allowed("169.254.1.1"));
        assert!(!expose_allowed("169.254.127.6"));
        assert!(!expose_allowed("8.8.8.8"));
        assert!(!expose_allowed("100.64.0.1"));
        assert!(!expose_allowed("2001:db8::1"));
        assert!(expose_allowed("fd53:1:1::9"));
        assert!(expose_allowed("fe80::1"));
    }

    fn iface(name: &str, role: &str, addrs: &[&str]) -> Iface {
        Iface {
            name: name.into(),
            placement: String::new(),
            role: Some(role.into()),
            addresses: addrs.iter().map(|s| (*s).to_string()).collect(),
            vlan: None,
            parent: None,
            dhcp: false,
        }
    }

    fn vlan_iface(name: &str, role: &str, parent: &str, vid: u16, addrs: &[&str]) -> Iface {
        Iface {
            name: name.into(),
            placement: String::new(),
            role: Some(role.into()),
            addresses: addrs.iter().map(|s| (*s).to_string()).collect(),
            vlan: Some(vid),
            parent: Some(parent.into()),
            dhcp: false,
        }
    }

    fn wan_lan() -> DesiredState {
        DesiredState {
            interfaces: vec![
                iface("enp1s0", "lan", &["10.0.2.15/24", "192.168.1.1/24"]),
                iface("enp2s0", "wan", &["192.0.2.1/24"]),
            ],
            ui_exposure: vec!["enp1s0".into()],
            lan_prefix: Some("192.168.1.0/24".into()),
            dhcp_pool: Some("192.168.1.100-192.168.1.200".into()),
            ..DesiredState::default()
        }
    }

    #[test]
    fn ui_exposure_is_lan_not_wan() {
        let state = wan_lan();
        let exp = ui_exposure(&state);
        assert_eq!(exp.len(), 1);
        assert_eq!(exp[0].0, "enp1s0");
        assert!(!exp.iter().any(|(n, _)| n == "enp2s0"));
        assert!(validate(&state).is_ok());
    }

    #[test]
    fn reject_placement_mgmt() {
        let mut state = wan_lan();
        state.interfaces[0].placement = "mgmt".into();
        let err = validate(&state).unwrap_err();
        assert!(err.contains("placement=mgmt"), "{err}");
    }

    #[test]
    fn reject_empty_ui_exposure() {
        let mut state = wan_lan();
        state.ui_exposure.clear();
        let err = validate(&state).unwrap_err();
        assert!(err.contains("ui_exposure"), "{err}");
    }

    #[test]
    fn reject_wan_in_ui_exposure() {
        let mut state = wan_lan();
        state.ui_exposure = vec!["enp2s0".into()];
        let err = validate(&state).unwrap_err();
        assert!(err.contains("WAN"), "{err}");
    }

    #[test]
    fn require_wan_and_lan() {
        let mut state = wan_lan();
        state
            .interfaces
            .retain(|i| i.role.as_deref() != Some("lan"));
        let err = validate(&state).unwrap_err();
        assert!(err.to_ascii_lowercase().contains("lan"), "{err}");
        let mut state = wan_lan();
        state
            .interfaces
            .retain(|i| i.role.as_deref() != Some("wan"));
        let err = validate(&state).unwrap_err();
        assert!(err.to_ascii_lowercase().contains("wan"), "{err}");
    }

    #[test]
    fn reject_wan_and_lan_same_parent_and_tag() {
        let state = DesiredState {
            interfaces: vec![
                iface("enp1s0", "wan", &["192.0.2.1/24"]),
                iface("enp1s0", "lan", &["192.168.1.1/24"]),
            ],
            ui_exposure: vec!["enp1s0".into()],
            ..DesiredState::default()
        };
        let err = validate(&state).unwrap_err();
        assert!(err.contains("parent") && err.contains("tag"), "{err}");
    }

    #[test]
    fn reject_wan_and_lan_same_parent_and_vid() {
        let state = DesiredState {
            interfaces: vec![
                vlan_iface("enp1s0.100", "wan", "enp1s0", 100, &["192.0.2.1/24"]),
                vlan_iface("lan100", "lan", "enp1s0", 100, &["192.168.1.1/24"]),
            ],
            ui_exposure: vec!["lan100".into()],
            ..DesiredState::default()
        };
        let err = validate(&state).unwrap_err();
        assert!(err.contains("parent") && err.contains("tag"), "{err}");
    }

    fn assert_one_nic_lan_only(state: &DesiredState, lan: &str, wan: &str) {
        assert!(validate(state).is_ok());
        let exp = ui_exposure(state);
        assert_eq!(exp.len(), 1);
        assert_eq!(exp[0].0, lan);
        assert!(!exp.iter().any(|(n, _)| n == wan));
    }

    #[test]
    fn one_nic_wan_untagged_lan_tagged() {
        let state = DesiredState {
            interfaces: vec![
                iface("enp1s0", "wan", &["192.0.2.1/24"]),
                vlan_iface("enp1s0.42", "lan", "enp1s0", 42, &["192.168.1.1/24"]),
            ],
            ui_exposure: vec!["enp1s0.42".into()],
            lan_prefix: Some("192.168.1.0/24".into()),
            ..DesiredState::default()
        };
        assert_one_nic_lan_only(&state, "enp1s0.42", "enp1s0");
    }

    #[test]
    fn one_nic_wan_tagged_lan_untagged() {
        let state = DesiredState {
            interfaces: vec![
                vlan_iface("enp1s0.100", "wan", "enp1s0", 100, &["192.0.2.1/24"]),
                iface("enp1s0", "lan", &["192.168.1.1/24"]),
            ],
            ui_exposure: vec!["enp1s0".into()],
            lan_prefix: Some("192.168.1.0/24".into()),
            ..DesiredState::default()
        };
        assert_one_nic_lan_only(&state, "enp1s0", "enp1s0.100");
    }

    #[test]
    fn one_nic_both_tagged() {
        let state = DesiredState {
            interfaces: vec![
                iface("enp1s0", "unused", &[]),
                vlan_iface("enp1s0.100", "wan", "enp1s0", 100, &["192.0.2.1/24"]),
                vlan_iface("enp1s0.200", "lan", "enp1s0", 200, &["192.168.1.1/24"]),
            ],
            ui_exposure: vec!["enp1s0.200".into()],
            lan_prefix: Some("192.168.1.0/24".into()),
            ..DesiredState::default()
        };
        assert_one_nic_lan_only(&state, "enp1s0.200", "enp1s0.100");
        assert!(!ui_exposure(&state).iter().any(|(n, _)| n == "enp1s0"));
    }

    #[test]
    fn extra_unused_nics_are_not_wans() {
        let state = DesiredState {
            interfaces: vec![
                iface("enp1s0", "lan", &["192.168.1.1/24"]),
                iface("enp2s0", "wan", &["192.0.2.1/24"]),
                iface("enp3s0", "unused", &[]),
            ],
            ui_exposure: vec!["enp1s0".into()],
            ..DesiredState::default()
        };
        assert!(validate(&state).is_ok());
        let wans: Vec<_> = state
            .interfaces
            .iter()
            .filter(|i| i.role.as_deref() == Some("wan"))
            .map(|i| i.name.as_str())
            .collect();
        assert_eq!(wans, vec!["enp2s0"]);
        let exp = ui_exposure(&state);
        assert!(!exp.iter().any(|(n, _)| n == "enp3s0"));
    }

    #[test]
    fn kea_and_unbound_bind_the_lan_l2_not_dummy() {
        let state = wan_lan();
        let lan = lan_l2(&state).unwrap();
        assert_eq!(lan.name, "enp1s0");
        assert_ne!(lan.name, "lan0");
        let kea4 = kea_dhcp4_conf(
            &lan.name,
            "192.168.1.0/24",
            "192.168.1.100",
            "192.168.1.200",
            "192.168.1.1",
        );
        assert!(kea4.contains("\"interfaces\": [ \"enp1s0\" ]"), "{kea4}");
        assert!(kea4.contains("\"interface\": \"enp1s0\""), "{kea4}");
        assert!(
            kea4.contains("\"service-sockets-require-all\": true"),
            "{kea4}"
        );
        assert!(!kea4.contains("lan0"), "{kea4}");
        let kea6 = kea_dhcp6_conf(&lan.name, "2001:db8::/64", "2001:db8::100", "2001:db8::1ff");
        assert!(kea6.contains("enp1s0"), "{kea6}");
        assert!(
            kea6.contains("\"service-sockets-require-all\": true"),
            "{kea6}"
        );
        assert!(!kea6.contains("lan0"), "{kea6}");
        let unbound = unbound_conf("192.168.1.1", "192.168.1.0/24");
        assert!(unbound.contains("interface: 192.168.1.1"), "{unbound}");
    }

    #[test]
    fn stick_json_with_ui_exposure_on_lan_vlan_is_valid() {
        let state = DesiredState {
            interfaces: vec![
                iface("enp1s0", "stick", &[]),
                vlan_iface("enp1s0.10", "wan", "enp1s0", 10, &["192.0.2.1/24"]),
                vlan_iface("enp1s0.20", "lan", "enp1s0", 20, &["192.168.1.1/24"]),
            ],
            ui_exposure: vec!["enp1s0.20".into()],
            lan_prefix: Some("192.168.1.0/24".into()),
            dhcp_pool: Some("192.168.1.100-192.168.1.200".into()),
            ..DesiredState::default()
        };
        assert!(validate(&state).is_ok());
        let exp = ui_exposure(&state);
        assert_eq!(exp[0].0, "enp1s0.20");
        let kea4 = kea_dhcp4_conf(
            "enp1s0.20",
            "192.168.1.0/24",
            "192.168.1.100",
            "192.168.1.200",
            "192.168.1.1",
        );
        assert!(kea4.contains("enp1s0.20"));
        assert!(!kea4.contains("lan0"));
    }

    fn wan_lan_mgmt() -> DesiredState {
        DesiredState {
            interfaces: vec![
                iface("enp1s0", "lan", &["192.168.1.1/24"]),
                iface("enp2s0", "wan", &["192.0.2.1/24"]),
                iface("enp3s0", "mgmt", &["10.0.2.15/24"]),
            ],
            ui_exposure: vec!["enp3s0".into()],
            lan_prefix: Some("192.168.1.0/24".into()),
            dhcp_pool: Some("192.168.1.100-192.168.1.200".into()),
            ..DesiredState::default()
        }
    }

    #[test]
    fn accept_role_mgmt_oob_only_exposure() {
        let state = wan_lan_mgmt();
        assert!(validate(&state).is_ok(), "{:?}", validate(&state).err());
        let exp = ui_exposure(&state);
        assert_eq!(exp.len(), 1);
        assert_eq!(exp[0].0, "enp3s0");
        assert!(!exp.iter().any(|(n, _)| n == "enp1s0"));
        assert!(!exp.iter().any(|(n, _)| n == "enp2s0"));
    }

    #[test]
    fn accept_role_mgmt_and_lan_in_exposure() {
        let mut state = wan_lan_mgmt();
        state.ui_exposure = vec!["enp3s0".into(), "enp1s0".into()];
        assert!(validate(&state).is_ok(), "{:?}", validate(&state).err());
        let exp = ui_exposure(&state);
        assert!(exp.iter().any(|(n, _)| n == "enp3s0"));
        assert!(exp.iter().any(|(n, _)| n == "enp1s0"));
    }

    #[test]
    fn reject_placement_mgmt_even_with_role_mgmt() {
        let mut state = wan_lan_mgmt();
        state.interfaces[2].placement = "mgmt".into();
        let err = validate(&state).unwrap_err();
        assert!(err.contains("placement=mgmt"), "{err}");
    }

    #[test]
    fn reject_wan_on_mgmt_parent() {
        let state = DesiredState {
            interfaces: vec![
                iface("enp1s0", "lan", &["192.168.1.1/24"]),
                iface("enp3s0", "mgmt", &["10.0.2.15/24"]),
                iface("enp3s0", "wan", &["192.0.2.1/24"]),
            ],
            ui_exposure: vec!["enp3s0".into()],
            ..DesiredState::default()
        };
        let err = validate(&state).unwrap_err();
        assert!(err.to_ascii_lowercase().contains("parent"), "{err}");
    }

    #[test]
    fn reject_lan_vlan_on_mgmt_parent() {
        let state = DesiredState {
            interfaces: vec![
                iface("enp2s0", "wan", &["192.0.2.1/24"]),
                iface("enp3s0", "mgmt", &["10.0.2.15/24"]),
                vlan_iface("enp3s0.20", "lan", "enp3s0", 20, &["192.168.1.1/24"]),
            ],
            ui_exposure: vec!["enp3s0".into()],
            ..DesiredState::default()
        };
        let err = validate(&state).unwrap_err();
        assert!(err.to_ascii_lowercase().contains("parent"), "{err}");
    }

    #[test]
    fn reject_wan_vlan_on_mgmt_parent() {
        let state = DesiredState {
            interfaces: vec![
                iface("enp1s0", "lan", &["192.168.1.1/24"]),
                iface("enp3s0", "mgmt", &["10.0.2.15/24"]),
                vlan_iface("enp3s0.10", "wan", "enp3s0", 10, &["192.0.2.1/24"]),
            ],
            ui_exposure: vec!["enp3s0".into()],
            ..DesiredState::default()
        };
        let err = validate(&state).unwrap_err();
        assert!(err.to_ascii_lowercase().contains("parent"), "{err}");
    }

    #[test]
    fn reject_mgmt_without_on_link_prefix() {
        let mut state = wan_lan_mgmt();
        state.interfaces[2].addresses.clear();
        let err = validate(&state).unwrap_err();
        assert!(
            err.to_ascii_lowercase().contains("static")
                || err.to_ascii_lowercase().contains("prefix")
                || err.to_ascii_lowercase().contains("address"),
            "{err}"
        );
    }

    #[test]
    fn reject_mgmt_dhcp() {
        let mut state = wan_lan_mgmt();
        state.interfaces[2].dhcp = true;
        let err = validate(&state).unwrap_err();
        assert!(
            err.to_ascii_lowercase().contains("dhcp")
                || err.to_ascii_lowercase().contains("static"),
            "{err}"
        );
    }

    #[test]
    fn reject_mgmt_vlan() {
        let state = DesiredState {
            interfaces: vec![
                iface("enp1s0", "lan", &["192.168.1.1/24"]),
                iface("enp2s0", "wan", &["192.0.2.1/24"]),
                vlan_iface("enp3s0.9", "mgmt", "enp3s0", 9, &["10.0.2.15/24"]),
            ],
            ui_exposure: vec!["enp3s0.9".into()],
            ..DesiredState::default()
        };
        let err = validate(&state).unwrap_err();
        assert!(
            err.to_ascii_lowercase().contains("parent")
                || err.to_ascii_lowercase().contains("vlan"),
            "{err}"
        );
    }

    #[test]
    fn reject_mgmt_missing_from_ui_exposure() {
        let mut state = wan_lan_mgmt();
        state.ui_exposure = vec!["enp1s0".into()];
        let err = validate(&state).unwrap_err();
        assert!(
            err.to_ascii_lowercase().contains("ui_exposure")
                || err.to_ascii_lowercase().contains("management"),
            "{err}"
        );
    }

    #[test]
    fn still_require_wan_and_lan_when_mgmt_exists() {
        let mut state = wan_lan_mgmt();
        state
            .interfaces
            .retain(|i| i.role.as_deref() != Some("lan"));
        let err = validate(&state).unwrap_err();
        assert!(err.to_ascii_lowercase().contains("lan"), "{err}");
    }

    #[test]
    fn kea_and_unbound_stay_on_lan_not_mgmt() {
        let state = wan_lan_mgmt();
        let lan = lan_l2(&state).unwrap();
        assert_eq!(lan.name, "enp1s0");
        assert_ne!(lan.name, "enp3s0");
        let kea4 = kea_dhcp4_conf(
            &lan.name,
            "192.168.1.0/24",
            "192.168.1.100",
            "192.168.1.200",
            "192.168.1.1",
        );
        assert!(kea4.contains("\"interfaces\": [ \"enp1s0\" ]"), "{kea4}");
        assert!(!kea4.contains("enp3s0"), "{kea4}");
        let unbound = unbound_conf("192.168.1.1", "192.168.1.0/24");
        assert!(unbound.contains("interface: 192.168.1.1"), "{unbound}");
        assert!(!unbound.contains("10.0.2.15"), "{unbound}");
    }

    #[test]
    fn nft_does_not_forward_mgmt_to_wan_or_lan() {
        let state = wan_lan_mgmt();
        let rules = nft_rules(&state);
        let iif_drop = rules
            .find("iifname \"enp3s0\" drop")
            .expect(&format!("mgmt iif drop missing in {rules}"));
        let oif_drop = rules
            .find("oifname \"enp3s0\" drop")
            .expect(&format!("mgmt oif drop missing in {rules}"));
        let wan_fwd = rules
            .find("oifname \"enp2s0\" accept")
            .expect(&format!("WAN forward missing in {rules}"));
        assert!(
            iif_drop < wan_fwd && oif_drop < wan_fwd,
            "Management NIC drop must precede WAN forward:\n{rules}"
        );
        assert!(
            !rules.contains("iifname \"enp3s0\" oifname \"enp2s0\" accept"),
            "{rules}"
        );
        assert!(
            !rules.contains("iifname \"enp3s0\" oifname \"enp1s0\" accept"),
            "{rules}"
        );
        assert!(
            rules.contains("iifname \"enp3s0\" ip daddr 10.0.2.15 tcp dport 443 dnat"),
            "UI DNAT on the Management NIC:\n{rules}"
        );
        assert!(
            rules.contains("iifname \"enp3s0\" oifname \"f0mgmt\" tcp dport 443 accept"),
            "HTTPS to the UI veth is not LAN/WAN forward:\n{rules}"
        );
    }

    #[test]
    fn host_service_result_requires_the_current_generation() {
        assert!(parse_lan_services_result("old ok\n", "current").is_none());
        assert!(parse_lan_services_result("current ok\n", "current")
            .unwrap()
            .is_ok());
        assert!(
            parse_lan_services_result("current failed:fwos-kea-dhcp4\n", "current")
                .unwrap()
                .is_err()
        );
    }

    #[test]
    fn missing_host_service_result_times_out_without_acceptance() {
        let error = wait_lan_services_at(Path::new("/dev/null"), "current", Duration::ZERO)
            .expect_err("no current-generation acknowledgement");
        assert!(error.contains("timed out"), "{error}");
    }
}

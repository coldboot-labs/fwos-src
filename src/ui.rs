use std::collections::HashMap;
use std::fs;
use std::io::{self, Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV6, TcpListener, TcpStream};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process;
use std::sync::{Arc, Mutex, OnceLock};
use std::thread;
use std::time::{Duration, Instant};

use fwos_fwd_setup::identity::{self, Authentication, AuthenticationResult};

use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::{ServerConfig, ServerConnection, StreamOwned};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

const SOCK: &str = "/var/lib/fwos/netd.sock";
const CERT: &str = "/var/lib/fwos/ui-cert.pem";
const KEY: &str = "/var/lib/fwos/ui-key.pem";
const BOOTSTRAP: &str = "/var/lib/fwos/bootstrapped";
const HOSTNAME_FILE: &str = "/var/lib/fwos/hostname";
const DESIRED: &str = "/var/lib/fwos/desired.toml";
const STATIC_DIR: &str = "/usr/share/fwos-ui";
const SESSION_COOKIE: &str = "__Host-fwos";
const SESSION_LIFETIME: Duration = Duration::from_secs(30 * 60);

struct Session {
    authentication: Authentication,
    expires: Instant,
}

fn sessions() -> &'static Mutex<HashMap<String, Session>> {
    static SESSIONS: OnceLock<Mutex<HashMap<String, Session>>> = OnceLock::new();
    SESSIONS.get_or_init(|| Mutex::new(HashMap::new()))
}
fn main() {
    if let Err(err) = run() {
        eprintln!("fwos-ui: {err}");
        process::exit(1);
    }
}

fn run() -> Result<(), String> {
    rustls::crypto::ring::default_provider()
        .install_default()
        .map_err(|_| "install rustls ring provider".to_string())?;
    ensure_cert()?;
    let cfg = tls_config()?;
    let addrs = wildcard_bind_addrs()?;
    let mut joins = Vec::new();
    for addr in addrs {
        let listener = match bind_one(&addr) {
            Ok(l) => l,
            Err(err) => {
                eprintln!("fwos-ui: bind {addr}: {err}");
                continue;
            }
        };
        let cfg = cfg.clone();
        joins.push(thread::spawn(move || serve(listener, cfg)));
    }
    if joins.is_empty() {
        return Err("no allowed addresses to bind".into());
    }
    match joins.pop().unwrap().join() {
        Ok(()) => Ok(()),
        Err(_) => Err("listener thread panicked".into()),
    }
}

fn tls_config() -> Result<Arc<ServerConfig>, String> {
    let cert_pem = fs::read(CERT).map_err(|e| format!("read {CERT}: {e}"))?;
    let key_pem = fs::read(KEY).map_err(|e| format!("read {KEY}: {e}"))?;
    let certs: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut cert_pem.as_slice())
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| format!("parse {CERT}: {e}"))?;
    let key: PrivateKeyDer<'static> = rustls_pemfile::private_key(&mut key_pem.as_slice())
        .map_err(|e| format!("parse {KEY}: {e}"))?
        .ok_or_else(|| format!("no private key in {KEY}"))?;
    let mut config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|e| format!("tls cert: {e}"))?;
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(Arc::new(config))
}

fn ensure_cert() -> Result<(), String> {
    if Path::new(CERT).exists() && Path::new(KEY).exists() {
        return Ok(());
    }
    if let Some(dir) = Path::new(CERT).parent() {
        fs::create_dir_all(dir).map_err(|e| format!("mkdir {}: {e}", dir.display()))?;
    }
    let pair = rcgen::generate_simple_self_signed(["fwos".to_string()])
        .map_err(|e| format!("generate cert: {e}"))?;
    fs::write(CERT, pair.cert.pem()).map_err(|e| format!("write {CERT}: {e}"))?;
    fs::write(KEY, pair.key_pair.serialize_pem()).map_err(|e| format!("write {KEY}: {e}"))?;
    fs::set_permissions(KEY, fs::Permissions::from_mode(0o600))
        .map_err(|e| format!("chmod {KEY}: {e}"))?;
    Ok(())
}

#[derive(Clone, Debug)]
struct BindAddr {
    ip: IpAddr,
    scope: u32,
}

impl std::fmt::Display for BindAddr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.ip {
            IpAddr::V4(ip) => write!(f, "{ip}:443"),
            IpAddr::V6(ip) if self.scope != 0 => write!(f, "[{ip}%{}]:443", self.scope),
            IpAddr::V6(ip) => write!(f, "[{ip}]:443"),
        }
    }
}

fn wildcard_bind_addrs() -> Result<Vec<BindAddr>, String> {
    // Wildcard listen in mgmt so nft DNAT of HTTPS from fwd lands on the
    // plumbing veth. Operator-facing addresses stay the Traffic NIC's.
    Ok(vec![
        BindAddr {
            ip: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            scope: 0,
        },
        BindAddr {
            ip: IpAddr::V6(Ipv6Addr::UNSPECIFIED),
            scope: 0,
        },
    ])
}

fn bind_one(addr: &BindAddr) -> io::Result<TcpListener> {
    match addr.ip {
        IpAddr::V4(ip) => TcpListener::bind((ip, 443)),
        IpAddr::V6(ip) => {
            TcpListener::bind(SocketAddr::V6(SocketAddrV6::new(ip, 443, 0, addr.scope)))
        }
    }
}

fn serve(listener: TcpListener, cfg: Arc<ServerConfig>) {
    for tcp in listener.incoming() {
        let Ok(tcp) = tcp else { continue };
        let cfg = cfg.clone();
        thread::spawn(move || {
            if let Err(err) = handle_conn(tcp, cfg) {
                eprintln!("fwos-ui: {err}");
            }
        });
    }
}

fn handle_conn(tcp: TcpStream, cfg: Arc<ServerConfig>) -> Result<(), String> {
    let _ = tcp.set_nodelay(true);
    let _ = tcp.set_read_timeout(Some(Duration::from_secs(120)));
    let _ = tcp.set_write_timeout(Some(Duration::from_secs(120)));
    let conn = ServerConnection::new(cfg).map_err(|e| format!("tls conn: {e}"))?;
    let mut tls = StreamOwned::new(conn, tcp);
    let req = read_request(&mut tls)?;
    // Keep concurrent unauthenticated Bootstrap submissions from replacing the
    // first administrator between applying networking and recording ownership.
    static BOOTSTRAP_LOCK: Mutex<()> = Mutex::new(());
    let _bootstrap_guard = (req.method == "POST"
        && req.path.split('?').next() == Some("/api/bootstrap"))
    .then(|| BOOTSTRAP_LOCK.lock().unwrap_or_else(|p| p.into_inner()));
    let resp = dispatch(&req);
    write_response(&mut tls, &resp)?;
    tls.conn.send_close_notify();
    let _ = tls.flush();
    if resp.stamp {
        if let Err(err) = stamp_bootstrap() {
            eprintln!("fwos-ui: stamp: {err}");
        }
    }
    Ok(())
}

struct HttpRequest {
    method: String,
    path: String,
    body: Vec<u8>,
    headers: HashMap<String, String>,
}

struct HttpResponse {
    status: u16,
    ctype: &'static str,
    body: Vec<u8>,
    stamp: bool,
    headers: Vec<(String, String)>,
}

fn read_request(stream: &mut impl Read) -> Result<HttpRequest, String> {
    let mut buf = Vec::new();
    let mut tmp = [0u8; 2048];
    let header_end = loop {
        let n = stream
            .read(&mut tmp)
            .map_err(|e| format!("read request: {e}"))?;
        if n == 0 {
            return Err("client closed during headers".into());
        }
        buf.extend_from_slice(&tmp[..n]);
        if let Some(pos) = find_headers_end(&buf) {
            if pos > 64 * 1024 {
                return Err("headers too large".into());
            }
            break pos;
        }
        if buf.len() > 64 * 1024 {
            return Err("headers too large".into());
        }
    };
    let headers = std::str::from_utf8(&buf[..header_end])
        .map_err(|_| "headers were not UTF-8".to_string())?;
    let mut lines = headers.split("\r\n");
    let req_line = lines.next().unwrap_or("");
    let mut req_parts = req_line.split_whitespace();
    let method = req_parts.next().unwrap_or("").to_string();
    let path = req_parts.next().unwrap_or("/").to_string();
    let mut content_length = 0usize;
    let mut request_headers = HashMap::new();
    for line in lines {
        let (name, value) = line.split_once(':').ok_or("invalid request header")?;
        let name = name.to_ascii_lowercase();
        if request_headers
            .insert(name, value.trim().to_string())
            .is_some()
        {
            return Err("duplicate request header".into());
        }
    }
    if request_headers.contains_key("transfer-encoding") {
        return Err("unsupported transfer encoding".into());
    }
    if let Some(value) = request_headers.get("content-length") {
        content_length = value.parse().map_err(|_| "invalid content length")?;
    }
    if content_length > 1024 * 1024 {
        return Err("body too large".into());
    }
    let mut body = buf[header_end + 4..].to_vec();
    while body.len() < content_length {
        let n = stream
            .read(&mut tmp)
            .map_err(|e| format!("read body: {e}"))?;
        if n == 0 {
            return Err("client closed during body".into());
        }
        body.extend_from_slice(&tmp[..n]);
    }
    body.truncate(content_length);
    Ok(HttpRequest {
        method,
        path,
        body,
        headers: request_headers,
    })
}

fn find_headers_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n")
}

fn write_response(stream: &mut impl Write, response: &HttpResponse) -> Result<(), String> {
    let status = response.status;
    let ctype = response.ctype;
    let body = &response.body;
    let reason = match status {
        200 => "OK",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        409 => "Conflict",
        415 => "Unsupported Media Type",
        429 => "Too Many Requests",
        502 => "Bad Gateway",
        503 => "Service Unavailable",
        _ => "Error",
    };
    let headers = response
        .headers
        .iter()
        .map(|(name, value)| format!("{name}: {value}\r\n"))
        .collect::<String>();
    write!(
        stream,
        "HTTP/1.1 {status} {reason}\r\nContent-Type: {ctype}\r\nContent-Length: {}\r\nConnection: close\r\nCache-Control: no-store\r\nX-Content-Type-Options: nosniff\r\nContent-Security-Policy: default-src 'self'; style-src 'self' 'unsafe-inline'; frame-ancestors 'none'; base-uri 'none'\r\n{headers}\r\n",
        body.len()
    )
    .and_then(|_| stream.write_all(body))
    .and_then(|_| stream.flush())
    .map_err(|e| format!("write response: {e}"))
}

fn dispatch(req: &HttpRequest) -> HttpResponse {
    let path = req.path.split('?').next().unwrap_or("/");
    if req.method == "POST" && path.starts_with("/api/") {
        if !same_origin_json(req) {
            return json_response(
                403,
                json!({"ok": false, "error": "same-origin JSON required"}),
            );
        }
    }
    let authentication = authenticated(req);
    if path.starts_with("/api/")
        && path != "/api/bootstrap"
        && path != "/api/login"
        && (Path::new(BOOTSTRAP).exists() || path == "/api/logout")
        && authentication.is_none()
    {
        return json_response(
            401,
            json!({"ok": false, "bootstrapped": Path::new(BOOTSTRAP).exists(), "error": "sign in required"}),
        );
    }
    match (req.method.as_str(), path) {
        ("GET", "/") | ("GET", "/index.html") => static_response("index.html"),
        ("GET", "/app.js") => static_response("app.js"),
        ("GET", "/api/status") => {
            let mut status = status_json();
            if let Some(authentication) = authentication {
                status["principal"] = json!(authentication.principal);
            }
            json_response(200, status)
        }
        ("POST", "/api/login") => login(req),
        ("POST", "/api/logout") => logout(req),
        ("POST", "/api/bootstrap") => bootstrap(&req.body),
        ("GET", _) if path.starts_with("/api/") => {
            json_response(404, json!({"ok": false, "error": "not found"}))
        }
        ("POST", _) => json_response(404, json!({"ok": false, "error": "not found"})),
        ("GET", _) => HttpResponse {
            status: 404,
            ctype: "text/plain; charset=utf-8",
            body: b"not found".to_vec(),
            stamp: false,
            headers: Vec::new(),
        },
        _ => HttpResponse {
            status: 405,
            ctype: "text/plain; charset=utf-8",
            body: b"method not allowed".to_vec(),
            stamp: false,
            headers: Vec::new(),
        },
    }
}

fn static_response(name: &str) -> HttpResponse {
    match read_static(name) {
        Ok(body) => HttpResponse {
            status: 200,
            ctype: mime(name),
            body,
            stamp: false,
            headers: Vec::new(),
        },
        Err(_) => HttpResponse {
            status: 404,
            ctype: "text/plain; charset=utf-8",
            body: b"not found".to_vec(),
            stamp: false,
            headers: Vec::new(),
        },
    }
}

fn mime(name: &str) -> &'static str {
    if name.ends_with(".js") {
        "application/javascript; charset=utf-8"
    } else {
        "text/html; charset=utf-8"
    }
}

fn read_static(name: &str) -> Result<Vec<u8>, String> {
    if name.contains("..") || name.contains('/') || name.contains('\\') {
        return Err("not found".into());
    }
    let path = PathBuf::from(STATIC_DIR).join(name);
    fs::read(&path).map_err(|e| format!("read {}: {e}", path.display()))
}

fn json_response(status: u16, value: Value) -> HttpResponse {
    HttpResponse {
        status,
        ctype: "application/json; charset=utf-8",
        body: value.to_string().into_bytes(),
        stamp: false,
        headers: Vec::new(),
    }
}

fn same_origin_json(req: &HttpRequest) -> bool {
    let is_json = req
        .headers
        .get("content-type")
        .and_then(|value| value.split(';').next())
        .is_some_and(|value| value.trim().eq_ignore_ascii_case("application/json"));
    let origin_matches = req.headers.get("origin").is_none_or(|origin| {
        req.headers
            .get("host")
            .is_some_and(|host| origin == &format!("https://{host}"))
    });
    is_json
        && origin_matches
        && req
            .headers
            .get("sec-fetch-site")
            .is_none_or(|site| site != "cross-site")
}

fn session_token(req: &HttpRequest) -> Option<&str> {
    let mut matches = req.headers.get("cookie")?.split(';').filter_map(|cookie| {
        let (name, value) = cookie.trim().split_once('=')?;
        (name == SESSION_COOKIE
            && value.len() == 64
            && value.bytes().all(|b| b.is_ascii_hexdigit()))
        .then_some(value)
    });
    let token = matches.next()?;
    matches.next().is_none().then_some(token)
}

fn authenticated(req: &HttpRequest) -> Option<Authentication> {
    let token = session_token(req)?;
    let mut sessions = sessions().lock().unwrap_or_else(|p| p.into_inner());
    let now = Instant::now();
    sessions.retain(|_, session| session.expires > now);
    let authentication = sessions.get(token)?.authentication.clone();
    drop(sessions);
    identity::authorize_administrator(&authentication).then_some(authentication)
}

fn login(req: &HttpRequest) -> HttpResponse {
    #[derive(Deserialize)]
    struct Login {
        source: String,
        username: String,
        password: String,
    }
    let credentials: Login = match serde_json::from_slice(&req.body) {
        Ok(credentials) => credentials,
        Err(_) => {
            return json_response(400, json!({"ok": false, "error": "invalid login request"}))
        }
    };
    // Bound concurrent expensive password checks; never queue an unbounded
    // number of hashing requests from connection threads.
    static LOGIN_LOCK: Mutex<()> = Mutex::new(());
    let Ok(_login_guard) = LOGIN_LOCK.try_lock() else {
        return json_response(
            429,
            json!({"ok": false, "error": "login busy; retry shortly"}),
        );
    };
    let authentication = match identity::authenticate(
        &credentials.source,
        &credentials.username,
        &credentials.password,
    ) {
        AuthenticationResult::Authenticated(authentication)
            if identity::authorize_administrator(&authentication) =>
        {
            authentication
        }
        AuthenticationResult::Challenge(challenge) => {
            return json_response(
                403,
                json!({"ok": false, "challenge": challenge, "error": "additional authentication required"}),
            );
        }
        _ => return json_response(401, json!({"ok": false, "error": "login failed"})),
    };
    let token = match identity::random_token() {
        Ok(token) => token,
        Err(_) => return json_response(503, json!({"ok": false, "error": "login unavailable"})),
    };
    let mut sessions = sessions().lock().unwrap_or_else(|p| p.into_inner());
    let now = Instant::now();
    sessions.retain(|_, session| session.expires > now);
    if let Some(previous) = session_token(req) {
        sessions.remove(previous);
    }
    if sessions.len() >= 1024 {
        return json_response(
            503,
            json!({"ok": false, "error": "session capacity reached"}),
        );
    }
    let mut response = json_response(
        200,
        json!({"ok": true, "principal": authentication.principal}),
    );
    sessions.insert(
        token.clone(),
        Session {
            authentication,
            expires: now + SESSION_LIFETIME,
        },
    );
    response.headers.push((
        "Set-Cookie".into(),
        format!(
            "{SESSION_COOKIE}={token}; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age={}",
            SESSION_LIFETIME.as_secs()
        ),
    ));
    response
}

fn logout(req: &HttpRequest) -> HttpResponse {
    if let Some(token) = session_token(req) {
        sessions()
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .remove(token);
    }
    let mut response = json_response(200, json!({"ok": true}));
    response.headers.push((
        "Set-Cookie".into(),
        format!("{SESSION_COOKIE}=; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age=0"),
    ));
    response
}

#[derive(Deserialize)]
struct Bootstrap {
    hostname: String,
    admin: String,
    password: String,
    #[serde(default)]
    interfaces: Vec<BootIface>,
    #[serde(default)]
    ui_exposure: Vec<String>,
    #[serde(default)]
    lan_prefix: String,
    #[serde(default)]
    dhcp_pool: String,
    #[serde(default)]
    wan_pd: String,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
struct BootIface {
    name: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    placement: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    role: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    addresses: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    vlan: Option<u16>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    parent: Option<String>,
    #[serde(default, skip_serializing_if = "is_false")]
    dhcp: bool,
}

fn is_false(v: &bool) -> bool {
    !*v
}

fn bootstrap(body: &[u8]) -> HttpResponse {
    if Path::new(BOOTSTRAP).exists() {
        return json_response(409, json!({"ok": false, "error": "already bootstrapped"}));
    }
    let req: Bootstrap = match serde_json::from_slice(body) {
        Ok(v) => v,
        Err(err) => {
            return json_response(400, json!({"ok": false, "error": err.to_string()}));
        }
    };
    let hostname = req.hostname.trim();
    let admin = req.admin.trim();
    if !valid_hostname(hostname) {
        return json_response(400, json!({"ok": false, "error": "invalid hostname"}));
    }
    if !valid_admin(admin) {
        return json_response(400, json!({"ok": false, "error": "invalid admin"}));
    }
    if !identity::valid_password(&req.password) {
        return json_response(
            400,
            json!({"ok": false, "error": "password must contain 1–1024 bytes without ASCII control characters"}),
        );
    }
    if req.interfaces.is_empty() {
        return json_response(400, json!({"ok": false, "error": "missing interfaces"}));
    }
    if let Err(err) = validate_bootstrap(&req) {
        return json_response(400, json!({"ok": false, "error": err}));
    }
    if let Err(err) = set_hostname(hostname) {
        return json_response(502, json!({"ok": false, "error": err}));
    }
    if let Err(err) = identity::create_first_administrator(admin, &req.password) {
        return json_response(502, json!({"ok": false, "error": err}));
    }
    let mut desired = json!({
        "hostname": hostname,
        "interfaces": req.interfaces,
        "ui_exposure": req.ui_exposure,
    });
    if !req.lan_prefix.trim().is_empty() {
        desired["lan_prefix"] = json!(req.lan_prefix.trim());
    }
    if !req.dhcp_pool.trim().is_empty() {
        desired["dhcp_pool"] = json!(req.dhcp_pool.trim());
    }
    if !req.wan_pd.trim().is_empty() {
        desired["wan_pd"] = json!(req.wan_pd.trim());
    }
    match netd_apply(&desired) {
        Ok(reply) => {
            let ok = reply.get("ok").and_then(Value::as_bool).unwrap_or(false);
            if ok {
                HttpResponse {
                    status: 200,
                    ctype: "application/json; charset=utf-8",
                    body: json!({"ok": true}).to_string().into_bytes(),
                    stamp: true,
                    headers: Vec::new(),
                }
            } else {
                json_response(502, reply)
            }
        }
        Err(err) => json_response(502, json!({"ok": false, "error": err})),
    }
}

fn validate_bootstrap(req: &Bootstrap) -> Result<(), String> {
    for iface in &req.interfaces {
        if iface.name.trim().is_empty() {
            return Err("missing NIC name".into());
        }
        if iface.placement == "mgmt" {
            return Err("placement=mgmt is not a contract; use roles and ui_exposure".into());
        }
        if !iface.placement.is_empty() && iface.placement != "fwd" {
            return Err("placement is not a contract; use roles and ui_exposure".into());
        }
        if let Some(role) = iface.role.as_deref() {
            if !matches!(role, "wan" | "lan" | "unused" | "stick" | "mgmt") {
                return Err(format!("unknown role {role}"));
            }
        }
        if iface.role.as_deref() == Some("mgmt") {
            if iface.vlan.is_some() || iface.parent.is_some() {
                return Err("Management NIC owns the whole parent".into());
            }
            if iface.dhcp {
                return Err("Management NIC is on-link static; no DHCP".into());
            }
            if iface.addresses.is_empty() {
                return Err("Management NIC needs an on-link static prefix".into());
            }
        }
    }
    let has_wan = req
        .interfaces
        .iter()
        .any(|i| i.role.as_deref() == Some("wan"));
    let has_lan = req
        .interfaces
        .iter()
        .any(|i| i.role.as_deref() == Some("lan"));
    if !has_wan {
        return Err("need at least one WAN".into());
    }
    if !has_lan {
        return Err("need at least one LAN".into());
    }
    for wan in req
        .interfaces
        .iter()
        .filter(|i| i.role.as_deref() == Some("wan"))
    {
        for lan in req
            .interfaces
            .iter()
            .filter(|i| i.role.as_deref() == Some("lan"))
        {
            if boot_l2_key(wan) == boot_l2_key(lan) {
                return Err("WAN and LAN must not share the same parent and tag".into());
            }
        }
    }
    let mgmt_parents: Vec<String> = req
        .interfaces
        .iter()
        .filter(|i| i.role.as_deref() == Some("mgmt"))
        .map(|i| boot_l2_key(i).0)
        .collect();
    for iface in req
        .interfaces
        .iter()
        .filter(|i| matches!(i.role.as_deref(), Some("wan") | Some("lan")))
    {
        if mgmt_parents.iter().any(|p| p == &boot_l2_key(iface).0) {
            return Err("WAN or LAN must not share a parent with a Management NIC".into());
        }
    }
    if req.ui_exposure.is_empty() {
        return Err("ui_exposure must not be empty".into());
    }
    for name in &req.ui_exposure {
        let Some(iface) = req.interfaces.iter().find(|i| i.name == *name) else {
            return Err(format!("ui_exposure {name} is not an interface"));
        };
        if iface.role.as_deref() == Some("wan") {
            return Err("ui_exposure cannot include a WAN".into());
        }
    }
    for iface in req
        .interfaces
        .iter()
        .filter(|i| i.role.as_deref() == Some("mgmt"))
    {
        if !req.ui_exposure.iter().any(|n| n == &iface.name) {
            return Err("Management NIC must be in ui_exposure".into());
        }
    }
    Ok(())
}

fn boot_l2_key(iface: &BootIface) -> (String, Option<u16>) {
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

fn stamp_bootstrap() -> Result<(), String> {
    if let Some(dir) = Path::new(BOOTSTRAP).parent() {
        fs::create_dir_all(dir).map_err(|e| format!("mkdir {}: {e}", dir.display()))?;
    }
    fs::write(BOOTSTRAP, "ok\n").map_err(|e| format!("write {BOOTSTRAP}: {e}"))
}

fn set_hostname(name: &str) -> Result<(), String> {
    if let Some(dir) = Path::new(HOSTNAME_FILE).parent() {
        fs::create_dir_all(dir).map_err(|e| format!("mkdir {}: {e}", dir.display()))?;
    }
    fs::write(HOSTNAME_FILE, format!("{name}\n"))
        .map_err(|e| format!("write {HOSTNAME_FILE}: {e}"))?;
    // The Host hostname program consumes this file. The UI does not need a
    // writable Host /etc mount or privileges for OS account administration.
    Ok(())
}

fn netd_apply(body: &Value) -> Result<Value, String> {
    let raw = serde_json::to_vec(body).map_err(|e| format!("encode desired: {e}"))?;
    let mut stream = UnixStream::connect(SOCK).map_err(|e| format!("connect {SOCK}: {e}"))?;
    let _ = stream.set_read_timeout(Some(Duration::from_secs(60)));
    let _ = stream.set_write_timeout(Some(Duration::from_secs(60)));
    stream
        .write_all(&raw)
        .map_err(|e| format!("write socket: {e}"))?;
    stream
        .shutdown(std::net::Shutdown::Write)
        .map_err(|e| format!("shutdown socket: {e}"))?;
    let mut reply = Vec::new();
    stream
        .read_to_end(&mut reply)
        .map_err(|e| format!("read socket: {e}"))?;
    serde_json::from_slice(&reply).or_else(|_| {
        Ok(json!({
            "ok": false,
            "error": String::from_utf8_lossy(&reply),
        }))
    })
}

fn status_json() -> Value {
    let bootstrapped = Path::new(BOOTSTRAP).exists();
    let hostname = fs::read_to_string(HOSTNAME_FILE)
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());
    let nics = list_nics();
    let mut out = json!({
        "bootstrapped": bootstrapped,
        "hostname": hostname,
        "nics": nics,
        "interfaces": [],
        "ui_exposure": [],
        "lan_prefix": Value::Null,
        "dhcp_pool": Value::Null,
        "wan_pd": Value::Null,
    });
    if let Ok(raw) = fs::read_to_string(DESIRED) {
        if let Ok(v) = raw.parse::<toml::Value>() {
            if let Some(hn) = v.get("hostname").and_then(|x| x.as_str()) {
                if hostname.is_none() {
                    out["hostname"] = json!(hn);
                }
            }
            if let Some(p) = v.get("lan_prefix").and_then(|x| x.as_str()) {
                out["lan_prefix"] = json!(p);
            }
            if let Some(p) = v.get("dhcp_pool").and_then(|x| x.as_str()) {
                out["dhcp_pool"] = json!(p);
            }
            if let Some(p) = v.get("wan_pd").and_then(|x| x.as_str()) {
                out["wan_pd"] = json!(p);
            }
            if let Some(exp) = v.get("ui_exposure") {
                if let Ok(j) = serde_json::to_value(exp) {
                    out["ui_exposure"] = j;
                }
            }
            if let Some(ifaces) = v.get("interfaces").and_then(|x| x.as_array()) {
                let mut shown = Vec::new();
                for iface in ifaces {
                    let mut one = serde_json::Map::new();
                    for key in ["name", "role", "vlan", "parent"] {
                        if let Some(val) = iface.get(key) {
                            if let Ok(j) = serde_json::to_value(val) {
                                one.insert(key.to_string(), j);
                            }
                        }
                    }
                    if let Some(addrs) = iface.get("addresses") {
                        if let Ok(j) = serde_json::to_value(addrs) {
                            one.insert("addresses".into(), j);
                        }
                    }
                    if iface.get("dhcp").and_then(|d| d.as_bool()) == Some(true) {
                        one.insert("dhcp".into(), json!(true));
                    }
                    shown.push(Value::Object(one));
                }
                out["interfaces"] = Value::Array(shown);
            }
        }
    }
    out
}

fn list_nics() -> Vec<Value> {
    let Ok(reply) = netd_cmd(&json!({"op": "list"})) else {
        return Vec::new();
    };
    reply
        .get("nics")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default()
}

fn netd_cmd(body: &Value) -> Result<Value, String> {
    let raw = serde_json::to_vec(body).map_err(|e| format!("encode netd cmd: {e}"))?;
    let mut stream = UnixStream::connect(SOCK).map_err(|e| format!("connect {SOCK}: {e}"))?;
    let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
    let _ = stream.set_write_timeout(Some(Duration::from_secs(5)));
    stream
        .write_all(&raw)
        .map_err(|e| format!("write socket: {e}"))?;
    stream
        .shutdown(std::net::Shutdown::Write)
        .map_err(|e| format!("shutdown socket: {e}"))?;
    let mut reply = Vec::new();
    stream
        .read_to_end(&mut reply)
        .map_err(|e| format!("read socket: {e}"))?;
    serde_json::from_slice(&reply).map_err(|e| format!("parse netd reply: {e}"))
}

fn valid_hostname(name: &str) -> bool {
    let mut chars = name.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    first.is_ascii_alphanumeric()
        && name.len() <= 253
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '.')
        && !name.starts_with('-')
        && !name.ends_with('-')
}

fn valid_admin(name: &str) -> bool {
    identity::valid_username(name)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ui_listens_wildcard_so_dnat_lands() {
        let addrs = wildcard_bind_addrs().unwrap();
        assert!(addrs
            .iter()
            .any(|a| a.ip == IpAddr::V4(Ipv4Addr::UNSPECIFIED)));
        assert!(addrs
            .iter()
            .any(|a| a.ip == IpAddr::V6(Ipv6Addr::UNSPECIFIED)));
    }

    fn parse_boot(raw: &str) -> Bootstrap {
        serde_json::from_str(raw).unwrap()
    }

    #[test]
    fn bootstrap_accepts_wan_lan_ui_exposure() {
        let req = parse_boot(
            r#"{"hostname":"fwos-box","admin":"alice","password":"secret12","interfaces":[{"name":"enp1s0","role":"lan","addresses":["192.168.1.1/24"]},{"name":"enp2s0","role":"wan","addresses":["192.0.2.1/24"]}],"ui_exposure":["enp1s0"],"lan_prefix":"192.168.1.0/24"}"#,
        );
        assert!(validate_bootstrap(&req).is_ok());
    }

    #[test]
    fn bootstrap_rejects_placement_mgmt() {
        let req = parse_boot(
            r#"{"hostname":"fwos-box","admin":"alice","password":"secret12","interfaces":[{"name":"enp1s0","placement":"mgmt"},{"name":"enp2s0","role":"wan","addresses":["192.0.2.1/24"]}],"lan_prefix":"192.168.1.0/24"}"#,
        );
        let err = validate_bootstrap(&req).unwrap_err();
        assert!(err.contains("placement=mgmt"), "{err}");
    }

    #[test]
    fn bootstrap_rejects_wan_in_exposure_and_empty_set() {
        let req = parse_boot(
            r#"{"hostname":"fwos-box","admin":"alice","password":"secret12","interfaces":[{"name":"enp1s0","role":"lan"},{"name":"enp2s0","role":"wan"}],"ui_exposure":["enp2s0"]}"#,
        );
        let err = validate_bootstrap(&req).unwrap_err();
        assert!(err.contains("WAN"), "{err}");
        let req = parse_boot(
            r#"{"hostname":"fwos-box","admin":"alice","password":"secret12","interfaces":[{"name":"enp1s0","role":"lan"},{"name":"enp2s0","role":"wan"}]}"#,
        );
        let err = validate_bootstrap(&req).unwrap_err();
        assert!(err.contains("ui_exposure"), "{err}");
    }

    #[test]
    fn bootstrap_rejects_wan_lan_same_parent_tag() {
        let req = parse_boot(
            r#"{"hostname":"fwos-box","admin":"alice","password":"secret12","interfaces":[{"name":"enp1s0","role":"wan"},{"name":"enp1s0","role":"lan"}],"ui_exposure":["enp1s0"]}"#,
        );
        let err = validate_bootstrap(&req).unwrap_err();
        assert!(err.contains("parent") && err.contains("tag"), "{err}");
    }

    #[test]
    fn bootstrap_rejects_wan_lan_same_parent_vid() {
        let req = parse_boot(
            r#"{"hostname":"fwos-box","admin":"alice","password":"secret12","interfaces":[{"name":"enp1s0.100","role":"wan","parent":"enp1s0","vlan":100},{"name":"lan100","role":"lan","parent":"enp1s0","vlan":100}],"ui_exposure":["lan100"]}"#,
        );
        let err = validate_bootstrap(&req).unwrap_err();
        assert!(err.contains("parent") && err.contains("tag"), "{err}");
    }

    #[test]
    fn bootstrap_one_nic_wan_untagged_lan_tagged() {
        let req = parse_boot(
            r#"{"hostname":"fwos-box","admin":"alice","password":"secret12","interfaces":[{"name":"enp1s0","role":"wan","addresses":["192.0.2.1/24"]},{"name":"enp1s0.42","role":"lan","parent":"enp1s0","vlan":42,"addresses":["192.168.1.1/24"]}],"ui_exposure":["enp1s0.42"],"lan_prefix":"192.168.1.0/24"}"#,
        );
        assert!(validate_bootstrap(&req).is_ok());
    }

    #[test]
    fn bootstrap_one_nic_wan_tagged_lan_untagged() {
        let req = parse_boot(
            r#"{"hostname":"fwos-box","admin":"alice","password":"secret12","interfaces":[{"name":"enp1s0.100","role":"wan","parent":"enp1s0","vlan":100,"addresses":["192.0.2.1/24"]},{"name":"enp1s0","role":"lan","addresses":["192.168.1.1/24"]}],"ui_exposure":["enp1s0"],"lan_prefix":"192.168.1.0/24"}"#,
        );
        assert!(validate_bootstrap(&req).is_ok());
    }

    #[test]
    fn bootstrap_one_nic_both_tagged() {
        let req = parse_boot(
            r#"{"hostname":"fwos-box","admin":"alice","password":"secret12","interfaces":[{"name":"enp1s0","role":"unused"},{"name":"enp1s0.100","role":"wan","parent":"enp1s0","vlan":100,"addresses":["192.0.2.1/24"]},{"name":"enp1s0.200","role":"lan","parent":"enp1s0","vlan":200,"addresses":["192.168.1.1/24"]}],"ui_exposure":["enp1s0.200"],"lan_prefix":"192.168.1.0/24"}"#,
        );
        assert!(validate_bootstrap(&req).is_ok());
    }

    #[test]
    fn bootstrap_one_nic_rejects_wan_in_exposure() {
        let req = parse_boot(
            r#"{"hostname":"fwos-box","admin":"alice","password":"secret12","interfaces":[{"name":"enp1s0","role":"wan","addresses":["192.0.2.1/24"]},{"name":"enp1s0.42","role":"lan","parent":"enp1s0","vlan":42}],"ui_exposure":["enp1s0"]}"#,
        );
        let err = validate_bootstrap(&req).unwrap_err();
        assert!(err.contains("WAN"), "{err}");
    }

    #[test]
    fn bootstrap_accepts_role_mgmt_oob_only() {
        let req = parse_boot(
            r#"{"hostname":"fwos-box","admin":"alice","password":"secret12","interfaces":[{"name":"enp1s0","role":"lan","addresses":["192.168.1.1/24"]},{"name":"enp2s0","role":"wan","addresses":["192.0.2.1/24"]},{"name":"enp3s0","role":"mgmt","addresses":["10.0.2.15/24"]}],"ui_exposure":["enp3s0"],"lan_prefix":"192.168.1.0/24"}"#,
        );
        assert!(
            validate_bootstrap(&req).is_ok(),
            "{:?}",
            validate_bootstrap(&req).err()
        );
    }

    #[test]
    fn bootstrap_accepts_mgmt_and_optional_lan_exposure() {
        let req = parse_boot(
            r#"{"hostname":"fwos-box","admin":"alice","password":"secret12","interfaces":[{"name":"enp1s0","role":"lan"},{"name":"enp2s0","role":"wan"},{"name":"enp3s0","role":"mgmt","addresses":["10.0.2.15/24"]}],"ui_exposure":["enp3s0","enp1s0"]}"#,
        );
        assert!(
            validate_bootstrap(&req).is_ok(),
            "{:?}",
            validate_bootstrap(&req).err()
        );
    }

    #[test]
    fn bootstrap_rejects_wan_on_mgmt_parent() {
        let req = parse_boot(
            r#"{"hostname":"fwos-box","admin":"alice","password":"secret12","interfaces":[{"name":"enp1s0","role":"lan"},{"name":"enp3s0","role":"mgmt","addresses":["10.0.2.15/24"]},{"name":"enp3s0","role":"wan","addresses":["192.0.2.1/24"]}],"ui_exposure":["enp3s0"]}"#,
        );
        let err = validate_bootstrap(&req).unwrap_err();
        assert!(err.to_ascii_lowercase().contains("parent"), "{err}");
    }

    #[test]
    fn bootstrap_rejects_lan_vlan_on_mgmt_parent() {
        let req = parse_boot(
            r#"{"hostname":"fwos-box","admin":"alice","password":"secret12","interfaces":[{"name":"enp2s0","role":"wan"},{"name":"enp3s0","role":"mgmt","addresses":["10.0.2.15/24"]},{"name":"enp3s0.20","role":"lan","parent":"enp3s0","vlan":20}],"ui_exposure":["enp3s0"]}"#,
        );
        let err = validate_bootstrap(&req).unwrap_err();
        assert!(err.to_ascii_lowercase().contains("parent"), "{err}");
    }

    #[test]
    fn bootstrap_rejects_mgmt_without_prefix() {
        let req = parse_boot(
            r#"{"hostname":"fwos-box","admin":"alice","password":"secret12","interfaces":[{"name":"enp1s0","role":"lan"},{"name":"enp2s0","role":"wan"},{"name":"enp3s0","role":"mgmt"}],"ui_exposure":["enp3s0"]}"#,
        );
        let err = validate_bootstrap(&req).unwrap_err();
        assert!(
            err.to_ascii_lowercase().contains("static")
                || err.to_ascii_lowercase().contains("prefix")
                || err.to_ascii_lowercase().contains("address"),
            "{err}"
        );
    }

    #[test]
    fn bootstrap_rejects_mgmt_missing_from_exposure() {
        let req = parse_boot(
            r#"{"hostname":"fwos-box","admin":"alice","password":"secret12","interfaces":[{"name":"enp1s0","role":"lan"},{"name":"enp2s0","role":"wan"},{"name":"enp3s0","role":"mgmt","addresses":["10.0.2.15/24"]}],"ui_exposure":["enp1s0"]}"#,
        );
        let err = validate_bootstrap(&req).unwrap_err();
        assert!(
            err.to_ascii_lowercase().contains("ui_exposure")
                || err.to_ascii_lowercase().contains("management"),
            "{err}"
        );
    }

    #[test]
    fn ui_has_no_host_update_route() {
        let req = HttpRequest {
            method: "POST".into(),
            path: "/api/update".into(),
            body: b"{\"image\":\"10.0.2.2:5000/fwos:next\"}".to_vec(),
            headers: HashMap::from([("content-type".into(), "application/json".into())]),
        };
        let resp = dispatch(&req);
        assert_eq!(resp.status, 404);
        let body = String::from_utf8_lossy(&resp.body);
        assert!(!body.contains("update.sock"));
        assert!(!body.contains("bootc"));
    }
}

use std::fs;
use std::io::{self, Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV6, TcpListener, TcpStream};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{self, Command, Stdio};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

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
const CGNAT: Ipv4Addr = Ipv4Addr::new(100, 64, 0, 0);

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
    let addrs = wait_bind_addrs()?;
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

fn wait_bind_addrs() -> Result<Vec<BindAddr>, String> {
    for _ in 0..300 {
        let addrs = host_bind_addrs()?;
        if !addrs.is_empty() {
            return Ok(addrs);
        }
        thread::sleep(Duration::from_millis(200));
    }
    Err("no allowed addresses to bind".into())
}

fn host_bind_addrs() -> Result<Vec<BindAddr>, String> {
    let out = ip_output(&["-o", "addr", "show"])?;
    let mut found = Vec::new();
    for line in out.lines() {
        let mut parts = line.split_whitespace();
        let Some(_idx) = parts.next() else { continue };
        let Some(ifname) = parts.next() else { continue };
        let ifname = ifname.split('@').next().unwrap_or(ifname);
        let Some(fam) = parts.next() else { continue };
        let Some(cidr) = parts.next() else { continue };
        let ip_s = cidr.split('/').next().unwrap_or(cidr);
        let Ok(ip) = ip_s.parse::<IpAddr>() else {
            continue;
        };
        if !bind_allowed(ip) {
            continue;
        }
        let mut scope = 0;
        if fam == "inet6" {
            if let IpAddr::V6(v6) = ip {
                if v6.is_unicast_link_local() {
                    match if_index(ifname) {
                        Some(idx) => scope = idx,
                        None => continue,
                    }
                }
            }
        }
        let addr = BindAddr { ip, scope };
        if !found
            .iter()
            .any(|a: &BindAddr| a.ip == addr.ip && a.scope == addr.scope)
        {
            found.push(addr);
        }
    }
    Ok(found)
}

fn bind_allowed(ip: IpAddr) -> bool {
    match ip {
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

fn if_index(name: &str) -> Option<u32> {
    let c = std::ffi::CString::new(name).ok()?;
    let idx = unsafe { libc::if_nametoindex(c.as_ptr()) };
    if idx == 0 {
        None
    } else {
        Some(idx)
    }
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
    let resp = dispatch(&req);
    write_response(&mut tls, resp.status, resp.ctype, &resp.body)?;
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
}

struct HttpResponse {
    status: u16,
    ctype: &'static str,
    body: Vec<u8>,
    stamp: bool,
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
    for line in lines {
        let lower = line.to_ascii_lowercase();
        if let Some(v) = lower.strip_prefix("content-length:") {
            content_length = v.trim().parse().unwrap_or(0);
        }
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
            break;
        }
        body.extend_from_slice(&tmp[..n]);
    }
    body.truncate(content_length);
    Ok(HttpRequest { method, path, body })
}

fn find_headers_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n")
}

fn write_response(
    stream: &mut impl Write,
    status: u16,
    ctype: &str,
    body: &[u8],
) -> Result<(), String> {
    let reason = match status {
        200 => "OK",
        400 => "Bad Request",
        404 => "Not Found",
        405 => "Method Not Allowed",
        409 => "Conflict",
        502 => "Bad Gateway",
        _ => "Error",
    };
    write!(
        stream,
        "HTTP/1.1 {status} {reason}\r\nContent-Type: {ctype}\r\nContent-Length: {}\r\nConnection: close\r\nCache-Control: no-store\r\n\r\n",
        body.len()
    )
    .and_then(|_| stream.write_all(body))
    .and_then(|_| stream.flush())
    .map_err(|e| format!("write response: {e}"))
}

fn dispatch(req: &HttpRequest) -> HttpResponse {
    let path = req.path.split('?').next().unwrap_or("/");
    match (req.method.as_str(), path) {
        ("GET", "/") | ("GET", "/index.html") => static_response("index.html"),
        ("GET", "/app.js") => static_response("app.js"),
        ("GET", "/api/status") => json_response(200, status_json()),
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
        },
        _ => HttpResponse {
            status: 405,
            ctype: "text/plain; charset=utf-8",
            body: b"method not allowed".to_vec(),
            stamp: false,
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
        },
        Err(_) => HttpResponse {
            status: 404,
            ctype: "text/plain; charset=utf-8",
            body: b"not found".to_vec(),
            stamp: false,
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
    }
}

#[derive(Debug, Deserialize)]
struct Bootstrap {
    hostname: String,
    admin: String,
    password: String,
    #[serde(default)]
    interfaces: Vec<BootIface>,
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
    if req.password.is_empty() {
        return json_response(400, json!({"ok": false, "error": "missing password"}));
    }
    if req.interfaces.is_empty() {
        return json_response(400, json!({"ok": false, "error": "missing interfaces"}));
    }
    for iface in &req.interfaces {
        if iface.name.trim().is_empty() {
            return json_response(400, json!({"ok": false, "error": "missing NIC name"}));
        }
        if iface.placement != "fwd" && iface.placement != "mgmt" {
            return json_response(
                400,
                json!({"ok": false, "error": "placement must be fwd or mgmt"}),
            );
        }
    }
    let has_mgmt = req.interfaces.iter().any(|i| i.placement == "mgmt");
    let has_stick = req
        .interfaces
        .iter()
        .any(|i| i.role.as_deref() == Some("stick"));
    let has_wan = req
        .interfaces
        .iter()
        .any(|i| i.role.as_deref() == Some("wan"));
    if !has_mgmt && !has_stick {
        return json_response(
            400,
            json!({"ok": false, "error": "need a mgmt NIC or stick exception"}),
        );
    }
    if !has_wan && !has_stick {
        return json_response(400, json!({"ok": false, "error": "need a WAN NIC"}));
    }
    if let Err(err) = set_hostname(hostname) {
        return json_response(502, json!({"ok": false, "error": err}));
    }
    if let Err(err) = create_admin(admin, &req.password) {
        return json_response(502, json!({"ok": false, "error": err}));
    }
    let mut desired = json!({
        "hostname": hostname,
        "interfaces": req.interfaces,
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
                }
            } else {
                json_response(502, reply)
            }
        }
        Err(err) => json_response(502, json!({"ok": false, "error": err})),
    }
}

fn stamp_bootstrap() -> Result<(), String> {
    if let Some(dir) = Path::new(BOOTSTRAP).parent() {
        fs::create_dir_all(dir).map_err(|e| format!("mkdir {}: {e}", dir.display()))?;
    }
    fs::write(BOOTSTRAP, "ok\n").map_err(|e| format!("write {BOOTSTRAP}: {e}"))
}

fn set_hostname(name: &str) -> Result<(), String> {
    fs::write("/etc/hostname", format!("{name}\n"))
        .map_err(|e| format!("write /etc/hostname: {e}"))?;
    if let Some(dir) = Path::new(HOSTNAME_FILE).parent() {
        fs::create_dir_all(dir).map_err(|e| format!("mkdir {}: {e}", dir.display()))?;
    }
    fs::write(HOSTNAME_FILE, format!("{name}\n"))
        .map_err(|e| format!("write {HOSTNAME_FILE}: {e}"))?;
    // The UI addon has no CAP_SYS_ADMIN; sethostname(2) fails here. Writing
    // /var/lib/fwos/hostname is the product path (fwos-hostname.service).
    let _ = Command::new("hostname")
        .arg(name)
        .env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin")
        .status();
    Ok(())
}

fn create_admin(name: &str, password: &str) -> Result<(), String> {
    let add = Command::new("useradd")
        .args(["-m", "-G", "wheel", name])
        .env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin")
        .output()
        .map_err(|e| format!("useradd: {e}"))?;
    if !add.status.success() {
        let err = String::from_utf8_lossy(&add.stderr);
        if !err.contains("already exists") {
            return Err(format!("useradd {name}: {}", err.trim()));
        }
    }
    let mut child = Command::new("chpasswd")
        .env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin")
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("chpasswd: {e}"))?;
    child
        .stdin
        .as_mut()
        .ok_or_else(|| "chpasswd stdin".to_string())?
        .write_all(format!("{name}:{password}\n").as_bytes())
        .map_err(|e| format!("chpasswd write: {e}"))?;
    let out = child
        .wait_with_output()
        .map_err(|e| format!("chpasswd wait: {e}"))?;
    if out.status.success() {
        Ok(())
    } else {
        Err(format!(
            "chpasswd failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        ))
    }
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
            if let Some(ifaces) = v.get("interfaces").and_then(|x| x.as_array()) {
                let mut shown = Vec::new();
                for iface in ifaces {
                    let mut one = serde_json::Map::new();
                    for key in ["name", "placement", "role", "vlan", "parent"] {
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
    let Ok(links) = ip_output(&["-o", "link", "show"]) else {
        return Vec::new();
    };
    let mut nics: Vec<(String, Vec<String>)> = Vec::new();
    for line in links.lines() {
        let name = link_name(line);
        if !is_ethernet(&name) {
            continue;
        }
        nics.push((name, Vec::new()));
    }
    if let Ok(addrs) = ip_output(&["-o", "addr", "show"]) {
        for line in addrs.lines() {
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

fn addr_cidr(line: &str) -> Option<String> {
    let mut toks = line.split_whitespace();
    while let Some(tok) = toks.next() {
        if tok == "inet" || tok == "inet6" {
            return toks.next().map(str::to_string);
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
    let mut chars = name.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    (first.is_ascii_lowercase() || first == '_')
        && name.len() <= 32
        && name != "root"
        && chars.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_' || c == '-')
}

fn ip_output(args: &[&str]) -> Result<String, String> {
    let output = Command::new("ip")
        .args(args)
        .env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin")
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ui_has_no_host_update_route() {
        let req = HttpRequest {
            method: "POST".into(),
            path: "/api/update".into(),
            body: b"{\"image\":\"10.0.2.2:5000/fwos:next\"}".to_vec(),
        };
        let resp = dispatch(&req);
        assert_eq!(resp.status, 404);
        let body = String::from_utf8_lossy(&resp.body);
        assert!(!body.contains("update.sock"));
        assert!(!body.contains("bootc"));
    }
}

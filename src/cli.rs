mod console;

use std::env;
use std::fs;
use std::io::{self, Read, Write};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::process;
use std::time::Duration;

const SOCK: &str = "/var/lib/fwos/netd.sock";
const UPDATE_SOCK: &str = "/var/lib/fwos/update.sock";
const DESIRED: &str = "/var/lib/fwos/desired.toml";
const UPDATE_TIMEOUT: Duration = Duration::from_secs(1200);

fn main() {
    if let Err(err) = run() {
        eprintln!("fwos: {err}");
        process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let mut args = env::args().skip(1);
    let cmd = match args.next() {
        None => return console::run(),
        Some(cmd) => cmd,
    };
    match cmd.as_str() {
        "console" => console::run(),
        "apply" => {
            let raw = match args.next().as_deref() {
                None | Some("-") => {
                    let mut buf = String::new();
                    io::stdin()
                        .read_to_string(&mut buf)
                        .map_err(|e| format!("read stdin: {e}"))?;
                    buf
                }
                Some(path) => fs::read_to_string(path).map_err(|e| format!("read {path}: {e}"))?,
            };
            print!("{}", apply_desired(&raw)?);
            Ok(())
        }
        "update" => {
            let image = args.next().unwrap_or_default();
            print!("{}", update_client(&image)?);
            Ok(())
        }
        _ => Err(format!("unknown command {cmd}; usage: fwos apply [file]")),
    }
}

fn apply_desired(raw: &str) -> Result<String, String> {
    let json = to_json(raw)?;
    socket_roundtrip(SOCK, json.as_bytes())
}

fn show_desired() -> Result<String, String> {
    fs::read_to_string(DESIRED).map_err(|e| format!("read {DESIRED}: {e}"))
}

fn update_client(image: &str) -> Result<String, String> {
    if image.is_empty() {
        return Err("usage: update <image>".into());
    }
    let body = serde_json::json!({"op": "stage", "image": image}).to_string();
    socket_roundtrip_for(UPDATE_SOCK, body.as_bytes(), UPDATE_TIMEOUT)
}

fn apply_source(rest: &str) -> Result<String, String> {
    if rest.starts_with('/') || Path::new(rest).is_file() {
        fs::read_to_string(rest).map_err(|e| format!("read {rest}: {e}"))
    } else {
        Ok(rest.to_string())
    }
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

fn to_json(raw: &str) -> Result<String, String> {
    let trimmed = raw.trim_start();
    if trimmed.starts_with('{') {
        return Ok(raw.to_string());
    }
    let value: toml::Value =
        toml::from_str(raw).map_err(|e| format!("parse TOML Desired state: {e}"))?;
    serde_json::to_string(&value).map_err(|e| format!("encode JSON: {e}"))
}

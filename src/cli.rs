use std::env;
use std::fs;
use std::io::{self, Read, Write};
use std::os::unix::net::UnixStream;
use std::process;

const SOCK: &str = "/var/lib/fwos/netd.sock";

fn main() {
    if let Err(err) = run() {
        eprintln!("fwos: {err}");
        process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let mut args = env::args().skip(1);
    let cmd = args
        .next()
        .ok_or_else(|| "usage: fwos apply [file]".to_string())?;
    if cmd != "apply" {
        return Err(format!("unknown command {cmd}; usage: fwos apply [file]"));
    }
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
    let json = to_json(&raw)?;
    let mut stream = UnixStream::connect(SOCK).map_err(|e| format!("connect {SOCK}: {e}"))?;
    stream
        .write_all(json.as_bytes())
        .map_err(|e| format!("write socket: {e}"))?;
    stream
        .shutdown(std::net::Shutdown::Write)
        .map_err(|e| format!("shutdown socket: {e}"))?;
    let mut reply = String::new();
    stream
        .read_to_string(&mut reply)
        .map_err(|e| format!("read socket: {e}"))?;
    print!("{reply}");
    Ok(())
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

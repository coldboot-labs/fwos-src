//! DNS resolvers the Forwarding netns learned from its WANs.
//!
//! netd is the only writer of [`PATH`]. It merges the resolvers that WAN
//! DHCPv6 leases name (one `<wan>.`[`LEASE_EXTENSION`] file per lease,
//! written by its DHCPv6 client script) with the RDNSS resolvers WAN Router
//! Advertisements name. The Host update worker resolves registry names with
//! them while it uses `fwd` networking; the Host netns has no resolver of its own.
use std::net::{IpAddr, Ipv6Addr};
use std::path::Path;

use crate::durable;

pub const PATH: &str = "/var/lib/fwos/fwd-resolv.conf";

/// Extension of the per-WAN file of `nameserver` lines from a DHCPv6 lease.
pub const LEASE_EXTENSION: &str = "dns";

/// The lease file of `wan` in `dir`.
pub fn lease_file(dir: &Path, wan: &str) -> std::path::PathBuf {
    dir.join(format!("{wan}.{LEASE_EXTENSION}"))
}

/// glibc reads at most three `nameserver` lines.
const MAX_NAMESERVERS: usize = 3;

/// A resolv.conf body holding only the distinct, well-formed `nameserver`
/// lines of `learned`. Without one, lookups fail rather than falling back to
/// a Host netns resolver.
pub fn resolv_conf(learned: &str) -> String {
    let mut servers: Vec<String> = Vec::new();
    for line in learned.lines() {
        let mut words = line.split_whitespace();
        if words.next() != Some("nameserver") {
            continue;
        }
        let Some(server) = words.next().and_then(nameserver) else {
            continue;
        };
        if words.next().is_none() && !servers.contains(&server) {
            servers.push(server);
        }
    }
    if servers.is_empty() {
        return "# No WAN resolver learned in the Forwarding netns\n".into();
    }
    servers
        .iter()
        .take(MAX_NAMESERVERS)
        .map(|server| format!("nameserver {server}\n"))
        .collect()
}

/// An address, or a link-local IPv6 address scoped to its interface.
fn nameserver(word: &str) -> Option<String> {
    match word.parse::<IpAddr>() {
        // A link-local resolver is unusable without its interface.
        Ok(IpAddr::V6(address)) if address.is_unicast_link_local() => return None,
        Ok(_) => return Some(word.to_string()),
        Err(_) => {}
    }
    let (address, scope) = word.split_once('%')?;
    let scoped = address.parse::<Ipv6Addr>().ok()?.is_unicast_link_local()
        && !scope.is_empty()
        && scope
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'));
    scoped.then(|| word.to_string())
}

/// Whether a resolv.conf body names at least one resolver.
pub fn has_resolver(conf: &str) -> bool {
    conf.lines().any(|line| line.starts_with("nameserver "))
}

/// Replace [`PATH`] (or `path`) atomically: a unique temporary file, synced,
/// then renamed, so a reader never sees a partial file.
pub fn publish(path: &Path, conf: &str) -> Result<(), String> {
    durable::write(path, conf.as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keeps_distinct_well_formed_nameservers() {
        let learned = "nameserver 2001:db8:ff::53\n\
                       nameserver 2001:db8:ff::53\n\
                       search example.test\n\
                       nameserver not-an-address\n\
                       nameserver 192.0.2.53 extra\n\
                       nameserver 192.0.2.54\n";
        assert_eq!(
            resolv_conf(learned),
            "nameserver 2001:db8:ff::53\nnameserver 192.0.2.54\n"
        );
    }

    #[test]
    fn at_most_three_nameservers() {
        let learned = "nameserver 2001:db8::1\nnameserver 2001:db8::2\n\
                       nameserver 2001:db8::3\nnameserver 2001:db8::4\n";
        assert_eq!(resolv_conf(learned).lines().count(), 3);
    }

    #[test]
    fn link_local_resolvers_keep_their_interface_scope() {
        let learned = "nameserver fe80::1%wan0\nnameserver fe80::2\nnameserver 2001:db8::1%wan0\nnameserver fe80::3%a;b\n";
        assert_eq!(resolv_conf(learned), "nameserver fe80::1%wan0\n");
    }

    #[test]
    fn concurrent_publishes_leave_one_complete_file() {
        let dir = std::env::temp_dir().join(format!("fwos-resolvers-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("fwd-resolv.conf");
        let bodies: Vec<String> = (0..8)
            .map(|i| format!("nameserver 2001:db8::{i}\nnameserver 2001:db8::{}\n", i + 100))
            .collect();
        std::thread::scope(|scope| {
            for body in &bodies {
                let path = &path;
                scope.spawn(move || {
                    for _ in 0..20 {
                        publish(path, body).unwrap();
                    }
                });
            }
        });
        let published = std::fs::read_to_string(&path).unwrap();
        assert!(bodies.contains(&published), "{published}");
        assert_eq!(std::fs::read_dir(&dir).unwrap().count(), 1, "no temporary file is left");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_resolver_is_a_nameserver_line() {
        assert!(has_resolver(&resolv_conf("nameserver 2001:db8::53\n")));
        assert!(!has_resolver(&resolv_conf("")));
    }

    #[test]
    fn nothing_learned_names_no_resolver() {
        let body = resolv_conf("");
        assert!(!body.contains("nameserver"), "{body}");
        assert!(body.starts_with('#'), "{body}");
    }
}

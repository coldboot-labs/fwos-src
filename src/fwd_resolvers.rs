//! DNS resolvers the Forwarding netns learned from its WANs.
//!
//! netd records the DNS servers named by WAN DHCPv6 leases in [`PATH`]. The
//! Host update worker resolves registry names with them while it uses `fwd`
//! networking; the Host netns resolver cannot reach an IPv6-only WAN.
use std::net::IpAddr;

pub const PATH: &str = "/var/lib/fwos/fwd-resolv.conf";

/// glibc reads at most three `nameserver` lines.
const MAX_NAMESERVERS: usize = 3;

/// A resolv.conf body holding only the distinct, well-formed `nameserver`
/// lines of `learned`. Without one, lookups fail rather than falling back to
/// a Host netns resolver.
pub fn resolv_conf(learned: &str) -> String {
    let mut servers: Vec<IpAddr> = Vec::new();
    for line in learned.lines() {
        let mut words = line.split_whitespace();
        if words.next() != Some("nameserver") {
            continue;
        }
        let Some(Ok(server)) = words.next().map(str::parse::<IpAddr>) else {
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
    fn nothing_learned_names_no_resolver() {
        let body = resolv_conf("");
        assert!(!body.contains("nameserver"), "{body}");
        assert!(body.starts_with('#'), "{body}");
    }
}

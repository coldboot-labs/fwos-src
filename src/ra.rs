//! IPv6 Router Advertisements from netd (ADR-0012: RA is part of address and
//! prefix Desired state, not a separate radvd product).
use std::net::Ipv6Addr;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::time::{Duration, Instant};

use super::network::ip_cmd;

const ROUTER_LIFETIME: u16 = 1800;
const VALID_LIFETIME: u32 = 3600;
const PREFERRED_LIFETIME: u32 = 1800;
const UNSOLICITED_INTERVAL: Duration = Duration::from_secs(30);
const INITIAL_INTERVAL: Duration = Duration::from_secs(1);
const INITIAL_ADVERTISEMENTS: u8 = 3;
const MIN_SOLICITED_GAP: Duration = Duration::from_secs(1);
const ICMP6_FILTER: libc::c_int = 1;
const ROUTER_SOLICIT: u8 = 133;
const ROUTER_ADVERT: u8 = 134;

/// One LAN link and the /64 prefixes routed onto it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Lan {
    pub dev: String,
    pub prefixes: Vec<Ipv6Addr>,
    /// Kea DHCPv6 serves addresses on this link.
    pub managed: bool,
}

/// Build one Router Advertisement. The kernel fills the ICMPv6 checksum.
pub fn advertisement(
    prefixes: &[Ipv6Addr],
    managed: bool,
    mac: Option<[u8; 6]>,
    withdraw: bool,
) -> Vec<u8> {
    let mut packet = vec![ROUTER_ADVERT, 0, 0, 0, 64, if managed { 0x80 } else { 0 }];
    let router_lifetime = if withdraw { 0 } else { ROUTER_LIFETIME };
    packet.extend_from_slice(&router_lifetime.to_be_bytes());
    packet.extend_from_slice(&[0; 8]);
    if let Some(mac) = mac {
        packet.extend_from_slice(&[1, 1]);
        packet.extend_from_slice(&mac);
    }
    let (valid, preferred) = if withdraw {
        (0, 0)
    } else {
        (VALID_LIFETIME, PREFERRED_LIFETIME)
    };
    for prefix in prefixes {
        packet.extend_from_slice(&[3, 4, 64, 0x80 | 0x40]);
        packet.extend_from_slice(&valid.to_be_bytes());
        packet.extend_from_slice(&preferred.to_be_bytes());
        packet.extend_from_slice(&[0; 4]);
        packet.extend_from_slice(&prefix.octets());
    }
    packet
}

struct Link {
    lan: Lan,
    fd: OwnedFd,
    ifindex: u32,
    mac: Option<[u8; 6]>,
    initial_left: u8,
    next_unsolicited: Instant,
    last_sent: Option<Instant>,
}

impl Link {
    fn open(lan: Lan) -> Result<Self, String> {
        let name = std::ffi::CString::new(lan.dev.clone())
            .map_err(|_| format!("invalid LAN name {}", lan.dev))?;
        let ifindex = unsafe { libc::if_nametoindex(name.as_ptr()) };
        if ifindex == 0 {
            return Err(format!("RA link {} is missing", lan.dev));
        }
        let raw = unsafe {
            libc::socket(
                libc::AF_INET6,
                libc::SOCK_RAW | libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC,
                libc::IPPROTO_ICMPV6,
            )
        };
        if raw < 0 {
            return Err(format!(
                "RA socket on {}: {}",
                lan.dev,
                std::io::Error::last_os_error()
            ));
        }
        let fd = unsafe { OwnedFd::from_raw_fd(raw) };
        let bytes = name.as_bytes_with_nul();
        set_option(&fd, libc::SOL_SOCKET, libc::SO_BINDTODEVICE, bytes)?;
        let hops: libc::c_int = 255;
        set_option(
            &fd,
            libc::IPPROTO_IPV6,
            libc::IPV6_MULTICAST_HOPS,
            as_bytes(&hops),
        )?;
        set_option(
            &fd,
            libc::IPPROTO_IPV6,
            libc::IPV6_UNICAST_HOPS,
            as_bytes(&hops),
        )?;
        let loop_off: libc::c_int = 0;
        set_option(
            &fd,
            libc::IPPROTO_IPV6,
            libc::IPV6_MULTICAST_LOOP,
            as_bytes(&loop_off),
        )?;
        let mut filter = [u32::MAX; 8];
        filter[usize::from(ROUTER_SOLICIT >> 5)] &= !(1 << (ROUTER_SOLICIT & 31));
        set_option(&fd, libc::IPPROTO_ICMPV6, ICMP6_FILTER, as_bytes(&filter))?;
        // Forwarding interfaces already join all-routers; joining again is harmless.
        let group = libc::ipv6_mreq {
            ipv6mr_multiaddr: libc::in6_addr {
                s6_addr: Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 2).octets(),
            },
            ipv6mr_interface: ifindex,
        };
        let _ = set_option(
            &fd,
            libc::IPPROTO_IPV6,
            libc::IPV6_ADD_MEMBERSHIP,
            as_bytes(&group),
        );
        let now = Instant::now();
        Ok(Self {
            mac: link_mac(&lan.dev),
            lan,
            fd,
            ifindex,
            initial_left: INITIAL_ADVERTISEMENTS,
            next_unsolicited: now,
            last_sent: None,
        })
    }

    fn send(&mut self, now: Instant, withdraw: bool) {
        let packet = advertisement(&self.lan.prefixes, self.lan.managed, self.mac, withdraw);
        let destination = libc::sockaddr_in6 {
            sin6_family: libc::AF_INET6 as libc::sa_family_t,
            sin6_port: 0,
            sin6_flowinfo: 0,
            sin6_addr: libc::in6_addr {
                s6_addr: Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 1).octets(),
            },
            sin6_scope_id: self.ifindex,
        };
        let sent = unsafe {
            libc::sendto(
                self.fd.as_raw_fd(),
                packet.as_ptr().cast(),
                packet.len(),
                0,
                (&destination as *const libc::sockaddr_in6).cast(),
                std::mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t,
            )
        };
        if sent < 0 {
            eprintln!(
                "netd: router advertisement on {}: {}",
                self.lan.dev,
                std::io::Error::last_os_error()
            );
        }
        self.last_sent = Some(now);
        if self.initial_left > 0 {
            self.initial_left -= 1;
        }
        self.next_unsolicited = now
            + if self.initial_left > 0 {
                INITIAL_INTERVAL
            } else {
                UNSOLICITED_INTERVAL
            };
    }

    fn solicited(&self) -> bool {
        let mut seen = false;
        let mut buffer = [0u8; 1500];
        loop {
            let received = unsafe {
                libc::recv(
                    self.fd.as_raw_fd(),
                    buffer.as_mut_ptr().cast(),
                    buffer.len(),
                    0,
                )
            };
            if received <= 0 {
                return seen;
            }
            seen |= buffer[0] == ROUTER_SOLICIT;
        }
    }
}

/// Advertises each LAN that has a routed /64 and answers Router Solicitations.
/// A LAN without a prefix gets no RA, so hosts do not use FWOS as an IPv6
/// default router for traffic it cannot route.
#[derive(Default)]
pub struct Advertiser {
    links: Vec<Link>,
    /// LANs whose RA socket failed; logged once until they open again.
    failed: Vec<String>,
}

impl Advertiser {
    pub fn configure(&mut self, lans: Vec<Lan>) {
        let now = Instant::now();
        let lans: Vec<Lan> = lans
            .into_iter()
            .filter(|lan| !lan.prefixes.is_empty())
            .collect();
        let mut kept = Vec::new();
        for mut link in std::mem::take(&mut self.links) {
            match lans.iter().find(|lan| lan.dev == link.lan.dev) {
                Some(lan) if *lan == link.lan => kept.push(link),
                _ => link.send(now, true),
            }
        }
        for lan in lans {
            if kept.iter().any(|link| link.lan.dev == lan.dev) {
                continue;
            }
            let dev = lan.dev.clone();
            match Link::open(lan) {
                Ok(link) => {
                    self.failed.retain(|failed| failed != &dev);
                    kept.push(link);
                }
                Err(error) => {
                    if !self.failed.contains(&dev) {
                        eprintln!("netd: {error}");
                        self.failed.push(dev);
                    }
                }
            }
        }
        self.links = kept;
    }

    #[cfg(test)]
    pub fn advertised(&self) -> Vec<(String, Vec<Ipv6Addr>)> {
        self.links
            .iter()
            .map(|link| (link.lan.dev.clone(), link.lan.prefixes.clone()))
            .collect()
    }

    pub fn poll(&mut self) {
        let now = Instant::now();
        for link in &mut self.links {
            let solicited = link.solicited()
                && link
                    .last_sent
                    .is_none_or(|sent| now.duration_since(sent) >= MIN_SOLICITED_GAP);
            if solicited || now >= link.next_unsolicited {
                link.send(now, false);
            }
        }
    }
}

/// RDNSS option (RFC 8106) in a Router Advertisement.
const RDNSS: u8 = 25;

/// The recursive DNS servers and their lifetimes (seconds) that one Router
/// Advertisement names. A malformed option ends parsing.
pub fn rdnss_servers(packet: &[u8]) -> Vec<(Ipv6Addr, u32)> {
    let mut servers = Vec::new();
    if packet.first() != Some(&ROUTER_ADVERT) || packet.len() < 16 {
        return servers;
    }
    let mut options = &packet[16..];
    while options.len() >= 8 {
        let length = usize::from(options[1]) * 8;
        if length == 0 || length > options.len() {
            break;
        }
        if options[0] == RDNSS && length >= 24 {
            let lifetime = u32::from_be_bytes([options[4], options[5], options[6], options[7]]);
            for address in options[8..length].chunks_exact(16) {
                let octets: [u8; 16] = address.try_into().expect("16-byte chunk");
                servers.push((Ipv6Addr::from(octets), lifetime));
            }
        }
        options = &options[length..];
    }
    servers
}

/// Learns RDNSS resolvers from the Router Advertisements each WAN receives.
/// It only listens: the kernel still processes the same RAs for addresses and
/// routes.
#[derive(Default)]
pub struct RdnssListener {
    links: Vec<(String, OwnedFd)>,
    learned: Vec<(String, Ipv6Addr, Instant)>,
    failed: Vec<String>,
}

impl RdnssListener {
    /// Listen on exactly these WANs; resolvers of other WANs are forgotten.
    pub fn configure(&mut self, wans: &[String]) {
        self.links.retain(|(dev, _)| wans.contains(dev));
        self.learned.retain(|(dev, _, _)| wans.contains(dev));
        for wan in wans {
            if self.links.iter().any(|(dev, _)| dev == wan) {
                continue;
            }
            match rdnss_socket(wan) {
                Ok(fd) => {
                    self.failed.retain(|failed| failed != wan);
                    self.links.push((wan.clone(), fd));
                }
                Err(error) => {
                    if !self.failed.contains(wan) {
                        eprintln!("netd: {error}");
                        self.failed.push(wan.clone());
                    }
                }
            }
        }
    }

    pub fn poll(&mut self) {
        let now = Instant::now();
        let mut received = Vec::new();
        for (dev, fd) in &self.links {
            while let Some(packet) = receive_advertisement(fd) {
                received.push((dev.clone(), packet));
            }
        }
        for (dev, packet) in received {
            self.learn(&dev, &packet, now);
        }
    }

    fn learn(&mut self, dev: &str, packet: &[u8], now: Instant) {
        for (server, lifetime) in rdnss_servers(packet) {
            self.learned.retain(|(d, s, _)| !(d == dev && *s == server));
            if lifetime > 0 {
                let expires = now + Duration::from_secs(u64::from(lifetime));
                self.learned.push((dev.to_string(), server, expires));
            }
        }
    }

    /// Unexpired resolvers learned on `dev`, as resolv.conf addresses
    /// (link-local ones scoped to the WAN).
    pub fn servers(&self, dev: &str) -> Vec<String> {
        let now = Instant::now();
        self.learned
            .iter()
            .filter(|(d, _, expires)| d == dev && *expires > now)
            .map(|(_, server, _)| {
                if server.is_unicast_link_local() {
                    format!("{server}%{dev}")
                } else {
                    server.to_string()
                }
            })
            .collect()
    }
}

fn rdnss_socket(dev: &str) -> Result<OwnedFd, String> {
    let name = std::ffi::CString::new(dev).map_err(|_| format!("invalid WAN name {dev}"))?;
    let raw = unsafe {
        libc::socket(
            libc::AF_INET6,
            libc::SOCK_RAW | libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC,
            libc::IPPROTO_ICMPV6,
        )
    };
    if raw < 0 {
        return Err(format!(
            "RDNSS socket on {dev}: {}",
            std::io::Error::last_os_error()
        ));
    }
    let fd = unsafe { OwnedFd::from_raw_fd(raw) };
    set_option(&fd, libc::SOL_SOCKET, libc::SO_BINDTODEVICE, name.as_bytes_with_nul())?;
    let mut filter = [u32::MAX; 8];
    filter[usize::from(ROUTER_ADVERT >> 5)] &= !(1 << (ROUTER_ADVERT & 31));
    set_option(&fd, libc::IPPROTO_ICMPV6, ICMP6_FILTER, as_bytes(&filter))?;
    Ok(fd)
}

/// One pending Router Advertisement from a link-local router, if any.
fn receive_advertisement(fd: &OwnedFd) -> Option<Vec<u8>> {
    loop {
        let mut buffer = [0u8; 1500];
        let mut source: libc::sockaddr_in6 = unsafe { std::mem::zeroed() };
        let mut length = std::mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t;
        let received = unsafe {
            libc::recvfrom(
                fd.as_raw_fd(),
                buffer.as_mut_ptr().cast(),
                buffer.len(),
                0,
                (&mut source as *mut libc::sockaddr_in6).cast(),
                &mut length,
            )
        };
        if received <= 0 {
            return None;
        }
        // Routers send RAs from their link-local address (RFC 4861 6.1.2).
        if Ipv6Addr::from(source.sin6_addr.s6_addr).is_unicast_link_local() {
            return Some(buffer[..received as usize].to_vec());
        }
    }
}

fn as_bytes<T>(value: &T) -> &[u8] {
    unsafe { std::slice::from_raw_parts((value as *const T).cast(), std::mem::size_of::<T>()) }
}

fn set_option(
    fd: &OwnedFd,
    level: libc::c_int,
    name: libc::c_int,
    value: &[u8],
) -> Result<(), String> {
    let result = unsafe {
        libc::setsockopt(
            fd.as_raw_fd(),
            level,
            name,
            value.as_ptr().cast(),
            value.len() as libc::socklen_t,
        )
    };
    if result == 0 {
        Ok(())
    } else {
        Err(format!(
            "RA socket option: {}",
            std::io::Error::last_os_error()
        ))
    }
}

fn link_mac(dev: &str) -> Option<[u8; 6]> {
    let output = ip_cmd()
        .args(["-j", "link", "show", "dev", dev])
        .output()
        .ok()?;
    let links: serde_json::Value = serde_json::from_slice(&output.stdout).ok()?;
    let text = links.get(0)?.get("address")?.as_str()?;
    let bytes: Vec<u8> = text
        .split(':')
        .filter_map(|part| u8::from_str_radix(part, 16).ok())
        .collect();
    bytes.try_into().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn advertisement_carries_on_link_autonomous_64_prefixes() {
        let prefix: Ipv6Addr = "2001:db8:1:2::".parse().unwrap();
        let packet = advertisement(&[prefix], true, Some([2, 0, 0, 0, 0, 1]), false);
        assert_eq!(packet[0], 134);
        assert_eq!(packet[5], 0x80, "managed flag for Kea DHCPv6");
        assert_eq!(u16::from_be_bytes([packet[6], packet[7]]), ROUTER_LIFETIME);
        assert_eq!(&packet[16..24], &[1, 1, 2, 0, 0, 0, 0, 1]);
        let option = &packet[24..];
        assert_eq!(&option[..4], &[3, 4, 64, 0xc0]);
        assert_eq!(
            u32::from_be_bytes(option[4..8].try_into().unwrap()),
            VALID_LIFETIME
        );
        assert_eq!(&option[16..32], &prefix.octets());
        assert_eq!(packet.len(), 16 + 8 + 32);
    }

    #[test]
    fn withdrawal_stops_default_routing_and_deprecates_prefixes() {
        let prefix: Ipv6Addr = "2001:db8:1:2::".parse().unwrap();
        let packet = advertisement(&[prefix], false, None, true);
        assert_eq!(packet[5], 0);
        assert_eq!(u16::from_be_bytes([packet[6], packet[7]]), 0);
        let option = &packet[16..];
        assert_eq!(u32::from_be_bytes(option[4..8].try_into().unwrap()), 0);
        assert_eq!(u32::from_be_bytes(option[8..12].try_into().unwrap()), 0);
    }

    fn advertisement_with_rdnss(lifetime: u32, servers: &[&str]) -> Vec<u8> {
        let mut packet = advertisement(&[], false, Some([2, 0, 0, 0, 0, 1]), false);
        packet.extend_from_slice(&[RDNSS, (1 + 2 * servers.len()) as u8, 0, 0]);
        packet.extend_from_slice(&lifetime.to_be_bytes());
        for server in servers {
            packet.extend_from_slice(&server.parse::<Ipv6Addr>().unwrap().octets());
        }
        packet
    }

    #[test]
    fn router_advertisement_rdnss_names_resolvers() {
        let packet = advertisement_with_rdnss(600, &["2001:db8:ff::53", "2001:db8:ff::54"]);
        assert_eq!(
            rdnss_servers(&packet),
            vec![
                ("2001:db8:ff::53".parse().unwrap(), 600),
                ("2001:db8:ff::54".parse().unwrap(), 600)
            ]
        );
        assert!(rdnss_servers(&advertisement(&[], false, None, false)).is_empty());
        let mut truncated = packet.clone();
        truncated.truncate(packet.len() - 4);
        assert_eq!(rdnss_servers(&truncated).len(), 0, "a truncated option is ignored");
        assert!(rdnss_servers(&[ROUTER_SOLICIT, 0, 0, 0]).is_empty());
    }

    #[test]
    fn wan_rdnss_expires_and_a_zero_lifetime_withdraws() {
        let mut listener = RdnssListener::default();
        let now = Instant::now();
        listener.learn("wan0", &advertisement_with_rdnss(600, &["2001:db8:ff::53"]), now);
        listener.learn("wan0", &advertisement_with_rdnss(600, &["fe80::1"]), now);
        assert_eq!(listener.servers("wan0"), ["2001:db8:ff::53", "fe80::1%wan0"]);
        assert!(listener.servers("wan1").is_empty());
        listener.learn("wan0", &advertisement_with_rdnss(0, &["fe80::1"]), now);
        assert_eq!(listener.servers("wan0"), ["2001:db8:ff::53"]);
        let past = now - Duration::from_secs(601);
        listener.learned.clear();
        listener.learn("wan0", &advertisement_with_rdnss(600, &["2001:db8:ff::53"]), past);
        assert!(listener.servers("wan0").is_empty(), "expired");
        listener.learn("wan0", &advertisement_with_rdnss(600, &["2001:db8:ff::53"]), now);
        listener.configure(&[]);
        assert!(listener.servers("wan0").is_empty(), "a removed WAN forgets its resolvers");
    }

    #[test]
    fn a_lan_without_a_prefix_is_not_advertised() {
        let mut advertiser = Advertiser::default();
        advertiser.configure(vec![Lan {
            dev: "fwos-missing0".into(),
            prefixes: Vec::new(),
            managed: false,
        }]);
        assert!(advertiser.advertised().is_empty());
    }
}

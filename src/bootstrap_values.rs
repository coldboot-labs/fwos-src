//! Pure validation shared by the HTTPS Bootstrap boundary and netd commit.
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

pub fn interface(
    name: &str,
    parent: Option<&str>,
    vlan: Option<u16>,
    addresses: &[String],
) -> Result<(), String> {
    if !interface_name(name) {
        return Err(format!("invalid interface name {name}"));
    }
    if let Some(parent) = parent {
        if !interface_name(parent) || parent == name {
            return Err(format!("invalid parent for interface {name}"));
        }
        if vlan.is_none() {
            return Err(format!("interface {name} has parent without VLAN"));
        }
    }
    if let Some(vid) = vlan {
        if !(1..=4094).contains(&vid) {
            return Err(format!("VLAN ID {vid} is outside 1-4094"));
        }
        if parent.is_none() && !name.contains('.') {
            return Err(format!("VLAN interface {name} needs a parent"));
        }
    }
    for address in addresses {
        if cidr(address).is_none() {
            return Err(format!("invalid interface address {address}"));
        }
    }
    Ok(())
}

pub fn addressing(
    lan_prefix: Option<&str>,
    dhcp_pool: Option<&str>,
    wan_pd: Option<&str>,
) -> Result<(), String> {
    let lan = match lan_prefix.filter(|value| !value.is_empty()) {
        Some(value) => match cidr(value) {
            Some((IpAddr::V4(ip), len)) if (1..=30).contains(&len) => Some((ip, len)),
            _ => return Err("invalid lan_prefix IPv4 CIDR".into()),
        },
        None => None,
    };
    if let Some(pool) = dhcp_pool.filter(|value| !value.is_empty()) {
        let (first, last) = pool.split_once('-').unwrap_or((pool, pool));
        let first: Ipv4Addr = first
            .trim()
            .parse()
            .map_err(|_| "invalid dhcp_pool start")?;
        let last: Ipv4Addr = last.trim().parse().map_err(|_| "invalid dhcp_pool end")?;
        if u32::from(first) > u32::from(last) {
            return Err("dhcp_pool start exceeds end".into());
        }
        let (base, len) = lan.unwrap_or((first, 24));
        let mask = if len == 0 { 0 } else { u32::MAX << (32 - len) };
        if u32::from(first) & mask != u32::from(base) & mask
            || u32::from(last) & mask != u32::from(base) & mask
        {
            return Err("dhcp_pool is outside lan_prefix".into());
        }
    }
    if let Some(pd) = wan_pd.filter(|value| !value.is_empty()) {
        if delegated_lan(pd).is_none() {
            return Err("invalid wan_pd IPv6 prefix".into());
        }
    }
    Ok(())
}

pub struct DelegatedLan {
    pub address_cidr: String,
    pub subnet_cidr: String,
    pub pool_start: String,
    pub pool_end: String,
}

/// Place the LAN in the first /64 of a delegated IPv6 prefix, independent of
/// whether the operator wrote compressed or expanded IPv6 notation.
pub fn delegated_lan(prefix: &str) -> Option<DelegatedLan> {
    let (IpAddr::V6(address), len) = cidr(prefix)? else {
        return None;
    };
    if len > 64 {
        return None;
    }
    let prefix_mask = if len == 0 {
        0
    } else {
        u128::MAX << (128 - len)
    };
    let subnet = u128::from(address) & prefix_mask & (u128::MAX << 64);
    Some(DelegatedLan {
        address_cidr: format!("{}/64", Ipv6Addr::from(subnet | 1)),
        subnet_cidr: format!("{}/64", Ipv6Addr::from(subnet)),
        pool_start: Ipv6Addr::from(subnet | 0x100).to_string(),
        pool_end: Ipv6Addr::from(subnet | 0x1ff).to_string(),
    })
}

fn interface_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 15
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
}

fn cidr(value: &str) -> Option<(IpAddr, u8)> {
    let (ip, len) = value.split_once('/')?;
    let ip: IpAddr = ip.parse().ok()?;
    let len: u8 = len.parse().ok()?;
    if len > if ip.is_ipv4() { 32 } else { 128 } {
        return None;
    }
    Some((ip, len))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn delegated_prefix_normalizes_expanded_and_compressed_notation() {
        let expanded = delegated_lan("fd53:0001:0001:00ff:0000:0000:0000:0000/56").unwrap();
        let compressed = delegated_lan("fd53:1:1:ff::/56").unwrap();
        assert_eq!(expanded.address_cidr, compressed.address_cidr);
        assert_eq!(expanded.address_cidr, "fd53:1:1::1/64");
        assert_eq!(expanded.subnet_cidr, "fd53:1:1::/64");
        assert_eq!(expanded.pool_start, "fd53:1:1::100");
        assert_eq!(expanded.pool_end, "fd53:1:1::1ff");
    }

    #[test]
    fn lan_prefix_requires_usable_ipv4_hosts() {
        assert!(addressing(Some("192.168.1.0/24"), None, None).is_ok());
        assert!(addressing(Some("192.168.1.0/31"), None, None).is_err());
        assert!(addressing(Some("192.168.1.0/32"), None, None).is_err());
    }
}

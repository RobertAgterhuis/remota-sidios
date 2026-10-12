//! Target checks (SidiOS research R6), enforced before any packet leaves. Every address is allowed
//! (owner decision, 2026-10-12) except the denies: loopback, link-local (including the cloud
//! metadata address), unspecified, multicast, broadcast, the networks SidiOS itself lives on, the
//! Docker host's addresses on Remota's networks, and any extra ranges the operator configures. A
//! policy Remota cannot fetch still refuses everything (its limits and RDP settings are unknown).
//!
//! Names are resolved once; every resolved address must be allowed, and the connection is made to
//! the first one, so a name cannot be re-pointed (DNS rebinding) between the check and the connect.

use std::{
    net::{IpAddr, SocketAddr},
    sync::Arc,
    time::{Duration, Instant},
};

use ipnet::IpNet;
use serde::Deserialize;
use tokio::sync::Mutex;

use crate::webos::SharedWebos;

/// How long a fetched policy is used before asking webOS again.
pub const POLICY_TTL: Duration = Duration::from_secs(30);

#[derive(Clone, Debug, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Clipboard {
    pub rdp: bool,
    pub ssh: bool,
}

/// The policy as webOS serves it (SidiOS `contracts/vault-and-identity.md`).
#[derive(Clone, Debug, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Policy {
    pub allow_rdp_without_nla: bool,
    pub clipboard: Clipboard,
    pub max_sessions_total: usize,
    pub max_sessions_user: usize,
    pub revision: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Refusal {
    /// The address is denied.
    TargetNotAllowed,
    /// The name does not resolve.
    Unresolvable,
    /// No policy could be fetched; everything is refused.
    PolicyUnavailable,
}

impl Refusal {
    pub fn code(self) -> &'static str {
        match self {
            Self::TargetNotAllowed | Self::Unresolvable => "target_not_allowed",
            Self::PolicyUnavailable => "policy_unavailable",
        }
    }
}

/// Ranges that are always refused, whatever the policy says.
#[derive(Clone, Debug, Default)]
pub struct Denies {
    networks: Vec<IpNet>,
}

impl Denies {
    /// The fixed denies plus `extra` (SidiOS's own networks and operator-configured ranges).
    pub fn new(extra: impl IntoIterator<Item = IpNet>) -> Self {
        let fixed = [
            "0.0.0.0/8",
            "127.0.0.0/8",
            "169.254.0.0/16",
            "224.0.0.0/4",
            "240.0.0.0/4",
            "255.255.255.255/32",
            "::/128",
            "::1/128",
            "fe80::/10",
            "ff00::/8",
            "fd00:ec2::254/128",
        ];
        let mut networks: Vec<IpNet> = fixed.iter().map(|n| n.parse().expect("valid")).collect();
        networks.extend(extra);
        Self { networks }
    }

    /// No denies at all, so tests can reach servers on loopback.
    #[cfg(test)]
    pub fn none() -> Self {
        Self::default()
    }

    pub fn denies(&self, ip: IpAddr) -> bool {
        let ip = canonical(ip);
        self.networks.iter().any(|network| network.contains(&ip))
    }
}

/// IPv4-mapped IPv6 addresses are checked as the IPv4 address they carry.
fn canonical(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(ip, IpAddr::V4),
        IpAddr::V4(_) => ip,
    }
}

/// Resolves `host` once and answers the address to connect to; every address it resolves to must
/// be allowed.
pub async fn resolve_pinned(denies: &Denies, host: &str, port: u16) -> Result<SocketAddr, Refusal> {
    let literal = host.trim_start_matches('[').trim_end_matches(']');
    let addresses: Vec<SocketAddr> = match literal.parse::<IpAddr>() {
        Ok(ip) => vec![SocketAddr::new(ip, port)],
        Err(_) => tokio::time::timeout(
            Duration::from_secs(5),
            tokio::net::lookup_host((host, port)),
        )
        .await
        .map_err(|_| Refusal::Unresolvable)?
        .map_err(|_| Refusal::Unresolvable)?
        .collect(),
    };
    let first = *addresses.first().ok_or(Refusal::Unresolvable)?;
    if addresses.iter().any(|address| denies.denies(address.ip())) {
        return Err(Refusal::TargetNotAllowed);
    }
    Ok(first)
}

struct Cached {
    fetched: Instant,
    policy: Policy,
}

/// The policy from webOS, cached for at most 30 seconds. When webOS cannot be asked and the cache
/// is stale, there is no policy and every connection is refused.
#[derive(Clone)]
pub struct PolicyClient {
    cached: Arc<Mutex<Option<Cached>>>,
    webos: SharedWebos,
}

impl PolicyClient {
    pub fn new(webos: SharedWebos) -> Self {
        Self {
            cached: Arc::new(Mutex::new(None)),
            webos,
        }
    }

    pub async fn current(&self) -> Result<Policy, Refusal> {
        let mut cached = self.cached.lock().await;
        if let Some(fresh) = cached.as_ref().filter(|c| c.fetched.elapsed() < POLICY_TTL) {
            return Ok(fresh.policy.clone());
        }
        let known = cached.as_ref().map_or(0, |c| c.policy.revision);
        match self.webos.policy(known).await {
            Ok(Some(policy)) => {
                *cached = Some(Cached {
                    fetched: Instant::now(),
                    policy: policy.clone(),
                });
                Ok(policy)
            }
            Ok(None) => match cached.as_mut() {
                Some(entry) => {
                    entry.fetched = Instant::now();
                    Ok(entry.policy.clone())
                }
                None => Err(Refusal::PolicyUnavailable),
            },
            Err(_) => {
                *cached = None;
                Err(Refusal::PolicyUnavailable)
            }
        }
    }
}

/// SidiOS's own networks: the subnets of this container's interfaces that reach `hosts` (webOS
/// and Caddy), so Remota can never be pointed at its own control or edge network.
pub fn protected_networks(hosts: &[String]) -> Vec<IpNet> {
    let Ok(interfaces) = if_addrs::get_if_addrs() else {
        return Vec::new();
    };
    let protected: Vec<IpAddr> = hosts
        .iter()
        .filter_map(|host| std::net::ToSocketAddrs::to_socket_addrs(&(host.as_str(), 0)).ok())
        .flatten()
        .map(|address| address.ip())
        .collect();
    interfaces
        .iter()
        .filter_map(|interface| interface_network(&interface.addr))
        .filter(|network| protected.iter().any(|ip| network.contains(ip)))
        .collect()
}

/// The Docker host's addresses as Remota sees them: the default gateway and, by Docker's
/// convention, the first address of every network Remota is attached to. Denying them keeps users
/// off the ports SidiOS publishes on the host. The host's LAN address cannot be seen from inside the
/// container; operators add it with `REMOTA_DENY_CIDRS`.
pub fn docker_host_addresses() -> Vec<IpNet> {
    let mut hosts: Vec<IpNet> = Vec::new();
    if let Ok(interfaces) = if_addrs::get_if_addrs() {
        for interface in interfaces.iter().filter(|i| !i.is_loopback()) {
            if let Some(IpNet::V4(network)) = interface_network(&interface.addr) {
                if let Some(first) = network.hosts().next() {
                    hosts.push(IpNet::from(IpAddr::V4(first)));
                }
            }
        }
    }
    if let Ok(routes) = std::fs::read_to_string("/proc/net/route") {
        hosts.extend(
            default_gateways(&routes)
                .into_iter()
                .map(|ip| IpNet::from(IpAddr::V4(ip))),
        );
    }
    hosts.sort();
    hosts.dedup();
    hosts
}

/// The gateways of default routes in `/proc/net/route` (little-endian hex addresses).
fn default_gateways(routes: &str) -> Vec<std::net::Ipv4Addr> {
    routes
        .lines()
        .skip(1)
        .filter_map(|line| {
            let fields: Vec<&str> = line.split_whitespace().collect();
            (fields.get(1) == Some(&"00000000"))
                .then(|| u32::from_str_radix(fields.get(2)?, 16).ok())
                .flatten()
                .map(|raw| std::net::Ipv4Addr::from(raw.to_le_bytes()))
        })
        .filter(|ip| !ip.is_unspecified())
        .collect()
}

fn interface_network(addr: &if_addrs::IfAddr) -> Option<IpNet> {
    match addr {
        if_addrs::IfAddr::V4(v4) => {
            let prefix = u32::from(v4.netmask).count_ones() as u8;
            ipnet::Ipv4Net::new(v4.ip, prefix)
                .ok()
                .map(|n| IpNet::V4(n.trunc()))
        }
        if_addrs::IfAddr::V6(v6) => {
            let prefix = u128::from(v6.netmask).count_ones() as u8;
            ipnet::Ipv6Net::new(v6.ip, prefix)
                .ok()
                .map(|n| IpNet::V6(n.trunc()))
        }
    }
}

/// Operator-configured extra denies: comma-separated CIDRs; malformed entries are ignored.
pub fn parse_networks(list: &str) -> Vec<IpNet> {
    list.split(',')
        .filter_map(|item| item.trim().parse::<IpNet>().ok())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(text: &str) -> SocketAddr {
        text.parse().unwrap()
    }

    #[tokio::test]
    async fn allows_every_address_except_the_denies() {
        let denies = Denies::new(parse_networks("172.30.250.0/24"));
        for target in ["10.20.0.5", "192.168.1.10", "8.8.8.8", "[2001:db8::1]"] {
            assert!(
                resolve_pinned(&denies, target, 22).await.is_ok(),
                "{target}"
            );
        }
        for target in [
            "127.0.0.1",
            "169.254.169.254",
            "0.0.0.0",
            "224.0.0.1",
            "255.255.255.255",
            "[::1]",
            "[fe80::1]",
            "[fd00:ec2::254]",
            "[::ffff:127.0.0.1]",
            "[::ffff:169.254.169.254]",
            "172.30.250.2",
        ] {
            assert_eq!(
                resolve_pinned(&denies, target, 22).await,
                Err(Refusal::TargetNotAllowed),
                "{target}"
            );
        }
    }

    #[tokio::test]
    async fn resolves_names_once_and_requires_every_address_allowed() {
        let denies = Denies::new([]);
        assert_eq!(
            resolve_pinned(&denies, "10.1.2.3", 22).await,
            Ok(addr("10.1.2.3:22"))
        );
        // "localhost" resolves to loopback, which is always denied.
        assert_eq!(
            resolve_pinned(&denies, "localhost", 22).await,
            Err(Refusal::TargetNotAllowed)
        );
        assert_eq!(
            resolve_pinned(&denies, "no-such-host.invalid", 22).await,
            Err(Refusal::Unresolvable)
        );
    }

    #[test]
    fn reads_default_gateways_from_the_routing_table() {
        let routes = "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\n\
            eth0\t00000000\t0101A8C0\t0003\t0\t0\t0\t00000000\n\
            eth0\t0001A8C0\t00000000\t0001\t0\t0\t0\t00FFFFFF\n";
        assert_eq!(
            default_gateways(routes),
            vec!["192.168.1.1".parse::<std::net::Ipv4Addr>().unwrap()]
        );
    }
}

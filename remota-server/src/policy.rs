//! The administrator's target policy (SidiOS research R6), enforced before any packet leaves:
//!
//! 1. built-in denies that no rule can lift: loopback, link-local (including the cloud metadata
//!    address), unspecified, multicast, broadcast, the networks SidiOS itself lives on, and any
//!    extra ranges the operator configures;
//! 2. the allow list: a target is allowed only if a rule names its address, port, and protocol.
//!    No rule means everything is refused (fail closed), and so does a policy Remota cannot fetch.
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

use crate::{model::Protocol, webos::SharedWebos};

/// How long a fetched policy is used before asking webOS again.
pub const POLICY_TTL: Duration = Duration::from_secs(30);

#[derive(Clone, Debug, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Clipboard {
    pub rdp: bool,
    pub ssh: bool,
}

#[derive(Clone, Debug, Deserialize, PartialEq)]
pub struct Rule {
    pub cidr: String,
    pub ports: String,
    pub protocols: Vec<Protocol>,
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
    pub rules: Vec<Rule>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Refusal {
    /// The address is denied or no rule allows it.
    TargetNotAllowed,
    /// The address is allowed, but not for this port or protocol.
    ProtocolNotAllowed,
    /// The name does not resolve.
    Unresolvable,
    /// No policy could be fetched; everything is refused.
    PolicyUnavailable,
}

impl Refusal {
    pub fn code(self) -> &'static str {
        match self {
            Self::TargetNotAllowed | Self::Unresolvable => "target_not_allowed",
            Self::ProtocolNotAllowed => "protocol_not_allowed",
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

/// Parses "22", "22,3389", and "8000-8100" lists; anything malformed matches nothing.
pub fn port_matches(ports: &str, port: u16) -> bool {
    ports
        .split(',')
        .map(str::trim)
        .any(|part| match part.split_once('-') {
            Some((low, high)) => match (low.trim().parse::<u16>(), high.trim().parse::<u16>()) {
                (Ok(low), Ok(high)) => (low..=high).contains(&port),
                _ => false,
            },
            None => part.parse::<u16>() == Ok(port),
        })
}

impl Policy {
    /// Checks one resolved address against the denies and the allow list.
    pub fn check(
        &self,
        denies: &Denies,
        protocol: Protocol,
        address: SocketAddr,
    ) -> Result<(), Refusal> {
        let ip = canonical(address.ip());
        if denies.denies(ip) {
            return Err(Refusal::TargetNotAllowed);
        }
        let covering: Vec<&Rule> = self
            .rules
            .iter()
            .filter(|rule| {
                rule.cidr
                    .parse::<IpNet>()
                    .is_ok_and(|net| net.contains(&ip))
            })
            .collect();
        if covering.is_empty() {
            return Err(Refusal::TargetNotAllowed);
        }
        let allowed = covering.iter().any(|rule| {
            rule.protocols.contains(&protocol) && port_matches(&rule.ports, address.port())
        });
        if allowed {
            Ok(())
        } else {
            Err(Refusal::ProtocolNotAllowed)
        }
    }
}

/// Resolves `host` once and answers the address to connect to; every address it resolves to must
/// be allowed.
pub async fn resolve_pinned(
    policy: &Policy,
    denies: &Denies,
    protocol: Protocol,
    host: &str,
    port: u16,
) -> Result<SocketAddr, Refusal> {
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
    for address in &addresses {
        policy.check(denies, protocol, *address)?;
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

    fn policy(rules: &[(&str, &str, &[Protocol])]) -> Policy {
        Policy {
            allow_rdp_without_nla: false,
            clipboard: Clipboard {
                rdp: false,
                ssh: true,
            },
            max_sessions_total: 20,
            max_sessions_user: 5,
            revision: 1,
            rules: rules
                .iter()
                .map(|(cidr, ports, protocols)| Rule {
                    cidr: (*cidr).into(),
                    ports: (*ports).into(),
                    protocols: protocols.to_vec(),
                })
                .collect(),
        }
    }

    fn addr(text: &str) -> SocketAddr {
        text.parse().unwrap()
    }

    const SSH: &[Protocol] = &[Protocol::Ssh];
    const BOTH: &[Protocol] = &[Protocol::Ssh, Protocol::Rdp];

    #[test]
    fn refuses_everything_without_rules() {
        let empty = policy(&[]);
        let denies = Denies::new([]);
        for target in ["10.20.0.5:22", "8.8.8.8:22", "[2001:db8::1]:22"] {
            assert_eq!(
                empty.check(&denies, Protocol::Ssh, addr(target)),
                Err(Refusal::TargetNotAllowed)
            );
        }
    }

    #[test]
    fn allows_only_the_listed_networks_ports_and_protocols() {
        let allowed = policy(&[
            ("10.20.0.0/16", "22,3389", BOTH),
            ("10.30.0.0/16", "2200-2299", SSH),
        ]);
        let denies = Denies::new([]);
        assert_eq!(
            allowed.check(&denies, Protocol::Ssh, addr("10.20.1.2:22")),
            Ok(())
        );
        assert_eq!(
            allowed.check(&denies, Protocol::Rdp, addr("10.20.1.2:3389")),
            Ok(())
        );
        assert_eq!(
            allowed.check(&denies, Protocol::Ssh, addr("10.30.0.9:2250")),
            Ok(())
        );
        assert_eq!(
            allowed.check(&denies, Protocol::Rdp, addr("10.30.0.9:2250")),
            Err(Refusal::ProtocolNotAllowed)
        );
        assert_eq!(
            allowed.check(&denies, Protocol::Ssh, addr("10.20.1.2:2222")),
            Err(Refusal::ProtocolNotAllowed)
        );
        assert_eq!(
            allowed.check(&denies, Protocol::Ssh, addr("10.21.0.1:22")),
            Err(Refusal::TargetNotAllowed)
        );
    }

    #[test]
    fn built_in_denies_win_over_any_rule() {
        let everything = policy(&[("0.0.0.0/0", "1-65535", BOTH), ("::/0", "1-65535", BOTH)]);
        let denies = Denies::new(parse_networks("172.30.250.0/24"));
        for target in [
            "127.0.0.1:22",
            "169.254.169.254:80",
            "0.0.0.0:22",
            "224.0.0.1:22",
            "255.255.255.255:22",
            "[::1]:22",
            "[fe80::1]:22",
            "[fd00:ec2::254]:80",
            "[::ffff:127.0.0.1]:22",
            "[::ffff:169.254.169.254]:80",
            "172.30.250.2:3000",
        ] {
            assert_eq!(
                everything.check(&denies, Protocol::Ssh, addr(target)),
                Err(Refusal::TargetNotAllowed),
                "{target}"
            );
        }
        assert_eq!(
            everything.check(&denies, Protocol::Ssh, addr("10.0.0.1:22")),
            Ok(())
        );
    }

    #[test]
    fn parses_port_lists_and_ranges_strictly() {
        assert!(port_matches("22", 22));
        assert!(port_matches("22, 3389", 3389));
        assert!(port_matches("8000-8100", 8050));
        assert!(!port_matches("8000-8100", 8101));
        assert!(!port_matches("abc", 22));
        assert!(!port_matches("", 22));
        assert!(!port_matches("22-", 22));
    }

    #[tokio::test]
    async fn resolves_literals_and_names_once_and_requires_every_address_allowed() {
        let local_only = policy(&[("10.0.0.0/8", "22", SSH)]);
        let denies = Denies::new([]);
        assert_eq!(
            resolve_pinned(&local_only, &denies, Protocol::Ssh, "10.1.2.3", 22).await,
            Ok(addr("10.1.2.3:22"))
        );
        assert_eq!(
            resolve_pinned(&local_only, &denies, Protocol::Ssh, "[2001:db8::1]", 22).await,
            Err(Refusal::TargetNotAllowed)
        );
        // "localhost" resolves to loopback, which is always denied, even with a rule for it.
        let loopback = policy(&[("127.0.0.0/8", "22", SSH), ("::1/128", "22", SSH)]);
        assert_eq!(
            resolve_pinned(&loopback, &denies, Protocol::Ssh, "localhost", 22).await,
            Err(Refusal::TargetNotAllowed)
        );
        assert_eq!(
            resolve_pinned(
                &local_only,
                &denies,
                Protocol::Ssh,
                "no-such-host.invalid",
                22
            )
            .await,
            Err(Refusal::Unresolvable)
        );
    }
}

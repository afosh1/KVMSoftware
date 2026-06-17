#![forbid(unsafe_code)]
//! LAN discovery via mDNS/DNS-SD (`mdns-sd`).
//!
//! We advertise a `_kvmshare._udp` service whose TXT record carries everything a
//! peer needs to attempt a connection: device id, name, platform, certificate
//! fingerprint (for pinning), protocol version, and the QUIC + TCP ports. The
//! TXT (de)serialization is factored into pure functions so it is unit-testable
//! without a live network.

use std::collections::HashMap;
use std::net::IpAddr;

use thiserror::Error;
use uuid::Uuid;

use kvm_proto::v1::handshake::Platform;

/// DNS-SD service type. UDP because the primary transport is QUIC.
pub const SERVICE_TYPE: &str = "_kvmshare._udp.local.";

#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[error("discovery error: {0}")]
pub struct DiscoveryError(String);

fn de(e: impl std::fmt::Display) -> DiscoveryError {
    DiscoveryError(e.to_string())
}

/// What this device advertises.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceAdvert {
    pub device_id: Uuid,
    pub name: String,
    pub platform: Platform,
    pub fingerprint_hex: String,
    pub protocol_version: u16,
    pub quic_port: u16,
    pub tcp_port: u16,
}

/// A peer found on the LAN.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiscoveredPeer {
    pub device_id: Uuid,
    pub name: String,
    pub platform: Platform,
    pub fingerprint_hex: String,
    pub protocol_version: u16,
    pub addrs: Vec<IpAddr>,
    pub quic_port: u16,
    pub tcp_port: u16,
}

impl DiscoveredPeer {
    /// The address to actually dial: a routable IPv4 on the LAN.
    ///
    /// IPv6 link-local (`fe80::`) addresses require a scope/zone id and can't be
    /// dialed from our IPv4 endpoint, so they're skipped. (`get_addresses`
    /// returns an unordered set, so we must choose deliberately rather than
    /// taking the first.)
    pub fn best_addr(&self) -> Option<IpAddr> {
        self.addrs.iter().copied().find(|a| match a {
            IpAddr::V4(v4) => !v4.is_loopback() && !v4.is_link_local(),
            IpAddr::V6(_) => false,
        })
    }
}

fn platform_str(p: Platform) -> &'static str {
    match p {
        Platform::Windows => "windows",
        Platform::MacOs => "macos",
        Platform::Linux => "linux",
    }
}

fn parse_platform(s: &str) -> Option<Platform> {
    match s {
        "windows" => Some(Platform::Windows),
        "macos" => Some(Platform::MacOs),
        "linux" => Some(Platform::Linux),
        _ => None,
    }
}

/// Build the TXT key/value pairs for an advert.
pub fn advert_txt(a: &DeviceAdvert) -> Vec<(String, String)> {
    vec![
        ("id".into(), a.device_id.to_string()),
        ("name".into(), a.name.clone()),
        ("platform".into(), platform_str(a.platform).into()),
        ("fp".into(), a.fingerprint_hex.clone()),
        ("ver".into(), a.protocol_version.to_string()),
        ("quic".into(), a.quic_port.to_string()),
        ("tcp".into(), a.tcp_port.to_string()),
    ]
}

/// Parse a peer from resolved TXT values + addresses. Returns `None` if any
/// required field is missing or malformed (a partial/foreign advert).
pub fn parse_peer(
    get: impl Fn(&str) -> Option<String>,
    addrs: Vec<IpAddr>,
) -> Option<DiscoveredPeer> {
    Some(DiscoveredPeer {
        device_id: Uuid::parse_str(&get("id")?).ok()?,
        name: get("name").unwrap_or_default(),
        platform: parse_platform(&get("platform")?)?,
        fingerprint_hex: get("fp")?,
        protocol_version: get("ver")?.parse().ok()?,
        quic_port: get("quic")?.parse().ok()?,
        tcp_port: get("tcp")?.parse().ok()?,
        addrs,
    })
}

/// Live mDNS daemon wrapper.
pub struct Discovery {
    daemon: mdns_sd::ServiceDaemon,
    /// Our own device id, so `browse` can filter our own advert out.
    self_id: Option<Uuid>,
}

impl Discovery {
    pub fn new() -> Result<Self, DiscoveryError> {
        Ok(Discovery {
            daemon: mdns_sd::ServiceDaemon::new().map_err(de)?,
            self_id: None,
        })
    }

    /// Advertise this device on the LAN.
    pub fn advertise(&mut self, advert: &DeviceAdvert) -> Result<(), DiscoveryError> {
        self.self_id = Some(advert.device_id);
        let instance = advert.device_id.to_string();
        let host = format!("{instance}.local.");
        let props: HashMap<String, String> = advert_txt(advert).into_iter().collect();
        let info =
            mdns_sd::ServiceInfo::new(SERVICE_TYPE, &instance, &host, "", advert.quic_port, props)
                .map_err(de)?
                .enable_addr_auto();
        self.daemon.register(info).map_err(de)?;
        Ok(())
    }

    /// Browse for peers; resolved peers are pushed to the returned channel.
    pub fn browse(&self) -> Result<tokio::sync::mpsc::Receiver<DiscoveredPeer>, DiscoveryError> {
        let receiver = self.daemon.browse(SERVICE_TYPE).map_err(de)?;
        let (tx, rx) = tokio::sync::mpsc::channel(64);
        let self_id = self.self_id;
        tokio::spawn(async move {
            while let Ok(event) = receiver.recv_async().await {
                if let mdns_sd::ServiceEvent::ServiceResolved(info) = event {
                    if let Some(peer) = peer_from_info(&info) {
                        if Some(peer.device_id) == self_id {
                            continue; // ignore our own advert
                        }
                        if tx.send(peer).await.is_err() {
                            break;
                        }
                    }
                }
            }
        });
        Ok(rx)
    }

    pub fn shutdown(&self) {
        let _ = self.daemon.shutdown();
    }
}

fn peer_from_info(info: &mdns_sd::ServiceInfo) -> Option<DiscoveredPeer> {
    let props = info.get_properties();
    let addrs: Vec<IpAddr> = info.get_addresses().iter().copied().collect();
    parse_peer(
        |k| props.get_property_val_str(k).map(|s| s.to_string()),
        addrs,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn txt_round_trips_through_parse() {
        let advert = DeviceAdvert {
            device_id: Uuid::from_u128(0x1234),
            name: "studio".into(),
            platform: Platform::Linux,
            fingerprint_hex: "ab".repeat(32),
            protocol_version: 1,
            quic_port: 51820,
            tcp_port: 51821,
        };
        let map: HashMap<String, String> = advert_txt(&advert).into_iter().collect();
        let addr: IpAddr = "192.168.1.7".parse().unwrap();
        let peer = parse_peer(|k| map.get(k).cloned(), vec![addr]).unwrap();

        assert_eq!(peer.device_id, advert.device_id);
        assert_eq!(peer.name, "studio");
        assert_eq!(peer.platform, Platform::Linux);
        assert_eq!(peer.fingerprint_hex, advert.fingerprint_hex);
        assert_eq!(peer.protocol_version, 1);
        assert_eq!(peer.quic_port, 51820);
        assert_eq!(peer.tcp_port, 51821);
        assert_eq!(peer.addrs, vec![addr]);
    }

    #[test]
    fn parse_rejects_incomplete_advert() {
        let mut map: HashMap<String, String> = HashMap::new();
        map.insert("id".into(), Uuid::nil().to_string());
        // Missing platform/fp/ver/ports → None.
        assert!(parse_peer(|k| map.get(k).cloned(), vec![]).is_none());
    }

    #[test]
    fn best_addr_prefers_routable_ipv4_and_skips_link_local() {
        let mut peer = parse_peer(
            |k| {
                [
                    ("id", Uuid::nil().to_string()),
                    ("platform", "linux".into()),
                    ("fp", "aa".into()),
                    ("ver", "1".into()),
                    ("quic", "1".into()),
                    ("tcp", "2".into()),
                ]
                .iter()
                .find(|(kk, _)| *kk == k)
                .map(|(_, v)| v.clone())
            },
            vec![
                "fe80::1".parse().unwrap(),      // link-local IPv6 — skip
                "127.0.0.1".parse().unwrap(),    // loopback — skip
                "192.168.1.20".parse().unwrap(), // routable — pick this
            ],
        )
        .unwrap();
        assert_eq!(peer.best_addr(), Some("192.168.1.20".parse().unwrap()));

        peer.addrs = vec!["fe80::1".parse().unwrap()];
        assert_eq!(peer.best_addr(), None);
    }

    #[test]
    fn parse_rejects_bad_uuid() {
        let mut map: HashMap<String, String> = HashMap::new();
        for (k, v) in [
            ("id", "not-a-uuid"),
            ("platform", "linux"),
            ("fp", "aa"),
            ("ver", "1"),
            ("quic", "1"),
            ("tcp", "2"),
        ] {
            map.insert(k.into(), v.into());
        }
        assert!(parse_peer(|k| map.get(k).cloned(), vec![]).is_none());
    }
}

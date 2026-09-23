// SPDX-License-Identifier: AGPL-3.0-only
//! A bounded HTTPS sender for ciphertext webhook bodies. No route or worker
//! invokes this module until endpoint secret custody and the inbound outbox
//! are wired. The network firewall remains a required second SSRF boundary.

use hmac::{Hmac, Mac};
use reqwest::{Url, redirect, retry};
use sha2::Sha256;
use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

const MAX_BODY_BYTES: usize = 65_536;
const MAX_DNS_ADDRESSES: usize = 16;
const WEBHOOK_PORT: u16 = 443;

#[derive(Debug, thiserror::Error)]
pub enum EgressError {
    #[error("invalid webhook target or payload")]
    InvalidInput,
    #[error("webhook DNS resolution is unsafe or unavailable")]
    UnsafeResolution,
    #[error("webhook transport is unavailable")]
    Transport,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DeliveryResponse {
    pub status: u16,
    pub acknowledged: bool,
}

/// Parse once at endpoint creation and again immediately before delivery.
/// Literal IPs, userinfo, fragments, local names and nonstandard ports are
/// refused; the resolved addresses get a separate connect-time check.
pub fn validate_target(raw: &str) -> Result<Url, EgressError> {
    if raw.len() > 2048
        || raw
            .bytes()
            .any(|byte| byte.is_ascii_whitespace() || byte == b'\\')
    {
        return Err(EgressError::InvalidInput);
    }
    let url = Url::parse(raw).map_err(|_| EgressError::InvalidInput)?;
    if url.scheme() != "https"
        || !url.username().is_empty()
        || url.password().is_some()
        || url.fragment().is_some()
        || url.port_or_known_default() != Some(WEBHOOK_PORT)
    {
        return Err(EgressError::InvalidInput);
    }
    let Some(host) = url.host_str() else {
        return Err(EgressError::InvalidInput);
    };
    if host.parse::<IpAddr>().is_ok()
        || host.len() > 253
        || host.ends_with('.')
        || !host.contains('.')
        || [
            ".local",
            ".localhost",
            ".internal",
            ".test",
            ".invalid",
            ".example",
            ".onion",
        ]
        .iter()
        .any(|suffix| host.ends_with(suffix))
        || host.split('.').any(|label| {
            label.is_empty()
                || label.len() > 63
                || label.starts_with('-')
                || label.ends_with('-')
                || !label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        })
    {
        return Err(EgressError::InvalidInput);
    }
    Ok(url)
}

/// Reject the entire DNS answer if any candidate is unsafe. Never fall back
/// to an unvalidated resolver answer on connect, retry or redirect.
pub fn validate_resolved_addresses(addrs: &[SocketAddr]) -> Result<(), EgressError> {
    if addrs.is_empty()
        || addrs.len() > MAX_DNS_ADDRESSES
        || addrs
            .iter()
            .any(|addr| addr.port() != WEBHOOK_PORT || !public_ip(addr.ip()))
    {
        return Err(EgressError::UnsafeResolution);
    }
    Ok(())
}

fn public_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => public_ipv4(v4),
        IpAddr::V6(v6) => public_ipv6(v6),
    }
}

fn public_ipv4(ip: Ipv4Addr) -> bool {
    let [a, b, c, _] = ip.octets();
    match a {
        0 | 10 | 127 | 224..=255 => false,
        100 if (64..=127).contains(&b) => false, // shared carrier space
        169 if b == 254 => false,                // link local / metadata
        172 if (16..=31).contains(&b) => false,
        192 if b == 168 => false,
        192 if b == 0 && c == 0 => false,
        192 if b == 0 && c == 2 => false,
        192 if b == 88 && c == 99 => false,
        198 if b == 18 || b == 19 => false,
        198 if b == 51 && c == 100 => false,
        203 if b == 0 && c == 113 => false,
        _ => true,
    }
}

fn public_ipv6(ip: Ipv6Addr) -> bool {
    let segments = ip.segments();
    // Public unicast only, with conservative exclusions for transition,
    // documentation and special-purpose allocations.
    if segments[0] & 0xe000 != 0x2000 {
        return false;
    }
    if segments[0] == 0x2002 || segments[0] == 0x3fff {
        return false;
    }
    if segments[0] == 0x2001 && (segments[1] <= 0x01ff || segments[1] == 0x0db8) {
        return false;
    }
    true
}

/// The receiver checks a five-minute timestamp window and deduplicates the
/// event ID inside the signed raw body. The signature is lowercase hex of
/// HMAC-SHA256(timestamp-as-ASCII || '.' || exact body bytes).
pub fn signature_header(
    secret: &[u8],
    timestamp_secs: u64,
    body: &[u8],
) -> Result<String, EgressError> {
    if secret.len() < 32 || body.is_empty() || body.len() > MAX_BODY_BYTES {
        return Err(EgressError::InvalidInput);
    }
    let mut mac = Hmac::<Sha256>::new_from_slice(secret).map_err(|_| EgressError::InvalidInput)?;
    mac.update(timestamp_secs.to_string().as_bytes());
    mac.update(b".");
    mac.update(body);
    let digest = mac.finalize().into_bytes();
    let mut signature = String::with_capacity(3 + 64);
    signature.push_str("v1=");
    for byte in digest {
        use std::fmt::Write as _;
        write!(&mut signature, "{byte:02x}").expect("writing to String cannot fail");
    }
    Ok(signature)
}

/// This call performs one network attempt. Outbox retry, tenant isolation,
/// secret decryption and event-body construction are separate responsibilities.
pub async fn post_signed(
    raw_url: &str,
    body: &[u8],
    secret: &[u8],
) -> Result<DeliveryResponse, EgressError> {
    let url = validate_target(raw_url)?;
    if body.is_empty() || body.len() > MAX_BODY_BYTES {
        return Err(EgressError::InvalidInput);
    }
    let host = url.host_str().ok_or(EgressError::InvalidInput)?;
    let answers = tokio::time::timeout(
        Duration::from_secs(2),
        tokio::net::lookup_host((host, WEBHOOK_PORT)),
    )
    .await
    .map_err(|_| EgressError::UnsafeResolution)?
    .map_err(|_| EgressError::UnsafeResolution)?;
    let addrs: Vec<SocketAddr> = answers.take(MAX_DNS_ADDRESSES + 1).collect();
    validate_resolved_addresses(&addrs)?;

    let timestamp_secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| EgressError::Transport)?
        .as_secs();
    let signature = signature_header(secret, timestamp_secs, body)?;
    // Build per attempt: no pooled connection or DNS lookup can outlive the
    // validated answer. The URL hostname remains the TLS SNI/certificate name.
    let client = reqwest::Client::builder()
        .no_proxy()
        .redirect(redirect::Policy::none())
        .retry(retry::never())
        .https_only(true)
        .http1_only()
        .http1_max_headers(32)
        .connect_timeout(Duration::from_secs(3))
        .timeout(Duration::from_secs(10))
        .pool_max_idle_per_host(0)
        .resolve_to_addrs(host, &addrs)
        .build()
        .map_err(|_| EgressError::Transport)?;
    let response = client
        .post(url)
        .header("content-type", "application/json")
        .header("x-zrotext-timestamp", timestamp_secs.to_string())
        .header("x-zrotext-signature", signature)
        .body(body.to_vec())
        .send()
        .await
        .map_err(|_| EgressError::Transport)?;
    // Do not consume the untrusted response body. Its read size is zero.
    Ok(DeliveryResponse {
        status: response.status().as_u16(),
        acknowledged: response.status().is_success(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn target_parser_and_dns_answer_fail_closed() {
        assert!(validate_target("https://hooks.example.org/v1/inbox?group=1").is_ok());
        for raw in [
            "http://hooks.example.org/",
            "https://127.0.0.1/hook",
            "https://[::1]/hook",
            "https://user:pass@hooks.example.org/hook",
            "https://hooks.example.org:8080/hook",
            "https://hooks.example.org/hook#fragment",
            "https://receiver.local/hook",
            "https://foo..org/hook",
            "https://foo.example/hook",
            " https://hooks.example.org/hook",
            "https:\\hooks.example.org/hook",
        ] {
            assert!(validate_target(raw).is_err(), "accepted {raw}");
        }
        let public = SocketAddr::from(([8, 8, 8, 8], 443));
        assert!(validate_resolved_addresses(&[public]).is_ok());
        for unsafe_ip in [
            "127.0.0.1",
            "10.0.0.1",
            "100.64.0.1",
            "169.254.169.254",
            "172.16.1.1",
            "192.168.1.1",
            "192.0.2.1",
            "198.19.1.1",
            "198.51.100.1",
            "203.0.113.1",
            "224.0.0.1",
            "::1",
            "::ffff:127.0.0.1",
            "fe80::1",
            "fc00::1",
            "2001:db8::1",
            "2002::1",
        ] {
            let address = SocketAddr::new(unsafe_ip.parse().unwrap(), 443);
            assert!(
                validate_resolved_addresses(&[public, address]).is_err(),
                "accepted {unsafe_ip}"
            );
        }
        assert!(
            validate_resolved_addresses(&[SocketAddr::new(
                "2606:4700:4700::1111".parse().unwrap(),
                443
            )])
            .is_ok()
        );
        assert!(validate_resolved_addresses(&[SocketAddr::from(([8, 8, 8, 8], 80))]).is_err());
    }

    #[test]
    fn signature_uses_exact_raw_body_and_timestamp() {
        let secret = b"0123456789abcdef0123456789abcdef";
        let body = br#"{"event":"test"}"#;
        let signed = signature_header(secret, 1_700_000_000, body).unwrap();
        assert_eq!(
            signed,
            "v1=036f0ddc8ddd72da03802b4a2b49547d6516ad1a6a5347527a093387536cb405"
        );
        assert_ne!(
            signed,
            signature_header(secret, 1_700_000_001, body).unwrap()
        );
        assert_ne!(
            signed,
            signature_header(secret, 1_700_000_000, br#"{ "event":"test"}"#).unwrap()
        );
        assert!(signature_header(b"short", 1_700_000_000, body).is_err());
    }
}

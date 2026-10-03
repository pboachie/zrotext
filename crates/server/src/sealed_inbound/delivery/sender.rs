// SPDX-License-Identifier: AGPL-3.0-only
//! Establish TLS without releasing signed headers or opaque content. The caller
//! rechecks its held authority after this awaited operation and before `send`.
use crate::webhook_egress::{self, DeliveryResponse, EgressError};
use std::{
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::time::Instant;

pub(super) trait Stream: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Stream for T {}
pub(super) struct Connection {
    stream: Box<dyn Stream>,
    target: String,
    host: String,
}

pub(super) async fn connect(raw: &str) -> Result<Connection, EgressError> {
    let url = webhook_egress::validate_target(raw)?;
    let host = url.host_str().ok_or(EgressError::InvalidInput)?.to_owned();
    let answers = tokio::time::timeout(
        Duration::from_secs(2),
        tokio::net::lookup_host((host.as_str(), 443)),
    )
    .await
    .map_err(|_| EgressError::ResolutionUnavailable)?
    .map_err(|_| EgressError::ResolutionUnavailable)?;
    let addresses: Vec<_> = answers.take(17).collect();
    webhook_egress::validate_resolved_addresses(&addresses)?;
    // One pinned answer, one connect, no retry or alternative resolver.
    let socket = tokio::net::TcpStream::connect(addresses[0])
        .await
        .map_err(|_| EgressError::Transport)?;
    let mut target = url.path().to_owned();
    if let Some(query) = url.query() {
        target.push('?');
        target.push_str(query);
    }
    establish_tls(
        socket,
        webhook_egress::shared_tls_config().await?,
        host,
        target,
    )
    .await
}

async fn establish_tls(
    socket: impl Stream + 'static,
    config: &rustls::ClientConfig,
    host: String,
    target: String,
) -> Result<Connection, EgressError> {
    let tls = tokio_rustls::TlsConnector::from(Arc::new(config.clone()));
    let server = rustls::pki_types::ServerName::try_from(host.clone())
        .map_err(|_| EgressError::InvalidInput)?;
    let stream = tls
        .connect(server, socket)
        .await
        .map_err(|_| EgressError::Transport)?;
    Ok(Connection {
        stream: Box::new(stream),
        target,
        host,
    })
}

#[cfg(test)]
fn tls_configs(trusted: bool) -> (rustls::ClientConfig, rustls::ServerConfig) {
    let identity = rcgen::generate_simple_self_signed(vec!["hooks.example.org".into()]).unwrap();
    let certificate = identity.cert.der().clone();
    let mut roots = rustls::RootCertStore::empty();
    if trusted {
        roots.add(certificate.clone()).unwrap();
    }
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let mut client = rustls::ClientConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
    client.alpn_protocols = vec![b"http/1.1".to_vec()];
    let key = rustls::pki_types::PrivatePkcs8KeyDer::from(identity.signing_key.serialize_der());
    let mut server = rustls::ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(vec![certificate], key.into())
        .unwrap();
    server.alpn_protocols = vec![b"http/1.1".to_vec()];
    (client, server)
}

#[cfg(test)]
pub(super) async fn synthetic_tls_pair() -> (
    Connection,
    tokio_rustls::server::TlsStream<tokio::io::DuplexStream>,
) {
    let (client, server) = tls_configs(true);
    let (outbound, inbound) = tokio::io::duplex(65_536);
    let server = tokio_rustls::TlsAcceptor::from(Arc::new(server));
    let (connected, accepted) = tokio::join!(
        establish_tls(
            outbound,
            &client,
            "hooks.example.org".into(),
            "/inbox".into()
        ),
        server.accept(inbound)
    );
    (connected.unwrap(), accepted.unwrap())
}

impl Connection {
    #[cfg(test)]
    pub(super) fn synthetic(stream: impl Stream + 'static) -> Self {
        Self {
            stream: Box::new(stream),
            target: "/inbox".into(),
            host: "hooks.example.org".into(),
        }
    }
    /// First signed request write is the irreversible boundary. The same fixed
    /// deadline bounds partial writes and status reads; a timeout is uncertain,
    /// never evidence that the receiver saw no content. Receiver dedup is mandatory.
    pub(super) async fn send(
        mut self,
        body: &[u8],
        secret: &[u8],
        deadline: Instant,
    ) -> Result<DeliveryResponse, EgressError> {
        if Instant::now() >= deadline {
            return Err(EgressError::Transport);
        }
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| EgressError::Transport)?
            .as_secs();
        let signature = webhook_egress::signature_header(secret, timestamp, body)?;
        let headers = format!(
            "POST {} HTTP/1.1\r\nHost: {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\nX-Zrotext-Timestamp: {}\r\nX-Zrotext-Signature: {}\r\n\r\n",
            self.target,
            self.host,
            body.len(),
            timestamp,
            signature
        );
        tokio::time::timeout_at(deadline, async {
            self.stream
                .write_all(headers.as_bytes())
                .await
                .map_err(|_| EgressError::Transport)?;
            self.stream
                .write_all(body)
                .await
                .map_err(|_| EgressError::Transport)?;
            self.stream
                .flush()
                .await
                .map_err(|_| EgressError::Transport)?;
            // Read exactly one header byte at a time; never consume any response
            // body. No redirect, informational response or second status accepted.
            let mut header = Vec::with_capacity(256);
            while !header.ends_with(b"\r\n\r\n") {
                if header.len() >= 8192 {
                    return Err(EgressError::Transport);
                }
                header.push(
                    self.stream
                        .read_u8()
                        .await
                        .map_err(|_| EgressError::Transport)?,
                );
            }
            status(&header)
        })
        .await
        .map_err(|_| EgressError::Transport)?
    }
}

fn status(raw: &[u8]) -> Result<DeliveryResponse, EgressError> {
    let text = std::str::from_utf8(raw).map_err(|_| EgressError::Transport)?;
    let mut lines = text.split("\r\n");
    let first = lines.next().ok_or(EgressError::Transport)?;
    let b = first.as_bytes();
    if b.len() < 13
        || &b[..9] != b"HTTP/1.1 "
        || !b[9..12].iter().all(u8::is_ascii_digit)
        || b[12] != b' '
        || b[13..].iter().any(|v| !matches!(v, 32..=126))
    {
        return Err(EgressError::Transport);
    }
    let code: u16 = first[9..12].parse().map_err(|_| EgressError::Transport)?;
    if !(200..=599).contains(&code) {
        return Err(EgressError::Transport);
    }
    for (index, line) in lines.take_while(|line| !line.is_empty()).enumerate() {
        if index >= 32 {
            return Err(EgressError::Transport);
        }
        let Some((name, value)) = line.split_once(':') else {
            return Err(EgressError::Transport);
        };
        if name.is_empty()
            || !name
                .bytes()
                .all(|v| v.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&v))
            || value.bytes().any(|v| !matches!(v, 9 | 32..=126))
        {
            return Err(EgressError::Transport);
        }
    }
    Ok(DeliveryResponse {
        status: code,
        acknowledged: (200..300).contains(&code),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn bounded_status_refuses_interim_duplicate_and_malformed_lines() {
        assert!(
            status(b"HTTP/1.1 204 No Content\r\nX-Test: ok\r\n\r\n")
                .unwrap()
                .acknowledged
        );
        assert!(
            !status(b"HTTP/1.1 302 Found\r\nLocation: /other\r\n\r\n")
                .unwrap()
                .acknowledged
        );
        for bad in [
            b"HTTP/1.1 100 Continue\r\n\r\n".as_slice(),
            b"HTTP/1.1 200 OK\r\nHTTP/1.1 200 OK\r\n\r\n",
            b"HTTP/1.1 200 OK\r\n folded\r\n\r\n",
            b"HTTP/1.1 200xOK\r\n\r\n",
        ] {
            assert!(status(bad).is_err());
        }
    }

    #[tokio::test]
    async fn real_tls_handshake_writes_no_http_before_explicit_send() {
        let (connection, mut received) = synthetic_tls_pair().await;
        assert!(
            tokio::time::timeout(Duration::from_millis(20), received.read_u8())
                .await
                .is_err()
        );
        let recipient = tokio::spawn(async move {
            let mut bytes = Vec::new();
            while !bytes.ends_with(b"\r\n\r\n") {
                bytes.push(received.read_u8().await.unwrap());
            }
            let mut body = [0u8; 3];
            received.read_exact(&mut body).await.unwrap();
            assert_eq!(&body, b"abc");
            received
                .write_all(b"HTTP/1.1 204 No Content\r\n\r\n")
                .await
                .unwrap();
        });
        assert!(
            connection
                .send(
                    b"abc",
                    &crate::test_keys::key(127),
                    Instant::now() + Duration::from_secs(2)
                )
                .await
                .unwrap()
                .acknowledged
        );
        recipient.await.unwrap();
    }

    #[tokio::test]
    async fn real_tls_untrusted_certificate_refuses_connection_before_http() {
        let (client, server) = tls_configs(false);
        let (outbound, inbound) = tokio::io::duplex(65_536);
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server));
        let (result, accepted) = tokio::join!(
            establish_tls(
                outbound,
                &client,
                "hooks.example.org".into(),
                "/inbox".into()
            ),
            acceptor.accept(inbound)
        );
        assert!(result.is_err());
        assert!(accepted.is_err());
    }
}

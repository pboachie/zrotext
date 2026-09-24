// SPDX-License-Identifier: AGPL-3.0-only
//! The one production PostgreSQL transport policy for server and operator tools.

use std::{
    env,
    fs::File,
    future::Future,
    net::IpAddr,
    path::Path,
    sync::{
        Arc, OnceLock,
        atomic::{AtomicBool, Ordering},
    },
};
use tokio_postgres::{
    Client, Config,
    config::{Host, SslMode},
};
use tokio_postgres_rustls::MakeRustlsConnect;

static TLS_CONFIG: OnceLock<Result<Arc<rustls::ClientConfig>, String>> = OnceLock::new();
static PLAINTEXT_WARNING: AtomicBool = AtomicBool::new(false);

#[derive(Debug, thiserror::Error)]
pub enum ConnectError {
    #[error("invalid PostgreSQL transport configuration: {0}")]
    Configuration(String),
    #[error("PostgreSQL connection failed: {0}")]
    Database(#[from] tokio_postgres::Error),
}

pub async fn connect(
    url: &str,
) -> Result<
    (
        Client,
        impl Future<Output = Result<(), tokio_postgres::Error>> + Send + use<>,
    ),
    ConnectError,
> {
    let config: Config = url.parse()?;
    connect_config(config).await
}

pub async fn connect_config(
    config: Config,
) -> Result<
    (
        Client,
        impl Future<Output = Result<(), tokio_postgres::Error>> + Send + use<>,
    ),
    ConnectError,
> {
    let allow_plaintext = match env::var("DATABASE_ALLOW_PLAINTEXT") {
        Ok(value) if value == "true" => true,
        Ok(value) if value == "false" => false,
        Err(env::VarError::NotPresent) => false,
        _ => {
            return Err(ConnectError::Configuration(
                "DATABASE_ALLOW_PLAINTEXT must be true or false".into(),
            ));
        }
    };
    let may_use_plaintext = may_use_plaintext(&config, allow_plaintext)?;
    if may_use_plaintext
        && !local_destination(&config)
        && !PLAINTEXT_WARNING.swap(true, Ordering::Relaxed)
    {
        eprintln!(
            "warning: PostgreSQL transport permits plaintext to a non-local host; set sslmode=require for verified TLS"
        );
    }
    let tls = TLS_CONFIG
        .get_or_init(load_tls_config)
        .as_ref()
        .map_err(|message| ConnectError::Configuration(message.clone()))?;
    let tls = MakeRustlsConnect::new((**tls).clone());
    Ok(config.connect(tls).await?)
}

fn may_use_plaintext(config: &Config, allow_plaintext: bool) -> Result<bool, ConnectError> {
    let may_use_plaintext = match config.get_ssl_mode() {
        SslMode::Require => false,
        SslMode::Prefer | SslMode::Disable => true,
        _ => return Err(ConnectError::Configuration("unsupported sslmode".into())),
    };
    if may_use_plaintext && !local_destination(config) && !allow_plaintext {
        return Err(ConnectError::Configuration(
            "non-local PostgreSQL requires sslmode=require, or DATABASE_ALLOW_PLAINTEXT=true"
                .into(),
        ));
    }
    Ok(may_use_plaintext)
}

fn local_destination(config: &Config) -> bool {
    config.get_hosts().iter().all(|host| match host {
        #[cfg(unix)]
        Host::Unix(_) => true,
        Host::Tcp(name) if matches!(name.as_str(), "localhost" | "db") => true,
        Host::Tcp(name) => name.parse::<IpAddr>().is_ok_and(|ip| ip.is_loopback()),
    })
}

fn load_tls_config() -> Result<Arc<rustls::ClientConfig>, String> {
    let mut roots = rustls::RootCertStore::empty();
    if let Some(path) = env::var_os("DATABASE_TLS_CA_FILE") {
        let path = Path::new(&path);
        let file = File::open(path)
            .map_err(|error| format!("cannot open DATABASE_TLS_CA_FILE: {error}"))?;
        let mut reader = std::io::BufReader::new(file);
        let certs = rustls_pemfile::certs(&mut reader)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| format!("cannot read DATABASE_TLS_CA_FILE certificates: {error}"))?;
        for certificate in certs {
            roots
                .add(certificate)
                .map_err(|error| format!("invalid DATABASE_TLS_CA_FILE certificate: {error}"))?;
        }
    } else {
        let native = rustls_native_certs::load_native_certs();
        for certificate in native.certs {
            roots
                .add(certificate)
                .map_err(|error| format!("invalid system CA certificate: {error}"))?;
        }
    }
    if roots.is_empty() {
        return Err("no trusted PostgreSQL CA certificates found".into());
    }
    let config = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .map_err(|error| format!("cannot initialize PostgreSQL TLS: {error}"))?
    .with_root_certificates(roots)
    .with_no_client_auth();
    Ok(Arc::new(config))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy(url: &str, allow: bool) -> Result<bool, ConnectError> {
        may_use_plaintext(&url.parse::<Config>().unwrap(), allow)
    }

    #[test]
    fn remote_hosts_require_verified_tls_by_default() {
        for url in [
            "postgres://u@writer.example/zrotext",
            "postgres://u@writer.example/zrotext?sslmode=prefer",
            "postgres://u@writer.example/zrotext?sslmode=disable",
        ] {
            assert!(policy(url, false).is_err());
            assert!(policy(url, true).unwrap());
        }
        assert!(!policy("postgres://u@writer.example/zrotext?sslmode=require", false).unwrap());
    }

    #[test]
    fn local_compose_and_loopback_allow_existing_plaintext_mode() {
        for host in ["db", "localhost", "127.0.0.1", "[::1]"] {
            let url = format!("postgres://u@{host}/zrotext?sslmode=disable");
            assert!(policy(&url, false).unwrap());
        }
        assert!(policy("postgres://u@10.0.0.2/zrotext?sslmode=prefer", false).is_err());
    }

    #[tokio::test]
    async fn verified_tls_connection_is_encrypted() {
        let Ok(url) = env::var("ZT_POSTGRES_TLS_TEST_DATABASE_URL") else {
            return;
        };
        let (client, connection) = connect(&url).await.unwrap();
        let driver = tokio::spawn(connection);
        let encrypted: bool = client
            .query_one(
                "SELECT ssl FROM pg_stat_ssl WHERE pid = pg_backend_pid()",
                &[],
            )
            .await
            .unwrap()
            .get(0);
        assert!(encrypted);
        drop(client);
        driver.await.unwrap().unwrap();
    }
}

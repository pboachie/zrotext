// SPDX-License-Identifier: AGPL-3.0-only
//! The one production PostgreSQL transport policy for server and operator tools.

use base64::{Engine, engine::general_purpose::STANDARD};
use std::{
    borrow::Cow,
    env,
    future::Future,
    net::IpAddr,
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
    connect_config(parse_config(url)?).await
}

/// Parse a connection string. Every mode that permits TLS verifies the
/// certificate chain and hostname, so libpq's `verify-full` and `verify-ca`
/// in a `postgres://` URL are accepted as `require` (for `verify-ca`, the
/// hostname check makes this stricter than libpq). Parse failures are
/// configuration errors whose text never includes the URL or its secrets.
pub fn parse_config(url: &str) -> Result<Config, ConnectError> {
    normalize_verified_sslmode(url)
        .parse()
        .map_err(|error| ConnectError::Configuration(describe_parse_error(&error)))
}

/// Apply the full transport policy to a connection string without connecting,
/// so a process can reject an unusable `DATABASE_URL` at startup instead of
/// later reporting the database as unreachable.
pub fn check_url(url: &str) -> Result<(), ConnectError> {
    let config = parse_config(url)?;
    may_use_plaintext(&config, allow_plaintext()?)?;
    tls_config()?;
    Ok(())
}

fn normalize_verified_sslmode(url: &str) -> Cow<'_, str> {
    let Some(rest) = ["postgres://", "postgresql://"]
        .into_iter()
        .find_map(|prefix| url.strip_prefix(prefix))
    else {
        return Cow::Borrowed(url);
    };
    // Mirror tokio-postgres: credentials end at the first '@', and the
    // parameters start at the first '?' after them.
    let after_credentials = rest.find('@').map_or(0, |at| at + 1);
    let Some(query) = rest[after_credentials..].find('?') else {
        return Cow::Borrowed(url);
    };
    let (head, query) = url.split_at(url.len() - rest.len() + after_credentials + query + 1);
    let mut changed = false;
    let params: Vec<&str> = query
        .split('&')
        .map(|param| match param.split_once('=') {
            Some(("sslmode", "verify-full" | "verify-ca")) => {
                changed = true;
                "sslmode=require"
            }
            _ => param,
        })
        .collect();
    if changed {
        Cow::Owned(format!("{head}{}", params.join("&")))
    } else {
        Cow::Borrowed(url)
    }
}

/// Options whose invalid values tokio-postgres reports under a fixed label.
const KNOWN_OPTIONS: &[&str] = &[
    "channel_binding",
    "connect_timeout",
    "host",
    "hostaddr",
    "keepalives",
    "keepalives_idle",
    "keepalives_interval",
    "keepalives_retries",
    "load_balance_hosts",
    "port",
    "sslnegotiation",
    "target_session_attrs",
    "tcp_user_timeout",
];

/// Map a parse failure to a fixed diagnostic. Cause text is only compared
/// against fixed strings and never copied, because some causes carry parts of
/// the connection string (an unknown option name, or text around a misquoted
/// value), which can include credentials.
fn describe_parse_error(error: &tokio_postgres::Error) -> String {
    let detail = std::error::Error::source(error).map(ToString::to_string);
    let detail = detail.as_deref().unwrap_or_default();
    if detail == "invalid value for option `sslmode`" {
        return "unsupported sslmode; use sslmode=require (certificate chain and hostname are \
                always verified), prefer, or disable; postgres:// URLs also accept verify-full \
                and verify-ca as require"
            .into();
    }
    if let Some(option) = KNOWN_OPTIONS
        .iter()
        .find(|option| detail == format!("invalid value for option `{option}`"))
    {
        return format!("invalid value for PostgreSQL connection option {option}");
    }
    if detail.starts_with("unknown option `") {
        return "PostgreSQL connection string contains an unsupported option".into();
    }
    "cannot parse PostgreSQL connection string".into()
}

fn allow_plaintext() -> Result<bool, ConnectError> {
    match env::var("DATABASE_ALLOW_PLAINTEXT") {
        Ok(value) if value == "true" => Ok(true),
        Ok(value) if value == "false" => Ok(false),
        Err(env::VarError::NotPresent) => Ok(false),
        _ => Err(ConnectError::Configuration(
            "DATABASE_ALLOW_PLAINTEXT must be true or false".into(),
        )),
    }
}

fn tls_config() -> Result<&'static Arc<rustls::ClientConfig>, ConnectError> {
    TLS_CONFIG
        .get_or_init(load_tls_config)
        .as_ref()
        .map_err(|message| ConnectError::Configuration(message.clone()))
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
    let may_use_plaintext = may_use_plaintext(&config, allow_plaintext()?)?;
    if may_use_plaintext
        && !local_destination(&config)
        && !PLAINTEXT_WARNING.swap(true, Ordering::Relaxed)
    {
        eprintln!(
            "warning: PostgreSQL transport permits plaintext to a non-local host; set sslmode=require for verified TLS"
        );
    }
    let tls = MakeRustlsConnect::new((**tls_config()?).clone());
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

/// Only destinations that cannot leave this host count as local. A service
/// name such as Compose's `db` is ordinary DNS and may resolve to another node,
/// so plaintext to it needs the explicit, warned `DATABASE_ALLOW_PLAINTEXT`.
fn local_destination(config: &Config) -> bool {
    config.get_hosts().iter().all(|host| match host {
        #[cfg(unix)]
        Host::Unix(_) => true,
        Host::Tcp(name) if name == "localhost" => true,
        Host::Tcp(name) => name.parse::<IpAddr>().is_ok_and(|ip| ip.is_loopback()),
    })
}

fn load_tls_config() -> Result<Arc<rustls::ClientConfig>, String> {
    let mut roots = rustls::RootCertStore::empty();
    if let Ok(encoded) = env::var("DATABASE_TLS_CA_PEM_B64") {
        if encoded.len() > 512 * 1024 {
            return Err("DATABASE_TLS_CA_PEM_B64 exceeds 512 KiB".into());
        }
        let pem = STANDARD
            .decode(encoded)
            .map_err(|_| "DATABASE_TLS_CA_PEM_B64 is not valid base64".to_string())?;
        let certs = rustls_pemfile::certs(&mut pem.as_slice())
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| {
                format!("cannot read DATABASE_TLS_CA_PEM_B64 certificates: {error}")
            })?;
        for certificate in certs {
            roots
                .add(certificate)
                .map_err(|error| format!("invalid DATABASE_TLS_CA_PEM_B64 certificate: {error}"))?;
        }
    } else if env::var_os("DATABASE_TLS_CA_PEM_B64").is_none() {
        let native = rustls_native_certs::load_native_certs();
        for certificate in native.certs {
            roots
                .add(certificate)
                .map_err(|error| format!("invalid system CA certificate: {error}"))?;
        }
    } else {
        return Err("DATABASE_TLS_CA_PEM_B64 must be valid UTF-8".into());
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
    fn loopback_allows_existing_plaintext_mode() {
        for host in ["localhost", "127.0.0.1", "[::1]"] {
            let url = format!("postgres://u@{host}/zrotext?sslmode=disable");
            assert!(policy(&url, false).unwrap());
        }
        assert!(policy("postgres://u@10.0.0.2/zrotext?sslmode=prefer", false).is_err());
    }

    #[test]
    fn service_names_need_explicit_plaintext_opt_in_and_warn() {
        for url in [
            "postgres://u@db/zrotext?sslmode=disable",
            "postgres://u@db:5432/zrotext",
            "postgres://u@localhost,db/zrotext?sslmode=prefer",
        ] {
            assert!(policy(url, false).is_err(), "{url}");
            assert!(policy(url, true).unwrap(), "{url}");
            // Opted-in plaintext to a name that may resolve remotely warns.
            assert!(!local_destination(&url.parse().unwrap()), "{url}");
        }
        assert!(!policy("postgres://u@db/zrotext?sslmode=require", false).unwrap());
    }

    #[test]
    fn libpq_verified_sslmodes_parse_as_verified_tls() {
        for mode in ["verify-full", "verify-ca"] {
            for scheme in ["postgres", "postgresql"] {
                let url = format!(
                    "{scheme}://u:p%40ss@writer.example:6543/zrotext?application_name=api&sslmode={mode}&connect_timeout=5"
                );
                let config = parse_config(&url).unwrap();
                assert_eq!(config.get_ssl_mode(), SslMode::Require);
                assert_eq!(config.get_ports(), [6543]);
                assert_eq!(config.get_dbname(), Some("zrotext"));
                assert_eq!(config.get_application_name(), Some("api"));
                assert_eq!(config.get_password(), Some(&b"p@ss"[..]));
                assert!(!may_use_plaintext(&config, false).unwrap());
            }
        }
    }

    #[test]
    fn sslmode_normalization_leaves_credentials_and_other_modes_alone() {
        let config =
            parse_config("postgres://u:<sslmode=verify-full>@db/zrotext?sslmode=disable").unwrap();
        assert_eq!(config.get_password(), Some(&b"<sslmode=verify-full>"[..]));
        assert_eq!(config.get_ssl_mode(), SslMode::Disable);
        let config = parse_config("host=writer.example sslmode=require dbname=zrotext").unwrap();
        assert_eq!(config.get_ssl_mode(), SslMode::Require);
    }

    #[test]
    fn invalid_connection_strings_are_redacted_configuration_errors() {
        for url in [
            "postgres://u:<secret>@writer.example/zrotext?sslmode=allow",
            "host=writer.example password=hunter2-secret sslmode=verify-full",
        ] {
            let Err(ConnectError::Configuration(message)) = parse_config(url) else {
                panic!("expected a configuration error");
            };
            assert!(message.contains("unsupported sslmode"), "{message}");
            assert!(!message.contains("hunter2") && !message.contains("<secret>"));
        }
        let Err(ConnectError::Configuration(message)) =
            parse_config("postgres://u:<secret>@writer.example/zrotext?sslrootcert=ca.pem")
        else {
            panic!("expected a configuration error");
        };
        assert!(message.contains("unsupported option"), "{message}");
        assert!(!message.contains("<secret>") && !message.contains("ca.pem"));
        let Err(ConnectError::Configuration(message)) =
            parse_config("postgres://u@writer.example/zrotext?connect_timeout=soon")
        else {
            panic!("expected a configuration error");
        };
        assert_eq!(
            message,
            "invalid value for PostgreSQL connection option connect_timeout"
        );
        assert!(matches!(
            check_url("postgres://u@writer.example/zrotext?sslmode=verify-any"),
            Err(ConnectError::Configuration(_))
        ));
    }

    const UNPARSEABLE: &str = "cannot parse PostgreSQL connection string";
    const UNSUPPORTED_OPTION: &str = "PostgreSQL connection string contains an unsupported option";

    /// Inputs whose tokio-postgres parse errors echo caller-supplied text,
    /// with the fixed diagnostic each must produce instead.
    const LEAKY_CONNECTION_STRINGS: &[(&str, &str)] = &[
        // A misquoted password: causes quote or point into the input.
        (
            "host=writer.example password='zt-leak-marker dbname=zrotext",
            UNPARSEABLE,
        ),
        (
            "host=writer.example password='zt' zt-leak-marker dbname=zrotext",
            UNPARSEABLE,
        ),
        (
            "host=writer.example password = 'zt-leak-marker\\",
            UNPARSEABLE,
        ),
        ("host=writer.example password=''zt-leak-marker", UNPARSEABLE),
        // An unknown option name is copied into the cause verbatim.
        (
            "postgres://u@writer.example/zrotext?zt-leak-marker=1",
            UNSUPPORTED_OPTION,
        ),
        ("host=writer.example zt-leak-marker=1", UNSUPPORTED_OPTION),
        // A percent-decoded newline in an option name.
        (
            "postgres://u@writer.example/zrotext?%0Azt-leak-marker%0A=1",
            UNSUPPORTED_OPTION,
        ),
    ];

    #[test]
    fn parse_errors_are_fixed_diagnostics_that_never_echo_input() {
        for (url, expected) in LEAKY_CONNECTION_STRINGS {
            let error = match parse_config(url) {
                Err(error @ ConnectError::Configuration(_)) => error,
                Err(error) => panic!("expected a configuration error, got {error:?}"),
                Ok(_) => panic!("expected {url:?} to be rejected"),
            };
            let ConnectError::Configuration(message) = &error else {
                unreachable!()
            };
            assert_eq!(message, expected, "{url:?}");
            for text in [error.to_string(), format!("{error:?}")] {
                assert!(!text.contains("zt-leak-marker"), "{url:?} leaked: {text:?}");
                assert!(!text.contains('\n'), "{url:?} injected a newline: {text:?}");
            }
        }
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

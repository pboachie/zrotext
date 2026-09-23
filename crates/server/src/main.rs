// SPDX-License-Identifier: AGPL-3.0-only
use axum::{
    Json, Router,
    extract::{
        State,
        ws::{Message, WebSocketUpgrade},
    },
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::get,
};
use base64::{Engine, engine::general_purpose::STANDARD};
use serde::Serialize;
use std::{
    env,
    net::SocketAddr,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};
use subtle::ConstantTimeEq;
use tokio::sync::Notify;
use tokio_postgres::NoTls;
use uuid::Uuid;
use zeroize::Zeroizing;
use zrotext_delivery_store::DeliveryStore;
use zrotext_server::{
    alpha_policy::AlphaPolicy,
    auth::TokenHasher,
    device_socket::{self, DeviceSocketState},
    enrollment::EnrollmentHasher,
    http_auth::{
        self, AuthHttpState, DisabledVerificationDispatcher, SmtpVerificationDispatcher,
        VerificationDispatcher,
    },
    http_enrollment::{self, EnrollmentHttpState},
    http_messages::{self, MessagesHttpState},
    http_webhooks::{self, WebhookHttpState},
    webhook_worker::{self, WebhookSecretVault},
};

#[derive(Clone)]
struct Config {
    database_url: String,
    site_id: String,
    instance_id: String,
    deployment_epoch: i64,
    m0_test_token: Option<String>,
    alpha_policy: Arc<AlphaPolicy>,
    dispatch_runtime_enabled: bool,
    draining: Arc<AtomicBool>,
    drain_notify: Arc<Notify>,
}

#[derive(Serialize)]
struct Health {
    status: &'static str,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let (webhook_vault, webhook_delivery_enabled) = webhook_config()?;
    let webhook_management_configured = webhook_vault.is_some();
    let alpha_policy = Arc::new(AlphaPolicy::parse(
        env::var("SYNTHETIC_ALPHA_ENABLED").ok().as_deref(),
        env::var("SYNTHETIC_ALPHA_ALLOWED_ACCOUNT_IDS")
            .ok()
            .as_deref(),
        env::var("SYNTHETIC_ALPHA_ALLOWED_RECIPIENTS")
            .ok()
            .as_deref(),
    )?);
    let dispatch_runtime_enabled = match required("DISPATCH_ENABLED")?.as_str() {
        "false" => false,
        "true" if alpha_policy.enabled() => true,
        _ => return Err("DISPATCH_ENABLED requires explicit synthetic alpha allowlists".into()),
    };
    let inbound_pilot_enabled = match env::var("INBOUND_PILOT_ENABLED").ok().as_deref() {
        None | Some("false") => false,
        Some("true") => true,
        Some(_) => return Err("INBOUND_PILOT_ENABLED must be true or false".into()),
    };
    let config = Arc::new(Config {
        database_url: required("DATABASE_URL")?,
        site_id: required("SITE_ID")?,
        instance_id: required("INSTANCE_ID")?,
        deployment_epoch: required("DEPLOYMENT_EPOCH")?.parse()?,
        m0_test_token: env::var("M0_TEST_TOKEN")
            .ok()
            .filter(|token| token.len() >= 32),
        alpha_policy,
        dispatch_runtime_enabled,
        draining: Arc::new(AtomicBool::new(false)),
        drain_notify: Arc::new(Notify::new()),
    });
    let bind: SocketAddr = env::var("BIND_ADDR")
        .unwrap_or_else(|_| "0.0.0.0:8080".to_owned())
        .parse()?;
    let mut app = Router::new()
        .route(
            "/healthz",
            get(|| async { Json(Health { status: "live" }) }),
        )
        .route("/readyz", get(ready))
        .route("/m0/device-test", get(device_test))
        .with_state(config.clone());
    if let Some((auth_state, enrollment_state)) = account_routes(&config)? {
        ensure_local_site(&config).await?;
        if let Some(vault) = webhook_vault {
            let vault = Arc::new(vault);
            app = app.merge(http_webhooks::router(WebhookHttpState {
                database_url: config.database_url.clone(),
                auth_hasher: auth_state.hasher.clone(),
                canonical_origin: auth_state.canonical_origin.clone(),
                vault: vault.clone(),
            }));
            if webhook_delivery_enabled {
                let worker_database = config.database_url.clone();
                let worker_draining = config.draining.clone();
                let worker_notify = config.drain_notify.clone();
                let worker_id = Uuid::new_v4().to_string();
                tokio::spawn(async move {
                    let mut checks = tokio::time::interval(Duration::from_secs(2));
                    checks.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
                    let mut unavailable_logged = false;
                    loop {
                        tokio::select! {
                            _ = checks.tick() => {
                                if worker_draining.load(Ordering::Acquire) { break; }
                                let result = async {
                                    let (mut client, connection) =
                                        tokio_postgres::connect(&worker_database, NoTls).await
                                            .map_err(|_| "webhook database unavailable")?;
                                    tokio::spawn(async move { let _ = connection.await; });
                                    webhook_worker::dispatch_one(&mut client, &vault, &worker_id).await
                                        .map_err(|_| "webhook dispatch failed")
                                }.await;
                                match result {
                                    Ok(_) => unavailable_logged = false,
                                    Err(_) if !unavailable_logged => {
                                        eprintln!("webhook delivery worker unavailable");
                                        unavailable_logged = true;
                                    }
                                    Err(_) => {}
                                }
                            }
                            _ = worker_notify.notified() => break,
                        }
                    }
                });
            }
        }
        let mail_state = auth_state.clone();
        let message_hasher = auth_state.hasher.clone();
        let mail_draining = config.draining.clone();
        let mail_drain_notify = config.drain_notify.clone();
        tokio::spawn(async move {
            let mut checks = tokio::time::interval(Duration::from_secs(5));
            checks.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            let mut unavailable_logged = false;
            loop {
                tokio::select! {
                    _ = checks.tick() => {
                        if mail_draining.load(Ordering::Acquire) { break; }
                        match http_auth::dispatch_one_verification(&mail_state).await {
                            Ok(_) => unavailable_logged = false,
                            Err(_) if !unavailable_logged => {
                                eprintln!("verification delivery worker unavailable");
                                unavailable_logged = true;
                            }
                            Err(_) => {}
                        }
                    }
                    _ = mail_drain_notify.notified() => break,
                }
            }
        });
        let recovery_database = config.database_url.clone();
        let recovery_draining = config.draining.clone();
        let recovery_drain_notify = config.drain_notify.clone();
        tokio::spawn(async move {
            let mut checks = tokio::time::interval(Duration::from_secs(15));
            checks.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            let mut unavailable_logged = false;
            loop {
                tokio::select! {
                    _ = checks.tick() => {
                        if recovery_draining.load(Ordering::Acquire) { break; }
                        let result = async {
                            let (mut client, connection) =
                                tokio_postgres::connect(&recovery_database, NoTls).await?;
                            tokio::spawn(async move { let _ = connection.await; });
                            let mut store = DeliveryStore::new(&mut client);
                            store.expire_due(100).await?;
                            store.reconcile_silent_attempts(100).await?;
                            store.reconcile_delivery_timeouts(100).await?;
                            Ok::<(), zrotext_delivery_store::StoreError>(())
                        }.await;
                        match result {
                            Ok(()) => unavailable_logged = false,
                            Err(_) if !unavailable_logged => {
                                eprintln!("delivery recovery worker unavailable");
                                unavailable_logged = true;
                            }
                            Err(_) => {}
                        }
                    }
                    _ = recovery_drain_notify.notified() => break,
                }
            }
        });
        let socket_state = DeviceSocketState {
            database_url: config.database_url.clone(),
            site_id: config.site_id.clone(),
            instance_id: config.instance_id.clone(),
            deployment_epoch: config.deployment_epoch,
            enrollment_hasher: enrollment_state.enrollment_hasher.clone(),
            alpha_policy: config.alpha_policy.clone(),
            dispatch_runtime_enabled: config.dispatch_runtime_enabled,
            inbound_pilot_enabled,
            draining: config.draining.clone(),
            drain_notify: config.drain_notify.clone(),
        };
        app = app
            .nest("/v1/auth", http_auth::router(auth_state))
            .nest("/v1/enrollment", http_enrollment::router(enrollment_state))
            .merge(device_socket::router(socket_state));
        if config.alpha_policy.enabled() {
            let message_state = MessagesHttpState::new(
                config.database_url.clone(),
                message_hasher,
                config.alpha_policy.clone(),
            )?;
            app = app.nest("/v1/alpha", http_messages::router(message_state));
        }
    } else if config.alpha_policy.enabled()
        || inbound_pilot_enabled
        || webhook_delivery_enabled
        || webhook_management_configured
    {
        return Err("account routes are required for enabled features".into());
    }
    eprintln!(
        "zrotext site={} instance={} listening={bind}",
        config.site_id, config.instance_id
    );
    let listener = tokio::net::TcpListener::bind(bind).await?;
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal(config))
        .await?;
    Ok(())
}

fn webhook_config() -> Result<(Option<WebhookSecretVault>, bool), Box<dyn std::error::Error>> {
    let delivery_enabled = match env::var("WEBHOOK_DELIVERY_ENABLED").ok().as_deref() {
        None | Some("false") => false,
        Some("true") => true,
        Some(_) => return Err("WEBHOOK_DELIVERY_ENABLED must be true or false".into()),
    };
    let vault = match (env::var("WEBHOOK_KEK_VERSION"), env::var("WEBHOOK_KEK_B64")) {
        (Err(env::VarError::NotPresent), Err(env::VarError::NotPresent)) if !delivery_enabled => {
            None
        }
        (Ok(version), Ok(encoded)) => {
            let version: i32 = version.parse()?;
            let encoded = Zeroizing::new(encoded);
            let decoded = Zeroizing::new(STANDARD.decode(encoded.as_bytes())?);
            Some(WebhookSecretVault::new(version, decoded)?)
        }
        _ => {
            return Err("WEBHOOK_KEK_VERSION and WEBHOOK_KEK_B64 must be supplied together".into());
        }
    };
    Ok((vault, delivery_enabled))
}

fn account_routes(
    config: &Config,
) -> Result<Option<(AuthHttpState, EnrollmentHttpState)>, Box<dyn std::error::Error>> {
    let origin = env::var("AUTH_ORIGIN").ok();
    let auth_pepper = env::var("AUTH_TOKEN_PEPPER_B64").ok();
    let enrollment_pepper = env::var("ENROLLMENT_TOKEN_PEPPER_B64").ok();
    if origin.is_none() && auth_pepper.is_none() && enrollment_pepper.is_none() {
        return Ok(None);
    }
    let origin = origin.ok_or("AUTH_ORIGIN is required when account routes are enabled")?;
    let auth_pepper = auth_pepper.ok_or("AUTH_TOKEN_PEPPER_B64 is required for account routes")?;
    let enrollment_pepper =
        enrollment_pepper.ok_or("ENROLLMENT_TOKEN_PEPPER_B64 is required for enrollment routes")?;
    let auth_pepper = STANDARD
        .decode(auth_pepper)
        .map_err(|_| "AUTH_TOKEN_PEPPER_B64 must be valid base64")?;
    let enrollment_pepper = STANDARD
        .decode(enrollment_pepper)
        .map_err(|_| "ENROLLMENT_TOKEN_PEPPER_B64 must be valid base64")?;
    let auth_hasher = Arc::new(
        TokenHasher::new(auth_pepper)
            .map_err(|_| "AUTH_TOKEN_PEPPER_B64 must decode to at least 32 bytes")?,
    );
    let enrollment_hasher = Arc::new(
        EnrollmentHasher::new(enrollment_pepper)
            .map_err(|_| "ENROLLMENT_TOKEN_PEPPER_B64 must decode to at least 32 bytes")?,
    );
    let dispatcher: Arc<dyn VerificationDispatcher> = match env::var("SMTP_HOST") {
        Ok(host) => {
            let port: u16 = required("SMTP_PORT")?
                .parse()
                .map_err(|_| "SMTP_PORT must be a valid port")?;
            Arc::new(SmtpVerificationDispatcher::new(
                &host,
                port,
                required("SMTP_USERNAME")?,
                required("SMTP_PASSWORD")?,
                &required("SMTP_FROM")?,
                env::var("SMTP_FROM_NAME").ok().as_deref(),
                env::var("SMTP_REPLY_TO").ok().as_deref(),
            )?)
        }
        Err(env::VarError::NotPresent) => Arc::new(DisabledVerificationDispatcher),
        Err(_) => return Err("SMTP_HOST must be valid UTF-8".into()),
    };
    let auth_state = AuthHttpState::new(
        config.database_url.clone(),
        auth_hasher.clone(),
        origin.clone(),
        dispatcher,
    )?;
    let enrollment_state = EnrollmentHttpState::new(
        config.database_url.clone(),
        auth_hasher,
        enrollment_hasher,
        origin,
    );
    Ok(Some((auth_state, enrollment_state)))
}

/// A configured M1 site registers once on a fresh writer. An operator-disabled
/// or draining existing site is never re-enabled by application startup.
async fn ensure_local_site(config: &Config) -> Result<(), Box<dyn std::error::Error>> {
    let (client, connection) = tokio_postgres::connect(&config.database_url, NoTls)
        .await
        .map_err(|_| "site registration unavailable")?;
    tokio::spawn(async move {
        let _ = connection.await;
    });
    client
        .execute(
            "INSERT INTO sites(site_id) VALUES($1) ON CONFLICT(site_id) DO NOTHING",
            &[&config.site_id],
        )
        .await
        .map_err(|_| "site registration unavailable")?;
    let site = client
        .query_one(
            "SELECT enabled,draining FROM sites WHERE site_id=$1",
            &[&config.site_id],
        )
        .await
        .map_err(|_| "site registration unavailable")?;
    if !site.get::<_, bool>(0) || site.get::<_, bool>(1) {
        return Err("configured site is disabled or draining".into());
    }
    Ok(())
}

async fn shutdown_signal(config: Arc<Config>) {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};
        if let Ok(mut terminate) = signal(SignalKind::terminate()) {
            tokio::select! {
                _ = tokio::signal::ctrl_c() => {},
                _ = terminate.recv() => {},
            }
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
    config.draining.store(true, Ordering::Release);
    config.drain_notify.notify_waiters();
}

fn required(key: &'static str) -> Result<String, Box<dyn std::error::Error>> {
    let value = env::var(key)?;
    if value.trim().is_empty() {
        return Err(format!("{key} must not be empty").into());
    }
    Ok(value)
}

async fn ready(
    axum::extract::State(config): axum::extract::State<Arc<Config>>,
) -> (StatusCode, Json<Health>) {
    if config.draining.load(Ordering::Acquire) {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(Health {
                status: "unavailable",
            }),
        );
    }
    // A frontend is write-ready only while it can reach the configured single
    // writer and observe the expected deployment epoch. This M0 service has no
    // dispatch endpoints; worker readiness is a later, separate contract.
    let status = match tokio_postgres::connect(&config.database_url, NoTls).await {
        Ok((client, connection)) => {
            tokio::spawn(async move {
                if let Err(error) = connection.await {
                    eprintln!("database connection closed: {error}");
                }
            });
            client
                .query_one(
                    "SELECT NOT pg_is_in_recovery(), epoch, \
                    COALESCE((SELECT enabled AND NOT draining FROM sites WHERE site_id=$1),TRUE) \
                    FROM deployment_authority WHERE singleton = TRUE",
                    &[&config.site_id],
                )
                .await
                .map(|row| {
                    row.get::<_, bool>(0)
                        && row.get::<_, i64>(1) == config.deployment_epoch
                        && row.get::<_, bool>(2)
                })
                .unwrap_or(false)
        }
        Err(_) => false,
    };
    if status {
        (StatusCode::OK, Json(Health { status: "ready" }))
    } else {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(Health {
                status: "unavailable",
            }),
        )
    }
}

async fn device_test(
    State(config): State<Arc<Config>>,
    headers: HeaderMap,
    upgrade: WebSocketUpgrade,
) -> Response {
    let Some(expected) = config.m0_test_token.as_deref() else {
        return StatusCode::NOT_FOUND.into_response();
    };
    if config.draining.load(Ordering::Acquire) {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    }
    let Some(received) = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|header| header.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
    else {
        return StatusCode::UNAUTHORIZED.into_response();
    };
    if received.len() != expected.len()
        || !bool::from(received.as_bytes().ct_eq(expected.as_bytes()))
    {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    upgrade
        .on_upgrade(move |mut socket| async move {
            if config.draining.load(Ordering::Acquire) {
                let _ = socket.send(Message::Close(None)).await;
                return;
            }
            loop {
                let message = tokio::select! {
                    message = socket.recv() => message,
                    _ = config.drain_notify.notified() => {
                        let _ = socket.send(Message::Close(None)).await;
                        break;
                    }
                };
                let Some(Ok(message)) = message else {
                    break;
                };
                match message {
                    Message::Text(text) if text.as_str() == r#"{"v":1,"type":"heartbeat"}"# => {
                        if socket
                            .send(Message::Text(r#"{"v":1,"type":"heartbeat_ack"}"#.into()))
                            .await
                            .is_err()
                        {
                            break;
                        }
                    }
                    Message::Close(_) => break,
                    _ => {}
                }
            }
        })
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;

    #[tokio::test]
    async fn configured_site_registers_once_and_disabled_site_fails_closed() {
        let Ok(base_url) = env::var("ZT_AUTH_TEST_DATABASE_URL") else {
            return;
        };
        let (setup, connection) = tokio_postgres::connect(&base_url, NoTls).await.unwrap();
        tokio::spawn(async move { connection.await.unwrap() });
        let schema = format!("site_test_{}", Uuid::new_v4().simple());
        setup
            .batch_execute(&format!("CREATE SCHEMA {schema}"))
            .await
            .unwrap();
        let database_url = format!("{base_url}?options=-csearch_path%3D{schema}");
        let (client, connection) = tokio_postgres::connect(&database_url, NoTls).await.unwrap();
        tokio::spawn(async move { connection.await.unwrap() });
        client
            .batch_execute(include_str!(
                "../../../deploy/compose/migrations/001_foundation.sql"
            ))
            .await
            .unwrap();
        let config = Config {
            database_url,
            site_id: "local-test".into(),
            instance_id: "test-hub".into(),
            deployment_epoch: 1,
            m0_test_token: None,
            alpha_policy: Arc::new(AlphaPolicy::parse(None, None, None).unwrap()),
            dispatch_runtime_enabled: false,
            draining: Arc::new(AtomicBool::new(false)),
            drain_notify: Arc::new(Notify::new()),
        };
        ensure_local_site(&config).await.unwrap();
        ensure_local_site(&config).await.unwrap();
        assert_eq!(
            ready(State(Arc::new(config.clone()))).await.0,
            StatusCode::OK
        );
        client
            .execute(
                "UPDATE sites SET enabled=FALSE WHERE site_id='local-test'",
                &[],
            )
            .await
            .unwrap();
        assert!(ensure_local_site(&config).await.is_err());
        assert_eq!(
            ready(State(Arc::new(config))).await.0,
            StatusCode::SERVICE_UNAVAILABLE
        );
        setup
            .batch_execute(&format!("DROP SCHEMA {schema} CASCADE"))
            .await
            .unwrap();
    }
}

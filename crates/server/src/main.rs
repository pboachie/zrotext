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
};
use subtle::ConstantTimeEq;
use tokio::sync::Notify;
use tokio_postgres::NoTls;
use zrotext_server::{
    auth::TokenHasher,
    enrollment::EnrollmentHasher,
    http_auth::{
        self, AuthHttpState, DisabledVerificationDispatcher, SmtpVerificationDispatcher,
        VerificationDispatcher,
    },
    http_enrollment::{self, EnrollmentHttpState},
};

struct Config {
    database_url: String,
    site_id: String,
    instance_id: String,
    deployment_epoch: i64,
    m0_test_token: Option<String>,
    draining: AtomicBool,
    drain_notify: Notify,
}

#[derive(Serialize)]
struct Health {
    status: &'static str,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    if required("DISPATCH_ENABLED")? != "false" {
        return Err("M0 contains no dispatcher; DISPATCH_ENABLED must be false".into());
    }
    let config = Arc::new(Config {
        database_url: required("DATABASE_URL")?,
        site_id: required("SITE_ID")?,
        instance_id: required("INSTANCE_ID")?,
        deployment_epoch: required("DEPLOYMENT_EPOCH")?.parse()?,
        m0_test_token: env::var("M0_TEST_TOKEN")
            .ok()
            .filter(|token| token.len() >= 32),
        draining: AtomicBool::new(false),
        drain_notify: Notify::new(),
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
        app = app
            .nest("/v1/auth", http_auth::router(auth_state))
            .nest("/v1/enrollment", http_enrollment::router(enrollment_state));
    }
    eprintln!(
        "zrotext M0 site={} instance={} listening={bind}",
        config.site_id, config.instance_id
    );
    let listener = tokio::net::TcpListener::bind(bind).await?;
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal(config))
        .await?;
    Ok(())
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
                .query_one("SELECT NOT pg_is_in_recovery(), epoch FROM deployment_authority WHERE singleton = TRUE", &[])
                .await
                .map(|row| row.get::<_, bool>(0) && row.get::<_, i64>(1) == config.deployment_epoch)
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

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
    let app = Router::new()
        .route(
            "/healthz",
            get(|| async { Json(Health { status: "live" }) }),
        )
        .route("/readyz", get(ready))
        .route("/m0/device-test", get(device_test))
        .with_state(config.clone());
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

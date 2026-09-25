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
#[cfg(test)]
use tokio_postgres::NoTls;
use uuid::Uuid;
use zeroize::Zeroizing;
use zrotext_delivery_store::DeliveryStore;
use zrotext_server::{
    alpha_policy::AlphaPolicy,
    auth::{
        self, TokenHasher, abuse_limits,
        mfa::{self, MfaCipher},
    },
    billing::{
        drain::{BillingQueueConfig, run_billing_queue},
        http::{self as billing_http, BillingHttpState},
        owner as billing_owner, parse_test_quota_plans, quota_configuration_fingerprint,
        reset_test_quotas_on_start,
        sessions::{self as billing_sessions, SessionState},
        worker::StripeTestWorker,
    },
    device_socket::{self, DeviceSocketState},
    enrollment::{self, EnrollmentHasher},
    http_auth::{
        self, AuthHttpState, DisabledVerificationDispatcher, RegistrationPolicy,
        SmtpVerificationDispatcher, VerificationDispatchOutcome, VerificationDispatcher,
        VerificationWarningGate,
    },
    http_enrollment::{self, EnrollmentHttpState},
    http_messages::{self, MessagesHttpState},
    http_owner_messages::{self, OwnerMessagesState},
    http_webhooks::{self, WebhookHttpState},
    owner_ui,
    retention::{self, RetentionPolicy},
    webhook_worker::{self, WebhookSecretVault},
};

/// Upper bound on deliveries one webhook lane makes per two-second tick.
const WEBHOOK_DELIVERIES_PER_TICK: usize = 16;
/// Upper bound on retention batches per table per fifteen-second tick.
const RETENTION_BATCHES_PER_TICK: usize = 10;
/// Upper bound on each kind of account mail sent per five-second tick.
const MAIL_DELIVERIES_PER_TICK: usize = 16;

#[derive(Clone)]
struct Config {
    database_url: String,
    site_id: String,
    instance_id: String,
    deployment_epoch: i64,
    m0_test_token: Option<String>,
    alpha_policy: Arc<AlphaPolicy>,
    dispatch_runtime_enabled: bool,
    mfa_recovery_only: bool,
    mfa_enrollment_enabled: bool,
    retention: RetentionPolicy,
    draining: Arc<AtomicBool>,
    drain_notify: Arc<Notify>,
    billing_provider_authorized: Option<(Arc<AtomicBool>, Arc<AtomicBool>)>,
}

#[derive(Serialize)]
struct Health {
    status: &'static str,
}

#[derive(Serialize)]
struct BuildVersion {
    bundle_version: Option<&'static str>,
    source_commit: Option<&'static str>,
    web_static_sha256: Option<&'static str>,
    device_stream_protocol: &'static str,
    device_stream_schema_sha256: Option<&'static str>,
    migration_last: Option<&'static str>,
}

fn build_version() -> BuildVersion {
    BuildVersion {
        bundle_version: option_env!("RELEASE_VERSION"),
        source_commit: option_env!("GIT_COMMIT"),
        web_static_sha256: option_env!("WEB_STATIC_SHA256"),
        device_stream_protocol: "v1",
        device_stream_schema_sha256: option_env!("DEVICE_STREAM_SCHEMA_SHA256"),
        migration_last: option_env!("MIGRATION_LAST"),
    }
}

fn bounded_worker_setting(
    name: &str,
    default: usize,
    maximum: usize,
) -> Result<usize, &'static str> {
    match env::var(name) {
        Err(env::VarError::NotPresent) => Ok(default),
        Ok(value) => match value.parse::<usize>() {
            Ok(value) if (1..=maximum).contains(&value) => Ok(value),
            _ => Err("invalid Stripe test reconciliation worker setting"),
        },
        Err(_) => Err("invalid Stripe test reconciliation worker setting"),
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let hosted_sessions_enabled = optional_bool("STRIPE_TEST_HOSTED_SESSIONS_ENABLED")?;
    let billing_test = match env::var("STRIPE_BILLING_TEST_ENABLED").ok().as_deref() {
        None | Some("false") => None,
        Some("true") => {
            let endpoint_secret = required("STRIPE_TEST_WEBHOOK_SECRET")?;
            if !endpoint_secret.starts_with("whsec_") || endpoint_secret.len() < 16 {
                return Err("invalid Stripe test webhook secret".into());
            }
            let prices: Vec<String> = required("STRIPE_TEST_PRICE_IDS")?
                .split(',')
                .map(str::trim)
                .map(str::to_owned)
                .collect();
            let plans = parse_test_quota_plans(
                &env::var("STRIPE_TEST_QUOTA_PLANS").unwrap_or_default(),
                &prices,
            )?;
            let device_caps_enabled = plans.iter().any(|plan| plan.device_limit.is_some());
            let batch_size = bounded_worker_setting("STRIPE_TEST_RECONCILE_BATCH_SIZE", 25, 100)?;
            let concurrency = bounded_worker_setting("STRIPE_TEST_RECONCILE_CONCURRENCY", 2, 4)?;
            let legacy_key = optional_secret("STRIPE_TEST_SECRET_KEY")?;
            let reader_key = select_stripe_test_key(
                optional_secret("STRIPE_TEST_RECONCILE_SECRET_KEY")?,
                legacy_key.clone(),
            )?;
            let config_fingerprint = quota_configuration_fingerprint(&prices, &plans, &reader_key);
            let session_candidate = optional_secret("STRIPE_TEST_SESSION_SECRET_KEY")?;
            let session_key = if hosted_sessions_enabled {
                Some(select_stripe_test_key(session_candidate, legacy_key)?)
            } else {
                None
            };
            let worker = StripeTestWorker::new_with_quotas(reader_key, prices.clone(), plans)?;
            Some((
                endpoint_secret,
                worker,
                session_key,
                prices,
                device_caps_enabled,
                config_fingerprint,
                batch_size,
                concurrency,
            ))
        }
        _ => return Err("invalid STRIPE_BILLING_TEST_ENABLED".into()),
    };
    if billing_test.is_none() && hosted_sessions_enabled {
        return Err("Stripe hosted sessions require STRIPE_BILLING_TEST_ENABLED=true".into());
    }
    let (webhook_vault, webhook_delivery_enabled) = webhook_config()?;
    // The process-wide worker database budget is four connections. Reserve at
    // least one for billing, recovery and other background work.
    let webhook_dispatch_concurrency = match env::var("WEBHOOK_DISPATCH_CONCURRENCY") {
        Ok(value) => match value.parse::<usize>() {
            Ok(count @ 1..=3) => count,
            _ => return Err("WEBHOOK_DISPATCH_CONCURRENCY must be 1..=3".into()),
        },
        Err(env::VarError::NotPresent) => 2,
        Err(_) => return Err("WEBHOOK_DISPATCH_CONCURRENCY must be valid UTF-8".into()),
    };
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
    let line_opt_out_enabled = optional_bool("LINE_OPT_OUT_ENABLED")?;
    let mfa_recovery_only = optional_bool("MFA_RECOVERY_ONLY")?;
    let mfa_enrollment_enabled = optional_bool("MFA_ENROLLMENT_ENABLED")?;
    if mfa_recovery_only && mfa_enrollment_enabled {
        return Err("MFA enrollment cannot be enabled in recovery-only mode".into());
    }
    let billing_provider_authorized = billing_test
        .as_ref()
        .map(|(_, worker, ..)| worker.authorization_state());
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
        mfa_recovery_only,
        mfa_enrollment_enabled,
        retention: RetentionPolicy::from_env()?,
        draining: Arc::new(AtomicBool::new(false)),
        drain_notify: Arc::new(Notify::new()),
        billing_provider_authorized,
    });
    let bind: SocketAddr = env::var("BIND_ADDR")
        .unwrap_or_else(|_| "0.0.0.0:8080".to_owned())
        .parse()?;
    let configured_source = match env::var("SOURCE_URL") {
        Ok(value) => Some(value),
        Err(env::VarError::NotPresent) => None,
        Err(_) => return Err("SOURCE_URL must be valid UTF-8".into()),
    };
    let source_url =
        owner_ui::source_destination(configured_source.as_deref(), option_env!("GIT_COMMIT"))?;
    let mut app = Router::new()
        .route(
            "/healthz",
            get(|| async { Json(Health { status: "live" }) }),
        )
        .route("/readyz", get(ready))
        .route("/about/version", get(|| async { Json(build_version()) }))
        .route("/m0/device-test", get(device_test))
        .merge(owner_ui::source_router(source_url))
        .with_state(config.clone());
    let retention_database = config.database_url.clone();
    let retention_policy = config.retention;
    let retention_draining = config.draining.clone();
    let retention_notify = config.drain_notify.clone();
    tokio::spawn(async move {
        let mut checks = tokio::time::interval(Duration::from_secs(15));
        checks.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        let mut unavailable_logged = false;
        loop {
            tokio::select! {
                _ = checks.tick() => {
                    if retention_draining.load(Ordering::Acquire) { break; }
                    let result = async {
                        let mut client =
                            zrotext_server::runtime_db::connect_worker(&retention_database).await?;
                        // Keep pruning while any table returns a full batch so a
                        // busy hub cannot fall permanently behind its policy.
                        for _ in 0..RETENTION_BATCHES_PER_TICK {
                            if retention_draining.load(Ordering::Acquire) { break; }
                            let counts = retention::prune(&mut client, retention_policy, retention::BATCH_SIZE).await?;
                            if !counts.any_full(retention::BATCH_SIZE) { break; }
                        }
                        Ok::<(), Box<dyn std::error::Error + Send + Sync>>(())
                    }.await;
                    match result {
                        Ok(()) => unavailable_logged = false,
                        Err(_) if !unavailable_logged => {
                            eprintln!("data retention worker unavailable");
                            unavailable_logged = true;
                        }
                        Err(_) => {}
                    }
                }
                _ = retention_notify.notified() => break,
            }
        }
    });
    let mut quotas_reset = false;
    let mut billing_auth_state = None;
    if let Some((auth_state, enrollment_state)) = account_routes(&config).await? {
        billing_auth_state = Some(auth_state.clone());
        ensure_mfa_startup(
            &config.database_url,
            auth_state.mfa_cipher.as_deref(),
            config.mfa_recovery_only,
        )
        .await?;
        if let Some(vault) = webhook_vault.as_ref() {
            let mut key_db = zrotext_server::runtime_db::connect(&config.database_url).await?;
            webhook_worker::validate_runtime_keys(&mut key_db, vault).await?;
        }
        ensure_local_site(&config).await?;
        reset_test_quotas_on_start(
            &config.database_url,
            billing_test.is_some(),
            billing_test.as_ref().is_some_and(|billing| billing.4),
            billing_test.as_ref().map(|billing| &billing.5),
        )
        .await?;
        quotas_reset = true;
        if let Some(vault) = webhook_vault {
            let vault = Arc::new(vault);
            app = app.merge(http_webhooks::router(WebhookHttpState {
                database_url: config.database_url.clone(),
                auth_hasher: auth_state.hasher.clone(),
                canonical_origin: auth_state.canonical_origin.clone(),
                vault: vault.clone(),
            }));
            if webhook_delivery_enabled {
                for lane in 0..webhook_dispatch_concurrency {
                    let worker_database = config.database_url.clone();
                    let worker_draining = config.draining.clone();
                    let worker_notify = config.drain_notify.clone();
                    let worker_vault = vault.clone();
                    let worker_id = Uuid::new_v4().to_string();
                    tokio::spawn(async move {
                        // Spread claims through each period so workers do not
                        // all contend for the same account cursor at once.
                        let offset_ms = 2_000 * lane / webhook_dispatch_concurrency;
                        let mut checks = tokio::time::interval_at(
                            tokio::time::Instant::now() + Duration::from_millis(offset_ms as u64),
                            Duration::from_secs(2),
                        );
                        checks.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
                        let mut unavailable_logged = false;
                        let mut ticks = 0_u32;
                        loop {
                            tokio::select! {
                                _ = checks.tick() => {
                                    if worker_draining.load(Ordering::Acquire) { break; }
                                    ticks = ticks.wrapping_add(1);
                                    let result = async {
                                        let mut client =
                                            zrotext_server::runtime_db::connect_worker(&worker_database).await
                                                .map_err(|_| "webhook database unavailable")?;
                                        // Drain a bounded backlog on one socket rather than
                                        // one delivery per lane per tick.
                                        let mut sent = 0;
                                        while sent < WEBHOOK_DELIVERIES_PER_TICK
                                            && !worker_draining.load(Ordering::Acquire)
                                            && webhook_worker::dispatch_one(&mut client, &worker_vault, &worker_id).await
                                                .map_err(|_| "webhook dispatch failed")?
                                        {
                                            sent += 1;
                                        }
                                        if lane == 0 && ticks % 30 == 1 {
                                            let (pending, oldest_age_seconds, in_flight) =
                                                webhook_worker::queue_signal(&client).await
                                                    .map_err(|_| "webhook metrics unavailable")?;
                                            eprintln!("webhook_queue pending={pending} oldest_pending_age_seconds={} in_flight={in_flight}",
                                                oldest_age_seconds.unwrap_or(0));
                                        }
                                        Ok::<usize, &str>(sent)
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
        }
        let abuse_database = config.database_url.clone();
        let abuse_draining = config.draining.clone();
        let abuse_drain_notify = config.drain_notify.clone();
        tokio::spawn(async move {
            let mut checks = tokio::time::interval(Duration::from_secs(60));
            checks.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            loop {
                tokio::select! {
                    _ = checks.tick() => {
                        if abuse_draining.load(Ordering::Acquire) { break; }
                        if let Ok(mut client) = zrotext_server::runtime_db::connect_worker(&abuse_database).await {
                            let _ = abuse_limits::prune(&client).await;
                            let _ = mfa::prune_expired_challenges(&client).await;
                            let _ = enrollment::prune_expired(&client).await;
                            let _ = auth::prune_expired_pending_owners(&mut client).await;
                            let _ = auth::account::prune_expired_password_resets(&client).await;
                        }
                    }
                    _ = abuse_drain_notify.notified() => break,
                }
            }
        });
        let mail_state = auth_state.clone();
        let message_hasher = auth_state.hasher.clone();
        let mail_draining = config.draining.clone();
        let mail_drain_notify = config.drain_notify.clone();
        tokio::spawn(async move {
            let mut checks = tokio::time::interval(Duration::from_secs(5));
            checks.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            let mut unavailable_logged = false;
            let mut failure_gate = VerificationWarningGate::default();
            loop {
                tokio::select! {
                    _ = checks.tick() => {
                        if mail_draining.load(Ordering::Acquire) { break; }
                        // Drain bounded backlogs; a failed send ends that kind's
                        // batch so an unreachable mail server is not hammered.
                        let mut verification = Ok(VerificationDispatchOutcome::Idle);
                        for _ in 0..MAIL_DELIVERIES_PER_TICK {
                            if mail_draining.load(Ordering::Acquire) { break; }
                            verification = http_auth::dispatch_one_verification_report(&mail_state).await;
                            match verification.as_ref() {
                                Ok(VerificationDispatchOutcome::Idle) | Err(_) => {}
                                Ok(VerificationDispatchOutcome::Delivered) => failure_gate.on_success(),
                                Ok(VerificationDispatchOutcome::Failed { category, dead_lettered }) => {
                                    if let Some(warning) = failure_gate.on_failure(*category, std::time::Instant::now()) {
                                        eprintln!("{warning}");
                                    }
                                    if *dead_lettered {
                                        eprintln!("verification mail dead-lettered after six failed attempts");
                                    }
                                }
                            }
                            if !matches!(verification, Ok(VerificationDispatchOutcome::Delivered)) { break; }
                        }
                        let mut reset = Ok(false);
                        for _ in 0..MAIL_DELIVERIES_PER_TICK {
                            if mail_draining.load(Ordering::Acquire) { break; }
                            reset = http_auth::dispatch_one_password_reset(&mail_state).await;
                            if !matches!(reset, Ok(true)) { break; }
                        }
                        let mut notice = Ok(false);
                        for _ in 0..MAIL_DELIVERIES_PER_TICK {
                            if mail_draining.load(Ordering::Acquire) { break; }
                            notice = http_auth::dispatch_one_password_reset_notice(&mail_state).await;
                            if !matches!(notice, Ok(true)) { break; }
                        }
                        let unavailable = verification.is_err() || reset.is_err() || notice.is_err();
                        if unavailable && !unavailable_logged {
                            eprintln!("account mail delivery worker unavailable");
                        }
                        unavailable_logged = unavailable;
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
                            let mut client =
                                zrotext_server::runtime_db::connect_worker(&recovery_database).await?;
                            let mut store = DeliveryStore::new(&mut client);
                            store.expire_due(100).await?;
                            store.reconcile_silent_attempts(100).await?;
                            store.reconcile_delivery_timeouts(100).await?;
                            Ok::<(), Box<dyn std::error::Error + Send + Sync>>(())
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
            auth_hasher: auth_state.hasher.clone(),
            alpha_policy: config.alpha_policy.clone(),
            dispatch_runtime_enabled: config.dispatch_runtime_enabled,
            inbound_pilot_enabled,
            line_opt_out_enabled,
            draining: config.draining.clone(),
            drain_notify: config.drain_notify.clone(),
        };
        let owner_messages_state = OwnerMessagesState {
            database_url: config.database_url.clone(),
            auth_hasher: auth_state.hasher.clone(),
            canonical_origin: auth_state.canonical_origin.clone(),
        };
        app = app
            .nest("/v1/auth", http_auth::router(auth_state))
            .nest("/v1/enrollment", http_enrollment::router(enrollment_state))
            .merge(http_owner_messages::router(owner_messages_state))
            .merge(owner_ui::router())
            .merge(device_socket::router(socket_state));
        if config.alpha_policy.enabled() {
            let message_state = MessagesHttpState::new(
                config.database_url.clone(),
                message_hasher,
                config.alpha_policy.clone(),
                billing_test.is_some(),
            )?
            .with_idempotency_days(config.retention.idempotency_days);
            app = app.nest("/v1/alpha", http_messages::router(message_state));
        }
    } else if config.alpha_policy.enabled()
        || inbound_pilot_enabled
        || line_opt_out_enabled
        || webhook_delivery_enabled
        || webhook_management_configured
    {
        return Err("account and enrollment routes are required for enabled features".into());
    }
    if let Some((
        endpoint_secret,
        worker,
        session_key,
        prices,
        device_caps_enabled,
        config_fingerprint,
        batch_size,
        concurrency,
    )) = billing_test
    {
        let billing_database = config.database_url.clone();
        if !quotas_reset {
            reset_test_quotas_on_start(
                &billing_database,
                true,
                device_caps_enabled,
                Some(&config_fingerprint),
            )
            .await?;
        }
        let mut billing_routes = billing_http::router(BillingHttpState {
            database_url: billing_database.clone(),
            endpoint_secret,
        });
        if hosted_sessions_enabled {
            let auth = billing_auth_state.ok_or("Stripe hosted sessions require account routes")?;
            let price_id = required("STRIPE_TEST_CHECKOUT_PRICE_ID")?;
            if !prices.contains(&price_id) {
                return Err("Stripe Checkout price must be in the recognized test prices".into());
            }
            let sessions = SessionState::new(
                auth.clone(),
                session_key.ok_or("Stripe test session key missing")?,
                price_id,
            )?;
            billing_routes = billing_routes.merge(billing_sessions::router(sessions));
            billing_routes = billing_routes.merge(billing_owner::status_router(auth.clone()));
            app = app
                .merge(billing_sessions::return_router())
                .merge(billing_owner::page_router(auth));
        }
        app = app.nest("/v1/billing", billing_routes);
        let billing_draining = config.draining.clone();
        let billing_notify = config.drain_notify.clone();
        let worker = Arc::new(worker);
        let permits = Arc::new(tokio::sync::Semaphore::new(concurrency));
        for risk in [false, true] {
            tokio::spawn(run_billing_queue(BillingQueueConfig {
                worker: worker.clone(),
                database_url: billing_database.clone(),
                batch_size,
                concurrency,
                risk,
                draining: billing_draining.clone(),
                notify: billing_notify.clone(),
                permits: permits.clone(),
            }));
        }
    }
    eprintln!(
        "zrotext site={} instance={} listening={bind}",
        config.site_id, config.instance_id
    );
    let listener = tokio::net::TcpListener::bind(bind).await?;
    axum::serve(listener, zrotext_server::ingress::protect(app))
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
    let secondary = match (
        env::var("WEBHOOK_KEK_SECONDARY_VERSION"),
        env::var("WEBHOOK_KEK_SECONDARY_B64"),
    ) {
        (Err(env::VarError::NotPresent), Err(env::VarError::NotPresent)) => None,
        (Ok(version), Ok(encoded)) => {
            let version: i32 = version.parse()?;
            let encoded = Zeroizing::new(encoded);
            let decoded = Zeroizing::new(STANDARD.decode(encoded.as_bytes())?);
            Some((version, decoded))
        }
        _ => return Err(
            "WEBHOOK_KEK_SECONDARY_VERSION and WEBHOOK_KEK_SECONDARY_B64 must be supplied together"
                .into(),
        ),
    };
    let vault = match (env::var("WEBHOOK_KEK_VERSION"), env::var("WEBHOOK_KEK_B64")) {
        (Err(env::VarError::NotPresent), Err(env::VarError::NotPresent))
            if !delivery_enabled && secondary.is_none() =>
        {
            None
        }
        (Ok(version), Ok(encoded)) => {
            let version: i32 = version.parse()?;
            let encoded = Zeroizing::new(encoded);
            let decoded = Zeroizing::new(STANDARD.decode(encoded.as_bytes())?);
            Some(WebhookSecretVault::with_secondary(
                version, decoded, secondary,
            )?)
        }
        _ => {
            return Err("WEBHOOK_KEK_VERSION and WEBHOOK_KEK_B64 must be supplied together".into());
        }
    };
    Ok((vault, delivery_enabled))
}

async fn account_routes(
    config: &Config,
) -> Result<Option<(AuthHttpState, EnrollmentHttpState)>, Box<dyn std::error::Error>> {
    let origin = env::var("AUTH_ORIGIN").ok();
    let auth_pepper = env::var("AUTH_TOKEN_PEPPER_B64").ok();
    let enrollment_pepper = env::var("ENROLLMENT_TOKEN_PEPPER_B64").ok();
    let mfa_key = env::var("MFA_ENCRYPTION_KEY_B64")
        .ok()
        .filter(|value| !value.is_empty());
    if origin.is_none() && auth_pepper.is_none() && enrollment_pepper.is_none() && mfa_key.is_none()
    {
        if config.mfa_recovery_only || config.mfa_enrollment_enabled {
            return Err("MFA mode requires configured account routes".into());
        }
        return Ok(None);
    }
    let origin = origin.ok_or("AUTH_ORIGIN is required when account routes are enabled")?;
    let registration_mode = smtp_env_option("REGISTRATION_MODE")?;
    let registration_emails = smtp_env_option("REGISTRATION_ALLOWED_EMAILS")?;
    let registration_domains = smtp_env_option("REGISTRATION_ALLOWED_DOMAINS")?;
    let registration_key = smtp_env_option("REGISTRATION_ENROLLMENT_KEY_B64")?.map(Zeroizing::new);
    let registration_policy = RegistrationPolicy::parse(
        registration_mode.as_deref(),
        registration_emails.as_deref(),
        registration_domains.as_deref(),
        registration_key.as_ref().map(|key| key.as_str()),
    )?;
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
            match smtp_env_option("SMTP_SECURE")?.as_deref() {
                None | Some("true") => {}
                _ => return Err("SMTP_SECURE must be true; plaintext SMTP is unsupported".into()),
            }
            let username = required_smtp_alias("SMTP_USERNAME", "SMTP_USER")?;
            let password = required_smtp_alias("SMTP_PASSWORD", "SMTP_PASS")?;
            let from = required_smtp_alias("SMTP_FROM", "EMAIL_FROM")?;
            let from_name = smtp_alias("SMTP_FROM_NAME", "EMAIL_FROM_NAME")?;
            let reply_to = smtp_alias("SMTP_REPLY_TO", "EMAIL_REPLY_TO")?;
            Arc::new(SmtpVerificationDispatcher::new(
                &host,
                port,
                username,
                password,
                &from,
                from_name.as_deref(),
                reply_to.as_deref(),
            )?)
        }
        Err(env::VarError::NotPresent) => Arc::new(DisabledVerificationDispatcher),
        Err(_) => return Err("SMTP_HOST must be valid UTF-8".into()),
    };
    let mut auth_state = AuthHttpState::new(
        config.database_url.clone(),
        auth_hasher.clone(),
        origin.clone(),
        dispatcher,
    )?
    .with_registration_policy(registration_policy);
    if let Some(encoded) = mfa_key.filter(|_| !config.mfa_recovery_only) {
        let key = STANDARD
            .decode(encoded)
            .map_err(|_| "MFA_ENCRYPTION_KEY_B64 must be valid base64")?;
        let cipher = MfaCipher::new(key)
            .map_err(|_| "MFA_ENCRYPTION_KEY_B64 must decode to exactly 32 bytes")?;
        auth_state = auth_state.with_mfa_cipher(Arc::new(cipher));
    }
    if config.mfa_enrollment_enabled {
        if auth_state.mfa_cipher.is_none() {
            return Err("MFA enrollment requires MFA_ENCRYPTION_KEY_B64".into());
        }
        auth_state = auth_state.with_mfa_enrollment_enabled();
    }
    let enrollment_state = EnrollmentHttpState::new(
        config.database_url.clone(),
        auth_hasher,
        enrollment_hasher,
        origin,
    );
    // NOOP checks TLS and credentials without sending a message. A broken SMTP
    // server must remain visible, but must not prevent unrelated API startup.
    match tokio::time::timeout(
        Duration::from_secs(10),
        auth_state.dispatcher.check_connection(),
    )
    .await
    {
        Ok(Err(category)) => eprintln!(
            "SMTP startup connection check failed: {}",
            category.warning()
        ),
        Ok(Ok(_)) => {}
        Err(_) => eprintln!("SMTP startup connection check failed (category=timeout)"),
    }
    Ok(Some((auth_state, enrollment_state)))
}

async fn ensure_mfa_startup(
    database_url: &str,
    cipher: Option<&MfaCipher>,
    recovery_only: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let client = zrotext_server::runtime_db::connect(database_url)
        .await
        .map_err(|_| "MFA startup key check could not reach database")?;
    mfa::validate_runtime_key(&client, cipher, recovery_only)
        .await
        .map_err(
            |_| "enabled owner MFA secrets need the matching key or explicit recovery-only mode",
        )?;
    Ok(())
}

/// A configured M1 site registers once on a fresh writer. An operator-disabled
/// or draining existing site is never re-enabled by application startup.
async fn ensure_local_site(config: &Config) -> Result<(), Box<dyn std::error::Error>> {
    let client = zrotext_server::runtime_db::connect(&config.database_url)
        .await
        .map_err(|_| "site registration unavailable")?;
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
    let value = env::var(key).map_err(|error| redacted_env_error(key, error))?;
    if value.trim().is_empty() {
        return Err(format!("{key} must not be empty").into());
    }
    Ok(value)
}

fn smtp_env_option(key: &'static str) -> Result<Option<String>, Box<dyn std::error::Error>> {
    match env::var(key) {
        Ok(value) if value.trim().is_empty() => Ok(None),
        Ok(value) => Ok(Some(value)),
        Err(env::VarError::NotPresent) => Ok(None),
        Err(env::VarError::NotUnicode(_)) => Err(format!("{key} must be valid UTF-8").into()),
    }
}

fn resolve_smtp_alias(
    primary: Option<String>,
    alternate: Option<String>,
) -> Result<Option<String>, &'static str> {
    match (primary, alternate) {
        (Some(primary), Some(alternate)) if primary != alternate => {
            Err("conflicting SMTP setting aliases")
        }
        (Some(primary), _) => Ok(Some(primary)),
        (_, Some(alternate)) => Ok(Some(alternate)),
        (None, None) => Ok(None),
    }
}

fn smtp_alias(
    primary: &'static str,
    alternate: &'static str,
) -> Result<Option<String>, Box<dyn std::error::Error>> {
    Ok(resolve_smtp_alias(
        smtp_env_option(primary)?,
        smtp_env_option(alternate)?,
    )?)
}

fn required_smtp_alias(
    primary: &'static str,
    alternate: &'static str,
) -> Result<String, Box<dyn std::error::Error>> {
    smtp_alias(primary, alternate)?
        .ok_or_else(|| format!("{primary} or {alternate} is required").into())
}

fn optional_secret(key: &'static str) -> Result<Option<String>, Box<dyn std::error::Error>> {
    match env::var(key) {
        Ok(value) if !value.trim().is_empty() => {
            validate_stripe_test_key(&value)?;
            Ok(Some(value))
        }
        Ok(_) => Err(format!("{key} must not be empty").into()),
        Err(env::VarError::NotPresent) => Ok(None),
        Err(error) => Err(redacted_env_error(key, error).into()),
    }
}

fn redacted_env_error(key: &'static str, error: env::VarError) -> String {
    match error {
        env::VarError::NotPresent => format!("{key} is required"),
        env::VarError::NotUnicode(_) => format!("{key} must be valid UTF-8"),
    }
}

fn select_stripe_test_key(
    scoped: Option<String>,
    legacy: Option<String>,
) -> Result<String, &'static str> {
    let key = scoped.or(legacy).ok_or("Stripe test API key missing")?;
    validate_stripe_test_key(&key)?;
    Ok(key)
}

fn validate_stripe_test_key(key: &str) -> Result<(), &'static str> {
    if !(key.starts_with("sk_test_") || key.starts_with("rk_test_")) || key.len() < 16 {
        return Err("Stripe test API key must be a test-mode key");
    }
    Ok(())
}

fn optional_bool(key: &'static str) -> Result<bool, Box<dyn std::error::Error>> {
    match env::var(key) {
        Err(env::VarError::NotPresent) => Ok(false),
        Ok(value) if value == "true" => Ok(true),
        Ok(value) if value == "false" => Ok(false),
        _ => Err(format!("{key} must be true or false").into()),
    }
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
    if config
        .billing_provider_authorized
        .as_ref()
        .is_some_and(|(subscription, risk)| {
            !subscription.load(Ordering::Acquire) || !risk.load(Ordering::Acquire)
        })
    {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(Health {
                status: "unavailable",
            }),
        );
    }
    // A frontend is write-ready only while it can reach the configured single
    // writer, observe the expected deployment epoch, and, when billing is
    // enabled, has no unresolved provider authorization failure.
    let status = match zrotext_server::runtime_db::connect(&config.database_url).await {
        Ok(client) => {
            let authority_ready = client
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
                .unwrap_or(false);
            if !authority_ready {
                false
            } else if config.billing_provider_authorized.is_some() {
                client.query_one(
                    "SELECT NOT EXISTS(SELECT 1 FROM billing_reconciliations WHERE dirty_generation>processed_generation AND last_failure_class='authorization') AND NOT EXISTS(SELECT 1 FROM billing_risk_events WHERE state IN ('queued','needs_review') AND last_failure_class='authorization')",
                    &[],
                ).await.map(|row| row.get::<_, bool>(0)).unwrap_or(false)
            } else {
                true
            }
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
    use rand::{Rng, rng};
    use uuid::Uuid;

    #[test]
    fn smtp_aliases_accept_supplied_names_but_reject_conflicts() {
        assert_eq!(
            resolve_smtp_alias(None, Some("alternate".into())).unwrap(),
            Some("alternate".into())
        );
        assert_eq!(
            resolve_smtp_alias(Some("same".into()), Some("same".into())).unwrap(),
            Some("same".into())
        );
        assert!(resolve_smtp_alias(Some("one".into()), Some("two".into())).is_err());
    }

    #[test]
    fn stripe_test_keys_select_scoped_reader_and_writer_independently() {
        let legacy = "sk_test_legacyfixture".to_owned();
        let reader = "rk_test_readfixture".to_owned();
        let writer = "rk_test_writefixture".to_owned();
        assert_eq!(
            select_stripe_test_key(Some(reader.clone()), Some(legacy.clone())).unwrap(),
            reader
        );
        assert_eq!(
            select_stripe_test_key(Some(writer.clone()), Some(legacy.clone())).unwrap(),
            writer
        );
        assert_eq!(
            select_stripe_test_key(None, Some(legacy.clone())).unwrap(),
            legacy
        );
        assert!(select_stripe_test_key(None, None).is_err());
        assert!(select_stripe_test_key(Some("sk_live_fixture1234".into()), None).is_err());
        assert!(select_stripe_test_key(Some("rk_test_short".into()), None).is_err());
        assert!(select_stripe_test_key(Some("sk_live_fixture1234".into()), Some(legacy)).is_err());
        assert!(validate_stripe_test_key("sk_live_unused_fixture1234").is_err());
    }

    #[test]
    fn malformed_secret_env_error_does_not_echo_value() {
        let error = env::VarError::NotUnicode(std::ffi::OsString::from("secret-canary"));
        let message = redacted_env_error("STRIPE_TEST_SESSION_SECRET_KEY", error);
        assert_eq!(
            message,
            "STRIPE_TEST_SESSION_SECRET_KEY must be valid UTF-8"
        );
        assert!(!message.contains("secret-canary"));
    }

    #[tokio::test]
    #[ignore = "requires ZT_AUTH_TEST_DATABASE_URL; run the documented PostgreSQL test command"]
    async fn account_startup_requires_matching_mfa_key_or_explicit_recovery_mode() {
        let base_url = env::var("ZT_AUTH_TEST_DATABASE_URL")
            .expect("set ZT_AUTH_TEST_DATABASE_URL for PostgreSQL-backed tests");
        let (setup, connection) = tokio_postgres::connect(&base_url, NoTls).await.unwrap();
        tokio::spawn(async move { connection.await.unwrap() });
        let schema = format!("mfa_startup_test_{}", Uuid::new_v4().simple());
        setup
            .batch_execute(&format!("CREATE SCHEMA {schema}"))
            .await
            .unwrap();
        let separator = if base_url.contains('?') { '&' } else { '?' };
        let database_url = format!("{base_url}{separator}options=-csearch_path%3D{schema}");
        let (client, connection) = tokio_postgres::connect(&database_url, NoTls).await.unwrap();
        tokio::spawn(async move { connection.await.unwrap() });
        for sql in [
            include_str!("../../../deploy/compose/migrations/002_auth.sql"),
            include_str!("../../../deploy/compose/migrations/013_owner_mfa.sql"),
            include_str!("../../../deploy/compose/migrations/014_owner_mfa_failure_budget.sql"),
        ] {
            client.batch_execute(sql).await.unwrap();
        }
        assert!(ensure_mfa_startup(&database_url, None, false).await.is_ok());
        let account_id = Uuid::new_v4();
        let user_id = Uuid::new_v4();
        client
            .execute("INSERT INTO accounts(id) VALUES($1)", &[&account_id])
            .await
            .unwrap();
        client
            .execute(
                "INSERT INTO users(id,email,password_hash,mfa_enabled) VALUES($1,$2,$3,true)",
                &[&user_id, &"startup@example.test", &"test-only-placeholder"],
            )
            .await
            .unwrap();
        client
            .execute(
                "INSERT INTO memberships(account_id,user_id,role) VALUES($1,$2,'owner')",
                &[&account_id, &user_id],
            )
            .await
            .unwrap();
        client
            .execute(
                "INSERT INTO owner_mfa(account_id,user_id,secret_nonce,secret_ciphertext,enabled_at) VALUES($1,$2,$3,$4,now())",
                &[&account_id, &user_id, &vec![0u8; 12], &vec![0u8; 36]],
            )
            .await
            .unwrap();
        let mut key = vec![0u8; 32];
        rng().fill_bytes(&mut key);
        let cipher = MfaCipher::new(key).unwrap();
        assert!(
            ensure_mfa_startup(&database_url, None, false)
                .await
                .is_err()
        );
        assert!(
            ensure_mfa_startup(&database_url, Some(&cipher), false)
                .await
                .is_err()
        );
        assert!(ensure_mfa_startup(&database_url, None, true).await.is_ok());
        setup
            .batch_execute(&format!("DROP SCHEMA {schema} CASCADE"))
            .await
            .unwrap();
    }

    #[tokio::test]
    #[ignore = "requires ZT_AUTH_TEST_DATABASE_URL; run the documented PostgreSQL test command"]
    async fn configured_site_registers_once_and_disabled_site_fails_closed() {
        let base_url = env::var("ZT_AUTH_TEST_DATABASE_URL")
            .expect("set ZT_AUTH_TEST_DATABASE_URL for PostgreSQL-backed tests");
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
            mfa_recovery_only: false,
            mfa_enrollment_enabled: false,
            retention: RetentionPolicy::default(),
            draining: Arc::new(AtomicBool::new(false)),
            drain_notify: Arc::new(Notify::new()),
            billing_provider_authorized: None,
        };
        ensure_local_site(&config).await.unwrap();
        ensure_local_site(&config).await.unwrap();
        assert_eq!(
            ready(State(Arc::new(config.clone()))).await.0,
            StatusCode::OK
        );
        client.batch_execute("CREATE TABLE billing_reconciliations(dirty_generation bigint,processed_generation bigint,last_failure_class text); CREATE TABLE billing_risk_events(state text,last_failure_class text)").await.unwrap();
        let provider_authorized = Arc::new(AtomicBool::new(false));
        let mut provider_config = config.clone();
        provider_config.billing_provider_authorized =
            Some((provider_authorized.clone(), Arc::new(AtomicBool::new(true))));
        assert_eq!(
            ready(State(Arc::new(provider_config.clone()))).await.0,
            StatusCode::SERVICE_UNAVAILABLE
        );
        provider_authorized.store(true, Ordering::Release);
        assert_eq!(
            ready(State(Arc::new(provider_config.clone()))).await.0,
            StatusCode::OK
        );
        client
            .execute(
                "INSERT INTO billing_reconciliations VALUES(2,1,'authorization')",
                &[],
            )
            .await
            .unwrap();
        assert_eq!(
            ready(State(Arc::new(provider_config.clone()))).await.0,
            StatusCode::SERVICE_UNAVAILABLE
        );
        client
            .execute("DELETE FROM billing_reconciliations", &[])
            .await
            .unwrap();
        client
            .execute(
                "INSERT INTO billing_risk_events VALUES('needs_review','authorization')",
                &[],
            )
            .await
            .unwrap();
        assert_eq!(
            ready(State(Arc::new(provider_config.clone()))).await.0,
            StatusCode::SERVICE_UNAVAILABLE
        );
        client
            .execute("DELETE FROM billing_risk_events", &[])
            .await
            .unwrap();
        assert_eq!(
            ready(State(Arc::new(provider_config))).await.0,
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

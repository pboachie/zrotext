// SPDX-License-Identifier: AGPL-3.0-only
//! Explicit isolated hosted runtime. Construction verifies both restricted
//! credentials, provider metadata, database identity and the old-binary fence.
//! No constructor provisions a namespace, a runtime key or commercial policy.
use super::{
    namespace::{Gate, Mode, Namespace},
    policy::Plan,
};
use crate::http_auth::AuthHttpState;
use std::{
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};
use tokio::sync::Notify;
use uuid::Uuid;

mod http;
mod provider;
mod repository;
#[cfg(test)]
mod tests;
mod worker;

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum Error {
    #[error("hosted billing configuration invalid")]
    Configuration,
    #[error("hosted billing identity mismatch")]
    Identity,
    #[error("hosted billing provider unavailable")]
    Provider,
    #[error("hosted billing database unavailable")]
    Database,
    #[error("hosted billing pending")]
    Pending,
    #[error("hosted billing request conflicts")]
    Conflict,
    #[error("hosted billing session expired")]
    Session,
    #[error("hosted billing request forbidden")]
    Forbidden,
    #[error("hosted billing request rate limited")]
    RateLimited,
}
impl From<crate::http_auth::AuthHttpError> for Error {
    fn from(value: crate::http_auth::AuthHttpError) -> Self {
        match value {
            crate::http_auth::AuthHttpError::Unauthorized => Self::Session,
            crate::http_auth::AuthHttpError::Forbidden => Self::Forbidden,
            crate::http_auth::AuthHttpError::TooManyRequests => Self::RateLimited,
            _ => Self::Database,
        }
    }
}
impl From<tokio_postgres::Error> for Error {
    fn from(_: tokio_postgres::Error) -> Self {
        Self::Database
    }
}
impl From<crate::runtime_db::ConnectError> for Error {
    fn from(_: crate::runtime_db::ConnectError) -> Self {
        Self::Database
    }
}

/// Secrets deliberately have no Debug implementation. Mode, provider identity,
/// namespace, price and policy are immutable for the lifetime of the runtime.
pub struct Options {
    namespace: Namespace,
    policy_revision: u64,
    plan: Plan,
    read_key: String,
    session_key: String,
    webhook_secret: String,
    webhook_endpoint: String,
    portal_configuration: String,
    runtime_key: [u8; 32],
    automatic_tax: bool,
}
impl Options {
    /// Missing/disabled mode performs no provider call and needs no secret.
    /// Legacy STRIPE_TEST_* configuration is dispatched separately by main.
    pub fn from_env() -> Result<Option<Self>, Error> {
        let get = |name: &str| std::env::var(name).map_err(|_| Error::Configuration);
        let value = match std::env::var("HOSTED_BILLING_MODE") {
            Ok(v) => Some(v),
            Err(std::env::VarError::NotPresent) => None,
            Err(_) => return Err(Error::Configuration),
        };
        let mode = match value.as_deref() {
            None | Some("disabled") => return Ok(None),
            Some("test") => Mode::Test,
            Some("live") => Mode::Live,
            _ => return Err(Error::Configuration),
        };
        let id = Uuid::parse_str(&get("HOSTED_BILLING_NAMESPACE_ID")?)
            .map_err(|_| Error::Configuration)?;
        let namespace = Namespace::new(
            id.into_bytes(),
            mode,
            &get("HOSTED_BILLING_PROVIDER_ACCOUNT")?,
        )
        .map_err(|_| Error::Configuration)?;
        let policy_revision = get("HOSTED_BILLING_POLICY_REVISION")?
            .parse()
            .map_err(|_| Error::Configuration)?;
        let plan = Plan::new(
            &get("HOSTED_BILLING_PRICE_ID")?,
            get("HOSTED_BILLING_OUTBOUND_LIMIT")?
                .parse()
                .map_err(|_| Error::Configuration)?,
            get("HOSTED_BILLING_DEVICE_CAP")?
                .parse()
                .map_err(|_| Error::Configuration)?,
            get("HOSTED_BILLING_GRACE_SECONDS")?
                .parse()
                .map_err(|_| Error::Configuration)?,
        )
        .map_err(|_| Error::Configuration)?;
        let encoded = get("HOSTED_BILLING_RUNTIME_KEY")?;
        let mut runtime_key = [0; 32];
        if encoded.len() != 64 || !encoded.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(Error::Configuration);
        }
        for (i, byte) in runtime_key.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&encoded[i * 2..i * 2 + 2], 16)
                .map_err(|_| Error::Configuration)?;
        }
        let automatic_tax = match get("HOSTED_BILLING_AUTOMATIC_TAX")?.as_str() {
            "true" => true,
            "false" => false,
            _ => return Err(Error::Configuration),
        };
        let value = Self {
            namespace,
            policy_revision,
            plan,
            read_key: get("HOSTED_BILLING_READ_KEY")?,
            session_key: get("HOSTED_BILLING_SESSION_KEY")?,
            webhook_secret: get("HOSTED_BILLING_WEBHOOK_SECRET")?,
            webhook_endpoint: get("HOSTED_BILLING_WEBHOOK_ENDPOINT_ID")?,
            portal_configuration: get("HOSTED_BILLING_PORTAL_CONFIGURATION_ID")?,
            runtime_key,
            automatic_tax,
        };
        value.validate()?;
        Ok(Some(value))
    }
    fn validate(&self) -> Result<(), Error> {
        let prefix = if self.namespace.mode() == Mode::Live {
            "rk_live_"
        } else {
            "rk_test_"
        };
        if self.policy_revision == 0
            || self.policy_revision > i64::MAX as u64
            || self.runtime_key == [0; 32]
            || self.plan.outbound_limit() > 9_007_199_254_740_991
            || self.plan.device_limit() > 9_007_199_254_740_991
            || !self.read_key.starts_with(prefix)
            || !self.session_key.starts_with(prefix)
            || self.read_key == self.session_key
            || self.read_key.len() > 512
            || self.session_key.len() > 512
            || self.read_key.bytes().any(|b| b.is_ascii_whitespace())
            || self.session_key.bytes().any(|b| b.is_ascii_whitespace())
            || !self.webhook_secret.starts_with("whsec_")
            || self.webhook_secret.len() < 16
            || self.webhook_secret.len() > 512
            || !provider::id(&self.webhook_endpoint, "we_")
            || !provider::id(&self.portal_configuration, "bpc_")
        {
            return Err(Error::Configuration);
        }
        Ok(())
    }
}

pub struct Runtime {
    auth: AuthHttpState,
    options: Options,
    gate: Gate,
    provider: provider::Provider,
    draining: Arc<AtomicBool>,
    notify: Arc<Notify>,
}
impl Runtime {
    pub async fn start(
        auth: AuthHttpState,
        options: Options,
        draining: Arc<AtomicBool>,
        notify: Arc<Notify>,
    ) -> Result<Arc<Self>, Error> {
        let provider = provider::Provider::new()?;
        Self::start_with(auth, options, draining, notify, provider).await
    }
    async fn start_with(
        auth: AuthHttpState,
        options: Options,
        draining: Arc<AtomicBool>,
        notify: Arc<Notify>,
        provider: provider::Provider,
    ) -> Result<Arc<Self>, Error> {
        options.validate()?;
        provider::canonical_origin(&auth.canonical_origin)?;
        let identity = provider.verify(&options, &auth.canonical_origin).await?;
        let mut db = crate::runtime_db::connect(&auth.database_url)
            .await
            .map_err(|_| Error::Database)?;
        let stored = repository::marker(&mut db).await?;
        let gate = Gate::verify(
            true,
            &options.namespace,
            options.policy_revision,
            &stored,
            &identity,
        )
        .map_err(|_| Error::Identity)?;
        // Handshake proves a separately provisioned runtime key. Register only
        // after provider identity, database marker and protected role checks.
        let binding = crate::runtime_db::HostedBinding::new(&gate, options.runtime_key)
            .map_err(|_| Error::Identity)?;
        crate::runtime_db::verify_hosted_connection(&db, &binding)
            .await
            .map_err(|_| Error::Identity)?;
        crate::runtime_db::register_hosted(&auth.database_url, binding)
            .map_err(|_| Error::Identity)?;
        drop(db);
        Ok(Arc::new(Self {
            auth,
            options,
            gate,
            provider,
            draining,
            notify,
        }))
    }
    pub fn gate(&self) -> &Gate {
        &self.gate
    }
    pub fn router(self: &Arc<Self>) -> axum::Router {
        http::router(self.clone())
    }
    pub fn spawn(self: &Arc<Self>) {
        let runtime = self.clone();
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(Duration::from_secs(5));
            tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            loop {
                tokio::select! {_=tick.tick()=>{},_=runtime.notify.notified()=>{}}
                if runtime.draining.load(Ordering::Acquire) {
                    break;
                }
                // Scheduled refresh owns provider I/O. Public plan GETs only
                // read a bounded verified snapshot, including during outages.
                let ready =
                    match crate::runtime_db::connect_worker(&runtime.auth.database_url).await {
                        Ok(mut connection) => repository::marker(&mut connection)
                            .await
                            .is_ok_and(|m| runtime.gate.check_marker(&m).is_ok()),
                        Err(_) => false,
                    };
                if ready {
                    let _ = runtime.provider.refresh_catalog(&runtime.options).await;
                }
                // Serial bounded lane leaves the other worker slots available.
                // No DB connection is held across provider requests.
                let _ = worker::run_one(&runtime).await;
            }
        });
    }
}

fn mode_name(mode: Mode) -> &'static str {
    match mode {
        Mode::Test => "test",
        Mode::Live => "live",
    }
}
fn marker_error(_: super::store::StoreError) -> Error {
    Error::Pending
}

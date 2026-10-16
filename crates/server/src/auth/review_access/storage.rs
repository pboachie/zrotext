// SPDX-License-Identifier: AGPL-3.0-only
//! Actual owned DB phases; the ordinary server does not compose this service.
//! Construction is not an isolation/activation proof. Password work owns no DB
//! client; a failed or uncertain final COMMIT never becomes a no-effect receipt.
use super::{
    AccessError, Result,
    frames::{self, Browser, Candidates, CookieKey, Identities, Operation, Preparation, Scope},
    passwords::{self, Aliases, PasswordEvidence},
};
use crate::{
    auth::{
        TokenHasher,
        abuse_limits::{self, Limit},
    },
    runtime_db,
};
use sha2::{Digest, Sha256};
use std::sync::Arc;
use tokio_postgres::{GenericClient, IsolationLevel, Row, Transaction};
use uuid::Uuid;
use zeroize::Zeroize;

#[cfg(test)]
#[path = "storage_tests.rs"]
mod tests;

pub struct ReviewAccess {
    pub(crate) scope: Scope,
    pub(crate) key: CookieKey,
    aliases: Aliases,
    pub(super) budget_hasher: TokenHasher,
    database_url: Arc<str>,
}
impl ReviewAccess {
    /// One bounded expiry-only transaction; it neither deletes workspaces nor
    /// infers that an absent receipt proves no effect. Assembly owns scheduling.
    pub async fn prune_once(&self) -> Result<u64> {
        let mut client = self.connect().await?;
        let tx = begin(&mut client).await?;
        let changed: i64 = tx
            .query_one("SELECT public.review_access_prune()", &[])
            .await?
            .get(0);
        if changed < 0 {
            return Err(AccessError::Unavailable);
        }
        tx.commit().await?;
        Ok(changed as u64)
    }
    /// Unmounted library service, not a production startup or isolation adapter.
    pub fn unmounted(
        database_url: String,
        scope: Scope,
        mut secret: [u8; 32],
        aliases: Aliases,
    ) -> Result<Self> {
        let key = CookieKey::new(secret, &scope)?;
        let base = TokenHasher::new(secret.to_vec()).map_err(|_| AccessError::Rejected)?;
        secret.zeroize();
        let scope_subject = format!("{}:{}:{}", scope.realm, hex(&scope.database), scope.origin);
        // Existing auth-abuse primitive with a separate review key and closed
        // scopes. Realm separation prevents cross-installation counter sharing.
        let budget_hasher = TokenHasher::new(
            base.digest(b"review-realm-budget-key-v1", &scope_subject)
                .to_vec(),
        )
        .map_err(|_| AccessError::Rejected)?;
        Ok(Self {
            scope,
            key,
            aliases,
            budget_hasher,
            database_url: database_url.into(),
        })
    }
    pub(crate) async fn connect(&self) -> Result<runtime_db::PooledClient> {
        let client = runtime_db::connect(&self.database_url)
            .await
            .map_err(|_| AccessError::Unavailable)?;
        // Review queries must not inherit an operator URL's function/operator
        // search path. Only pg_catalog participates, including overload lookup.
        // This is scoped to this review checkout, not the common pool policy.
        client
            .batch_execute("SET search_path TO pg_catalog")
            .await?;
        Ok(client)
    }
    pub(crate) async fn browser_prepare(
        &self,
        existing: Option<&str>,
    ) -> Result<(Browser, u64, bool)> {
        let mut client = self.connect().await?;
        let tx = begin(&mut client).await?;
        let now = clock(&tx, 0).await?;
        let fresh = existing.is_none();
        let browser = match existing {
            Some(value) => Browser::open(value, &self.key, &self.scope, now)?,
            None => Browser::fresh(now)?,
        };
        let digest = browser.digest(&self.key, &self.scope);
        if !fresh && !tx.query_one("SELECT EXISTS(SELECT FROM public.review_access_preparations WHERE browser_digest=$1)",&[&&digest[..]]).await?.get::<_,bool>(0) {
            return Err(AccessError::Unavailable);
        }
        if fresh
            && !abuse_limits::consume_review(&tx, &self.budget_hasher, Limit::ReviewBrowser, "")
                .await?
        {
            tx.commit().await?;
            return Err(AccessError::RateLimited);
        }
        self.browser_phase(&tx, &browser, false).await?;
        let now = clock(&tx, now).await?;
        tx.commit().await?;
        Ok((browser, now, fresh))
    }
    async fn browser_phase(
        &self,
        client: &impl GenericClient,
        browser: &Browser,
        confirm: bool,
    ) -> Result<Row> {
        let s = &self.scope;
        let digest = browser.digest(&self.key, s);
        Ok(client
            .query_one(
                "SELECT * FROM public.review_access_browser($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)",
                &[
                    &s.realm,
                    &&s.database[..],
                    &s.origin,
                    &&s.key[..],
                    &&s.config[..],
                    &(s.config_revision as i64),
                    &&digest[..],
                    &(browser.issued as i64),
                    &(browser.expires as i64),
                    &confirm,
                ],
            )
            .await?)
    }
    pub(crate) async fn browser_confirm(&self, browser: &Browser) -> Result<u64> {
        let client = self.connect().await?;
        self.browser_phase(&*client, browser, true).await?;
        clock(&*client, browser.issued).await
    }
    /// Public continuity metadata only. A returned row is not a held owner or
    /// a no-effect proof; mutation/status paths recheck their exact DB fences.
    pub(crate) async fn browser_view(&self, browser: &Browser) -> Result<Row> {
        let client = self.connect().await?;
        let s = &self.scope;
        let digest = browser.digest(&self.key, s);
        client.query_opt("SELECT g.* FROM public.review_access_preparations g JOIN public.review_realm_installation m ON m.realm_id=g.realm_id \
            WHERE g.browser_digest=$1 AND g.realm_id=$2 AND g.database_commitment=$3 AND g.origin=$4 AND g.auth_key_commitment=$5 \
            AND g.config_digest=$6 AND g.config_revision=$7 AND m.active_config_digest=$6 AND m.active_config_revision=$7 \
            AND m.auth_key_digest=$5 AND pg_catalog.sha256(pg_catalog.uuid_send(m.database_id))=$3 \
            AND g.created_ms<=(extract(epoch FROM pg_catalog.clock_timestamp())*1000)::bigint \
            AND g.browser_expires_ms>(extract(epoch FROM pg_catalog.clock_timestamp())*1000)::bigint",
            &[&&digest[..],&s.realm,&&s.database[..],&s.origin,&&s.key[..],&&s.config[..],&(s.config_revision as i64)]).await?.ok_or(AccessError::Unavailable)
    }
    pub(crate) async fn prepare_login(
        &self,
        browser: &Browser,
        request: Uuid,
        alias: String,
        resume: bool,
    ) -> Result<Preparation> {
        if request.is_nil() || !frames::valid_alias(&alias) {
            return Err(AccessError::Rejected);
        }
        let mut client = self.connect().await?;
        let tx = begin(&mut client).await?;
        let guard = self.guard(&tx, browser).await?;
        let now = clock(&tx, browser.issued).await?;
        let generation = guard
            .get::<_, i64>("generation")
            .checked_add(1)
            .ok_or(AccessError::Unavailable)? as u64;
        let operation = if resume {
            Operation::BrokerForResume
        } else {
            Operation::InitialBootstrap
        };
        let identities = Identities {
            principal: Uuid::nil(),
            credential: Uuid::nil(),
            revision: 0,
            broker_session: Uuid::new_v4(),
            event: Uuid::new_v4(),
            owner_session: if resume { Uuid::nil() } else { Uuid::new_v4() },
            account: if resume { Uuid::nil() } else { Uuid::new_v4() },
            user: if resume { Uuid::nil() } else { Uuid::new_v4() },
        };
        let prep = Preparation {
            operation,
            browser: browser.digest(&self.key, &self.scope),
            id: Uuid::new_v4(),
            request,
            generation,
            prepared: now,
            create_deadline: now
                .checked_add(frames::WINDOW)
                .ok_or(AccessError::Unavailable)?
                .min(browser.expires),
            delivery_deadline: now
                .checked_add(frames::DELIVERY)
                .ok_or(AccessError::Unavailable)?
                .min(browser.expires),
            alias,
            identities,
            target: [0; 32],
            candidates: Candidates::fresh(operation),
        };
        prep.validate(browser, &self.key, &self.scope, now, true)?;
        let s = &self.scope;
        let digest = prep.commitment(&self.key, s);
        let csrf_digest: [u8; 32] = Sha256::digest(prep.candidates.csrf.as_ref()).into();
        tx.query_one("SELECT * FROM public.review_access_prepare($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16)",
            &[&s.realm,&&s.database[..],&s.origin,&&s.key[..],&&s.config[..],&(s.config_revision as i64),&&prep.browser[..],
            &prep.id,&prep.request,&(prep.operation as i16),&&digest[..],&(prep.generation as i64),&(prep.prepared as i64),
            &(prep.create_deadline as i64),&(prep.delivery_deadline as i64),&&csrf_digest[..]]).await?;
        tx.commit().await?;
        Ok(prep)
    }
    pub(super) async fn guard(&self, tx: &Transaction<'_>, browser: &Browser) -> Result<Row> {
        let s = &self.scope;
        let digest = browser.digest(&self.key, s);
        Ok(tx
            .query_one(
                "SELECT * FROM public.review_access_guard_lock($1,$2,$3,$4,$5,$6,$7)",
                &[
                    &s.realm,
                    &&s.database[..],
                    &s.origin,
                    &&s.key[..],
                    &&s.config[..],
                    &(s.config_revision as i64),
                    &&digest[..],
                ],
            )
            .await?)
    }
    pub(crate) async fn transition(&self, prep: &Preparation, transition: &str) -> Result<String> {
        if !matches!(transition, "confirm" | "cancel" | "inspect") {
            return Err(AccessError::Rejected);
        }
        let mut client = self.connect().await?;
        let tx = begin(&mut client).await?;
        let state = self.transition_in(&tx, prep, transition).await?;
        tx.commit().await?;
        Ok(state)
    }
    pub(super) async fn transition_in(
        &self,
        tx: &Transaction<'_>,
        prep: &Preparation,
        transition: &str,
    ) -> Result<String> {
        let s = &self.scope;
        let digest = prep.commitment(&self.key, s);
        Ok(tx.query_one("SELECT public.review_access_transition($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)",
            &[&s.realm,&&s.database[..],&s.origin,&&s.key[..],&&s.config[..],&(s.config_revision as i64),&&prep.browser[..],
            &prep.id,&prep.request,&(prep.operation as i16),&&digest[..],&(prep.generation as i64),&transition]).await?.get(0))
    }
    pub(crate) async fn login(&self, prep: &Preparation, password: &str) -> Result<Row> {
        if !matches!(
            prep.operation,
            Operation::InitialBootstrap | Operation::BrokerForResume
        ) {
            return Err(AccessError::Rejected);
        }
        let snapshot = {
            let mut client = self.connect().await?;
            let tx = begin(&mut client).await?;
            self.transition_in(&tx, prep, "claim").await?;
            let subject = format!("{}:{}", self.scope.realm, prep.alias);
            if !abuse_limits::consume_review(&tx, &self.budget_hasher, Limit::ReviewLogin, &subject)
                .await?
            {
                self.transition_in(&tx, prep, "reject_rolled_back").await?;
                tx.commit().await?;
                return Err(AccessError::RateLimited);
            }
            let snapshot = passwords::capture(&tx, &self.scope, &self.aliases, &prep.alias).await?;
            tx.commit().await?;
            snapshot
        }; // Client and every transaction lock are released before Argon2.
        let checked = passwords::check(snapshot, &self.key, &self.scope, prep, password).await;
        match checked {
            Ok(evidence) => self.finish_login(prep, evidence).await,
            Err(error) => {
                // No business transaction has started. A concurrent cancel may
                // already have won; failing this exact CAS preserves its state.
                if let Ok(mut client) = self.connect().await
                    && let Ok(tx) = begin(&mut client).await
                    && self
                        .transition_in(&tx, prep, "reject_rolled_back")
                        .await
                        .is_ok()
                {
                    let _ = tx.commit().await;
                }
                Err(error)
            }
        }
    }
    async fn finish_login(&self, prep: &Preparation, evidence: PasswordEvidence) -> Result<Row> {
        let s = &self.scope;
        if evidence.snapshot.scope != *s
            || evidence.request_digest != prep.commitment(&self.key, s)
            || evidence.operation != prep.operation
        {
            return Err(AccessError::Rejected);
        }
        let broker_token =
            self.key
                .broker_token(s, prep.identities.broker_session, &prep.candidates.broker)?;
        let broker_csrf = self.key.broker_csrf(
            s,
            prep.identities.broker_session,
            &prep.candidates.broker_csrf,
        )?;
        let bootstrap = prep.operation == Operation::InitialBootstrap;
        let account = bootstrap.then_some(prep.identities.account);
        let user = bootstrap.then_some(prep.identities.user);
        let owner = bootstrap.then_some(prep.identities.owner_session);
        let owner_token = if bootstrap {
            Some(
                self.key
                    .owner_token(s, prep.identities.owner_session, &prep.candidates.owner)?,
            )
        } else {
            None
        };
        let owner_csrf = if bootstrap {
            Some(self.key.owner_csrf(
                s,
                prep.identities.owner_session,
                &prep.candidates.owner_csrf,
            )?)
        } else {
            None
        };
        let locator = if bootstrap {
            Some(self.key.locator(s, &prep.candidates.locator)?)
        } else {
            None
        };
        let mut client = self.connect().await?;
        let tx = begin(&mut client).await?;
        // The only final writer consumes actual owned verifier evidence. The
        // SQL wrapper independently locks/rechecks its exact current snapshot.
        let b = &evidence.snapshot;
        let result=tx.query_one("SELECT * FROM public.review_access_login($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23,$24,$25,$26,$27)",
            &[&s.realm,&&s.database[..],&s.origin,&&s.key[..],&&s.config[..],&(s.config_revision as i64),&&prep.browser[..],
            &prep.id,&prep.request,&(prep.operation as i16),&&evidence.request_digest[..],&(prep.generation as i64),
            &b.principal,&b.credential,&b.revision,&b.verifier.as_str(),&prep.identities.broker_session,&prep.identities.event,
            &&broker_token[..],&&broker_csrf[..],&account,&user,&owner,&owner_token.as_ref().map(|x|&x[..]),
            &owner_csrf.as_ref().map(|x|&x[..]),&locator.as_ref().map(|x|&x[..]),&b.observed_ms]).await?;
        // Any error from this point is UNKNOWN, never RejectedNoEffect. A lost
        // acknowledgement is reconciled using the original immutable result.
        tx.commit().await?;
        Ok(result)
    }
}
pub(crate) async fn begin(client: &mut tokio_postgres::Client) -> Result<Transaction<'_>> {
    let tx = client
        .build_transaction()
        .isolation_level(IsolationLevel::ReadCommitted)
        .start()
        .await?;
    tx.batch_execute("SET LOCAL search_path TO pg_catalog; SET LOCAL lock_timeout='3s'; SET LOCAL statement_timeout='5s'")
        .await?;
    Ok(tx)
}
pub(crate) async fn clock(client: &impl GenericClient, floor: u64) -> Result<u64> {
    let value: i64 = client
        .query_one(
            "SELECT floor(extract(epoch FROM pg_catalog.clock_timestamp())*1000)::bigint",
            &[],
        )
        .await?
        .get(0);
    if value <= 0 || (value as u64) < floor {
        return Err(AccessError::Unavailable);
    }
    Ok(value as u64)
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|x| format!("{x:02x}")).collect()
}

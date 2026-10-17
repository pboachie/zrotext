// SPDX-License-Identifier: AGPL-3.0-only
//! Current typed review credentials and transaction-borrowed owner witness.
//! Neither metadata nor a password check can construct this held witness.
use super::frames::LocatorSelector;
use super::{
    AccessError, Result,
    frames::{Browser, Preparation},
    storage::{self, ReviewAccess},
};
use crate::http_review_access::dto::{
    Capability, Decimal, RootState, TypedSessionContext, Version1,
};
use base64::{Engine, engine::general_purpose::STANDARD};
use sha2::{Digest, Sha256};
use tokio_postgres::{Row, Transaction};
use uuid::Uuid;

pub(crate) enum LocatorPhase {
    Context,
    Confirm,
    Status,
}
pub(crate) struct LocatorObservation<'a> {
    pub phase: LocatorPhase,
    pub preparation: Uuid,
    pub request: Uuid,
    pub selector_hash: &'a [u8; 32],
    pub selector_value: Option<&'a str>,
}
struct Settlement<'a> {
    action: &'a str,
    preparation: Uuid,
    request: Uuid,
    generation: u64,
    csrf: Option<&'a [u8; 32]>,
    locator: Option<&'a [u8; 32]>,
    selector: Option<&'a [u8; 32]>,
}

/// Owned digests, not ordinary SessionPrincipal or cookie contents. Fields are
/// private; constructing them does not authenticate anything until the DB locks.
pub(crate) struct Credentials {
    pub(super) broker: Uuid,
    pub(super) broker_token: [u8; 32],
    pub(super) broker_csrf: [u8; 32],
    pub(super) owner: Uuid,
    pub(super) owner_token: [u8; 32],
    pub(super) owner_csrf: [u8; 32],
}
impl ReviewAccess {
    pub(crate) async fn acknowledge(
        &self,
        browser: &Browser,
        c: &Credentials,
        preparation: Uuid,
        request: Uuid,
        generation: u64,
        csrf: &[u8; 32],
    ) -> Result<()> {
        let digest: [u8; 32] = Sha256::digest(csrf).into();
        self.settlement(
            browser,
            c,
            Settlement {
                action: "delivery_ack",
                preparation,
                request,
                generation,
                csrf: Some(&digest),
                locator: None,
                selector: None,
            },
        )
        .await?;
        Ok(())
    }
    pub(crate) async fn locator_retention(
        &self,
        browser: &Browser,
        c: &Credentials,
        observation: LocatorObservation<'_>,
    ) -> Result<bool> {
        let LocatorObservation {
            phase,
            preparation,
            request,
            selector_hash,
            selector_value,
        } = observation;
        let client = self.connect().await?;
        let now = storage::clock(&*client, 0).await?;
        drop(client);
        let selector = selector_value
            .map(|value| {
                if <[u8; 32]>::from(Sha256::digest(value.as_bytes())) != *selector_hash {
                    return Err(AccessError::Rejected);
                }
                LocatorSelector::open(value, &self.key, &self.scope, now)
            })
            .transpose()?;
        if selector.is_none() && !matches!(phase, LocatorPhase::Status) {
            return Err(AccessError::Unavailable);
        }
        if let Some(selector) = &selector {
            let mut client = self.connect().await?;
            let tx = storage::begin(&mut client).await?;
            let held = HeldOwner::acquire(self, &tx, browser, c, true).await?;
            let row = tx
                .query_one(
                    "SELECT * FROM public.review_access_locators WHERE account_id=$1",
                    &[&held.account()],
                )
                .await?;
            if selector.account != held.account()
                || selector.user != held.user()
                || selector.preparation != preparation
                || selector.preparation != row.get::<_, Uuid>("preparation_id")
                || selector.request != row.get::<_, Uuid>("request_id")
                || selector.generation != row.get::<_, i64>("generation") as u64
                || selector.created != row.get::<_, i64>("created_ms") as u64
                || row.get::<_, Vec<u8>>("locator_digest")
                    != selector.digest(&self.key, &self.scope)?
            {
                return Err(AccessError::Rejected);
            }
            held.check(now).await?;
            drop(held);
            tx.commit().await?;
        }
        let digest = selector
            .as_ref()
            .map(|value| value.digest(&self.key, &self.scope))
            .transpose()?;
        let action = match phase {
            LocatorPhase::Context => "locator_context",
            LocatorPhase::Confirm => "locator_ack",
            LocatorPhase::Status => "locator_status",
        };
        self.settlement(
            browser,
            c,
            Settlement {
                action,
                preparation,
                request,
                generation: 0,
                csrf: None,
                locator: digest.as_ref(),
                selector: Some(selector_hash),
            },
        )
        .await
    }
    async fn settlement(
        &self,
        browser: &Browser,
        c: &Credentials,
        operation: Settlement<'_>,
    ) -> Result<bool> {
        let Settlement {
            action,
            preparation,
            request,
            generation,
            csrf,
            locator,
            selector,
        } = operation;
        let mut client = self.connect().await?;
        let tx = storage::begin(&mut client).await?;
        let s = &self.scope;
        let digest = browser.digest(&self.key, s);
        let result:bool=tx.query_one("SELECT public.review_access_owner_settlement($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20)",
            &[&s.realm,&&s.database[..],&s.origin,&&s.key[..],&&s.config[..],&(s.config_revision as i64),&&digest[..],
              &c.broker,&&c.broker_token[..],&&c.broker_csrf[..],&c.owner,&&c.owner_token[..],&&c.owner_csrf[..],&action,
              &preparation,&request,&(generation as i64),&csrf.map(|v|&v[..]),&locator.map(|v|&v[..]),&selector.map(|v|&v[..])]).await?.get(0);
        tx.commit().await?;
        Ok(result)
    }
    pub(crate) async fn context(
        &self,
        browser: &Browser,
        c: &Credentials,
        request: Uuid,
    ) -> Result<TypedSessionContext> {
        let mut client = self.connect().await?;
        let tx = storage::begin(&mut client).await?;
        let held = HeldOwner::acquire(self, &tx, browser, c, false).await?;
        let state = held.root_state().await?;
        let parent=tx.query_one("SELECT b.expires_ms,b.last_used_ms,a.delivery_deadline_ms FROM public.review_broker_sessions b \
            JOIN public.review_access_authentications a ON a.broker_session_id=b.id WHERE b.id=$1",&[&c.broker]).await?;
        let retained:bool=tx.query_one("SELECT EXISTS(SELECT FROM public.review_access_locators WHERE account_id=$1 AND retained_ms IS NOT NULL)",&[&held.account()]).await?.get(0);
        let absolute = (held.row.get::<_, i64>("expires_ms") as u64)
            .min(parent.get::<_, i64>(0) as u64)
            .min(parent.get::<_, i64>(2) as u64)
            .min(browser.expires);
        let idle = (held.row.get::<_, i64>("last_used_ms") as u64)
            .checked_add(72 * 60 * 60 * 1000)
            .ok_or(AccessError::Unavailable)?
            .min(
                (parent.get::<_, i64>(1) as u64)
                    .checked_add(72 * 60 * 60 * 1000)
                    .ok_or(AccessError::Unavailable)?,
            )
            .min(absolute);
        let now = held.check(held.checked_ms).await?;
        if now >= idle {
            return Err(AccessError::Unavailable);
        }
        let s = &self.scope;
        let result = TypedSessionContext {
            version: Version1,
            request_id: request,
            realm: s.realm,
            database_commitment_b64: STANDARD.encode(s.database),
            config_digest_b64: STANDARD.encode(s.config),
            config_revision: Decimal(s.config_revision),
            origin: s.origin.clone(),
            account: held.account(),
            owner_user: held.user(),
            review_owner_session: held.session(),
            broker_principal: held.row.get("broker_id"),
            credential_id: held.row.get("credential_id"),
            credential_revision: Decimal(held.row.get::<_, i64>("credential_revision") as u64),
            broker_session: c.broker,
            auth_event: held.row.get("authentication_event_id"),
            issued_ms: Decimal(held.row.get::<_, i64>("issued_ms") as u64),
            absolute_expiry_ms: Decimal(absolute),
            idle_deadline_ms: Decimal(idle),
            server_now_ms: Decimal(now),
            capabilities: [
                Capability::BootstrapSession,
                Capability::RootIssue,
                Capability::RootComplete,
                Capability::RootReceipt,
                Capability::RootCustodyExport,
            ],
            locator_retained: retained,
            root_state: state,
        };
        drop(held);
        tx.commit().await?;
        Ok(result)
    }
    pub(crate) fn credentials(
        &self,
        broker: Uuid,
        broker_token: &[u8; 32],
        broker_csrf: &[u8; 32],
        owner: Uuid,
        owner_token: &[u8; 32],
        owner_csrf: &[u8; 32],
    ) -> Result<Credentials> {
        Ok(Credentials {
            broker,
            broker_token: self.key.broker_token(&self.scope, broker, broker_token)?,
            broker_csrf: self.key.broker_csrf(&self.scope, broker, broker_csrf)?,
            owner,
            owner_token: self.key.owner_token(&self.scope, owner, owner_token)?,
            owner_csrf: self.key.owner_csrf(&self.scope, owner, owner_csrf)?,
        })
    }
    pub(crate) async fn login_status(&self, prep: &Preparation) -> Result<Row> {
        // Original MAC-authenticated candidates are already held. Status can
        // publish only their exact committed broker, never allocate/redeliver
        // new credentials or refresh any deadline.
        let token = self.key.broker_token(
            &self.scope,
            prep.identities.broker_session,
            &prep.candidates.broker,
        )?;
        let csrf = self.key.broker_csrf(
            &self.scope,
            prep.identities.broker_session,
            &prep.candidates.broker_csrf,
        )?;
        let mut client = self.connect().await?;
        let tx = storage::begin(&mut client).await?;
        let s = &self.scope;
        let row=tx.query_one("SELECT * FROM public.review_access_broker_current($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,false)",
            &[&s.realm,&&s.database[..],&s.origin,&&s.key[..],&&s.config[..],&(s.config_revision as i64),&&prep.browser[..],
              &prep.identities.broker_session,&&token[..],&&csrf[..]]).await?;
        if row.get::<_, Uuid>("preparation_id") != prep.id
            || row.get::<_, Uuid>("request_id") != prep.request
            || row.get::<_, i64>("generation") as u64 != prep.generation
            || row.get::<_, Vec<u8>>("request_digest") != prep.commitment(&self.key, s)
            || row.get::<_, i16>("operation") != prep.operation as i16
        {
            return Err(AccessError::Unavailable);
        }
        tx.commit().await?;
        Ok(row)
    }
}

/// A genuine borrowed transaction witness. No public constructor, Clone,
/// Debug, Serialize, detached boolean, or ordinary principal conversion.
pub(super) struct HeldOwner<'a, 'db> {
    pub(super) tx: &'a Transaction<'db>,
    pub(super) row: Row,
    access: &'a ReviewAccess,
    browser: &'a Browser,
    credentials: &'a Credentials,
    mutation: bool,
    pub(super) checked_ms: u64,
}
impl<'a, 'db> HeldOwner<'a, 'db> {
    pub(super) async fn acquire(
        access: &'a ReviewAccess,
        tx: &'a Transaction<'db>,
        browser: &'a Browser,
        credentials: &'a Credentials,
        mutation: bool,
    ) -> Result<Self> {
        let row = owner_query(access, tx, browser, credentials, mutation).await?;
        let checked_ms = storage::clock(tx, row.get::<_, i64>("last_used_ms") as u64).await?;
        Ok(Self {
            tx,
            row,
            access,
            browser,
            credentials,
            mutation,
            checked_ms,
        })
    }
    pub(super) async fn check(&self, floor: u64) -> Result<u64> {
        let row = owner_query(
            self.access,
            self.tx,
            self.browser,
            self.credentials,
            self.mutation,
        )
        .await?;
        if row.get::<_, Uuid>("id") != self.row.get::<_, Uuid>("id")
            || row.get::<_, Uuid>("account_id") != self.account()
        {
            return Err(AccessError::Unavailable);
        }
        storage::clock(self.tx, floor.max(self.checked_ms)).await
    }
    pub(super) fn account(&self) -> Uuid {
        self.row.get("account_id")
    }
    pub(super) fn user(&self) -> Uuid {
        self.row.get("user_id")
    }
    pub(super) fn session(&self) -> Uuid {
        self.row.get("id")
    }
    pub(super) async fn root_state(&self) -> Result<RootState> {
        let account = self.account();
        if let Some(row)=self.tx.query_opt("SELECT root_pin,root_fingerprint,generation FROM public.sealed_manifest_authorities WHERE account_id=$1",&[&account]).await? {
            let pin:Vec<u8>=row.get(0); let fp:Vec<u8>=row.get(1);let generation:i64=row.get(2);
            if generation<=0 || crate::sealed_root_enrollment::root_fingerprint(&pin,account.as_bytes()).ok().as_ref().map(|x|&x[..])!=Some(fp.as_slice()) {
                return Ok(RootState::Unavailable);
            }
            return Ok(RootState::Enrolled {root_pin_b64:STANDARD.encode(pin),root_fingerprint_b64:STANDARD.encode(fp),generation:Decimal(generation as u64)});
        }
        let pending=self.tx.query_opt("SELECT r.root_challenge_id,r.root_pin,r.root_fingerprint,r.encrypted_backup_digest,r.public_card_digest, \
            pg_catalog.sha256(r.unsigned_enrollment),r.statement_digest,r.expires_ms FROM public.review_access_root_reauth r \
            JOIN public.sealed_root_challenges c ON c.account_id=r.account_id AND c.challenge_id=r.root_challenge_id \
            WHERE r.account_id=$1 AND r.state='pending' AND c.consumed_ms IS NULL ORDER BY r.issued_ms LIMIT 1",&[&account]).await?;
        if let Some(r) = pending {
            let expires = r.get::<_, i64>(7) as u64;
            if self.checked_ms < expires {
                return Ok(RootState::PendingEnrollment {
                    challenge_id: r.get(0),
                    root_pin_b64: STANDARD.encode(r.get::<_, Vec<u8>>(1)),
                    root_fingerprint_b64: STANDARD.encode(r.get::<_, Vec<u8>>(2)),
                    encrypted_backup_sha256_b64: STANDARD.encode(r.get::<_, Vec<u8>>(3)),
                    public_card_sha256_b64: STANDARD.encode(r.get::<_, Vec<u8>>(4)),
                    unsigned_enrollment_sha256_b64: STANDARD.encode(r.get::<_, Vec<u8>>(5)),
                    custody_statement_sha256_b64: STANDARD.encode(r.get::<_, Vec<u8>>(6)),
                    expires_ms: Decimal(expires),
                });
            }
        }
        let history:bool=self.tx.query_one("SELECT EXISTS(SELECT FROM public.sealed_root_challenges WHERE account_id=$1) \
            OR EXISTS(SELECT FROM public.sealed_root_receipts WHERE account_id=$1) OR EXISTS(SELECT FROM public.sealed_root_custody WHERE account_id=$1) \
            OR EXISTS(SELECT FROM public.sealed_root_enrollments WHERE account_id=$1) OR EXISTS(SELECT FROM public.known_signing_point_reservations WHERE account_id=$1) \
            OR EXISTS(SELECT FROM public.known_signing_role_claims WHERE account_id=$1) OR EXISTS(SELECT FROM public.review_access_root_reauth WHERE account_id=$1)",&[&account]).await?.get(0);
        Ok(if history {
            RootState::History
        } else {
            RootState::NoRootHistory
        })
    }
}
async fn owner_query(
    access: &ReviewAccess,
    tx: &Transaction<'_>,
    browser: &Browser,
    c: &Credentials,
    mutation: bool,
) -> Result<Row> {
    let s = &access.scope;
    let digest = browser.digest(&access.key, s);
    Ok(tx.query_one("SELECT * FROM public.review_access_owner_current($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)",
        &[&s.realm,&&s.database[..],&s.origin,&&s.key[..],&&s.config[..],&(s.config_revision as i64),&&digest[..],
          &c.broker,&&c.broker_token[..],&&c.broker_csrf[..],&c.owner,&&c.owner_token[..],&&c.owner_csrf[..],&mutation]).await?)
}

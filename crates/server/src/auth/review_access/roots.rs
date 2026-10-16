// SPDX-License-Identifier: AGPL-3.0-only
//! Genuine first-root/custody consumers for a distinct review owner. No ordinary
//! SessionPrincipal, MFA row, verified email or synthetic ConsumedFactor exists.
use super::{
    AccessError, Result,
    current::{Credentials, HeldOwner},
    frames::{self, Browser, Candidates, Identities, Operation, Preparation},
    passwords,
    storage::{self, ReviewAccess},
};
use crate::{
    auth::abuse_limits::{self, Limit},
    http_review_access::dto::{
        Decimal, RootCustodyExport, RootIssueResponse, RootReceipt, RootState, Version1,
    },
    sealed_root_custody as custody, sealed_root_enrollment as proof,
};
use base64::{Engine, engine::general_purpose::STANDARD};
use rand::{Rng, rng};
use sha2::{Digest, Sha256};
use tokio_postgres::Row;
use uuid::Uuid;
use zrotext_root_material::{recovery_kit::decode_public_card, root_backup};

/// Bounded public pin/ciphertext/card, never a private software root or password.
pub(crate) struct Material {
    pub(crate) pin: [u8; 94],
    pub(crate) compared: [u8; 32],
    pub(crate) backup: Vec<u8>,
    pub(crate) card: Vec<u8>,
}
impl Material {
    fn validate(&self, account: Uuid, origin: &str) -> Result<Uuid> {
        let fingerprint = proof::root_fingerprint(&self.pin, account.as_bytes())
            .map_err(|_| AccessError::Rejected)?;
        if fingerprint != self.compared
            || self.backup.len() > custody::MAX_BACKUP
            || self.card.len() > custody::MAX_CARD
        {
            return Err(AccessError::Rejected);
        }
        let expected = root_backup::ExpectedIdentity {
            account_id: *account.as_bytes(),
            origin: origin.into(),
            root_fingerprint: fingerprint,
        };
        let id = root_backup::validate_public_header(&self.backup, &expected)
            .map_err(|_| AccessError::Rejected)?;
        decode_public_card(&self.card, &expected, &Sha256::digest(&self.backup).into())
            .map_err(|_| AccessError::Rejected)?;
        Ok(Uuid::from_bytes(id))
    }
    fn issue_target(&self, origin: &str) -> [u8; 32] {
        let mut bytes = vec![Operation::RootIssue as u8];
        bytes.extend_from_slice(&(origin.len() as u16).to_be_bytes());
        bytes.extend_from_slice(origin.as_bytes());
        bytes.extend_from_slice(&self.pin);
        bytes.extend_from_slice(&self.compared);
        bytes.extend_from_slice(&Sha256::digest(&self.backup));
        bytes.extend_from_slice(&Sha256::digest(&self.card));
        Sha256::digest(bytes).into()
    }
}
pub(crate) struct Completion {
    pub(crate) root: Uuid,
    pub(crate) reauth: Uuid,
    pub(crate) nonce: [u8; 32],
    pub(crate) unsigned: Vec<u8>,
    pub(crate) enrollment_signature: [u8; 64],
    pub(crate) custody_signature: [u8; 64],
    pub(crate) material: Material,
}
impl Completion {
    fn target(&self, origin: &str) -> Result<[u8; 32]> {
        let mut bytes = vec![Operation::RootComplete as u8];
        bytes.extend_from_slice(&(origin.len() as u16).to_be_bytes());
        bytes.extend_from_slice(origin.as_bytes());
        bytes.extend_from_slice(self.root.as_bytes());
        bytes.extend_from_slice(self.reauth.as_bytes());
        bytes.extend_from_slice(&self.nonce);
        bytes.extend_from_slice(
            &custody::statement(
                &self.unsigned,
                &self.material.backup,
                &self.material.card,
                &self.material.compared,
            )
            .map_err(|_| AccessError::Rejected)?,
        );
        bytes.extend_from_slice(&self.enrollment_signature);
        bytes.extend_from_slice(&self.custody_signature);
        Ok(Sha256::digest(bytes).into())
    }
    fn verify(&self, expected: &proof::Challenge, pin: &[u8], now: u64) -> Result<()> {
        if Uuid::from_bytes(expected.challenge_id) != self.root {
            return Err(AccessError::Rejected);
        }
        proof::verify(
            pin,
            &self.unsigned,
            &self.enrollment_signature,
            expected,
            now,
        )
        .map_err(|_| AccessError::Rejected)?;
        custody::validate(
            custody::Publication {
                encrypted_backup: &self.material.backup,
                public_card: &self.material.card,
                independently_compared_fingerprint: self.material.compared,
                signature: &self.custody_signature,
            },
            pin,
            Uuid::from_bytes(expected.account_id),
            &expected.origin,
            &self.unsigned,
        )
        .map_err(|_| AccessError::Rejected)?;
        Ok(())
    }
}
pub(crate) enum RootPreparation<'a> {
    Issue(&'a Material),
    Complete(&'a Completion),
}
impl ReviewAccess {
    pub(crate) async fn completion_pin(
        &self,
        browser: &Browser,
        c: &Credentials,
        reauth: Uuid,
    ) -> Result<[u8; 94]> {
        let mut client = self.connect().await?;
        let tx = storage::begin(&mut client).await?;
        let held = HeldOwner::acquire(self, &tx, browser, c, false).await?;
        let row = reauth_row(&held, reauth).await?;
        let pin = row
            .get::<_, Vec<u8>>("root_pin")
            .try_into()
            .map_err(|_| AccessError::Unavailable)?;
        held.check(held.checked_ms).await?;
        drop(held);
        tx.commit().await?;
        Ok(pin)
    }
    pub(crate) async fn read_root(
        &self,
        browser: &Browser,
        c: &Credentials,
        request: Uuid,
        compared: &[u8; 32],
    ) -> Result<(RootReceipt, RootCustodyExport)> {
        let mut client = self.connect().await?;
        let tx = storage::begin(&mut client).await?;
        let held = HeldOwner::acquire(self, &tx, browser, c, false).await?;
        let account = held.account();
        let row=tx.query_opt("SELECT c.*,r.user_id AS actor_user,r.session_id AS actor_session,r.completed_ms,a.root_pin AS current_pin, \
            a.root_fingerprint AS current_fingerprint,a.generation AS current_generation FROM public.sealed_root_custody c \
            JOIN public.sealed_root_receipts r ON r.account_id=c.account_id AND r.challenge_id=c.challenge_id \
            JOIN public.sealed_manifest_authorities a ON a.account_id=c.account_id WHERE c.account_id=$1",&[&account]).await?.ok_or(AccessError::Unavailable)?;
        let pin: Vec<u8> = row.get("root_pin");
        let fp: Vec<u8> = row.get("root_fingerprint");
        let backup: Vec<u8> = row.get("encrypted_backup");
        let card: Vec<u8> = row.get("public_card");
        let unsigned: Vec<u8> = row.get("unsigned_enrollment");
        let signature: Vec<u8> = row.get("custody_signature");
        let challenge = proof::parse(&unsigned).map_err(|_| AccessError::Unavailable)?;
        let backup_id = root_backup::validate_public_header(
            &backup,
            &root_backup::ExpectedIdentity {
                account_id: *account.as_bytes(),
                origin: self.scope.origin.clone(),
                root_fingerprint: *compared,
            },
        )
        .map_err(|_| AccessError::Unavailable)?;
        if fp.as_slice() != compared
            || pin != row.get::<_, Vec<u8>>("current_pin")
            || fp != row.get::<_, Vec<u8>>("current_fingerprint")
            || row.get::<_, i64>("current_generation") != 1
            || row.get::<_, i64>("generation") != 1
            || Sha256::digest(&backup).as_slice() != row.get::<_, Vec<u8>>("backup_sha256")
            || Sha256::digest(&card).as_slice() != row.get::<_, Vec<u8>>("card_sha256")
            || row.get::<_, Uuid>("backup_id") != Uuid::from_bytes(backup_id)
            || challenge.account_id != *account.as_bytes()
            || challenge.user_id != *row.get::<_, Uuid>("actor_user").as_bytes()
            || challenge.session_id != *row.get::<_, Uuid>("actor_session").as_bytes()
            || challenge.challenge_id != *row.get::<_, Uuid>("challenge_id").as_bytes()
            || challenge.root_fingerprint != *compared
            || challenge.origin != self.scope.origin
            || row.get::<_, i64>("committed_ms") != row.get::<_, i64>("completed_ms")
            || (row.get::<_, i64>("completed_ms") as u64) < challenge.issued_ms
            || row.get::<_, i64>("completed_ms") as u64 >= challenge.expires_ms
        {
            return Err(AccessError::Unavailable);
        }
        custody::validate(
            custody::Publication {
                encrypted_backup: &backup,
                public_card: &card,
                independently_compared_fingerprint: *compared,
                signature: &signature,
            },
            &pin,
            account,
            &self.scope.origin,
            &unsigned,
        )
        .map_err(|_| AccessError::Unavailable)?;
        let now = held.check(row.get::<_, i64>("completed_ms") as u64).await?;
        let receipt = RootReceipt {
            version: Version1,
            request_id: request,
            account,
            actor_owner_user: row.get("actor_user"),
            actor_review_owner_session: row.get("actor_session"),
            root_challenge_id: row.get("challenge_id"),
            root_pin_b64: STANDARD.encode(&pin),
            root_fingerprint_b64: STANDARD.encode(&fp),
            completed_ms: Decimal(row.get::<_, i64>("completed_ms") as u64),
            server_now_ms: Decimal(now),
        };
        let export = RootCustodyExport {
            version: Version1,
            request_id: request,
            account,
            root_challenge_id: row.get("challenge_id"),
            backup_id: row.get("backup_id"),
            generation: Decimal(1),
            root_pin_b64: STANDARD.encode(pin),
            root_fingerprint_b64: STANDARD.encode(fp),
            encrypted_backup_b64: STANDARD.encode(backup),
            public_card_b64: STANDARD.encode(card),
            unsigned_enrollment_b64: STANDARD.encode(unsigned),
            custody_signature_b64: STANDARD.encode(signature),
            committed_ms: Decimal(row.get::<_, i64>("committed_ms") as u64),
            server_now_ms: Decimal(now),
        };
        drop(held);
        tx.commit().await?;
        Ok((receipt, export))
    }
    pub(crate) async fn complete_root(
        &self,
        browser: &Browser,
        c: &Credentials,
        prep: &Preparation,
        body: &Completion,
        password: &str,
    ) -> Result<RootReceipt> {
        if prep.operation != Operation::RootComplete
            || prep.target != body.target(&self.scope.origin)?
        {
            return Err(AccessError::Rejected);
        }
        let (snapshot, expected, pin) = {
            let mut client = self.connect().await?;
            let tx = storage::begin(&mut client).await?;
            let held = HeldOwner::acquire(self, &tx, browser, c, true).await?;
            same_owner(&held, prep)?;
            let row = reauth_row(&held, body.reauth).await?;
            let expected = matching_completion(&held, &row, body)?;
            self.transition_in(&tx, prep, "claim").await?;
            let subject = held.account().to_string();
            if !abuse_limits::review_root_failure_open(&tx, &self.budget_hasher, &subject).await?
                || !abuse_limits::consume_review(
                    &tx,
                    &self.budget_hasher,
                    Limit::ReviewRootPassword,
                    &subject,
                )
                .await?
            {
                self.transition_in(&tx, prep, "reject_rolled_back").await?;
                drop(held);
                tx.commit().await?;
                return Err(AccessError::RateLimited);
            }
            let snapshot =
                passwords::capture_principal(&tx, &self.scope, held.row.get("broker_id")).await?;
            let pin: Vec<u8> = row.get("root_pin");
            held.check(held.checked_ms).await?;
            drop(held);
            tx.commit().await?;
            (snapshot, expected, pin)
        }; // Every pooled client and DB lock is gone before real password work.
        let checked = passwords::check(snapshot, &self.key, &self.scope, prep, password).await;
        let evidence = match checked {
            Ok(evidence) => evidence,
            Err(error) => {
                self.reject_root_attempt(browser, c, prep, true).await;
                return Err(error);
            }
        };
        // Genuine P-256/root/card/backup verification outside any writer. The
        // final borrowed witness independently repeats it against locked rows.
        if let Err(error) = body.verify(&expected, &pin, evidence.snapshot.observed_ms as u64) {
            self.reject_root_attempt(browser, c, prep, false).await;
            return Err(error);
        }
        let mut client = self.connect().await?;
        let tx = storage::begin(&mut client).await?;
        let held = HeldOwner::acquire(self, &tx, browser, c, true).await?;
        same_owner(&held, prep)?;
        let row = reauth_row(&held, body.reauth).await?;
        let confirmed =
            ReviewReauthentication::confirm(&held, &row, body, &evidence, self, prep).await?;
        let backup_id = body.material.validate(held.account(), &self.scope.origin)?;
        let b = &evidence.snapshot;
        let data = serde_json::json!({"backup":hex(&body.material.backup),"backup_id":backup_id.to_string(),"card":hex(&body.material.card),
            "custody_signature":hex(&body.custody_signature),"enrollment_signature":hex(&body.enrollment_signature),"nonce":hex(&body.nonce),
            "reauth":body.reauth.to_string(),"root":body.root.to_string(),"unsigned":hex(&body.unsigned)});
        let result = root_commit(
            confirmed.owner,
            self,
            browser,
            c,
            prep,
            &data,
            Some(&evidence),
        )
        .await?;
        let completed = result.get::<_, i64>("completed_ms") as u64;
        let now = held.check((b.observed_ms as u64).max(completed)).await?;
        body.verify(&confirmed.expected, &pin, now)?;
        if now >= prep.create_deadline {
            return Err(AccessError::Unavailable);
        }
        let receipt = RootReceipt {
            version: Version1,
            request_id: prep.request,
            account: held.account(),
            actor_owner_user: Uuid::from_bytes(confirmed.expected.user_id),
            actor_review_owner_session: Uuid::from_bytes(confirmed.expected.session_id),
            root_challenge_id: body.root,
            root_pin_b64: STANDARD.encode(&pin),
            root_fingerprint_b64: STANDARD.encode(body.material.compared),
            completed_ms: Decimal(result.get::<_, i64>("completed_ms") as u64),
            server_now_ms: Decimal(now),
        };
        drop(confirmed);
        drop(held);
        tx.commit().await?;
        Ok(receipt)
    }
    async fn reject_root_attempt(
        &self,
        browser: &Browser,
        c: &Credentials,
        prep: &Preparation,
        password_failed: bool,
    ) {
        // This path is reachable only before any business writer is started.
        // A failed cleanup/CAS preserves Checking/UNKNOWN; never infer no effect.
        let result: Result<()> = async {
            let mut client = self.connect().await?;
            let tx = storage::begin(&mut client).await?;
            let held = HeldOwner::acquire(self, &tx, browser, c, true).await?;
            same_owner(&held, prep)?;
            if password_failed {
                abuse_limits::record_review_root_failure(
                    &tx,
                    &self.budget_hasher,
                    &held.account().to_string(),
                )
                .await?;
            }
            self.transition_in(&tx, prep, "reject_rolled_back").await?;
            held.check(held.checked_ms).await?;
            drop(held);
            tx.commit().await?;
            Ok(())
        }
        .await;
        // Deliberately no retry, secret/raw DB logging, or alternate state.
        drop(result);
    }
    pub(crate) async fn prepare_root(
        &self,
        browser: &Browser,
        c: &Credentials,
        request: Uuid,
        body: RootPreparation<'_>,
    ) -> Result<Preparation> {
        let mut client = self.connect().await?;
        let tx = storage::begin(&mut client).await?;
        let held = HeldOwner::acquire(self, &tx, browser, c, true).await?;
        let (operation, target, root_expiry) = match body {
            RootPreparation::Issue(material) => {
                if !matches!(held.root_state().await?, RootState::NoRootHistory) {
                    return Err(AccessError::Unavailable);
                }
                material.validate(held.account(), &self.scope.origin)?;
                (
                    Operation::RootIssue,
                    material.issue_target(&self.scope.origin),
                    u64::MAX,
                )
            }
            RootPreparation::Complete(completion) => {
                let row = reauth_row(&held, completion.reauth).await?;
                matching_completion(&held, &row, completion)?;
                (
                    Operation::RootComplete,
                    completion.target(&self.scope.origin)?,
                    row.get::<_, i64>("expires_ms") as u64,
                )
            }
        };
        let guard = self.guard(&tx, browser).await?;
        let bounds = parent_bounds(&held, browser).await?;
        let now = held.check(held.checked_ms).await?;
        let create = now
            .checked_add(frames::WINDOW)
            .ok_or(AccessError::Unavailable)?
            .min(bounds)
            .min(root_expiry);
        let delivery = now
            .checked_add(frames::DELIVERY)
            .ok_or(AccessError::Unavailable)?
            .min(bounds);
        let prep = Preparation {
            operation,
            browser: browser.digest(&self.key, &self.scope),
            id: Uuid::new_v4(),
            request,
            generation: (guard
                .get::<_, i64>("generation")
                .checked_add(1)
                .ok_or(AccessError::Unavailable)?) as u64,
            prepared: now,
            create_deadline: create,
            delivery_deadline: delivery,
            alias: String::new(),
            identities: Identities {
                principal: held.row.get("broker_id"),
                credential: held.row.get("credential_id"),
                revision: held.row.get::<_, i64>("credential_revision") as u64,
                broker_session: held.row.get("broker_session_id"),
                event: held.row.get("authentication_event_id"),
                owner_session: held.session(),
                account: held.account(),
                user: held.user(),
            },
            target,
            candidates: Candidates::fresh(operation),
        };
        prep.validate(browser, &self.key, &self.scope, now, true)?;
        let s = &self.scope;
        let digest = prep.commitment(&self.key, s);
        let csrf: [u8; 32] = Sha256::digest(prep.candidates.csrf.as_ref()).into();
        tx.query_one("SELECT * FROM public.review_access_prepare($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16)",
            &[&s.realm,&&s.database[..],&s.origin,&&s.key[..],&&s.config[..],&(s.config_revision as i64),&&prep.browser[..],&prep.id,&prep.request,
              &(operation as i16),&&digest[..],&(prep.generation as i64),&(prep.prepared as i64),&(create as i64),&(delivery as i64),&&csrf[..]]).await?;
        held.check(now).await?;
        drop(held);
        tx.commit().await?;
        Ok(prep)
    }
    pub(crate) async fn transition_root(
        &self,
        browser: &Browser,
        c: &Credentials,
        prep: &Preparation,
        action: &str,
    ) -> Result<String> {
        if !matches!(
            prep.operation,
            Operation::RootIssue | Operation::RootComplete
        ) || !matches!(action, "confirm" | "cancel" | "inspect")
        {
            return Err(AccessError::Rejected);
        }
        let mut client = self.connect().await?;
        let tx = storage::begin(&mut client).await?;
        let held = HeldOwner::acquire(self, &tx, browser, c, true).await?;
        same_owner(&held, prep)?;
        let state = self.transition_in(&tx, prep, action).await?;
        held.check(held.checked_ms).await?;
        drop(held);
        tx.commit().await?;
        Ok(state)
    }
    pub(crate) async fn issue_root(
        &self,
        browser: &Browser,
        c: &Credentials,
        prep: &Preparation,
        material: &Material,
    ) -> Result<RootIssueResponse> {
        if prep.operation != Operation::RootIssue
            || prep.target != material.issue_target(&self.scope.origin)
        {
            return Err(AccessError::Rejected);
        }
        material.validate(prep.identities.account, &self.scope.origin)?;
        {
            let mut client = self.connect().await?;
            let tx = storage::begin(&mut client).await?;
            let held = HeldOwner::acquire(self, &tx, browser, c, true).await?;
            same_owner(&held, prep)?;
            if !matches!(held.root_state().await?, RootState::NoRootHistory) {
                return Err(AccessError::Unavailable);
            }
            self.transition_in(&tx, prep, "claim").await?;
            if !abuse_limits::consume_review(
                &tx,
                &self.budget_hasher,
                Limit::ReviewRootManage,
                &held.account().to_string(),
            )
            .await?
            {
                self.transition_in(&tx, prep, "reject_rolled_back").await?;
                tx.commit().await?;
                return Err(AccessError::RateLimited);
            }
            held.check(held.checked_ms).await?;
            drop(held);
            tx.commit().await?;
        }
        let mut client = self.connect().await?;
        let tx = storage::begin(&mut client).await?;
        let held = HeldOwner::acquire(self, &tx, browser, c, true).await?;
        same_owner(&held, prep)?;
        if !matches!(held.root_state().await?, RootState::NoRootHistory) {
            return Err(AccessError::Unavailable);
        }
        let now = held.check(prep.prepared).await?;
        let expires = prep
            .create_deadline
            .min(parent_bounds(&held, browser).await?);
        let retain = prep
            .delivery_deadline
            .min(parent_bounds(&held, browser).await?);
        let mut nonce = [0; 32];
        let mut reauth_nonce = [0; 32];
        rng().fill_bytes(&mut nonce);
        rng().fill_bytes(&mut reauth_nonce);
        let challenge = proof::Challenge {
            account_id: *held.account().as_bytes(),
            user_id: *held.user().as_bytes(),
            session_id: *held.session().as_bytes(),
            challenge_id: *Uuid::new_v4().as_bytes(),
            nonce,
            root_fingerprint: material.compared,
            issued_ms: now,
            expires_ms: expires,
            origin: self.scope.origin.clone(),
        };
        let unsigned = proof::encode(&challenge).map_err(|_| AccessError::Rejected)?;
        let statement = custody::statement(
            &unsigned,
            &material.backup,
            &material.card,
            &material.compared,
        )
        .map_err(|_| AccessError::Rejected)?;
        let data = serde_json::json!({"backup_digest":hex(&Sha256::digest(&material.backup)),"card_digest":hex(&Sha256::digest(&material.card)),
            "expires":expires.to_string(),"fingerprint":hex(&material.compared),"issued":now.to_string(),"nonce":hex(&nonce),"pin":hex(&material.pin),
            "reauth":Uuid::new_v4().to_string(),"reauth_nonce":hex(&reauth_nonce),"retain":retain.to_string(),"root":Uuid::from_bytes(challenge.challenge_id).to_string(),
            "statement":hex(&statement),"unsigned":hex(&unsigned)});
        let row = root_commit(&held, self, browser, c, prep, &data, None).await?;
        let now = held.check(now).await?;
        if now >= expires {
            return Err(AccessError::Unavailable);
        }
        let response = issue_response(&row, prep, now);
        drop(held);
        tx.commit().await?;
        Ok(response)
    }
    pub(crate) async fn root_issue_status(
        &self,
        browser: &Browser,
        c: &Credentials,
        prep: &Preparation,
    ) -> Result<RootIssueResponse> {
        if prep.operation != Operation::RootIssue {
            return Err(AccessError::Rejected);
        }
        let mut client = self.connect().await?;
        let tx = storage::begin(&mut client).await?;
        let held = HeldOwner::acquire(self, &tx, browser, c, false).await?;
        same_owner(&held, prep)?;
        let row=tx.query_opt("SELECT * FROM public.review_access_root_reauth WHERE preparation_id=$1 AND request_id=$2 AND request_digest=$3 AND owner_session_id=$4",
            &[&prep.id,&prep.request,&&prep.commitment(&self.key,&self.scope)[..],&held.session()]).await?.ok_or(AccessError::Unavailable)?;
        let now = held.check(prep.prepared).await?;
        if now >= prep.delivery_deadline || now >= row.get::<_, i64>("retain_until_ms") as u64 {
            return Err(AccessError::Unavailable);
        }
        let guard = tx
            .query_one(
                "SELECT * FROM public.review_access_preparations WHERE browser_digest=$1",
                &[&&prep.browser[..]],
            )
            .await?;
        if guard.get::<_, Uuid>("preparation_id") != prep.id
            || guard.get::<_, i64>("generation") as u64 != prep.generation
            || guard.get::<_, String>("state") != "committed"
        {
            return Err(AccessError::Unavailable);
        }
        let now = held.check(now).await?;
        if now >= prep.delivery_deadline || now >= row.get::<_, i64>("retain_until_ms") as u64 {
            return Err(AccessError::Unavailable);
        }
        let response = issue_response(&row, prep, now);
        drop(held);
        tx.commit().await?;
        Ok(response)
    }
}
/// Private one-use completion authorization borrowed from the actual final
/// transaction. It is not an ordinary MFA factor or a detached password proof.
struct ReviewReauthentication<'a, 'db> {
    owner: &'a HeldOwner<'a, 'db>,
    expected: proof::Challenge,
}
impl<'a, 'db> ReviewReauthentication<'a, 'db> {
    async fn confirm(
        owner: &'a HeldOwner<'a, 'db>,
        row: &Row,
        body: &Completion,
        evidence: &passwords::PasswordEvidence,
        access: &ReviewAccess,
        prep: &Preparation,
    ) -> Result<Self> {
        let b = &evidence.snapshot;
        if b.scope != access.scope
            || evidence.operation != Operation::RootComplete
            || evidence.request_digest != prep.commitment(&access.key, &access.scope)
            || b.principal != owner.row.get::<_, Uuid>("broker_id")
            || b.credential != owner.row.get::<_, Uuid>("credential_id")
            || b.revision != owner.row.get::<_, i64>("credential_revision")
        {
            return Err(AccessError::Rejected);
        }
        let expected = matching_completion(owner, row, body)?;
        if !abuse_limits::review_root_failure_open(
            owner.tx,
            &access.budget_hasher,
            &owner.account().to_string(),
        )
        .await?
        {
            return Err(AccessError::RateLimited);
        }
        let now = owner.check(b.observed_ms as u64).await?;
        body.verify(&expected, &row.get::<_, Vec<u8>>("root_pin"), now)?;
        Ok(Self { owner, expected })
    }
}
fn same_owner(held: &HeldOwner<'_, '_>, prep: &Preparation) -> Result<()> {
    let i = &prep.identities;
    if i.account != held.account()
        || i.user != held.user()
        || i.owner_session != held.session()
        || i.principal != held.row.get::<_, Uuid>("broker_id")
        || i.credential != held.row.get::<_, Uuid>("credential_id")
        || i.revision != held.row.get::<_, i64>("credential_revision") as u64
        || i.broker_session != held.row.get::<_, Uuid>("broker_session_id")
        || i.event != held.row.get::<_, Uuid>("authentication_event_id")
    {
        return Err(AccessError::Unavailable);
    }
    Ok(())
}
async fn parent_bounds(held: &HeldOwner<'_, '_>, browser: &Browser) -> Result<u64> {
    let row=held.tx.query_one("SELECT LEAST(b.expires_ms,b.last_used_ms+259200000,a.delivery_deadline_ms) FROM public.review_broker_sessions b \
        JOIN public.review_access_authentications a ON a.broker_session_id=b.id WHERE b.id=$1",&[&held.row.get::<_,Uuid>("broker_session_id")]).await?;
    Ok((row.get::<_, i64>(0) as u64)
        .min(held.row.get::<_, i64>("expires_ms") as u64)
        .min(
            (held.row.get::<_, i64>("last_used_ms") as u64)
                .checked_add(259200000)
                .ok_or(AccessError::Unavailable)?,
        )
        .min(browser.expires))
}
async fn reauth_row(held: &HeldOwner<'_, '_>, id: Uuid) -> Result<Row> {
    held.tx.query_opt("SELECT * FROM public.review_access_root_reauth WHERE id=$1 AND owner_session_id=$2 AND account_id=$3 AND state='pending'",
        &[&id,&held.session(),&held.account()]).await?.ok_or(AccessError::Unavailable)
}
fn matching_completion(
    held: &HeldOwner<'_, '_>,
    row: &Row,
    body: &Completion,
) -> Result<proof::Challenge> {
    let unsigned: Vec<u8> = row.get("unsigned_enrollment");
    let challenge = proof::parse(&unsigned).map_err(|_| AccessError::Unavailable)?;
    if body.root != row.get::<_, Uuid>("root_challenge_id")
        || body.unsigned != unsigned
        || body.nonce.as_slice() != row.get::<_, Vec<u8>>("reauth_nonce")
        || body.material.pin.as_slice() != row.get::<_, Vec<u8>>("root_pin")
        || body.material.compared.as_slice() != row.get::<_, Vec<u8>>("root_fingerprint")
        || Sha256::digest(&body.material.backup).as_slice()
            != row.get::<_, Vec<u8>>("encrypted_backup_digest")
        || Sha256::digest(&body.material.card).as_slice()
            != row.get::<_, Vec<u8>>("public_card_digest")
        || Uuid::from_bytes(challenge.account_id) != held.account()
        || Uuid::from_bytes(challenge.user_id) != held.user()
        || Uuid::from_bytes(challenge.session_id) != held.session()
        || held.checked_ms >= challenge.expires_ms
    {
        return Err(AccessError::Rejected);
    }
    Ok(challenge)
}
async fn root_commit(
    held: &HeldOwner<'_, '_>,
    access: &ReviewAccess,
    browser: &Browser,
    c: &Credentials,
    prep: &Preparation,
    data: &serde_json::Value,
    evidence: Option<&passwords::PasswordEvidence>,
) -> Result<Row> {
    let s = &access.scope;
    let digest = browser.digest(&access.key, s);
    let request = prep.commitment(&access.key, s);
    Ok(held.tx.query_one("SELECT * FROM public.review_access_root_commit($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18::text::jsonb,$19,$20,$21,$22,$23)",
        &[&s.realm,&&s.database[..],&s.origin,&&s.key[..],&&s.config[..],&(s.config_revision as i64),&&digest[..],&c.broker,&&c.broker_token[..],&&c.broker_csrf[..],
            &c.owner,&&c.owner_token[..],&&c.owner_csrf[..],&prep.id,&prep.request,&(prep.generation as i64),&&request[..],&data.to_string(),
            &evidence.map(|e|e.snapshot.principal),&evidence.map(|e|e.snapshot.credential),&evidence.map(|e|e.snapshot.revision),
            &evidence.map(|e|e.snapshot.verifier.as_str()),&evidence.map(|e|e.snapshot.observed_ms)]).await?)
}
fn issue_response(row: &Row, prep: &Preparation, now: u64) -> RootIssueResponse {
    RootIssueResponse {
        version: Version1,
        request_id: prep.request,
        preparation_id: prep.id,
        generation: Decimal(prep.generation),
        root_challenge_id: row.get("root_challenge_id"),
        reauth_challenge_id: row.get("id"),
        reauth_nonce_b64: STANDARD.encode(row.get::<_, Vec<u8>>("reauth_nonce")),
        unsigned_enrollment_b64: STANDARD.encode(row.get::<_, Vec<u8>>("unsigned_enrollment")),
        custody_statement_b64: STANDARD.encode(row.get::<_, Vec<u8>>("custody_statement")),
        root_pin_b64: STANDARD.encode(row.get::<_, Vec<u8>>("root_pin")),
        request_commitment_b64: STANDARD.encode(row.get::<_, Vec<u8>>("request_digest")),
        expires_ms: Decimal(row.get::<_, i64>("expires_ms") as u64),
        server_now_ms: Decimal(now),
    }
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

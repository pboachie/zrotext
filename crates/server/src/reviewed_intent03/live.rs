// SPDX-License-Identifier: AGPL-3.0-only
//! Real cookie owner, installed consent, exact reviewed originals and genuine
//! billing queue writes share one transaction. Historical retry never queues.
use super::*;
use crate::auth::ordinary_owner03::HeldOrdinaryOwner03;
use crate::conversation_interval03::live::StoredInterval03;
use crate::sealed_payload_election03::live::{self as selected, Error};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD as B};
use tokio_postgres::{Row, Transaction};
use zrotext_delivery_store::{
    StoreError,
    sealed::{self, Profile03QueueInput},
};
type Result<T> = std::result::Result<T, Error>;
mod billing;
pub(crate) mod execution;

/// Immutable replay identity survives permitted content redaction. These
/// structural fields grant no permission and cannot restore erased originals.
struct StoredSend03 {
    ids: [Uuid; 8],
    numbers: [u64; 8],
    digests: [[u8; 32]; 11],
    intent_hash: [u8; 32],
    signature_hash: [u8; 32],
    originals: Option<(Intent03, [u8; 64])>,
    ceiling: u8,
    admitted: u64,
    permission_deadline: u64,
    device_session: [u8; 32],
    physical: [u8; 32],
    interval_digest: [u8; 32],
}
fn time(value: i64) -> Result<u64> {
    u64::try_from(value)
        .ok()
        .filter(|n| *n > 0)
        .ok_or(Error::Unsupported)
}
fn sqltime(value: u64) -> Result<i64> {
    i64::try_from(value).map_err(|_| Error::Unsupported)
}
fn fixed<const N: usize>(row: &Row, name: &str) -> Result<[u8; N]> {
    row.try_get::<_, Vec<u8>>(name)?
        .try_into()
        .map_err(|_| Error::Unsupported)
}
async fn ready(tx: &Transaction<'_>) -> Result<()> {
    crate::conversation_reviewed_send03_storage::require(tx)
        .await
        .map_err(|_| Error::Unavailable)
}
fn store_error(error: StoreError) -> Error {
    match error {
        StoreError::Database(error) => Error::Database(error),
        StoreError::QuotaNotConfigured | StoreError::InvalidInput => Error::Unsupported,
        _ => Error::Conflict,
    }
}
impl StoredSend03 {
    fn from_row(r: &Row) -> Result<Self> {
        let mut ids = [Uuid::nil(); 8];
        for (value, name) in ids.iter_mut().zip([
            "account_id",
            "device_id",
            "line_id",
            "binding_id",
            "initiating_user_id",
            "initiating_session_id",
            "interval_id",
            "message_id",
        ]) {
            *value = r.try_get(name)?;
            if value.is_nil() {
                return Err(Error::Unsupported);
            }
        }
        let mut numbers = [0; 8];
        for (value, name) in numbers.iter_mut().zip([
            "binding_generation",
            "vault_generation",
            "manifest_version",
            "selection_epoch",
            "observed_ms",
            "message_expires_ms",
            "review_issued_ms",
            "review_expires_ms",
        ]) {
            *value = time(r.try_get(name)?)?;
        }
        let mut digests = [[0; 32]; 11];
        for (value, name) in digests.iter_mut().zip([
            "selected_reader_key_id",
            "root_fingerprint",
            "manifest_digest",
            "election_commitment",
            "election_bundle_sha256",
            "owner_session_digest",
            "configured_origin_digest",
            "signer_key_id",
            "envelope_sha256",
            "unsigned_digest",
            "body_digest",
        ]) {
            *value = fixed(r, name)?;
            if *value == [0; 32] {
                return Err(Error::Unsupported);
            }
        }
        let intent_hash = fixed(r, "intent_sha256")?;
        let signature_hash = fixed(r, "signature_sha256")?;
        let ceiling = u8::try_from(r.try_get::<_, i16>("authenticated_segment_ceiling")?)
            .map_err(|_| Error::Unsupported)?;
        let admitted = time(r.try_get("admitted_ms")?)?;
        let permission_deadline = time(r.try_get("permission_deadline_ms")?)?;
        if numbers[1] != 1
            || numbers[3] != 1
            || !(1..=6).contains(&ceiling)
            || admitted < numbers[6]
            || admitted >= numbers[7]
            || admitted >= permission_deadline
            || permission_deadline > numbers[7]
        {
            return Err(Error::Unsupported);
        }
        let originals = match (
            r.try_get::<_, Option<Vec<u8>>>("intent")?,
            r.try_get::<_, Option<Vec<u8>>>("signature")?,
            r.try_get::<_, Option<String>>("peer")?,
            r.try_get::<_, Option<i64>>("redacted_ms")?,
        ) {
            (Some(intent), Some(signature), Some(peer), None) => {
                let intent = Intent03::decode(&intent).map_err(|_| Error::Unsupported)?;
                let signature: [u8; 64] = signature.try_into().map_err(|_| Error::Unsupported)?;
                let recipients: Vec<u8> = intent
                    .recipients
                    .iter()
                    .flat_map(|(role, id)| std::iter::once(*role).chain(id.iter().copied()))
                    .collect();
                if intent.ids.map(Uuid::from_bytes) != ids
                    || intent.numbers != numbers
                    || intent.digests != digests
                    || intent.ceiling != ceiling
                    || intent.peer != peer.as_bytes()
                    || r.try_get::<_, Vec<u8>>("recipients")? != recipients
                    || crypto::sha(intent.bytes()) != intent_hash
                    || crypto::sha(&signature) != signature_hash
                {
                    return Err(Error::Conflict);
                }
                Some((intent, signature))
            }
            (None, None, None, Some(at)) if time(at)? >= admitted => None,
            _ => return Err(Error::Unsupported),
        };
        Ok(Self {
            ids,
            numbers,
            digests,
            intent_hash,
            signature_hash,
            originals,
            ceiling,
            admitted,
            permission_deadline,
            device_session: fixed(r, "device_session_digest")?,
            physical: fixed(r, "physical_selection_digest")?,
            interval_digest: fixed(r, "interval_statement_sha256")?,
        })
    }
    async fn read(tx: &Transaction<'_>, account: Uuid, message: Uuid) -> Result<Option<Self>> {
        ready(tx).await?;
        tx.query_opt("SELECT * FROM public.conversation_reviewed_sends03 WHERE account_id=$1 AND message_id=$2 FOR SHARE NOWAIT", &[&account,&message]).await?.map(|r|Self::from_row(&r)).transpose()
    }
    fn matches(&self, intent: &[u8], signature: &[u8], envelope: &[u8]) -> Result<()> {
        if crypto::sha(intent) != self.intent_hash
            || crypto::sha(signature) != self.signature_hash
            || crypto::sha(envelope) != self.digests[8]
            || self
                .originals
                .as_ref()
                .is_some_and(|(i, s)| i.bytes() != intent || s.as_slice() != signature)
        {
            return Err(Error::Conflict);
        }
        Ok(())
    }
    fn receipt(&self) -> serde_json::Value {
        serde_json::json!({"v":1,"message_id":self.ids[7],"interval_id":self.ids[6],"accepted_ms":self.admitted.to_string(),"expires_ms":self.numbers[5].to_string(),"selection_epoch":self.numbers[3].to_string(),"envelope_sha256":B.encode(self.digests[8]),"reviewed_intent_sha256":B.encode(self.intent_hash),"reviewed_signature_sha256":B.encode(self.signature_hash),"sms_ceiling":self.ceiling})
    }
}
pub(crate) async fn admit<'held, 'db>(
    tx: &'held Transaction<'db>,
    owner: &mut HeldOrdinaryOwner03<'held, 'db>,
    intent: &[u8],
    signature: &[u8],
    envelope: &[u8],
    origin: &str,
) -> Result<(bool, serde_json::Value)> {
    if !owner.uses_transaction(tx) {
        return Err(Error::Authentication);
    }
    ready(tx).await?;
    owner
        .revalidate()
        .await
        .map_err(|_| Error::Authentication)?;
    let who = owner.selected_identity();
    let candidate = Intent03::decode(intent).map_err(|_| Error::Unsupported)?;
    if candidate.account_id() != who.account {
        return Err(Error::Authentication);
    }
    if let Some(prior) = StoredSend03::read(tx, who.account, candidate.message_id()).await? {
        if prior.ids[4] != who.user {
            return Err(Error::Authentication);
        }
        prior.matches(intent, signature, envelope)?;
        owner
            .revalidate()
            .await
            .map_err(|_| Error::Authentication)?;
        return Ok((false, prior.receipt()));
    }
    // Billing risk ingress owns customer-before-account order. An actual
    // customer NOWAIT prelock precedes exclusive account mode and account row
    // upgrade, even though genuine owner authentication already holds SHARE.
    // No advisory guard substitutes for the customer tuple lock itself.
    tx.query_opt(
        "SELECT account_id FROM public.billing_customers WHERE account_id=$1 FOR SHARE NOWAIT",
        &[&who.account],
    )
    .await?;
    selected::manifest_history::exclusive_owner(tx, owner).await?;
    // Trusted profile policy requires a real configured quota. Hosted protected
    // triggers keep their own reserve path; manual self-hosted quotas are valid.
    let account = billing::lock(tx, who.account).await?;
    let mut held = selected::hold_owner_selection(tx, owner, candidate.line_id(), origin).await?;
    let interval = StoredInterval03::active(tx, &mut held, candidate.interval_id()).await?;
    let current_deadline = interval.admission_deadline(&mut held).await?;
    let statement = interval.statement();
    let (_, _, browser) = statement.keys();
    let (_, _, starts, expires) = statement.times();
    let recipients = statement.recipients(true);
    let expected = held.review_context(
        statement.interval_id(),
        starts,
        expires,
        statement.peer(),
        browser,
        &recipients,
    );
    let verified = verify(candidate, signature, envelope, &expected, held.now_ms())
        .map_err(|_| Error::Unsupported)?;
    if verified.expires_ms() > current_deadline {
        return Err(Error::Expired);
    }
    let before = held.now_ms();
    // Original review expiry bounds acceptance, never a later grant's current
    // permission. It must not be renewed by queueing or exact historical retry.
    let acceptance_deadline = current_deadline.min(verified.intent.numbers[7]);
    let rows = tx
        .query(
            "SELECT * FROM public.conversation_reviewed_send03_admit($1,$2,$3,$4,$5,$6,$7)",
            &[
                &who.account,
                &statement.interval_id(),
                &verified.intent().message_id(),
                &verified.intent().bytes(),
                &verified.signature().as_slice(),
                &verified.envelope().bytes(),
                &sqltime(acceptance_deadline)?,
            ],
        )
        .await?;
    if rows.len() != 1 {
        return Err(Error::Conflict);
    }
    let stored = StoredSend03::from_row(&rows[0])?;
    stored.matches(intent, signature, envelope)?;
    let candidate = verified.intent();
    let queued = account
        .enqueue(&Profile03QueueInput {
            message_id: candidate.message_id(),
            device_id: Uuid::from_bytes(candidate.ids[1]),
            line_id: candidate.line_id(),
            binding_generation: sqltime(candidate.numbers[0])?,
            manifest_generation: sqltime(candidate.numbers[1])?,
            manifest_version: sqltime(candidate.numbers[2])?,
            manifest_digest: &candidate.digests[2],
            signer_key_id: &candidate.digests[7],
            unsigned_digest: &candidate.digests[9],
            recipient: std::str::from_utf8(&candidate.peer).map_err(|_| Error::Unsupported)?,
            envelope: verified.envelope().bytes(),
            expires_at_ms: sqltime(candidate.numbers[5])?,
            segment_limit: candidate.ceiling,
        })
        .await?;
    if !queued.created {
        return Err(Error::Conflict);
    }
    held.revalidate().await?;
    let current_deadline = interval.admission_deadline(&mut held).await?;
    if stored.admitted < before
        || stored.admitted > held.now_ms()
        || stored.permission_deadline > current_deadline.min(candidate.numbers[7])
        || stored.device_session != *held.device_session_digest()
        || stored.physical != *held.physical_digest()
        || stored.interval_digest != statement.digest()
        || stored.digests[10] != *verified.body_digest()
    {
        return Err(Error::Conflict);
    }
    let expected = held.review_context(
        statement.interval_id(),
        starts,
        expires,
        statement.peer(),
        browser,
        &recipients,
    );
    verify(
        Intent03::decode(intent).map_err(|_| Error::Unsupported)?,
        signature,
        envelope,
        &expected,
        held.now_ms(),
    )
    .map_err(|_| Error::Expired)?;
    Ok((true, stored.receipt()))
}
pub(crate) struct Status03 {
    pub message: Uuid,
    pub interval: Uuid,
    pub envelope: [u8; 32],
    pub intent: [u8; 32],
    pub signature: [u8; 32],
}
pub(crate) async fn status(
    tx: &Transaction<'_>,
    owner: &mut HeldOrdinaryOwner03<'_, '_>,
    expected: Status03,
) -> Result<serde_json::Value> {
    if !owner.uses_transaction(tx) {
        return Err(Error::Authentication);
    }
    owner
        .revalidate()
        .await
        .map_err(|_| Error::Authentication)?;
    let who = owner.selected_identity();
    let stored = StoredSend03::read(tx, who.account, expected.message)
        .await?
        .ok_or(Error::NotFound)?;
    if stored.ids[4] != who.user {
        return Err(Error::Authentication);
    }
    if stored.ids[6] != expected.interval
        || stored.digests[8] != expected.envelope
        || stored.intent_hash != expected.intent
        || stored.signature_hash != expected.signature
    {
        return Err(Error::Conflict);
    }
    owner
        .revalidate()
        .await
        .map_err(|_| Error::Authentication)?;
    Ok(stored.receipt())
}

// SPDX-License-Identifier: AGPL-3.0-only
//! Actual03 cookie-owner admission. Immutable reviewed originals, current
//! installed consent and physical/read-grant selection share ONE transaction.
//! Historical observation returns receipts only, never another queue attempt.
use super::*;
use crate::auth::ordinary_owner03::HeldOrdinaryOwner03;
use crate::conversation_interval03::live::StoredInterval03;
use crate::sealed_payload_election03::live::{self as selected, Error};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD as B};
use tokio_postgres::{Row, Transaction};
type Result<T> = std::result::Result<T, Error>;
struct StoredSend03 {
    intent: Intent03,
    signature: [u8; 64],
    envelope: Vec<u8>,
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
impl StoredSend03 {
    fn from_row(r: &Row) -> Result<Self> {
        let intent = Intent03::decode(&r.try_get::<_, Vec<u8>>("intent")?)
            .map_err(|_| Error::Unsupported)?;
        for (name, id) in [
            "account_id",
            "device_id",
            "line_id",
            "binding_id",
            "initiating_user_id",
            "initiating_session_id",
            "interval_id",
            "message_id",
        ]
        .into_iter()
        .zip(intent.ids)
        {
            if r.try_get::<_, Uuid>(name)? != Uuid::from_bytes(id) {
                return Err(Error::Conflict);
            }
        }
        for (name, n) in [
            "binding_generation",
            "vault_generation",
            "manifest_version",
            "selection_epoch",
            "observed_ms",
            "message_expires_ms",
            "review_issued_ms",
            "review_expires_ms",
        ]
        .into_iter()
        .zip(intent.numbers)
        {
            if time(r.try_get(name)?)? != n {
                return Err(Error::Conflict);
            }
        }
        for (name, digest) in [
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
        ]
        .into_iter()
        .zip(intent.digests)
        {
            if fixed::<32>(r, name)? != digest {
                return Err(Error::Conflict);
            }
        }
        let envelope: Vec<u8> = r.try_get("envelope")?;
        let recipients: Vec<u8> = intent
            .recipients
            .iter()
            .flat_map(|(role, id)| std::iter::once(*role).chain(id.iter().copied()))
            .collect();
        let ceiling = r.try_get::<_, i16>("authenticated_segment_ceiling")?;
        if !(557..=34213).contains(&envelope.len())
            || &envelope[..8] != b"ZTSE\x03\x01\0\0"
            || crypto::sha(&envelope) != intent.digests[8]
            || fixed::<32>(r, "intent_sha256")? != crypto::sha(intent.bytes())
            || r.try_get::<_, Vec<u8>>("recipients")? != recipients
            || ceiling != i16::from(intent.ceiling)
            || r.try_get::<_, String>("peer")?.as_bytes() != intent.peer
        {
            return Err(Error::Conflict);
        }
        let value = Self {
            intent,
            signature: fixed(r, "signature")?,
            envelope,
            admitted: time(r.try_get("admitted_ms")?)?,
            permission_deadline: time(r.try_get("permission_deadline_ms")?)?,
            device_session: fixed(r, "device_session_digest")?,
            physical: fixed(r, "physical_selection_digest")?,
            interval_digest: fixed(r, "interval_statement_sha256")?,
        };
        if value.admitted < value.intent.numbers[6]
            || value.admitted >= value.intent.numbers[7]
            || value.admitted >= value.permission_deadline
        {
            return Err(Error::Unsupported);
        }
        Ok(value)
    }
    async fn read(tx: &Transaction<'_>, account: Uuid, message: Uuid) -> Result<Option<Self>> {
        ready(tx).await?;
        tx.query_opt("SELECT * FROM public.conversation_reviewed_sends03 WHERE account_id=$1 AND message_id=$2",&[&account,&message]).await?.map(|r|Self::from_row(&r)).transpose()
    }
    fn owner(&self) -> Uuid {
        Uuid::from_bytes(self.intent.ids[4])
    }
    fn matches(&self, intent: &[u8], signature: &[u8], envelope: &[u8]) -> Result<()> {
        if self.intent.bytes() != intent
            || self.signature.as_slice() != signature
            || self.envelope != envelope
        {
            return Err(Error::Conflict);
        }
        Ok(())
    }
    fn receipt(&self) -> serde_json::Value {
        serde_json::json!({"v":1,"message_id":self.intent.message_id(),"interval_id":self.intent.interval_id(),"accepted_ms":self.admitted.to_string(),"expires_ms":self.intent.numbers[5].to_string(),"selection_epoch":self.intent.numbers[3].to_string(),"envelope_sha256":B.encode(self.intent.digests[8]),"reviewed_intent_sha256":B.encode(crypto::sha(self.intent.bytes())),"reviewed_signature_sha256":B.encode(crypto::sha(&self.signature)),"sms_ceiling":self.intent.ceiling})
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
        if prior.owner() != who.user {
            return Err(Error::Authentication);
        }
        prior.matches(intent, signature, envelope)?;
        owner
            .revalidate()
            .await
            .map_err(|_| Error::Authentication)?;
        return Ok((false, prior.receipt()));
    }
    let mut held = selected::hold_owner_selection(tx, owner, candidate.line_id(), origin).await?;
    let interval = StoredInterval03::active(tx, &mut held, candidate.interval_id()).await?;
    let deadline = interval.admission_deadline(&mut held).await?;
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
    if verified.expires_ms() > deadline {
        return Err(Error::Expired);
    }
    let before = held.now_ms();
    let deadline = i64::try_from(deadline).map_err(|_| Error::Unsupported)?;
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
                &deadline,
            ],
        )
        .await?;
    if rows.len() != 1 {
        return Err(Error::Conflict);
    }
    let stored = StoredSend03::from_row(&rows[0])?;
    stored.matches(intent, signature, envelope)?;
    held.revalidate().await?;
    let current_deadline = interval.admission_deadline(&mut held).await?;
    if stored.admitted < before
        || stored.admitted > held.now_ms()
        || stored.permission_deadline > current_deadline
        || stored.device_session != *held.device_session_digest()
        || stored.physical != *held.physical_digest()
        || stored.interval_digest != statement.digest()
        || stored.intent.digests[10] != *verified.body_digest()
    {
        return Err(Error::Conflict);
    }
    // Repeat original review window and current permission after SQL waits. The
    // deferred storage checks repeat the structural deadline at actual COMMIT.
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
    if stored.owner() != who.user {
        return Err(Error::Authentication);
    }
    if stored.intent.interval_id() != expected.interval
        || stored.intent.digests[8] != expected.envelope
        || crypto::sha(stored.intent.bytes()) != expected.intent
        || crypto::sha(&stored.signature) != expected.signature
    {
        return Err(Error::Conflict);
    }
    owner
        .revalidate()
        .await
        .map_err(|_| Error::Authentication)?;
    Ok(stored.receipt())
}

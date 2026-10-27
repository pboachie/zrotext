// SPDX-License-Identifier: AGPL-3.0-only
//! Exact retained acceptance plus separately held present effect permission.
//! Original review expiry is checked at admission, never used as a fresh grant.
use super::*;
use crate::conversation_grant03::Mode03;
use crate::sealed_payload_election03::{live::HeldMessageSelection03, owner_records};

pub(crate) struct HeldReviewed03<'held, 'db> {
    held: HeldMessageSelection03<'held, 'held, 'db>,
    interval: StoredInterval03,
    stored: StoredSend03,
    envelope: Vec<u8>,
}

pub(crate) async fn lock<'held, 'db>(
    mode: &Mode03<'held, 'db>,
    message: Uuid,
) -> Result<HeldReviewed03<'held, 'db>> {
    let tx = mode.tx();
    let actor = mode.actor();
    // An immutable row is a selector hint only. Choose owner records before
    // interval/line/device locks; the actual locked row is compared afterward.
    let row = tx.query_opt("SELECT * FROM public.conversation_reviewed_sends03 WHERE account_id=$1 AND message_id=$2", &[&actor.session.account_id,&message]).await?.ok_or(Error::NotFound)?;
    let hint = StoredSend03::from_row(&row)?;
    if hint.intent_version != 2 {
        return Err(Error::Unsupported);
    }
    let selector = owner_records::Selector {
        account: hint.ids[0],
        user: hint.ids[4],
        session: hint.ids[5],
    };
    let mut owner = owner_records::lock(tx, selector)
        .await
        .map_err(|_| Error::Authentication)?;
    let interval = StoredInterval03::read(tx, selector.account, hint.ids[6]).await?;
    if interval.selected_owner() != selector {
        return Err(Error::Conflict);
    }
    let held = selected::hold_interval_selection(
        tx,
        &interval,
        actor.session,
        actor.site,
        actor.instance,
        actor.deployment,
        actor.origin,
    )
    .await?;
    let stored = StoredSend03::read(tx, selector.account, message)
        .await?
        .ok_or(Error::NotFound)?;
    if stored.ids != hint.ids
        || stored.intent_version != 2
        || stored.intent_hash != hint.intent_hash
        || stored.signature_hash != hint.signature_hash
        || stored.admitted != hint.admitted
    {
        return Err(Error::Conflict);
    }
    owner
        .revalidate()
        .await
        .map_err(|_| Error::Authentication)?;
    let mut value = HeldReviewed03 {
        held,
        interval,
        stored,
        envelope: Vec::new(),
    };
    value.read_message().await?;
    Ok(value)
}

impl<'held, 'db> HeldReviewed03<'held, 'db> {
    async fn read_message(&mut self) -> Result<()> {
        let s = &self.stored;
        let row = self.held.tx().query_opt("SELECT device_id,sealed_line_id,sealed_binding_generation,sealed_manifest_generation,sealed_manifest_version,sealed_manifest_digest,sealed_signer_key_id,sealed_segment_limit,request_digest,transport_mode,recipient_e164,transport_payload,pg_catalog.floor(extract(epoch FROM expires_at)*1000)::bigint AS expires_ms FROM public.messages WHERE account_id=$1 AND id=$2 FOR SHARE NOWAIT", &[&s.ids[0],&s.ids[7]]).await?.ok_or(Error::NotFound)?;
        let originals = s.originals.as_ref().ok_or(Error::NotFound)?;
        let peer: String = row
            .try_get::<_, Option<String>>("recipient_e164")?
            .ok_or(Error::NotFound)?;
        let envelope: Vec<u8> = row
            .try_get::<_, Option<Vec<u8>>>("transport_payload")?
            .ok_or(Error::NotFound)?;
        if row.try_get::<_, String>("transport_mode")? != "sealed_profile03"
            || row.try_get::<_, Uuid>("device_id")? != s.ids[1]
            || row.try_get::<_, Option<Uuid>>("sealed_line_id")? != Some(s.ids[2])
            || row.try_get::<_, Option<i64>>("sealed_binding_generation")?
                != Some(sqltime(s.numbers[0])?)
            || row.try_get::<_, Option<i64>>("sealed_manifest_generation")? != Some(1)
            || row.try_get::<_, Option<i64>>("sealed_manifest_version")?
                != Some(sqltime(s.numbers[2])?)
            || row
                .try_get::<_, Option<Vec<u8>>>("sealed_manifest_digest")?
                .as_deref()
                != Some(s.digests[2].as_slice())
            || row
                .try_get::<_, Option<Vec<u8>>>("sealed_signer_key_id")?
                .as_deref()
                != Some(s.digests[7].as_slice())
            || row.try_get::<_, Option<i16>>("sealed_segment_limit")? != Some(i16::from(s.ceiling))
            || row.try_get::<_, Vec<u8>>("request_digest")? != s.digests[9]
            || peer.as_bytes() != originals.0.common().peer
            || time(row.try_get("expires_ms")?)? != s.numbers[5]
            || crypto::sha(&envelope) != s.digests[8]
            || (!self.envelope.is_empty() && self.envelope != envelope)
        {
            return Err(Error::Conflict);
        }
        self.envelope = envelope;
        Ok(())
    }
    pub(crate) async fn deadline(&mut self) -> Result<u64> {
        let deadline = self
            .interval
            .admission_deadline(&mut self.held)
            .await?
            .min(self.stored.numbers[5]);
        self.held.revalidate().await?;
        if deadline <= self.held.now_ms() {
            return Err(Error::Expired);
        }
        Ok(deadline)
    }
    pub(crate) async fn verify_until(&mut self, required_until: u64) -> Result<()> {
        self.read_message().await?;
        let deadline = self.interval.admission_deadline(&mut self.held).await?;
        if required_until > deadline {
            return Err(Error::Expired);
        }
        self.verify_current(required_until)
    }
    fn verify_current(&self, required_until: u64) -> Result<()> {
        let s = &self.stored;
        if s.intent_version != 2
            || required_until <= self.held.now_ms()
            || s.device_session != *self.held.device_session_digest()
            || s.physical != *self.held.physical_digest()
            || s.interval_digest != self.interval.statement().digest()
            || s.ids[6] != self.interval.statement().interval_id()
            || s.admitted < self.interval.original_installed_ms()?
        {
            return Err(Error::Conflict);
        }
        let (intent, signature) = s.originals.as_ref().ok_or(Error::NotFound)?;
        let statement = self.interval.statement();
        let (_, _, signer) = statement.keys();
        let (_, _, starts, expires) = statement.times();
        let recipients = statement.recipients(true);
        let expected = self.held.review_context(
            statement.interval_id(),
            starts,
            expires,
            statement.peer(),
            signer,
            &recipients,
        );
        v2::verify_retained(
            v2::Intent03V2::decode(intent.bytes()).map_err(|_| Error::Unsupported)?,
            signature,
            &self.envelope,
            &expected,
            self.held.now_ms(),
            RetainedTiming03 {
                admitted_ms: s.admitted,
                installed_ms: self.interval.original_installed_ms()?,
                required_until_ms: required_until,
            },
        )
        .map_err(|_| Error::Unsupported)?;
        Ok(())
    }
    pub(crate) fn selected(&self) -> &HeldMessageSelection03<'held, 'held, 'db> {
        &self.held
    }
    pub(crate) fn stored_message(&self) -> Uuid {
        self.stored.ids[7]
    }
    pub(crate) fn admitted_ms(&self) -> u64 {
        self.stored.admitted
    }
    pub(crate) fn intent_sha256(&self) -> &[u8; 32] {
        &self.stored.intent_hash
    }
    pub(crate) fn signature_sha256(&self) -> &[u8; 32] {
        &self.stored.signature_hash
    }
    pub(crate) fn interval_id(&self) -> Uuid {
        self.stored.ids[6]
    }
    pub(crate) fn interval_receipt_id(&self) -> Uuid {
        self.interval.statement().receipt_id()
    }
    pub(crate) fn interval_sha256(&self) -> &[u8; 32] {
        &self.stored.interval_digest
    }
    pub(crate) fn origin_sha256(&self) -> &[u8; 32] {
        &self.stored.digests[6]
    }
    pub(crate) fn sms_ceiling(&self) -> u8 {
        self.stored.ceiling
    }
    pub(crate) fn envelope_sha256(&self) -> &[u8; 32] {
        &self.stored.digests[8]
    }
    pub(crate) fn unsigned_sha256(&self) -> &[u8; 32] {
        &self.stored.digests[9]
    }
    pub(crate) async fn response(
        &mut self,
        grant: &crate::sealed_dispatch::wire03::GrantFrame03,
    ) -> Result<serde_json::Value> {
        let claims = grant.claims();
        let end = time(claims.expires_at_ms)?;
        self.read_message().await?;
        let interval_permission = self
            .interval
            .fetch_permission(&mut self.held, claims.attempt_id, end)
            .await?;
        // Mapping/physical/owner revalidation above left one actual comparison
        // time. Reverify crypto synchronously at it, then emit both projections
        // with that same time and exact original grant expiry, without awaits.
        self.verify_current(end)?;
        let current =
            self.held
                .message_projection(claims.attempt_id, &grant.fetch_transcript(), end)?;
        let (intent, signature) = self.stored.originals.as_ref().ok_or(Error::NotFound)?;
        let (_, _, starts, expires) = self.interval.statement().times();
        Ok(
            serde_json::json!({"v":1,"envelope":B.encode(&self.envelope),"reviewed_intent":B.encode(intent.bytes()),"reviewed_signature":B.encode(signature),"accepted_ms":self.stored.admitted.to_string(),"interval_starts_ms":starts.to_string(),"interval_expires_ms":expires.to_string(),"selection_epoch":self.stored.numbers[3].to_string(),"current":current,"interval_permission":interval_permission}),
        )
    }
    /// Called only on a genuinely NEW accepted submit path, after its exact
    /// SQL transition and final current checks. Commit still belongs to caller.
    pub(crate) async fn submit_permission(
        &mut self,
        grant: &crate::sealed_dispatch::wire03::GrantFrame03,
        event: Uuid,
    ) -> Result<(serde_json::Value, serde_json::Value)> {
        let end = time(grant.claims().expires_at_ms)?;
        self.read_message().await?;
        let interval = self
            .interval
            .submit_permission(&mut self.held, event, end)
            .await?;
        // Last async held revalidation leaves one comparison for BOTH outputs.
        // No async read separates this synchronous original-crypto check from
        // the current projection. The caller emits them only after COMMIT.
        self.verify_current(end)?;
        let current = self
            .held
            .submit_projection(event, &grant.fetch_transcript(), end)?;
        Ok((current, interval))
    }
}

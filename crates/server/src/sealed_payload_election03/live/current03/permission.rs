// SPDX-License-Identifier: AGPL-3.0-only
//! Genuine owner/current/physical composition, borrowed from the caller's exact
//! transaction. No received selector, detached digest or historical election
//! owner becomes present HTTP authorization through this type.
use super::*;
use crate::conversation_interval03::{ExpectedConsent03, IntegrationReader03};

enum Proof<'a, 'held, 'db> {
    Ordinary(&'a mut HeldOrdinaryOwner03<'held, 'db>),
    StepUp(&'a mut HeldStepUp03<'held, 'db>),
    IntervalRecords {
        tx: &'held Transaction<'db>,
        selector: super::super::Selector,
        records:
            Box<crate::sealed_payload_election03::owner_records::HeldOwnerRecords03<'held, 'db>>,
    },
}
impl Proof<'_, '_, '_> {
    fn selector(&self) -> super::super::Selector {
        match self {
            Self::Ordinary(p) => p.selected_identity(),
            Self::StepUp(p) => p.selected_identity(),
            Self::IntervalRecords { selector, .. } => *selector,
        }
    }
    fn uses(&self, tx: &Transaction<'_>) -> bool {
        match self {
            Self::Ordinary(p) => p.uses_transaction(tx),
            Self::StepUp(p) => p.uses_transaction(tx),
            Self::IntervalRecords { tx: held, .. } => std::ptr::eq(*held, tx),
        }
    }
    fn epoch(&self) -> u64 {
        match self {
            Self::Ordinary(p) => p.selection_epoch(),
            Self::StepUp(p) => p.selection_epoch(),
            Self::IntervalRecords { records, .. } => records.selection_epoch(),
        }
    }
    fn owner_deadline(&self) -> u64 {
        match self {
            Self::Ordinary(p) => p.session_deadline_ms(),
            Self::StepUp(p) => p.owner_session_deadline_ms(),
            Self::IntervalRecords { records, .. } => records.session_deadline_ms(),
        }
    }
    fn deadline(&self) -> u64 {
        match self {
            Self::Ordinary(p) => p.session_deadline_ms(),
            Self::StepUp(p) => p.expires_at_ms(),
            Self::IntervalRecords { records, .. } => records.session_deadline_ms(),
        }
    }
    fn checked(&self) -> u64 {
        match self {
            Self::Ordinary(p) => p.checked_at_ms(),
            Self::StepUp(p) => p.checked_primary_ms(),
            Self::IntervalRecords { records, .. } => records.checked_at_ms(),
        }
    }
    async fn revalidate(&mut self) -> Result<()> {
        match self {
            Self::Ordinary(p) => p.revalidate().await.map_err(|_| Error::Authentication),
            Self::StepUp(p) => p.revalidate().await.map_err(|_| Error::Authentication),
            Self::IntervalRecords { records, .. } => records
                .revalidate()
                .await
                .map_err(|_| Error::Authentication),
        }
    }
}
pub(crate) struct HeldMessageSelection03<'a, 'held, 'db> {
    tx: &'held Transaction<'db>,
    proof: Proof<'a, 'held, 'db>,
    current: Current<'held, 'db>,
    physical: physical::Physical,
    origin: String,
}
pub(crate) async fn hold_owner_selection<'a, 'held, 'db>(
    tx: &'held Transaction<'db>,
    owner: &'a mut HeldOrdinaryOwner03<'held, 'db>,
    line: Uuid,
    origin: &str,
) -> Result<HeldMessageSelection03<'a, 'held, 'db>> {
    hold(tx, Proof::Ordinary(owner), line, origin).await
}
pub(crate) async fn hold_step_up_selection<'a, 'held, 'db>(
    tx: &'held Transaction<'db>,
    proof: &'a mut HeldStepUp03<'held, 'db>,
    line: Uuid,
    origin: &str,
) -> Result<HeldMessageSelection03<'a, 'held, 'db>> {
    hold(tx, Proof::StepUp(proof), line, origin).await
}
/// Device-only continuation of an already retained interval. Its original owner
/// selectors come from the closed immutable interval reader, never wire fields.
/// This reads their current permission; it authenticates no cookie or factor.
pub(crate) async fn hold_interval_selection<'held, 'db>(
    tx: &'held Transaction<'db>,
    interval: &crate::conversation_interval03::live::StoredInterval03,
    session: crate::device_socket::DeviceSession,
    site: &str,
    instance: &str,
    deployment: u64,
    origin: &str,
) -> Result<HeldMessageSelection03<'held, 'held, 'db>> {
    let selector = interval.selected_owner();
    if selector.account != session.account_id {
        return Err(Error::Authentication);
    }
    let records = crate::sealed_payload_election03::owner_records::lock(tx, selector)
        .await
        .map_err(|_| Error::Authentication)?;
    let held = hold(
        tx,
        Proof::IntervalRecords {
            tx,
            selector,
            records: Box::new(records),
        },
        interval.statement().line_id(),
        origin,
    )
    .await?;
    let actual = held.current.context.selected_identity();
    if actual.device != session.device_id
        || actual.site != site
        || actual.instance != instance
        || actual.connection_epoch != positive(session.connection_epoch)?
        || actual.deployment_epoch != deployment
    {
        return Err(Error::Authentication);
    }
    Ok(held)
}
async fn hold<'a, 'held, 'db>(
    tx: &'held Transaction<'db>,
    mut proof: Proof<'a, 'held, 'db>,
    line: Uuid,
    origin: &str,
) -> Result<HeldMessageSelection03<'a, 'held, 'db>> {
    if !proof.uses(tx) {
        return Err(Error::Authentication);
    }
    proof.revalidate().await?;
    let current = Current::lock_ancestry(tx, proof.selector().account, line, origin).await?;
    let physical = current.physical(tx).await?;
    let mut held = HeldMessageSelection03 {
        tx,
        proof,
        current,
        physical,
        origin: origin.to_owned(),
    };
    held.revalidate().await?;
    Ok(held)
}
impl HeldMessageSelection03<'_, '_, '_> {
    pub(crate) fn physical_identity(&self) -> (&'static str, Option<Uuid>) {
        self.physical.identity()
    }
    pub(crate) async fn revalidate(&mut self) -> Result<()> {
        self.proof.revalidate().await?;
        self.current
            .context
            .revalidate()
            .await
            .map_err(|_| Error::Unavailable)?;
        if self.proof.epoch() != self.current.epoch {
            return Err(Error::Conflict);
        }
        let physical = self.current.physical(self.tx).await?;
        if physical.digest() != self.physical.digest() {
            return Err(Error::Conflict);
        }
        let now = clock(
            self.tx,
            self.current
                .checked
                .max(self.proof.checked())
                .max(self.current.context.checked_primary_ms()),
        )
        .await?;
        if now >= self.current.deadline.min(self.proof.deadline()) {
            return Err(Error::Expired);
        }
        self.current.checked = now;
        self.current.authority.compared_at_ms = now;
        self.current.authority.permission_expires_at_ms =
            self.current.deadline.min(self.proof.owner_deadline());
        Ok(())
    }
    pub(crate) fn tx(&self) -> &Transaction<'_> {
        self.tx
    }
    pub(crate) fn now_ms(&self) -> u64 {
        self.current.checked
    }
    pub(crate) fn device_session_digest(&self) -> &[u8; 32] {
        self.current.context.identity_digest()
    }
    pub(crate) fn physical_digest(&self) -> &[u8; 32] {
        self.physical.digest()
    }
    pub(crate) fn selected(&self) -> super::super::Selector {
        self.proof.selector()
    }
    pub(crate) fn authority(&self) -> &election::CurrentAuthority03 {
        &self.current.authority
    }
    pub(crate) fn factor_deadline_ms(&self) -> Option<u64> {
        match &self.proof {
            Proof::StepUp(p) => Some(p.expires_at_ms()),
            Proof::Ordinary(_) => None,
            Proof::IntervalRecords { .. } => None,
        }
    }
    pub(crate) fn owner_deadline_ms(&self) -> u64 {
        self.proof.owner_deadline()
    }
    pub(crate) fn manifest(&self) -> &crypto::VerifiedManifest03 {
        &self.current.manifest
    }
    pub(crate) fn review_context<'a>(
        &'a self,
        interval: Uuid,
        starts: u64,
        expires: u64,
        peer: &'a [u8],
        signer: &'a [u8; 32],
        recipients: &'a [(u8, [u8; 32])],
    ) -> crate::reviewed_intent03::ExpectedReview03<'a> {
        let owner = self.proof.selector();
        crate::reviewed_intent03::ExpectedReview03 {
            current: &self.current.authority,
            election: &self.current.proof,
            manifest: &self.current.manifest,
            selection_epoch: self.current.epoch,
            user: owner.user,
            session: owner.session,
            canonical_origin: &self.origin,
            interval,
            interval_starts_ms: starts,
            interval_expires_ms: expires,
            peer,
            signer,
            recipients,
        }
    }
    pub(crate) fn device_projection(&self) -> Result<serde_json::Value> {
        let mut value = self.current.projection(&self.origin)?;
        let object = value.as_object_mut().ok_or(Error::Unavailable)?;
        object.insert(
            "kind".into(),
            serde_json::json!("device_manifest_selection03"),
        );
        object.insert(
            "selection_expires_ms".into(),
            serde_json::json!(self.current.deadline.to_string()),
        );
        object.insert("physical_selection".into(), self.physical.projection());
        Ok(value)
    }
    pub(crate) fn enrolled_signing_key(&self) -> Result<p256::ecdsa::VerifyingKey> {
        if crate::sealed_manifest::key_id(4, &self.current.reservation.device_point)
            != *self.current.context.enrollment_signing_key_id()
        {
            return Err(Error::Conflict);
        }
        p256::ecdsa::VerifyingKey::from_sec1_bytes(&self.current.reservation.device_point)
            .map_err(|_| Error::Unsupported)
    }
    pub(crate) fn original_binding_ids(&self) -> (Uuid, Uuid) {
        (
            self.current.reservation.challenge,
            self.current.reservation.old_binding,
        )
    }
    /// A separate full message projection, selected by a retained issued grant.
    /// Old first-only and reader-only JSON contracts are left unchanged.
    pub(crate) fn message_projection(
        &self,
        attempt: Uuid,
        fetch_transcript: &[u8; 362],
        grant_expires: u64,
    ) -> Result<serde_json::Value> {
        if attempt.is_nil()
            || self.current.selected_manifest.is_none()
            || grant_expires <= self.now_ms()
            || grant_expires > self.authority().permission_expires_at_ms
        {
            return Err(Error::Expired);
        }
        let who = self.selected();
        let owner_digest =
            crate::sealed_payload_election03::adapter_contract::OwnerSessionIdentity03 {
                account_id: *who.account.as_bytes(),
                user_id: *who.user.as_bytes(),
                session_id: *who.session.as_bytes(),
            }
            .digest()
            .map_err(|_| Error::Unsupported)?;
        let mut value = self.current.projection(&self.origin)?;
        let object = value.as_object_mut().ok_or(Error::Unavailable)?;
        object.insert(
            "kind".into(),
            serde_json::json!("message_manifest_permission03"),
        );
        object.insert("request_kind".into(), serde_json::json!("fetch"));
        object.insert("request_id".into(), serde_json::json!(attempt));
        object.insert(
            "fetch_transcript_sha256".into(),
            serde_json::json!(B.encode(crypto::sha(fetch_transcript))),
        );
        object.insert("user_id".into(), serde_json::json!(who.user));
        object.insert("owner_session_id".into(), serde_json::json!(who.session));
        object.insert(
            "owner_session_digest".into(),
            serde_json::json!(B.encode(owner_digest)),
        );
        object.insert(
            "permission_expires_ms".into(),
            serde_json::json!(grant_expires.to_string()),
        );
        object.insert("physical_selection".into(), self.physical.projection());
        Ok(value)
    }
    /// Same-held owner/current projection for a purpose-specific context read.
    /// The supplied conservative bound is calculated by the locked interval
    /// adapter, never accepted as authority from a request or unsigned packet.
    pub(crate) fn owner_projection(&self, deadline: u64) -> Result<serde_json::Value> {
        if self.current.selected_manifest.is_none()
            || deadline <= self.now_ms()
            || deadline > self.authority().permission_expires_at_ms
        {
            return Err(Error::Expired);
        }
        let who = self.selected();
        let digest = crate::sealed_payload_election03::adapter_contract::OwnerSessionIdentity03 {
            account_id: *who.account.as_bytes(),
            user_id: *who.user.as_bytes(),
            session_id: *who.session.as_bytes(),
        }
        .digest()
        .map_err(|_| Error::Unsupported)?;
        let mut value = self.current.projection(&self.origin)?;
        let object = value.as_object_mut().ok_or(Error::Unavailable)?;
        object.insert(
            "kind".into(),
            serde_json::json!("owner_manifest_selection03"),
        );
        object.insert("user_id".into(), serde_json::json!(who.user));
        object.insert("owner_session_id".into(), serde_json::json!(who.session));
        object.insert(
            "owner_session_digest".into(),
            serde_json::json!(B.encode(digest)),
        );
        object.insert(
            "permission_expires_ms".into(),
            serde_json::json!(deadline.to_string()),
        );
        object.insert("physical_selection".into(), self.physical.projection());
        Ok(value)
    }
    pub(crate) fn consent_context<'a>(
        &'a self,
        archive: &'a [u8; 32],
        phone: &'a [u8; 32],
        browser: &'a [u8; 32],
        peer: &'a [u8],
        integrations: &'a [IntegrationReader03],
    ) -> ExpectedConsent03<'a> {
        let owner = self.proof.selector();
        ExpectedConsent03 {
            current: &self.current.authority,
            election: &self.current.proof,
            manifest: &self.current.manifest,
            selection_epoch: self.current.epoch,
            user: owner.user,
            session: owner.session,
            canonical_origin: &self.origin,
            device_session_digest: self.current.context.identity_digest(),
            physical_digest: self.physical.digest(),
            archive_reader: archive,
            phone_signer: phone,
            browser_signer: browser,
            owner_deadline_ms: self.proof.owner_deadline(),
            peer,
            integrations,
        }
    }
}

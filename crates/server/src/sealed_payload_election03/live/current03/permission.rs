// SPDX-License-Identifier: AGPL-3.0-only
//! Genuine owner/current/physical composition, borrowed from the caller's exact
//! transaction. No received selector, detached digest or historical election
//! owner becomes present HTTP authorization through this type.
use super::*;
use crate::conversation_interval03::{ExpectedConsent03, IntegrationReader03};
use crate::reviewed_intent03::ExpectedReview03;

enum Proof<'a, 'held, 'db> {
    Ordinary(&'a mut HeldOrdinaryOwner03<'held, 'db>),
    StepUp(&'a mut HeldStepUp03<'held, 'db>),
}
impl Proof<'_, '_, '_> {
    fn selector(&self) -> super::super::Selector {
        match self {
            Self::Ordinary(p) => p.selected_identity(),
            Self::StepUp(p) => p.selected_identity(),
        }
    }
    fn uses(&self, tx: &Transaction<'_>) -> bool {
        match self {
            Self::Ordinary(p) => p.uses_transaction(tx),
            Self::StepUp(p) => p.uses_transaction(tx),
        }
    }
    fn epoch(&self) -> u64 {
        match self {
            Self::Ordinary(p) => p.selection_epoch(),
            Self::StepUp(p) => p.selection_epoch(),
        }
    }
    fn owner_deadline(&self) -> u64 {
        match self {
            Self::Ordinary(p) => p.session_deadline_ms(),
            Self::StepUp(p) => p.owner_session_deadline_ms(),
        }
    }
    fn deadline(&self) -> u64 {
        match self {
            Self::Ordinary(p) => p.session_deadline_ms(),
            Self::StepUp(p) => p.expires_at_ms(),
        }
    }
    fn checked(&self) -> u64 {
        match self {
            Self::Ordinary(p) => p.checked_at_ms(),
            Self::StepUp(p) => p.checked_primary_ms(),
        }
    }
    async fn revalidate(&mut self) -> Result<()> {
        match self {
            Self::Ordinary(p) => p.revalidate().await.map_err(|_| Error::Authentication),
            Self::StepUp(p) => p.revalidate().await.map_err(|_| Error::Authentication),
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
    let current = Current::lock(tx, proof.selector().account, line, origin).await?;
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
    pub(crate) fn selection_epoch(&self) -> u64 {
        self.current.epoch
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
        }
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
    pub(crate) fn review_context<'a>(
        &'a self,
        interval: Uuid,
        starts: u64,
        expires: u64,
        peer: &'a [u8],
        signer: &'a [u8; 32],
        recipients: &'a [(u8, [u8; 32])],
    ) -> ExpectedReview03<'a> {
        let owner = self.proof.selector();
        ExpectedReview03 {
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
}

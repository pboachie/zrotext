// SPDX-License-Identifier: AGPL-3.0-only
//! Exact retained reservation, never a proof of present permission.
use super::*;
use crate::sealed_manifest::{ChainPosition, ManifestTrust};
use crate::sealed_manifest03::{self as crypto, AuthenticatedCheckpoint02};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD as B};
use uuid::Uuid;
mod closures;

pub struct Reservation {
    pub(super) account: Uuid,
    pub(super) opening: Uuid,
    pub(super) challenge: Uuid,
    pub(super) user: Uuid,
    pub(super) session: Uuid,
    pub(super) line: Uuid,
    pub(super) device: Uuid,
    pub(super) old_binding: Uuid,
    pub(super) new_binding: Uuid,
    pub(super) old_generation: u64,
    pub(super) new_generation: u64,
    pub(super) epoch: u64,
    pub(super) issued: u64,
    pub(super) expires: u64,
    pub(super) core: [u8; 500],
    pub(super) pin: [u8; 94],
    pub(super) prior: Vec<u8>,
    pub(super) prior_accepted: u64,
    pub(super) successor: Vec<u8>,
    pub(super) device_point: [u8; 65],
    pub(super) owner_point: [u8; 65],
    pub(super) device_signature: Option<[u8; 64]>,
    pub(super) accepted: bool,
    pub(super) closed: Option<u64>,
    closures: Vec<serde_json::Value>,
}

const COLUMNS: &str = "c.account_id,c.opening_id,c.challenge_id,c.initiating_user_id,c.initiating_session_id,c.line_id,c.device_id,c.old_binding_id,c.new_binding_id,c.old_binding_generation,c.new_binding_generation,c.prior_selection_epoch,c.issued_ms,c.expires_ms,c.core,c.root_pin,c.prior_signed_manifest,c.prior_accepted_at_ms,c.accepted_signed_manifest,c.device_point,c.owner_point,c.device_signature,(e.challenge_id IS NOT NULL),c.closed_unaccepted_ms";

impl Reservation {
    pub fn matches_successor(&self, successor: &[u8]) -> bool {
        self.successor == successor
    }
    pub fn projection(&self) -> serde_json::Value {
        serde_json::json!({"v":1,"opening_id":self.opening,"challenge_id":self.challenge,
            "new_binding_id":self.new_binding,"core":B.encode(self.core),
            "successor_manifest03":B.encode(&self.successor),"issued_ms":self.issued.to_string(),
            "expires_ms":self.expires.to_string(),"status":if self.accepted {"accepted"} else {"reserved"},"closed_unaccepted":self.closures})
    }
    pub fn proof_projection(&self, now: u64) -> Result<serde_json::Value> {
        if now >= self.expires || self.closed.is_some() {
            return Err(Error::Expired);
        }
        let signature = self.device_signature.ok_or(Error::NotFound)?;
        Ok(
            serde_json::json!({"v":1,"opening_id":self.opening,"challenge_id":self.challenge,"device_signature":B.encode(signature)}),
        )
    }
    pub(super) async fn read(
        tx: &Transaction<'_>,
        account: Uuid,
        opening: Uuid,
    ) -> Result<Option<Self>> {
        let sql = format!(
            "SELECT {COLUMNS} FROM public.payload_profile_election_challenges c LEFT JOIN public.payload_profile_elections e ON (e.account_id,e.challenge_id)=(c.account_id,c.challenge_id) WHERE c.account_id=$1 AND c.opening_id=$2"
        );
        let Some(r) = tx.query_opt(&sql, &[&account, &opening]).await? else {
            return Ok(None);
        };
        let mut value = Self {
            account: r.try_get(0)?,
            opening: r.try_get(1)?,
            challenge: r.try_get(2)?,
            user: r.try_get(3)?,
            session: r.try_get(4)?,
            line: r.try_get(5)?,
            device: r.try_get(6)?,
            old_binding: r.try_get(7)?,
            new_binding: r.try_get(8)?,
            old_generation: positive(r.try_get(9)?)?,
            new_generation: positive(r.try_get(10)?)?,
            epoch: u64::try_from(r.try_get::<_, i64>(11)?).map_err(|_| Error::Unsupported)?,
            issued: positive(r.try_get(12)?)?,
            expires: positive(r.try_get(13)?)?,
            core: fixed(&r, 14)?,
            pin: fixed(&r, 15)?,
            prior: r.try_get(16)?,
            prior_accepted: positive(r.try_get(17)?)?,
            successor: r.try_get(18)?,
            device_point: fixed(&r, 19)?,
            owner_point: fixed(&r, 20)?,
            device_signature: r
                .try_get::<_, Option<Vec<u8>>>(21)?
                .map(|s| s.try_into().map_err(|_| Error::Unsupported))
                .transpose()?,
            accepted: r.try_get(22)?,
            closed: r.try_get::<_, Option<i64>>(23)?.map(positive).transpose()?,
            closures: Vec::new(),
        };
        value.verify_original()?;
        value.closures = value.read_closures(tx).await?;
        Ok(Some(value))
    }
    pub(super) fn closure_projection(&self) -> &[serde_json::Value] {
        &self.closures
    }
    async fn read_closures(&self, tx: &Transaction<'_>) -> Result<Vec<serde_json::Value>> {
        let rows=tx.query("WITH RECURSIVE ancestors AS (SELECT account_id,opening_id,challenge_id,new_binding_id,new_binding_generation,old_binding_id,line_id,device_id,core,expires_ms,closed_unaccepted_ms,superseded_by_challenge_id FROM public.payload_profile_election_challenges WHERE account_id=$1 AND superseded_by_challenge_id=$2 UNION SELECT p.account_id,p.opening_id,p.challenge_id,p.new_binding_id,p.new_binding_generation,p.old_binding_id,p.line_id,p.device_id,p.core,p.expires_ms,p.closed_unaccepted_ms,p.superseded_by_challenge_id FROM public.payload_profile_election_challenges p JOIN ancestors a ON (p.account_id,p.superseded_by_challenge_id)=(a.account_id,a.challenge_id)) SELECT opening_id,challenge_id,new_binding_id,new_binding_generation,old_binding_id,line_id,device_id,core,expires_ms,closed_unaccepted_ms,superseded_by_challenge_id FROM ancestors ORDER BY new_binding_generation LIMIT 17",&[&self.account,&self.challenge]).await?;
        if rows.len() > 16 {
            return Err(Error::Unsupported);
        }
        let mut closed = Vec::with_capacity(rows.len());
        for r in rows {
            let core: [u8; 500] = fixed(&r, 7)?;
            if r.try_get::<_, Uuid>(4)? != self.old_binding
                || r.try_get::<_, Uuid>(5)? != self.line
                || r.try_get::<_, Uuid>(6)? != self.device
                || positive(r.try_get(3)?)?
                    != crypto::number(&core[96..104]).map_err(|_| Error::Unsupported)?
                || positive(r.try_get(8)?)?
                    != crypto::number(&core[392..400]).map_err(|_| Error::Unsupported)?
            {
                return Err(Error::Unsupported);
            }
            closed.push(closures::Closed {
                opening: r.try_get(0)?,
                challenge: r.try_get(1)?,
                binding: r.try_get(2)?,
                core,
                closed_ms: positive(r.try_get(9)?)?,
                target: r.try_get(10)?,
            });
        }
        closures::project(
            &self.core,
            self.opening,
            self.challenge,
            self.new_binding,
            &closed,
        )
    }
    pub(super) fn checkpoint(&self) -> Result<crypto::VerifiedCheckpoint02> {
        let core = &self.core;
        let trust = ManifestTrust {
            account_id: *self.account.as_bytes(),
            root_fingerprint: core[136..168].try_into().unwrap(),
            generation: crypto::number(&core[168..176]).map_err(|_| Error::Unsupported)?,
            position: ChainPosition::Current {
                version: crypto::number(&core[176..184]).map_err(|_| Error::Unsupported)?,
                digest: core[184..216].try_into().unwrap(),
            },
        };
        crypto::verify_checkpoint02(
            &self.pin,
            &self.prior,
            &AuthenticatedCheckpoint02 {
                trust,
                anchor_digest: [0; 32],
                accepted_at_ms: self.prior_accepted,
                last_verified_ms: self.issued,
            },
            self.issued,
        )
        .map_err(|_| Error::Unsupported)
    }
    fn verify_original(&self) -> Result<()> {
        let c = &self.core;
        let owner_session = super::super::adapter_contract::OwnerSessionIdentity03 {
            account_id: *self.account.as_bytes(),
            user_id: *self.user.as_bytes(),
            session_id: *self.session.as_bytes(),
        }
        .digest()
        .map_err(|_| Error::Unsupported)?;
        if c[432..464] != owner_session {
            return Err(Error::Unsupported);
        }
        if &c[..8] != b"ZTPE\x03\x01\x02\x03"
            || c[496..] != [0; 4]
            || self.account.is_nil()
            || self.opening.is_nil()
            || self.challenge.is_nil()
            || self.new_binding.is_nil()
            || self.new_binding == self.old_binding
            || self.challenge == self.new_binding
            || self.old_generation >= self.new_generation
            || self.issued >= self.expires
            || self.expires - self.issued > 300_000
            || crypto::number(&c[384..392]).map_err(|_| Error::Unsupported)? != self.issued
            || crypto::number(&c[392..400]).map_err(|_| Error::Unsupported)? != self.expires
        {
            return Err(Error::Unsupported);
        }
        for (at, id) in [
            (8, self.account),
            (24, self.device),
            (40, self.line),
            (56, self.challenge),
            (72, self.old_binding),
        ] {
            if id.is_nil() || c[at..at + 16] != *id.as_bytes() {
                return Err(Error::Unsupported);
            }
        }
        for (at, n) in [(88, self.old_generation), (96, self.new_generation)] {
            if crypto::number(&c[at..at + 8]).map_err(|_| Error::Unsupported)? != n {
                return Err(Error::Unsupported);
            }
        }
        for at in [104, 136, 184, 224, 256, 288, 320, 352, 400, 432, 464] {
            if c[at..at + 32] == [0; 32] {
                return Err(Error::Unsupported);
            }
        }
        let checkpoint = self.checkpoint()?;
        let successor = crypto::verify_from_02(&self.successor, &checkpoint, self.issued)
            .map_err(|_| Error::Unsupported)?;
        let identity = successor
            .identity_at(self.issued)
            .map_err(|_| Error::Unsupported)?;
        let selected = successor
            .profile_election_keys(
                self.device.as_bytes(),
                self.line.as_bytes(),
                &self.device_point,
                &self.owner_point,
                self.issued,
            )
            .map_err(|_| Error::Unsupported)?;
        if identity.digest != c[224..256]
            || identity.version != crypto::number(&c[216..224]).map_err(|_| Error::Unsupported)?
            || selected.reader_id != c[256..288]
            || selected.device_signer_id != c[288..320]
            || selected.approval_id != c[320..352]
        {
            return Err(Error::Unsupported);
        }
        if let Some(signature) = &self.device_signature {
            crypto::signature(
                &self.device_point,
                signature,
                &crypto::framed(b"ZTSE/line/payload-profile/device/v1\0", c)
                    .map_err(|_| Error::Unsupported)?,
            )
            .map_err(|_| Error::Unsupported)?;
        }
        Ok(())
    }
    pub(super) fn matches_current(
        &self,
        owner: &Owner<'_, '_, '_>,
        current: &state02::Current02<'_, '_>,
    ) -> Result<()> {
        let who = owner.selector();
        if self.account != who.account
            || self.user != who.user
            || self.session != who.session
            || self.line != current.line
            || self.device != current.device
            || self.epoch != owner.epoch()
            || self.old_binding != current.history.binding_id()
            || self.old_generation != current.generation
            || self.pin != current.pin
            || self.prior != current.manifest
            || self.prior_accepted != current.prior_accepted_ms
            || self.device_point != current.device_point
            || self.owner_point != current.owner_point
            || self.core[104..136] != *current.history.old_binding_proof_digest()
            || self.core[256..288] != current.selected.reader_id
            || self.core[288..320] != current.selected.device_signer_id
            || self.core[320..352] != current.selected.approval_id
            || self.core[400..432] != *owner.origin()
            || self.core[432..464] != *owner.session()
            || self.core[464..496] != *current.context.identity_digest()
        {
            return Err(Error::Conflict);
        }
        if self.closed.is_some()
            || current.checked_ms < self.issued
            || current.checked_ms >= self.expires
        {
            return Err(Error::Expired);
        }
        Ok(())
    }
}

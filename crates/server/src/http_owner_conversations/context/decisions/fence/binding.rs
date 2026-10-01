// SPDX-License-Identifier: AGPL-3.0-only
use super::*;
use crate::{
    sealed_envelope::{self, ExpectedRecipient, Kind, Profile},
    sealed_manifest::EnvelopeAuthority,
};

impl LockedAction<'_, '_> {
    /// Explicit owner confirmation of independently rendered, authenticated ciphertext.
    /// The server proves framing and scope, never plaintext equivalence.
    pub(crate) async fn bind_message(
        &mut self,
        message: Uuid,
        dispatch: Uuid,
        digest: [u8; 32],
    ) -> Result<(), ConversationError> {
        if message.is_nil() || dispatch.is_nil() {
            return Err(ConversationError::Invalid);
        }
        self.recheck().await?;
        self.transaction().query_opt("SELECT 1 FROM dispatch_jobs WHERE account_id=$1 AND message_id=$2 AND grant_issued_at IS NULL AND finished_at IS NULL FOR UPDATE",
            &[&self.key.account_id,&message]).await?.ok_or(ConversationError::Conflict)?;
        let row=self.transaction().query_opt("SELECT transport_payload,recipient_e164,sealed_line_id,sealed_binding_generation,device_id,sealed_manifest_generation,sealed_manifest_version,sealed_manifest_digest FROM messages WHERE account_id=$1 AND id=$2 AND transport_mode='sealed_candidate02' AND state IN ('queued','claimed') AND expires_at>clock_timestamp() AND NOT EXISTS(SELECT 1 FROM message_attempts a WHERE a.account_id=$1 AND a.message_id=$2) FOR UPDATE",
            &[&self.key.account_id,&message]).await?.ok_or(ConversationError::Conflict)?;
        let bytes: Vec<u8> = row
            .get::<_, Option<Vec<u8>>>(0)
            .ok_or(ConversationError::Unavailable)?;
        let peer: String = row
            .get::<_, Option<String>>(1)
            .ok_or(ConversationError::Unavailable)?;
        if Sha256::digest(&bytes).as_slice() != digest
            || Sha256::digest(peer.as_bytes()).as_slice() != self.header.peer_digest
            || row.get::<_, Option<Uuid>>(2) != Some(self.header.line)
            || row.get::<_, Option<i64>>(3) != Some(self.header.binding_generation)
            || row.get::<_, Uuid>(4) != self.header.device
            || row.get::<_, Option<i64>>(5) != Some(self.header.trust_generation)
            || row.get::<_, Option<i64>>(6) != Some(self.header.manifest_version)
            || row.get::<_, Option<Vec<u8>>>(7).as_deref()
                != Some(self.header.manifest_digest.as_slice())
        {
            return Err(ConversationError::Forbidden);
        }
        let claims = sealed_envelope::parse(&bytes, Profile::Draft02Candidate)
            .map_err(|_| ConversationError::Forbidden)?;
        let recipients: Vec<_> = claims
            .wraps
            .iter()
            .map(|w| {
                Ok(ExpectedRecipient {
                    role: w.role,
                    key_id: w
                        .key_id
                        .try_into()
                        .map_err(|_| ConversationError::Forbidden)?,
                })
            })
            .collect::<Result<_, ConversationError>>()?;
        let wanted = EnvelopeAuthority {
            kind: Kind::Outbound,
            account_id: *self.key.account_id.as_bytes(),
            device_id: *self.header.device.as_bytes(),
            line_id: *self.header.line.as_bytes(),
            message_id: *message.as_bytes(),
            signer_key_id: claims
                .signer_key_id
                .try_into()
                .map_err(|_| ConversationError::Forbidden)?,
            peer: peer.as_bytes(),
            recipients: &recipients,
        };
        let verified = self.authority.context(&wanted).await?;
        sealed_envelope::verify(&bytes, &verified).map_err(|_| ConversationError::Forbidden)?;
        if claims
            .expires_ms
            .is_none_or(|expiry| expiry > self.expires_at_ms() as u64)
        {
            return Err(ConversationError::Forbidden);
        }
        let actor = self.actor_user_id();
        self.transaction().execute("INSERT INTO workflow_message_links(account_id,action_id,revision,binding_digest,message_id,live_message_id,dispatch_id,message_digest,confirmed_by) VALUES($1,$2,$3,$4,$5,$5,$6,$7,$8)",
            &[&self.key.account_id,&self.key.action_id,&self.key.revision,&&self.key.binding_digest[..],&message,&dispatch,&&digest[..],&actor]).await?;
        self.transaction()
            .execute(
                "UPDATE messages SET workflow_action_id=$3 WHERE account_id=$1 AND id=$2",
                &[&self.key.account_id, &message, &self.key.action_id],
            )
            .await?;
        self.recheck().await
    }
}

// SPDX-License-Identifier: AGPL-3.0-only
//! Dormant confirmed-send verification, not a queue/execution grant or radio path.
//! The phone must independently check the decrypted content digest and fresh
//! shared admission gate before execution. Only synthetic transport consumes it.
use super::{ConversationError, SessionPrincipal, activation, fresh_owner, lock_line, lock_owner};
use crate::{
    inbound::InboundSession,
    sealed_envelope::{self, ExpectedRecipient, Kind, Profile},
    sealed_manifest::EnvelopeAuthority,
    sealed_manifest_store::outbound::lock_current,
};
use p256::ecdsa::{Signature, VerifyingKey, signature::Verifier};
use sha2::{Digest, Sha256};
use tokio_postgres::{Client, Transaction};
pub mod queue;
use uuid::Uuid;

const DOMAIN: &[u8] = b"zrotext/conversation/confirm-send/v1\0";

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Confirmation {
    pub account: Uuid,
    pub device: Uuid,
    pub line: Uuid,
    pub interval: Uuid,
    pub session: Uuid,
    pub message: Uuid,
    pub generation: i64,
    pub trust_generation: i64,
    pub version: i64,
    pub expires_ms: i64,
    pub peer: String,
    pub signer: [u8; 32],
    pub reader: [u8; 32],
    pub manifest: [u8; 32],
    pub envelope_digest: [u8; 32],
    pub body_digest: [u8; 32],
}
impl Confirmation {
    pub fn encode(&self) -> Result<Vec<u8>, ConversationError> {
        if [
            self.account,
            self.device,
            self.line,
            self.interval,
            self.session,
            self.message,
        ]
        .iter()
        .any(Uuid::is_nil)
            || [
                self.generation,
                self.trust_generation,
                self.version,
                self.expires_ms,
            ]
            .iter()
            .any(|v| *v <= 0)
            || !(3..=16).contains(&self.peer.len())
            || !self.peer.starts_with('+')
            || !self.peer.as_bytes()[1].is_ascii_digit()
            || self.peer.as_bytes()[1] == b'0'
            || !self.peer.as_bytes()[2..].iter().all(u8::is_ascii_digit)
        {
            return Err(ConversationError::Invalid);
        }
        let mut out = b"ZTCS\x01".to_vec();
        for id in [
            self.account,
            self.device,
            self.line,
            self.interval,
            self.session,
            self.message,
        ] {
            out.extend(id.as_bytes());
        }
        for n in [
            self.generation,
            self.trust_generation,
            self.version,
            self.expires_ms,
        ] {
            out.extend(n.to_be_bytes());
        }
        out.push(self.peer.len() as u8);
        out.extend(self.peer.as_bytes());
        for h in [
            self.signer,
            self.reader,
            self.manifest,
            self.envelope_digest,
            self.body_digest,
        ] {
            out.extend(h);
        }
        Ok(out)
    }
    pub fn decode(bytes: &[u8]) -> Result<Self, ConversationError> {
        if !(297..=310).contains(&bytes.len()) || !bytes.starts_with(b"ZTCS\x01") {
            return Err(ConversationError::Invalid);
        }
        let mut at = 5;
        let mut id = || {
            let v = Uuid::from_slice(&bytes[at..at + 16]).map_err(|_| ConversationError::Invalid);
            at += 16;
            v
        };
        let (account, device, line, interval, session, message) =
            (id()?, id()?, id()?, id()?, id()?, id()?);
        let mut num = || {
            let v = i64::from_be_bytes(bytes[at..at + 8].try_into().unwrap());
            at += 8;
            v
        };
        let (generation, trust_generation, version, expires_ms) = (num(), num(), num(), num());
        let n = bytes[at] as usize;
        at += 1;
        if !(3..=16).contains(&n) || at + n + 160 != bytes.len() {
            return Err(ConversationError::Invalid);
        }
        let peer = std::str::from_utf8(&bytes[at..at + n])
            .map_err(|_| ConversationError::Invalid)?
            .into();
        at += n;
        let mut hash = || {
            let h = bytes[at..at + 32].try_into().unwrap();
            at += 32;
            h
        };
        let c = Self {
            account,
            device,
            line,
            interval,
            session,
            message,
            generation,
            trust_generation,
            version,
            expires_ms,
            peer,
            signer: hash(),
            reader: hash(),
            manifest: hash(),
            envelope_digest: hash(),
            body_digest: hash(),
        };
        if c.encode()?.as_slice() != bytes {
            return Err(ConversationError::Invalid);
        }
        Ok(c)
    }
    pub fn transcript(&self) -> Result<Vec<u8>, ConversationError> {
        let bytes = self.encode()?;
        Ok([DOMAIN, &(bytes.len() as u32).to_be_bytes(), &bytes].concat())
    }
}

/// Both authorities are supplied by authenticated adapters, never request claims.
/// The short confirmation deadline is rechecked after all lock waits. This
/// verifies a single immutable intent; it deliberately stores/dispatches nothing.
pub async fn authorize_confirmed_send(
    client: &mut Client,
    owner: &SessionPrincipal,
    phone: InboundSession<'_>,
    envelope: &[u8],
    confirmation: &[u8],
    signature: &[u8],
) -> Result<Confirmation, ConversationError> {
    let tx = client.transaction().await?;
    let c = authorize_in_transaction(&tx, owner, phone, envelope, confirmation, signature).await?;
    tx.commit().await?;
    Ok(c)
}

// Database locks remain held by the caller until its complete transaction commits.
async fn authorize_in_transaction(
    tx: &Transaction<'_>,
    owner: &SessionPrincipal,
    phone: InboundSession<'_>,
    envelope: &[u8],
    confirmation: &[u8],
    signature: &[u8],
) -> Result<Confirmation, ConversationError> {
    authorize_bound(
        tx,
        Some(owner),
        phone,
        owner.session_id,
        envelope,
        confirmation,
        signature,
    )
    .await
}

/// Phone delivery uses only retained origin provenance, never a forged browser principal.
pub(super) async fn authorize_delivery(
    tx: &Transaction<'_>,
    phone: InboundSession<'_>,
    origin: Uuid,
    envelope: &[u8],
    confirmation: &[u8],
    signature: &[u8],
) -> Result<Confirmation, ConversationError> {
    authorize_bound(tx, None, phone, origin, envelope, confirmation, signature).await
}

async fn authorize_bound(
    tx: &Transaction<'_>,
    owner: Option<&SessionPrincipal>,
    phone: InboundSession<'_>,
    origin: Uuid,
    envelope: &[u8],
    confirmation: &[u8],
    signature: &[u8],
) -> Result<Confirmation, ConversationError> {
    let c = Confirmation::decode(confirmation)?;
    let e = sealed_envelope::parse(envelope, Profile::Draft02Candidate)
        .map_err(|_| ConversationError::Invalid)?;
    if e.kind != Kind::Outbound
        || owner.is_some_and(|owner| c.account != owner.tenant.account_id())
        || c.session != origin
        || c.account != phone.account_id
        || c.device != phone.device_id
        || e.account_id != c.account.as_bytes()
        || e.device_id != c.device.as_bytes()
        || e.line_id != c.line.as_bytes()
        || e.message_id != c.message.as_bytes()
        || e.peer != c.peer.as_bytes()
        || e.signer_key_id != c.signer
        || e.keyset_version != c.version as u64
        || e.manifest_digest != c.manifest
        || e.expires_ms != Some(c.expires_ms as u64)
        || Sha256::digest(envelope).as_slice() != c.envelope_digest
        || e.wraps.len() != 2
        || e.wraps[0].role != 1
        || e.wraps[1].role != 2
        || e.wraps[1].key_id != c.reader
    {
        return Err(ConversationError::Forbidden);
    }
    let mut authority = lock_current(tx, c.account).await?;
    if let Some(owner) = owner {
        lock_owner(tx, owner).await?;
    } else {
        tx.query_opt(
            "SELECT 1 FROM accounts WHERE id=$1 AND disabled_at IS NULL FOR UPDATE",
            &[&phone.account_id],
        )
        .await?
        .ok_or(ConversationError::Forbidden)?;
    }
    let row = activation::load(tx, c.account, c.interval).await?;
    let s = &row.statement;
    if row.phase != "active"
        || s.account != c.account
        || s.device != c.device
        || s.line != c.line
        || s.generation != c.generation
        || s.originating_session != c.session
        || s.peer != c.peer
        || s.reader != c.reader
        || s.trust_generation != c.trust_generation
        || authority.generation() != c.trust_generation
    {
        return Err(ConversationError::Forbidden);
    }
    lock_line(tx, c.account, c.device, c.line, c.generation).await?;
    if authority.conversation_keys(c.device, c.line).await? != (s.reader, s.signer) {
        return Err(ConversationError::Forbidden);
    }
    activation::device_live(tx, phone, s).await?;
    let r = [
        ExpectedRecipient {
            role: 1,
            key_id: e.wraps[0].key_id.try_into().unwrap(),
        },
        ExpectedRecipient {
            role: 2,
            key_id: c.reader,
        },
    ];
    let w = EnvelopeAuthority {
        kind: Kind::Outbound,
        account_id: *c.account.as_bytes(),
        device_id: *c.device.as_bytes(),
        line_id: *c.line.as_bytes(),
        message_id: *c.message.as_bytes(),
        signer_key_id: c.signer,
        peer: c.peer.as_bytes(),
        recipients: &r,
    };
    let context = authority.context(&w).await?;
    sealed_envelope::verify(envelope, &context).map_err(|_| ConversationError::Forbidden)?;
    let sig = Signature::from_slice(signature).map_err(|_| ConversationError::Forbidden)?;
    if sig.to_bytes() != sig.normalize_s().to_bytes() {
        return Err(ConversationError::Forbidden);
    }
    VerifyingKey::from_sec1_bytes(context.signer_public_point)
        .map_err(|_| ConversationError::Forbidden)?
        .verify(&c.transcript()?, &sig)
        .map_err(|_| ConversationError::Forbidden)?;
    let now = activation::now(tx).await?;
    if c.expires_ms <= now
        || c.expires_ms - now > 30_000
        || e.observed_ms > now as u64
        || c.expires_ms - e.observed_ms as i64 > 30_000
    {
        return Err(ConversationError::Forbidden);
    }
    if let Some(owner) = owner {
        fresh_owner(tx, owner).await?;
    }
    activation::origin(tx, s).await?;
    activation::device_live(tx, phone, s).await?;
    authority.context(&w).await?;
    if authority.conversation_keys(c.device, c.line).await? != (s.reader, s.signer) {
        return Err(ConversationError::Forbidden);
    }
    if activation::now(tx).await? >= c.expires_ms {
        return Err(ConversationError::Forbidden);
    }
    drop(authority);
    Ok(c)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn cross_language_confirmation_vector_binds_body_and_transcript() {
        let v: serde_json::Value = serde_json::from_str(include_str!(
            "../../../../protocol/v1/vectors/conversation-send.json"
        ))
        .unwrap();
        let hex = |key: &str| {
            v[key]
                .as_str()
                .unwrap()
                .as_bytes()
                .chunks_exact(2)
                .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
                .collect::<Vec<_>>()
        };
        let bytes = hex("canonical_hex");
        let c = Confirmation::decode(&bytes).unwrap();
        assert_eq!(c.encode().unwrap(), bytes);
        assert_eq!(c.transcript().unwrap(), hex("transcript_hex"));
        assert_eq!(
            c.account.to_string(),
            v["confirmation"]["account"].as_str().unwrap()
        );
        assert_eq!(
            c.session.to_string(),
            v["confirmation"]["session"].as_str().unwrap()
        );
        assert_eq!(c.peer, v["confirmation"]["peer"].as_str().unwrap());
        assert_eq!(
            c.body_digest.as_slice(),
            Sha256::digest(v["body"].as_str().unwrap().as_bytes()).as_slice()
        );
    }
    #[test]
    fn confirmation_rejects_truncation_trailing_and_scope_mutation() {
        let c = Confirmation {
            account: Uuid::new_v4(),
            device: Uuid::new_v4(),
            line: Uuid::new_v4(),
            interval: Uuid::new_v4(),
            session: Uuid::new_v4(),
            message: Uuid::new_v4(),
            generation: 1,
            trust_generation: 1,
            version: 1,
            expires_ms: 1,
            peer: "+12".into(),
            signer: [1; 32],
            reader: [2; 32],
            manifest: [3; 32],
            envelope_digest: [4; 32],
            body_digest: [5; 32],
        };
        let bytes = c.encode().unwrap();
        assert_eq!(Confirmation::decode(&bytes).unwrap(), c);
        for n in 0..bytes.len() {
            assert!(Confirmation::decode(&bytes[..n]).is_err());
        }
        let mut extra = bytes.clone();
        extra.push(0);
        assert!(Confirmation::decode(&extra).is_err());
        let mut changed = c.clone();
        changed.body_digest[0] ^= 1;
        assert_ne!(c.transcript().unwrap(), changed.transcript().unwrap());
        changed = c.clone();
        changed.session = Uuid::nil();
        assert!(changed.encode().is_err());
    }
}

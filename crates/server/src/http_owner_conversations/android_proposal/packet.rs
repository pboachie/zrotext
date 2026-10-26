// SPDX-License-Identifier: AGPL-3.0-only
//! Exact typed verification; expected identity/checkpoint/key fields come from
//! locked server authority and separately registered public inputs, not a file.
use super::super::{ConversationError, SessionPrincipal};
use super::{
    GenesisInputs,
    authority::{Current, Selection},
    store::Record,
};
use uuid::Uuid;
use zrotext_root_material::{
    conversation_activation as activation, conversation_genesis as genesis,
    conversation_refresh as refresh, root_backup::ExpectedIdentity,
};

fn reject() -> ConversationError {
    ConversationError::Forbidden
}
pub(super) fn selection(kind: i16, bytes: &[u8]) -> Result<Selection, ConversationError> {
    let (d, l, g, peer) = match kind {
        3 => {
            let p = genesis::decode(bytes).map_err(|_| reject())?;
            let s = p.scope();
            (s.device, s.line, s.generation, s.peer.clone())
        }
        4 => {
            let p = activation::decode(bytes).map_err(|_| reject())?;
            let s = p.scope;
            (s.device, s.line, s.line_generation, s.peer)
        }
        5 => {
            let p = refresh::decode(bytes).map_err(|_| reject())?;
            let s = p.scope;
            (s.device, s.line, s.line_generation, s.peer)
        }
        _ => return Err(ConversationError::Invalid),
    };
    Ok(Selection {
        device: Uuid::from_bytes(d),
        line: Uuid::from_bytes(l),
        generation: g.try_into().map_err(|_| reject())?,
        peer,
    })
}
pub(super) fn signer_point(expected: &serde_json::Value) -> Result<[u8; 65], ConversationError> {
    bytes(&expected["scope"]["point"])
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
fn bytes<const N: usize>(value: &serde_json::Value) -> Result<[u8; N], ConversationError> {
    let text = value.as_str().ok_or_else(reject)?;
    if text.len() != N * 2
        || !text
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(reject());
    }
    let mut out = [0; N];
    for (i, pair) in text.as_bytes().as_chunks::<2>().0.iter().enumerate() {
        out[i] = u8::from_str_radix(std::str::from_utf8(pair).map_err(|_| reject())?, 16)
            .map_err(|_| reject())?;
    }
    Ok(out)
}
pub(super) fn retained_genesis(
    expected: &serde_json::Value,
) -> Result<GenesisInputs, ConversationError> {
    Ok(GenesisInputs {
        phone_reader: bytes(&expected["phone_reader"])?,
        archive_reader: bytes(&expected["archive_reader"])?,
        phone_signer: bytes(&expected["phone_signer"])?,
        archive_backup_sha256: bytes(&expected["archive_backup_sha256"])?,
        phone_export_sha256: [0; 32],
    })
}
fn deadline(issued: u64, upper: u64, now: i64) -> Result<i64, ConversationError> {
    let expires = issued.checked_add(300000).ok_or_else(reject)?.min(upper);
    if issued == 0 || issued > now as u64 || expires <= now as u64 || expires > i64::MAX as u64 {
        return Err(reject());
    }
    Ok(expires as i64)
}
fn role(c: &Current, kind: u8, s: &Selection, now: i64) -> Result<[u8; 32], ConversationError> {
    let m = c.manifest.as_deref().ok_or_else(reject)?;
    // Current::verify has verified framing/signature/checkpoint before this parsing.
    let mut found = m[151..m.len() - 64]
        .as_chunks::<149>()
        .0
        .iter()
        .filter(|r| {
            r[0] == kind
                && r[148] == 1
                && u16::from_be_bytes(r[130..132].try_into().unwrap())
                    & if kind == 4 { 2 } else { 4 }
                    != 0
                && i64::from_be_bytes(r[132..140].try_into().unwrap()) <= now
                && now < i64::from_be_bytes(r[140..148].try_into().unwrap())
                && (kind == 2
                    || (r[98..114] == *s.device.as_bytes() && r[114..130] == *s.line.as_bytes()))
        });
    let record = found.next().ok_or_else(reject)?;
    if found.next().is_some() {
        return Err(reject());
    }
    record[1..33].try_into().map_err(|_| reject())
}
pub(super) struct Context<'a> {
    pub p: &'a SessionPrincipal,
    pub s: &'a Selection,
    pub c: &'a Current,
    pub origin: &'a str,
    pub now: i64,
}
pub(super) fn validate(
    kind: i16,
    context: Context<'_>,
    packet: &[u8],
    inputs: Option<&GenesisInputs>,
) -> Result<Record, ConversationError> {
    let Context {
        p,
        s,
        c,
        origin,
        now,
    } = context;
    c.verify(p.tenant.account_id(), now)?;
    let a = *p.tenant.account_id().as_bytes();
    let sid = *p.session_id.as_bytes();
    let device = *s.device.as_bytes();
    let line = *s.line.as_bytes();
    let identity = ExpectedIdentity {
        account_id: a,
        origin: origin.into(),
        root_fingerprint: c.fingerprint,
    };
    match kind {
        3 => {
            if c.version != 0 {
                return Err(reject());
            }
            let proposal = genesis::decode(packet).map_err(|_| reject())?;
            let untrusted = proposal.scope();
            let i = inputs.ok_or_else(reject)?;
            let scope = genesis::Scope {
                account: a,
                session: sid,
                device,
                line,
                device_signing_fingerprint: c.paired_fingerprint,
                generation: s.generation as u64,
                peer: s.peer.clone(),
                origin: origin.into(),
                fingerprint: c.fingerprint,
                issued_ms: untrusted.issued_ms,
                expires_ms: untrusted.expires_ms,
            };
            let expires = deadline(scope.issued_ms, scope.expires_ms, now)?;
            let e = genesis::Expected {
                identity,
                scope: scope.clone(),
                root_pin: c.pin,
                phone_reader: i.phone_reader,
                archive_reader: i.archive_reader,
                phone_signer: i.phone_signer,
            };
            genesis::inspect(&proposal, &e, now as u64).map_err(|_| reject())?;
            let scope = serde_json::json!({"account":hex(&a),"session":hex(&sid),"device":hex(&device),"line":hex(&line),"device_signing_fingerprint":hex(&c.paired_fingerprint),"generation":scope.generation,"peer":scope.peer,"origin":origin,"fingerprint":hex(&c.fingerprint),"issued_ms":scope.issued_ms,"expires_ms":scope.expires_ms});
            let expected = serde_json::json!({"scope":scope,"root_pin":hex(&c.pin),"phone_reader":hex(&i.phone_reader),"archive_reader":hex(&i.archive_reader),"phone_signer":hex(&i.phone_signer),"archive_backup_sha256":hex(&i.archive_backup_sha256)});
            Ok(Record {
                kind,
                packet: packet.to_vec(),
                expected,
                issued: untrusted.issued_ms as i64,
                expires,
                interval: None,
            })
        }
        4 => {
            if c.version <= 0 {
                return Err(reject());
            }
            let proposal = activation::decode(packet).map_err(|_| reject())?;
            if Some(proposal.predecessor()) != c.manifest.as_deref() {
                return Err(reject());
            }
            let scope = activation::Scope {
                account: a,
                session: sid,
                device,
                line,
                line_generation: s.generation as u64,
                peer: s.peer.clone(),
                origin: origin.into(),
                fingerprint: c.fingerprint,
                predecessor_version: c.version as u64,
                predecessor_digest: c.digest.ok_or_else(reject)?,
                phone_reader: role(c, 1, s, now)?,
                archive_reader: role(c, 2, s, now)?,
                phone_signer: role(c, 4, s, now)?,
                issued_ms: proposal.scope.issued_ms,
            };
            activation::inspect(
                &proposal,
                &activation::Expected {
                    identity,
                    scope: scope.clone(),
                },
                now as u64,
            )
            .map_err(|_| reject())?;
            let upper = u64::from_be_bytes(
                proposal.unsigned()[45..53]
                    .try_into()
                    .map_err(|_| reject())?,
            );
            let expires = deadline(scope.issued_ms, upper, now)?;
            let expected = serde_json::json!({"scope":{"account":hex(&a),"session":hex(&sid),"device":hex(&device),"line":hex(&line),"line_generation":scope.line_generation,"peer":scope.peer,"origin":origin,"fingerprint":hex(&c.fingerprint),"predecessor_version":scope.predecessor_version,"predecessor_digest":hex(&scope.predecessor_digest),"phone_reader":hex(&scope.phone_reader),"archive_reader":hex(&scope.archive_reader),"phone_signer":hex(&scope.phone_signer),"issued_ms":scope.issued_ms}});
            Ok(Record {
                kind,
                packet: packet.to_vec(),
                expected,
                issued: scope.issued_ms as i64,
                expires,
                interval: None,
            })
        }
        5 => {
            if c.version <= 0 {
                return Err(reject());
            }
            let proposal = refresh::decode(packet).map_err(|_| reject())?;
            if Some(proposal.predecessor()) != c.manifest.as_deref() {
                return Err(reject());
            }
            let scope = refresh::Scope {
                account: a,
                session: sid,
                interval: proposal.scope.interval,
                device,
                line,
                line_generation: s.generation as u64,
                peer: s.peer.clone(),
                origin: origin.into(),
                fingerprint: c.fingerprint,
                predecessor_version: c.version as u64,
                predecessor_digest: c.digest.ok_or_else(reject)?,
                phone_reader: role(c, 1, s, now)?,
                archive_reader: role(c, 2, s, now)?,
                signer: proposal.scope.signer,
                point: proposal.scope.point,
                until_ms: proposal.scope.until_ms,
            };
            refresh::inspect(
                &proposal,
                &refresh::Expected {
                    identity,
                    scope: scope.clone(),
                },
                now as u64,
            )
            .map_err(|_| reject())?;
            let issued = u64::from_be_bytes(
                proposal.unsigned()[37..45]
                    .try_into()
                    .map_err(|_| reject())?,
            );
            let expires = deadline(issued, scope.until_ms, now)?;
            let expected = serde_json::json!({"scope":{"account":hex(&a),"session":hex(&sid),"interval":hex(&scope.interval),"device":hex(&device),"line":hex(&line),"line_generation":scope.line_generation,"peer":scope.peer,"origin":origin,"fingerprint":hex(&c.fingerprint),"predecessor_version":scope.predecessor_version,"predecessor_digest":hex(&scope.predecessor_digest),"phone_reader":hex(&scope.phone_reader),"archive_reader":hex(&scope.archive_reader),"signer":hex(&scope.signer),"point":hex(&scope.point),"until_ms":scope.until_ms}});
            Ok(Record {
                kind,
                packet: packet.to_vec(),
                expected,
                issued: issued as i64,
                expires,
                interval: Some(Uuid::from_bytes(scope.interval)),
            })
        }
        _ => Err(ConversationError::Invalid),
    }
}

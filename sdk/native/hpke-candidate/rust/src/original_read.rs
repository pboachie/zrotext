//! Correlated original read, authenticated history and final current-proof fence.
use crate::{
    Error,
    original_checkpoint::accepted_manifest_at,
    original_current::{OriginalCurrentClient, VerifiedOriginalCurrent, sample, uuid},
    original_http::{HttpError, Request},
    original_reply::{OriginalRead, authority, open_checked, verify_original_reply_selection02},
};
use base64::{Engine, engine::general_purpose::STANDARD};
use serde::Deserialize;
use serde_json::value::RawValue;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

/// Transient plaintext and exact ciphertext identity; not consumption permission.
pub struct VerifiedOriginalRead {
    pub plaintext: Zeroizing<String>,
    pub event: [u8; 16],
    pub envelope_digest: [u8; 32],
    pub accepted_manifest_version: u64,
    pub authority: VerifiedOriginalCurrent,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WireRead {
    event_id: String,
    accepted_at_ms: u64,
    envelope_b64: String,
    historical_manifest_version: u64,
    statement_b64: String,
    approval_signature_b64: String,
    installation_signature_b64: String,
    activation_manifest_version: u64,
    proof: Box<RawValue>,
}
fn need(v: bool) -> Result<(), HttpError> {
    if v {
        Ok(())
    } else {
        Err(HttpError::Unavailable)
    }
}
fn decode(s: &str, max: usize) -> Result<Vec<u8>, HttpError> {
    need(s.len() <= max.div_ceil(3) * 4)?;
    let b = STANDARD.decode(s).map_err(|_| HttpError::Unavailable)?;
    need(b.len() <= max && STANDARD.encode(&b) == s)?;
    Ok(b)
}
impl OriginalCurrentClient {
    /// Explicit exportable-key path. None selects the oldest retained version
    /// inside the service's 32-manifest history window.
    pub fn read_software(
        &self,
        grant: &str,
        event: [u8; 16],
        baseline: Option<u64>,
        scalar: &[u8],
        clock: impl Fn() -> u64,
    ) -> Result<VerifiedOriginalRead, HttpError> {
        let owned = Zeroizing::new(scalar.to_vec());
        self.read(grant, event, baseline, clock, |p, e, i, a, t| {
            crate::open_software_cek(&owned, p, e, i, a, t)
        })
    }
    /// Qualified protected recipient only; no key export or software fallback.
    #[cfg(windows)]
    pub fn read_hardware(
        &self,
        grant: &str,
        event: [u8; 16],
        baseline: Option<u64>,
        custody: &crate::cng::HardwareRecipient,
        clock: impl Fn() -> u64,
    ) -> Result<VerifiedOriginalRead, HttpError> {
        self.read(grant, event, baseline, clock, |p, e, i, a, t| {
            custody.open_cek(p, e, i, a, t)
        })
    }
    fn read<U>(
        &self,
        grant: &str,
        event: [u8; 16],
        baseline: Option<u64>,
        clock: impl Fn() -> u64,
        unwrap: U,
    ) -> Result<VerifiedOriginalRead, HttpError>
    where
        U: FnOnce(&[u8], &[u8], &[u8], &[u8], &[u8]) -> Result<Zeroizing<Vec<u8>>, Error>,
    {
        let bad = HttpError::Unavailable;
        need(event != [0; 16])?;
        let mut state = self.state.try_lock().map_err(|_| bad)?;
        need(!state.failed)?;
        let now = sample(&mut state, &clock)?;
        let saved = self.checkpoint.snapshot(&self.scope, now).map_err(|_| {
            state.failed = true;
            bad
        })?;
        if saved.revision != state.revision {
            state.failed = true;
            return Err(bad);
        }
        let latest = saved.history.last().ok_or(bad)?;
        let first = saved
            .history
            .iter()
            .find(|m| {
                m.version <= latest.version
                    && latest.version - m.version < 32
                    && baseline.is_none_or(|v| v == m.version)
            })
            .ok_or(bad)?;
        let wire = self.transport.exchange(
            grant,
            first.version,
            Request::Read {
                event_id: uuid(&event),
            },
        )?;
        let r: WireRead = serde_json::from_str(wire.json.get()).map_err(|_| bad)?;
        need(r.event_id == uuid(&event))?;
        let mut current = self.accept_proof(r.proof.get(), &saved, first, &clock, &mut state)?;
        let snap = self
            .checkpoint
            .snapshot(&self.scope, state.last)
            .map_err(|_| {
                state.failed = true;
                bad
            })?;
        if snap.revision != state.revision {
            state.failed = true;
            return Err(bad);
        }
        need(
            r.historical_manifest_version >= first.version
                && (1..=9007199254740991).contains(&r.accepted_at_ms)
                && r.accepted_at_ms <= state.last + 30000,
        )?;
        let historical = snap
            .history
            .iter()
            .find(|m| m.version == r.historical_manifest_version)
            .ok_or(bad)?;
        let activation = snap
            .history
            .iter()
            .find(|m| m.version == r.activation_manifest_version)
            .ok_or(bad)?;
        let activation = accepted_manifest_at(
            &activation.raw,
            &self.root,
            Some(activation),
            r.accepted_at_ms,
        )
        .map_err(|_| bad)?;
        let selection = verify_original_reply_selection02(
            &decode(&r.statement_b64, 1536)?,
            &decode(&r.approval_signature_b64, 64)?,
            &decode(&r.installation_signature_b64, 64)?,
            &activation,
            r.accepted_at_ms,
            &self.scope,
        )
        .map_err(|_| bad)?;
        let envelope = decode(&r.envelope_b64, 34082)?;
        let options = OriginalRead {
            event,
            scope: &self.scope,
            historical,
            selection: &selection,
        };
        let mut once = true;
        let plaintext = open_checked(
            &envelope,
            &options,
            || {
                if once {
                    once = false;
                } else {
                    current = self
                        .current_locked(grant, &clock, &mut state)
                        .map_err(|_| Error::Authentication)?;
                }
                authority(current.authority(), &self.scope)
            },
            unwrap,
        )
        .map_err(|_| bad)?;
        Ok(VerifiedOriginalRead {
            plaintext,
            event,
            envelope_digest: Sha256::digest(&envelope).into(),
            accepted_manifest_version: first.version,
            authority: current,
        })
    }
}

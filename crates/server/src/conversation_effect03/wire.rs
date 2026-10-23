// SPDX-License-Identifier: AGPL-3.0-only
//! Closed typed-effect wire candidates. Parsing or building canonical bytes is
//! not authentication, a committed submit, a durable phone phase or a permit.
use super::{NoSubmitCore03, NoSubmitRecord03, OutcomeCommand03, SubmitCommand03};
use crate::sealed_inbound::line_activation::v2_runtime::object_body;
use crate::sealed_manifest03::Check;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD as B};
use uuid::Uuid;

object_body! {struct SubmitBody{v:u8,r#type:String,connection_epoch:i64,event_id:String,message_id:String,attempt_id:String,fetch_transcript_sha256:String,segment_count:u8,observed_ms:String}}
object_body! {struct OutcomeBody{v:u8,r#type:String,connection_epoch:i64,event_id:String,message_id:String,attempt_id:String,submit_event_id:String,submit_command_sha256:String,fetch_transcript_sha256:String,submit_observed_ms:String,segment_count:u8,evidence:String,observed_ms:String,segment_index:serde_json::Value}}
object_body! {struct SubmitStatusBody{v:u8,r#type:String,connection_epoch:i64,request_id:String,event_id:String,message_id:String,attempt_id:String,submit_command_sha256:String}}
object_body! {struct ChallengeBody{v:u8,r#type:String,connection_epoch:i64,proof_request_id:String,closure_id:String,event_id:String,message_id:String,attempt_id:String,submit_command_sha256:String,fetch_transcript_sha256:String,segment_count:u8,submit_observed_ms:String,closed_from:String,closed_ms:String,closure_record_sha256:String,previous_challenge_id:serde_json::Value}}
object_body! {struct ProofBody{v:u8,r#type:String,connection_epoch:i64,proof_request_id:String,closure_id:String,challenge_id:String,core:String,signature:String}}
object_body! {struct ProofStatusBody{v:u8,r#type:String,connection_epoch:i64,request_id:String,proof_request_id:String,closure_id:String,message_id:String,attempt_id:String,submit_command_sha256:String,closure_record_sha256:String}}

/// Ordinary admission is additional to the shared typed120/FIXED60 budget.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OrdinaryAdmission03 {
    Evidence,
    Manage,
    Read,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind03 {
    Submit,
    Outcome,
    SubmitStatus,
    Challenge,
    Proof,
    ProofStatus,
}
impl Kind03 {
    pub fn admission(self) -> OrdinaryAdmission03 {
        match self {
            Self::Submit | Self::Outcome => OrdinaryAdmission03::Evidence,
            Self::Challenge | Self::Proof => OrdinaryAdmission03::Manage,
            Self::SubmitStatus | Self::ProofStatus => OrdinaryAdmission03::Read,
        }
    }
    fn name(self) -> &'static str {
        match self {
            Self::Submit => "payload_profile_submit03",
            Self::Outcome => "payload_profile_outcome03",
            Self::SubmitStatus => "payload_profile_submit_status03_request",
            Self::Challenge => "payload_profile_no_submit_challenge03_request",
            Self::Proof => "payload_profile_no_submit_proof03",
            Self::ProofStatus => "payload_profile_no_submit_status03_request",
        }
    }
}
fn id(s: &str) -> Check<Uuid> {
    let id = Uuid::parse_str(s).map_err(|_| "effect UUID")?;
    if id.is_nil() || id.to_string() != s {
        return Err("effect canonical UUID");
    }
    Ok(id)
}
fn hash(s: &str) -> Check<[u8; 32]> {
    let value = binary::<32>(s)?;
    super::nonzero(&value)?;
    Ok(value)
}
fn binary<const N: usize>(s: &str) -> Check<[u8; N]> {
    let value = B.decode(s).map_err(|_| "effect base64")?;
    if B.encode(&value) != s {
        return Err("effect canonical base64");
    }
    value.try_into().map_err(|_| "effect binary width")
}
fn time(s: &str) -> Check<u64> {
    let value = s.parse::<u64>().map_err(|_| "effect decimal time")?;
    if value.to_string() != s {
        return Err("effect canonical decimal time");
    }
    crate::sealed_manifest03::time(value)?;
    Ok(value)
}
fn header(v: u8, tag: &str, epoch: i64, kind: Kind03) -> Check<i64> {
    if v != 1 || tag != kind.name() || epoch <= 0 {
        return Err("effect header/connection");
    }
    Ok(epoch)
}
fn segments(value: u8) -> Check<u8> {
    super::count(value)?;
    Ok(value)
}
fn closed<T: for<'de> serde::Deserialize<'de>>(raw: &str) -> Check<T> {
    serde_json::from_str(raw).map_err(|_| "effect closed object")
}

/// Immutable untrusted wire claims. Original account/device/session are never
/// taken from these fields: a held authenticated adapter must select them.
pub enum Request03 {
    Submit(Submit03),
    Outcome(Outcome03),
    SubmitStatus(SubmitStatus03),
    Challenge(Challenge03),
    Proof(Proof03),
    ProofStatus(ProofStatus03),
}
impl Request03 {
    pub fn parse(raw: &str) -> Check<Option<Self>> {
        if raw.len() > 4096 {
            return Err("effect frame size");
        }
        #[derive(serde::Deserialize)]
        struct Route {
            r#type: String,
        }
        let mut decoder = serde_json::Deserializer::from_str(raw);
        let route: Route =
            crate::sealed_inbound::line_activation::v2_runtime::decode_object(&mut decoder)
                .map_err(|_| "effect object route")?;
        decoder.end().map_err(|_| "effect trailing input")?;
        Ok(Some(match route.r#type.as_str() {
            "payload_profile_submit03" => {
                let b: SubmitBody = closed(raw)?;
                Self::Submit(Submit03 {
                    connection_epoch: header(b.v, &b.r#type, b.connection_epoch, Kind03::Submit)?,
                    event_id: id(&b.event_id)?,
                    message_id: id(&b.message_id)?,
                    attempt_id: id(&b.attempt_id)?,
                    fetch_sha256: hash(&b.fetch_transcript_sha256)?,
                    segment_count: segments(b.segment_count)?,
                    observed_ms: time(&b.observed_ms)?,
                })
            }
            "payload_profile_outcome03" => {
                let b: OutcomeBody = closed(raw)?;
                let evidence = match b.evidence.as_str() {
                    "sent_callback_ok" => 0,
                    "sent_callback_failed" => 1,
                    "delivery_callback_ok" => 2,
                    "delivery_timeout" => 3,
                    "crash_without_callback" => 4,
                    "callback_conflict" => 5,
                    _ => return Err("effect outcome evidence"),
                };
                let count = segments(b.segment_count)?;
                let index = if evidence <= 1 {
                    let index = b.segment_index.as_u64().ok_or("effect sent index")?;
                    if index >= u64::from(count) {
                        return Err("effect sent index");
                    }
                    Some(index as u8)
                } else {
                    if !b.segment_index.is_null() {
                        return Err("effect aggregate index");
                    }
                    None
                };
                Self::Outcome(Outcome03 {
                    connection_epoch: header(b.v, &b.r#type, b.connection_epoch, Kind03::Outcome)?,
                    event_id: id(&b.event_id)?,
                    message_id: id(&b.message_id)?,
                    attempt_id: id(&b.attempt_id)?,
                    submit_event_id: id(&b.submit_event_id)?,
                    submit_sha256: hash(&b.submit_command_sha256)?,
                    fetch_sha256: hash(&b.fetch_transcript_sha256)?,
                    submit_observed_ms: time(&b.submit_observed_ms)?,
                    segment_count: count,
                    evidence,
                    observed_ms: time(&b.observed_ms)?,
                    segment_index: index,
                })
            }
            "payload_profile_submit_status03_request" => {
                let b: SubmitStatusBody = closed(raw)?;
                Self::SubmitStatus(SubmitStatus03 {
                    connection_epoch: header(
                        b.v,
                        &b.r#type,
                        b.connection_epoch,
                        Kind03::SubmitStatus,
                    )?,
                    request_id: id(&b.request_id)?,
                    event_id: id(&b.event_id)?,
                    message_id: id(&b.message_id)?,
                    attempt_id: id(&b.attempt_id)?,
                    submit_sha256: hash(&b.submit_command_sha256)?,
                })
            }
            "payload_profile_no_submit_challenge03_request" => {
                let b: ChallengeBody = closed(raw)?;
                let from = match b.closed_from.as_str() {
                    "reserved" => 0,
                    "ack_authorized" => 1,
                    _ => return Err("effect closure phase"),
                };
                let previous = if b.previous_challenge_id.is_null() {
                    None
                } else {
                    Some(id(b
                        .previous_challenge_id
                        .as_str()
                        .ok_or("effect previous challenge")?)?)
                };
                Self::Challenge(Challenge03 {
                    connection_epoch: header(
                        b.v,
                        &b.r#type,
                        b.connection_epoch,
                        Kind03::Challenge,
                    )?,
                    proof_request_id: id(&b.proof_request_id)?,
                    closure_id: id(&b.closure_id)?,
                    event_id: id(&b.event_id)?,
                    message_id: id(&b.message_id)?,
                    attempt_id: id(&b.attempt_id)?,
                    submit_sha256: hash(&b.submit_command_sha256)?,
                    fetch_sha256: hash(&b.fetch_transcript_sha256)?,
                    segment_count: segments(b.segment_count)?,
                    submit_observed_ms: time(&b.submit_observed_ms)?,
                    closed_from: from,
                    closed_ms: time(&b.closed_ms)?,
                    record_sha256: hash(&b.closure_record_sha256)?,
                    previous_challenge_id: previous,
                })
            }
            "payload_profile_no_submit_proof03" => {
                let b: ProofBody = closed(raw)?;
                let epoch = header(b.v, &b.r#type, b.connection_epoch, Kind03::Proof)?;
                let request = id(&b.proof_request_id)?;
                let closure = id(&b.closure_id)?;
                let challenge = id(&b.challenge_id)?;
                let core = NoSubmitCore03::decode(&binary::<441>(&b.core)?)?;
                if core.identities()[5] != *closure.as_bytes()
                    || core.identities()[6] != *request.as_bytes()
                    || core.identities()[7] != *challenge.as_bytes()
                    || core.numbers()[2] != epoch as u64
                {
                    return Err("effect proof outer/core correlation");
                }
                Self::Proof(Proof03 {
                    connection_epoch: epoch,
                    proof_request_id: request,
                    closure_id: closure,
                    challenge_id: challenge,
                    core,
                    signature: binary::<64>(&b.signature)?,
                })
            }
            "payload_profile_no_submit_status03_request" => {
                let b: ProofStatusBody = closed(raw)?;
                Self::ProofStatus(ProofStatus03 {
                    connection_epoch: header(
                        b.v,
                        &b.r#type,
                        b.connection_epoch,
                        Kind03::ProofStatus,
                    )?,
                    request_id: id(&b.request_id)?,
                    proof_request_id: id(&b.proof_request_id)?,
                    closure_id: id(&b.closure_id)?,
                    message_id: id(&b.message_id)?,
                    attempt_id: id(&b.attempt_id)?,
                    submit_sha256: hash(&b.submit_command_sha256)?,
                    record_sha256: hash(&b.closure_record_sha256)?,
                })
            }
            _ => return Ok(None),
        }))
    }
    pub fn kind(&self) -> Kind03 {
        match self {
            Self::Submit(_) => Kind03::Submit,
            Self::Outcome(_) => Kind03::Outcome,
            Self::SubmitStatus(_) => Kind03::SubmitStatus,
            Self::Challenge(_) => Kind03::Challenge,
            Self::Proof(_) => Kind03::Proof,
            Self::ProofStatus(_) => Kind03::ProofStatus,
        }
    }
    pub fn connection_epoch(&self) -> i64 {
        match self {
            Self::Submit(v) => v.connection_epoch,
            Self::Outcome(v) => v.connection_epoch,
            Self::SubmitStatus(v) => v.connection_epoch,
            Self::Challenge(v) => v.connection_epoch,
            Self::Proof(v) => v.connection_epoch,
            Self::ProofStatus(v) => v.connection_epoch,
        }
    }
}

pub struct Submit03 {
    pub connection_epoch: i64,
    pub event_id: Uuid,
    pub message_id: Uuid,
    pub attempt_id: Uuid,
    pub fetch_sha256: [u8; 32],
    pub segment_count: u8,
    pub observed_ms: u64,
}
impl Submit03 {
    pub fn candidate_command(
        &self,
        account: Uuid,
        device: Uuid,
        original_session: &[u8; 32],
    ) -> Check<SubmitCommand03> {
        let mut bytes = Vec::with_capacity(153);
        for id in [
            account,
            device,
            self.event_id,
            self.message_id,
            self.attempt_id,
        ] {
            bytes.extend(id.as_bytes());
        }
        bytes.extend(self.fetch_sha256);
        bytes.extend(original_session);
        bytes.push(self.segment_count);
        bytes.extend(self.observed_ms.to_be_bytes());
        SubmitCommand03::decode(&bytes)
    }
}
pub struct SubmitStatus03 {
    pub connection_epoch: i64,
    pub request_id: Uuid,
    pub event_id: Uuid,
    pub message_id: Uuid,
    pub attempt_id: Uuid,
    pub submit_sha256: [u8; 32],
}
pub struct Outcome03 {
    pub connection_epoch: i64,
    pub event_id: Uuid,
    pub message_id: Uuid,
    pub attempt_id: Uuid,
    pub submit_event_id: Uuid,
    pub submit_sha256: [u8; 32],
    pub fetch_sha256: [u8; 32],
    pub submit_observed_ms: u64,
    pub segment_count: u8,
    pub evidence: u8,
    pub observed_ms: u64,
    pub segment_index: Option<u8>,
}
impl Outcome03 {
    pub fn candidate_command(
        &self,
        account: Uuid,
        device: Uuid,
        original_session: &[u8; 32],
    ) -> Check<OutcomeCommand03> {
        let submit = Submit03 {
            connection_epoch: self.connection_epoch,
            event_id: self.submit_event_id,
            message_id: self.message_id,
            attempt_id: self.attempt_id,
            fetch_sha256: self.fetch_sha256,
            segment_count: self.segment_count,
            observed_ms: self.submit_observed_ms,
        }
        .candidate_command(account, device, original_session)?;
        if submit.digest()? != self.submit_sha256 {
            return Err("effect original submit commitment");
        }
        let mut bytes = Vec::with_capacity(211);
        for id in [
            account,
            device,
            self.event_id,
            self.message_id,
            self.attempt_id,
            self.submit_event_id,
        ] {
            bytes.extend(id.as_bytes());
        }
        bytes.extend(self.submit_sha256);
        bytes.extend(self.fetch_sha256);
        bytes.extend(original_session);
        bytes.extend(self.submit_observed_ms.to_be_bytes());
        bytes.extend([self.segment_count, self.evidence]);
        bytes.extend(self.observed_ms.to_be_bytes());
        bytes.push(self.segment_index.unwrap_or(255));
        OutcomeCommand03::decode(&bytes)
    }
}
pub struct Challenge03 {
    pub connection_epoch: i64,
    pub proof_request_id: Uuid,
    pub closure_id: Uuid,
    pub event_id: Uuid,
    pub message_id: Uuid,
    pub attempt_id: Uuid,
    pub submit_sha256: [u8; 32],
    pub fetch_sha256: [u8; 32],
    pub segment_count: u8,
    pub submit_observed_ms: u64,
    pub closed_from: u8,
    pub closed_ms: u64,
    pub record_sha256: [u8; 32],
    pub previous_challenge_id: Option<Uuid>,
}
impl Challenge03 {
    pub fn candidate_record(
        &self,
        account: Uuid,
        device: Uuid,
        original_session: &[u8; 32],
    ) -> Check<NoSubmitRecord03> {
        let submit = Submit03 {
            connection_epoch: self.connection_epoch,
            event_id: self.event_id,
            message_id: self.message_id,
            attempt_id: self.attempt_id,
            fetch_sha256: self.fetch_sha256,
            segment_count: self.segment_count,
            observed_ms: self.submit_observed_ms,
        }
        .candidate_command(account, device, original_session)?;
        if submit.digest()? != self.submit_sha256 {
            return Err("effect closure submit commitment");
        }
        let mut bytes = Vec::with_capacity(210);
        for id in [
            account,
            device,
            self.event_id,
            self.message_id,
            self.attempt_id,
            self.closure_id,
        ] {
            bytes.extend(id.as_bytes());
        }
        bytes.extend(self.fetch_sha256);
        bytes.extend(self.submit_sha256);
        bytes.extend(original_session);
        bytes.push(self.segment_count);
        bytes.extend(self.submit_observed_ms.to_be_bytes());
        bytes.push(self.closed_from);
        bytes.extend(self.closed_ms.to_be_bytes());
        let value = NoSubmitRecord03::decode(&bytes)?;
        if value.digest()? != self.record_sha256 {
            return Err("effect closure record commitment");
        }
        Ok(value)
    }
}
pub struct Proof03 {
    pub connection_epoch: i64,
    pub proof_request_id: Uuid,
    pub closure_id: Uuid,
    pub challenge_id: Uuid,
    pub core: NoSubmitCore03,
    pub signature: [u8; 64],
}
pub struct ProofStatus03 {
    pub connection_epoch: i64,
    pub request_id: Uuid,
    pub proof_request_id: Uuid,
    pub closure_id: Uuid,
    pub message_id: Uuid,
    pub attempt_id: Uuid,
    pub submit_sha256: [u8; 32],
    pub record_sha256: [u8; 32],
}

#[cfg(test)]
mod tests;

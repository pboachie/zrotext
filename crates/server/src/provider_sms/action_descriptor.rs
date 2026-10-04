// SPDX-License-Identifier: AGPL-3.0-only
//! Inert proposed provider action descriptor conformance. No runtime consumer.
//! Parsing proves closed canonical metadata only; it grants no content or SEND authority.
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

const SAFE: i64 = 9_007_199_254_740_991;
const SECONDS: i64 = 9_007_199_254_740;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Descriptor {
    profile: String,
    action: Action,
    route: Route,
    reader: Reader,
    disclosure: Disclosure,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Action {
    account_id: String,
    action_id: String,
    revision: i64,
    line_id: String,
    recipient_id: String,
    purpose_id: String,
    content_ref: String,
    content_digest: String,
    content_version: i64,
    not_before: i64,
    expires_at: i64,
    timezone: String,
    window_id: String,
    routine_id: String,
    authority_generation: i64,
    commitment: String,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Route {
    kind: String,
    adapter: String,
    route_id: String,
    route_version: i64,
    organization_id: String,
    messaging_profile_id: String,
    sender_config_id: String,
    sender_config_version: i64,
    route_fingerprint: String,
    eligibility_policy_id: String,
    eligibility_policy_version: i64,
    eligibility_digest: String,
    exposure_route_policy_id: String,
    exposure_policy_version: i64,
}
#[derive(Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum Reader {
    OwnerLocal {
        role: i64,
        key_id: String,
        trust_generation: i64,
        manifest_version: i64,
        manifest_digest: String,
    },
    CustomerSelected {
        role: i64,
        key_id: String,
        trust_generation: i64,
        manifest_version: i64,
        manifest_digest: String,
        grant_id: String,
        grant_version: i64,
    },
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Disclosure {
    mode: String,
    recipient_commitment: String,
    request_digest: String,
}

fn uuid(v: &str) -> bool {
    v.len() == 36
        && v != "00000000-0000-0000-0000-000000000000"
        && v.bytes().enumerate().all(|(i, c)| {
            if [8, 13, 18, 23].contains(&i) {
                c == b'-'
            } else {
                c.is_ascii_digit() || (b'a'..=b'f').contains(&c)
            }
        })
}
fn digest(v: &str, nonzero: bool) -> bool {
    v.len() == 64
        && v.bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
        && (!nonzero || v.bytes().any(|c| c != b'0'))
}
fn positive(v: i64) -> bool {
    (1..=SAFE).contains(&v)
}
fn text(v: &str, max: usize) -> bool {
    !v.is_empty() && v.len() <= max && v.bytes().all(|c| (33..=126).contains(&c))
}
fn valid(d: &Descriptor) -> bool {
    let a = &d.action;
    let r = &d.route;
    let disc = &d.disclosure;
    d.profile == "workflow-action-02"
        && [
            &a.account_id,
            &a.action_id,
            &a.line_id,
            &a.recipient_id,
            &a.content_ref,
            &a.routine_id,
        ]
        .into_iter()
        .all(|v| uuid(v))
        && [
            "00000000-0000-0000-0000-000000000001",
            "00000000-0000-0000-0000-000000000002",
            "00000000-0000-0000-0000-000000000003",
        ]
        .contains(&a.purpose_id.as_str())
        && (1..=128).contains(&a.revision)
        && (1..=128).contains(&a.content_version)
        && positive(a.authority_generation)
        && digest(&a.content_digest, false)
        && (0..=SECONDS).contains(&a.not_before)
        && (1..=SECONDS).contains(&a.expires_at)
        && a.not_before < a.expires_at
        && text(&a.timezone, 64)
        && a.timezone != "unknown"
        && text(&a.window_id, 128)
        && ["informational", "sensitive"].contains(&a.commitment.as_str())
        && r.kind == "provider"
        && r.adapter == "telnyx-sms-v2"
        && [
            &r.route_id,
            &r.organization_id,
            &r.messaging_profile_id,
            &r.sender_config_id,
            &r.eligibility_policy_id,
            &r.exposure_route_policy_id,
        ]
        .into_iter()
        .all(|v| uuid(v))
        && [
            r.route_version,
            r.sender_config_version,
            r.eligibility_policy_version,
            r.exposure_policy_version,
        ]
        .into_iter()
        .all(positive)
        && digest(&r.route_fingerprint, false)
        && digest(&r.eligibility_digest, false)
        && match &d.reader {
            Reader::OwnerLocal {
                role,
                key_id,
                trust_generation,
                manifest_version,
                manifest_digest,
            } => {
                *role == 2
                    && digest(key_id, true)
                    && positive(*trust_generation)
                    && positive(*manifest_version)
                    && digest(manifest_digest, true)
            }
            Reader::CustomerSelected {
                role,
                key_id,
                trust_generation,
                manifest_version,
                manifest_digest,
                grant_id,
                grant_version,
            } => {
                *role == 3
                    && digest(key_id, true)
                    && positive(*trust_generation)
                    && positive(*manifest_version)
                    && digest(manifest_digest, true)
                    && uuid(grant_id)
                    && positive(*grant_version)
            }
        }
        && disc.mode == "provider_plaintext"
        && digest(&disc.recipient_commitment, true)
        && digest(&disc.request_digest, false)
}

fn canonical(v: &Value) -> Vec<u8> {
    match v {
        Value::Object(map) => {
            let sorted: BTreeMap<_, _> = map.iter().collect();
            let mut bytes = vec![b'{'];
            for (i, (key, value)) in sorted.into_iter().enumerate() {
                if i != 0 {
                    bytes.push(b',');
                }
                bytes.extend(serde_json::to_vec(key).expect("ASCII key"));
                bytes.push(b':');
                bytes.extend(canonical(value));
            }
            bytes.push(b'}');
            bytes
        }
        _ => serde_json::to_vec(v).expect("closed primitive"),
    }
}
fn parse(raw: &[u8]) -> Result<Descriptor, ()> {
    if raw.len() > 4096 {
        return Err(());
    }
    let descriptor: Descriptor = serde_json::from_slice(raw).map_err(|_| ())?;
    if !valid(&descriptor) {
        return Err(());
    }
    let value = serde_json::to_value(&descriptor).map_err(|_| ())?;
    if raw != canonical(&value) {
        return Err(());
    }
    Ok(descriptor)
}

// No raw_value feature is needed: retain the complete bounded original body,
// deserialize directly to closed types, and compare the entire canonical body.
// A generic RPC Value ingress cannot demonstrate original-body equality.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Proposal {
    request_id: String,
    descriptor: Descriptor,
}
fn parse_proposal(raw: &[u8]) -> Result<Descriptor, ()> {
    if raw.len() > 8192 {
        return Err(());
    }
    let proposal: Proposal = serde_json::from_slice(raw).map_err(|_| ())?;
    if !uuid(&proposal.request_id) {
        return Err(());
    }
    let descriptor = proposal.descriptor;
    if !valid(&descriptor) {
        return Err(());
    }
    let descriptor_value = serde_json::to_value(&descriptor).map_err(|_| ())?;
    if canonical(&descriptor_value).len() > 4096 {
        return Err(());
    }
    // Exact complete original-body equality rejects normalized duplicate keys,
    // escaped aliases, numeric spellings and separator padding.
    let envelope = serde_json::json!({
        "descriptor": descriptor_value,
        "request_id": proposal.request_id,
    });
    if raw != canonical(&envelope) {
        return Err(());
    }
    Ok(descriptor)
}

/// Closed failure without raw values or internal parser diagnostics.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConformanceError {
    InvalidWire,
}

/// Validated proposed metadata only. Existing action consumers do not accept it.
/// No configuration, consent, reader trust, approval or transport is established.
pub struct ProposedDescriptor(Descriptor);
impl ProposedDescriptor {
    pub fn parse_wire(raw: &[u8]) -> Result<Self, ConformanceError> {
        parse(raw)
            .map(Self)
            .map_err(|_| ConformanceError::InvalidWire)
    }
    /// Checks the entire original closed request, including its nested descriptor.
    /// This helper is not mounted in HTTP and never records a proposal.
    pub fn parse_owner_proposal_wire(raw: &[u8]) -> Result<Self, ConformanceError> {
        parse_proposal(raw)
            .map(Self)
            .map_err(|_| ConformanceError::InvalidWire)
    }
    pub fn canonical_wire(&self) -> Vec<u8> {
        canonical(&serde_json::to_value(&self.0).expect("validated closed metadata"))
    }
    pub fn binding_digest(&self) -> [u8; 32] {
        Sha256::digest(self.canonical_wire()).into()
    }
}

#[cfg(test)]
mod tests;

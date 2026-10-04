// SPDX-License-Identifier: AGPL-3.0-only
//! Explicit owner-configured routines. Values describe requests, never authority.
use crate::encrypted_schedule::policy::WindowPolicy;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Kind {
    Faq,
    Intake,
    Note,
    Reminder,
    OwnerReply,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Executor {
    DeterministicLocal,
    LocalProcess,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Period {
    UtcDay,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OriginalInput {
    /// Exact independently owner-issued original-reader credential grant.
    pub grant_id: Uuid,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Policy {
    pub request_id: Uuid,
    pub policy_id: Uuid,
    pub context_id: Uuid,
    pub routine_id: Uuid,
    pub generation: i64,
    pub kind: Kind,
    pub executor: Executor,
    /// Absent preserves owner-declared input; original messages require explicit
    /// owner approval and independent current original-reader authentication.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub original_input: Option<OriginalInput>,
    /// Explicit owner-approved local installation identity; never a model path.
    #[serde(default)]
    pub adapter_id: Option<String>,
    /// Domain-separated digest of the exact trusted executable installation.
    #[serde(default)]
    pub artifact_digest: Option<String>,
    pub period: Period,
    pub expires_ms: i64,
    pub call_limit: u16,
    pub unit_limit: u32,
    pub units_per_call: u32,
    pub turn_limit: u16,
    pub timeout_ms: u32,
    pub window: WindowPolicy,
}
impl Policy {
    pub fn valid_executor(&self) -> bool {
        match self.executor {
            Executor::DeterministicLocal => {
                self.adapter_id.is_none() && self.artifact_digest.is_none()
            }
            Executor::LocalProcess => {
                self.adapter_id.as_ref().is_some_and(|id| {
                    id.as_bytes().first().is_some_and(u8::is_ascii_lowercase)
                        && id.len() <= 64
                        && id.bytes().all(|b| {
                            b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'_'
                        })
                }) && self.artifact_digest.as_ref().is_some_and(|digest| {
                    digest.len() == 64
                        && digest
                            .bytes()
                            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
                })
            }
        }
    }
    pub fn validate(&self) -> bool {
        ![self.request_id,self.policy_id,self.context_id,self.routine_id].iter().any(Uuid::is_nil)
            && self.generation > 0 && self.expires_ms > 0 && self.valid_executor()
            && self.original_input.as_ref().is_none_or(|original|
                !original.grant_id.is_nil() && self.executor == Executor::LocalProcess)
            && (1..=100).contains(&self.call_limit)
            && (1..=1_000_000).contains(&self.unit_limit)
            && (1..=self.unit_limit).contains(&self.units_per_call)
            && (1..=3).contains(&self.turn_limit) && (10..=30_000).contains(&self.timeout_ms) && self.window.valid_shape()
            // One exact declared window, not permission to mint future turns.
            && self.window.max_occurrences == 1 && self.window.repeat_every_days.is_none()
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Invocation {
    pub request_id: Uuid,
    pub policy_id: Uuid,
    pub context_id: Uuid,
    pub input_revision: i64,
    pub input_source_digest: String,
    pub direction: Direction,
}
/// Distinct original-event admission. Event digest/version are equality
/// assertions, never substitutes for retained verified provenance or authority.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OriginalAdmit {
    pub request_id: Uuid,
    pub policy_id: Uuid,
    pub context_id: Uuid,
    pub input_revision: i64,
    pub input_source_digest: String,
    pub event_id: Uuid,
    pub accepted_manifest_version: i64,
    pub event_envelope_digest: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Direction {
    OwnerDeclared,
    Inbound,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Phase {
    Unknown,
    Produced,
    Published,
    Proposed,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Call {
    pub call_id: Uuid,
    /// Assigned by the authenticated call admission, never by model output.
    pub assigned_output_context_id: Uuid,
    /// True only on the response to the transaction that first debited this call.
    /// A lost response/replay is conservatively non-executable.
    pub execute_once: bool,
    pub policy_id: Uuid,
    pub phase: Phase,
    pub output_context_id: Option<Uuid>,
    pub output_revision: Option<i64>,
    pub action_id: Option<Uuid>,
    pub binding_digest: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OutputBinding {
    pub request_id: Uuid,
    pub call_id: Uuid,
    pub output_context_id: Uuid,
    pub output_revision: i64,
    pub output_source_digest: String,
    /// SHA-256 of the exact already encrypted archive artifact, never plaintext.
    /// Owner publication uses these same opaque bytes; the separately encrypted
    /// role-3 projection remains an explicit independent owner declaration.
    pub produced_digest: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    fn policy() -> Policy {
        serde_json::from_value(serde_json::json!({
            "request_id":Uuid::new_v4(),"policy_id":Uuid::new_v4(),
            "context_id":Uuid::new_v4(),"routine_id":Uuid::new_v4(),
            "generation":1,"kind":"faq","executor":"deterministic_local",
            "period":"utc_day","expires_ms":1,"call_limit":1,"unit_limit":1,
            "units_per_call":1,"turn_limit":1,"timeout_ms":1000,
            "window":{"timezone":"UTC","first_local_date":"2030-01-01",
                "opens_minute":0,"closes_minute":60,"repeat_every_days":null,
                "max_occurrences":1,"pacing_seconds":60}
        }))
        .unwrap()
    }
    #[test]
    fn local_process_requires_the_exact_owner_declared_installation_pair() {
        let mut p = policy();
        assert!(p.validate()); // Existing deterministic policies omit the pair.
        p.executor = Executor::LocalProcess;
        assert!(!p.validate());
        p.adapter_id = Some("customer_faq".into());
        assert!(!p.validate());
        p.artifact_digest = Some("ab".repeat(32));
        assert!(p.validate());
        p.artifact_digest = Some("AB".repeat(32));
        assert!(!p.validate());
        p.artifact_digest = Some("ab".repeat(32));
        p.adapter_id = Some("../model-selected".into());
        assert!(!p.validate());
        p.adapter_id = Some("customer_faq".into());
        p.executor = Executor::DeterministicLocal;
        assert!(!p.validate());
    }
    #[test]
    fn original_input_requires_explicit_local_executor_and_exact_grant() {
        let mut p = policy();
        assert!(p.original_input.is_none());
        assert!(
            serde_json::to_value(&p)
                .unwrap()
                .get("original_input")
                .is_none()
        );
        p.original_input = Some(OriginalInput {
            grant_id: Uuid::new_v4(),
        });
        assert!(!p.validate());
        p.executor = Executor::LocalProcess;
        p.adapter_id = Some("customer_faq".into());
        p.artifact_digest = Some("ab".repeat(32));
        assert!(p.validate());
        p.original_input.as_mut().unwrap().grant_id = Uuid::nil();
        assert!(!p.validate());
    }

    #[test]
    fn inbound_is_distinct_and_model_cannot_supply_owner_authority() {
        let id = Uuid::new_v4();
        let value = serde_json::json!({"request_id":id,"policy_id":id,"context_id":id,
            "input_revision":1,"input_source_digest":"ab".repeat(32),"direction":"inbound"});
        let request: Invocation = serde_json::from_value(value.clone()).unwrap();
        assert_eq!(request.direction, Direction::Inbound);
        let mut edited = value;
        edited["approved"] = serde_json::json!(true);
        assert!(serde_json::from_value::<Invocation>(edited).is_err());
    }
}

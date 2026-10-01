// SPDX-License-Identifier: AGPL-3.0-only
//! Dormant, transport-neutral request shapes. Parsing and hints are not authority.
use super::Operation;
use crate::{
    encrypted_schedule::policy::WindowPolicy,
    http_owner_conversations::context::decisions::{ActionKey, ActionState, Descriptor},
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Method {
    #[serde(rename = "workflow.contact.read")]
    ContactRead,
    #[serde(rename = "workflow.context.metadata")]
    ContextMetadata,
    #[serde(rename = "workflow.context.content")]
    ContextContent,
    #[serde(rename = "workflow.action.propose")]
    Propose,
    #[serde(rename = "workflow.action.status")]
    Status,
    #[serde(rename = "workflow.action.schedule")]
    Schedule,
    #[serde(rename = "workflow.action.send")]
    Send,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Implementation {
    LibraryCandidate,
}
#[derive(Clone, Copy, Debug, Serialize)]
pub struct MethodInfo {
    pub method: Method,
    pub operation: Operation,
    /// Domain reads still create bounded access/audit records.
    pub read_only_hint: bool,
    pub destructive_hint: bool,
    /// Exact semantic request replay only; never a permission to resend.
    pub idempotent_hint: bool,
    pub implementation: Implementation,
    pub transport_mounted: bool,
}
impl Method {
    pub const ALL: [Self; 7] = [
        Self::ContactRead,
        Self::ContextMetadata,
        Self::ContextContent,
        Self::Propose,
        Self::Status,
        Self::Schedule,
        Self::Send,
    ];
    pub fn operation(self) -> Operation {
        match self {
            Self::ContactRead => Operation::ContactRead,
            Self::ContextMetadata => Operation::ContextMetadata,
            Self::ContextContent => Operation::ContextContent,
            Self::Propose => Operation::Propose,
            Self::Status => Operation::Status,
            Self::Schedule => Operation::Schedule,
            Self::Send => Operation::Send,
        }
    }
    pub fn info(self) -> MethodInfo {
        MethodInfo {
            method: self,
            operation: self.operation(),
            read_only_hint: matches!(
                self,
                Self::ContactRead | Self::ContextMetadata | Self::ContextContent | Self::Status
            ),
            destructive_hint: self == Self::Send,
            idempotent_hint: true,
            implementation: Implementation::LibraryCandidate,
            transport_mounted: false,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContextRequest {
    pub request_id: Uuid,
    pub context_id: Uuid,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProposalRequest {
    pub request_id: Uuid,
    pub descriptor: Descriptor,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StatusRequest {
    pub request_id: Uuid,
    pub context_id: Uuid,
    /// Read the current durable head, including its exact revision/digest.
    pub action_id: Uuid,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScheduleRequest {
    pub request_id: Uuid,
    pub key: ActionKey,
    pub policy: WindowPolicy,
    pub series_id: Uuid,
    pub ordinal: u16,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SendRequest {
    pub request_id: Uuid,
    pub key: ActionKey,
    pub occurrence_id: Option<Uuid>,
}
/// Clients cannot select an actor, substitute permission bits, approve a draft,
/// or supply a queue/message/dispatch marker through this closed vocabulary.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "method", content = "params", deny_unknown_fields)]
pub enum Request {
    #[serde(rename = "workflow.contact.read")]
    ContactRead(ContextRequest),
    #[serde(rename = "workflow.context.metadata")]
    ContextMetadata(ContextRequest),
    #[serde(rename = "workflow.context.content")]
    ContextContent(ContextRequest),
    #[serde(rename = "workflow.action.propose")]
    Propose(ProposalRequest),
    #[serde(rename = "workflow.action.status")]
    Status(StatusRequest),
    #[serde(rename = "workflow.action.schedule")]
    Schedule(ScheduleRequest),
    #[serde(rename = "workflow.action.send")]
    Send(SendRequest),
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[error("invalid workflow request")]
pub struct InvalidRequest;
impl Request {
    pub fn method(&self) -> Method {
        match self {
            Self::ContactRead(_) => Method::ContactRead,
            Self::ContextMetadata(_) => Method::ContextMetadata,
            Self::ContextContent(_) => Method::ContextContent,
            Self::Propose(_) => Method::Propose,
            Self::Status(_) => Method::Status,
            Self::Schedule(_) => Method::Schedule,
            Self::Send(_) => Method::Send,
        }
    }
    /// Pure shape validation only. Every operation still authenticates and
    /// checks its current transaction-bound service proof through commit.
    pub fn validate(&self) -> Result<(), InvalidRequest> {
        let valid = match self {
            Self::ContactRead(v) | Self::ContextMetadata(v) | Self::ContextContent(v) => {
                !v.request_id.is_nil() && !v.context_id.is_nil()
            }
            Self::Propose(v) => {
                !v.request_id.is_nil()
                    && v.descriptor.key().is_ok()
                    && v.descriptor.identities().is_ok()
            }
            Self::Status(v) => {
                !v.request_id.is_nil() && !v.context_id.is_nil() && !v.action_id.is_nil()
            }
            Self::Schedule(v) => {
                !v.request_id.is_nil()
                    && !v.series_id.is_nil()
                    && v.key.validate().is_ok()
                    && v.policy.valid_shape()
                    && v.ordinal < v.policy.max_occurrences
            }
            Self::Send(v) => {
                !v.request_id.is_nil()
                    && !v.occurrence_id.is_some_and(|id| id.is_nil())
                    && v.key.validate().is_ok()
            }
        };
        if valid { Ok(()) } else { Err(InvalidRequest) }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContactResponse {
    pub contact_id: Uuid,
    pub purpose: String,
    pub peer_digest: String,
}
/// Public context metadata, not the source reader header or a content proof.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContextMetadataResponse {
    pub context_id: Uuid,
    /// SHA-256 of exact archive-source bytes for Descriptor.content_digest.
    /// It proves neither plaintext meaning nor role-3 ciphertext equivalence.
    pub source_content_digest: String,
    pub revision: i64,
    pub kind: u8,
    pub expires_at_ms: i64,
    pub binding_generation: i64,
    pub trust_generation: i64,
    pub manifest_version: i64,
}
/// Only the successful checked role-3 content operation may supply these bytes.
/// DTO construction itself proves neither authority nor encryption validity.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContextContentResponse {
    pub context_id: Uuid,
    pub revision: i64,
    pub envelope_base64url: String,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OccurrenceResponse {
    pub occurrence_id: Uuid,
    pub series_id: Uuid,
    pub ordinal: u16,
    pub phase: String,
    pub opens_at_ms: Option<i64>,
    pub closes_at_ms: Option<i64>,
    pub expires_at_ms: i64,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UnavailableReason {
    TransportNotMounted,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "kind", content = "result", deny_unknown_fields)]
pub enum Response {
    #[serde(rename = "contact")]
    Contact(ContactResponse),
    #[serde(rename = "context_metadata")]
    ContextMetadata(ContextMetadataResponse),
    #[serde(rename = "context_content")]
    ContextContent(ContextContentResponse),
    #[serde(rename = "action")]
    Action(ActionState),
    #[serde(rename = "occurrence")]
    Occurrence(OccurrenceResponse),
    #[serde(rename = "send")]
    Send(super::SendOutcome),
    #[serde(rename = "unavailable")]
    Unavailable(UnavailableReason),
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{Value, json};

    fn scope() -> Value {
        json!({"request_id":"aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa","context_id":"bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"})
    }
    #[test]
    fn seven_methods_map_independent_operations_and_exclude_owner_decisions() {
        let expected = [
            Operation::ContactRead,
            Operation::ContextMetadata,
            Operation::ContextContent,
            Operation::Propose,
            Operation::Status,
            Operation::Schedule,
            Operation::Send,
        ];
        for (method, operation) in Method::ALL.into_iter().zip(expected) {
            assert_eq!(method.operation(), operation);
            assert!(!method.info().transport_mounted);
            if matches!(method, Method::Schedule | Method::Send) {
                assert_eq!(
                    method.info().implementation,
                    Implementation::LibraryCandidate
                );
            }
        }
        for method in [
            "workflow.action.approve",
            "workflow.takeover",
            "send",
            "workflow.action.cancel",
        ] {
            assert!(
                serde_json::from_value::<Request>(json!({"method":method,"params":scope()}))
                    .is_err()
            );
        }
    }
    #[test]
    fn reads_parse_without_accepting_caller_authority_or_extra_outer_fields() {
        for method in [
            "workflow.contact.read",
            "workflow.context.metadata",
            "workflow.context.content",
        ] {
            let request: Request =
                serde_json::from_value(json!({"method":method,"params":scope()})).unwrap();
            request.validate().unwrap();
            assert!(request.method().info().read_only_hint);
            for field in [
                "actor",
                "permissions",
                "owner",
                "approved",
                "credential",
                "message_id",
                "dispatch_id",
            ] {
                let mut params = scope();
                params[field] = true.into();
                assert!(
                    serde_json::from_value::<Request>(json!({"method":method,"params":params}))
                        .is_err()
                );
            }
            assert!(
                serde_json::from_value::<Request>(
                    json!({"method":method,"params":scope(),"approved":true})
                )
                .is_err()
            );
        }
        let mut nil = scope();
        nil["context_id"] = Uuid::nil().to_string().into();
        assert!(
            serde_json::from_value::<Request>(
                json!({"method":"workflow.contact.read","params":nil})
            )
            .unwrap()
            .validate()
            .is_err()
        );
    }
    #[test]
    fn effect_shapes_reuse_exact_keys_and_refuse_arbitrary_queue_markers() {
        let key = json!({"account_id":"aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa","action_id":"bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb","revision":1,"binding_digest":"ab".repeat(32)});
        let params = json!({"request_id":"cccccccc-cccc-4ccc-8ccc-cccccccccccc","key":key,"occurrence_id":"dddddddd-dddd-4ddd-8ddd-dddddddddddd"});
        let request: Request =
            serde_json::from_value(json!({"method":"workflow.action.send","params":params}))
                .unwrap();
        request.validate().unwrap();
        for occurrence in [None, Some(serde_json::Value::Null)] {
            let mut immediate = params.clone();
            if let Some(value) = occurrence {
                immediate["occurrence_id"] = value;
            } else {
                immediate.as_object_mut().unwrap().remove("occurrence_id");
            }
            let parsed: Request =
                serde_json::from_value(json!({"method":"workflow.action.send","params":immediate}))
                    .unwrap();
            parsed.validate().unwrap();
            assert!(matches!(
                parsed,
                Request::Send(SendRequest {
                    occurrence_id: None,
                    ..
                })
            ));
        }
        let mut nil = params.clone();
        nil["occurrence_id"] = Uuid::nil().to_string().into();
        assert!(
            serde_json::from_value::<Request>(
                json!({"method":"workflow.action.send","params":nil})
            )
            .unwrap()
            .validate()
            .is_err()
        );
        for field in [
            "actor",
            "permissions",
            "owner",
            "message_id",
            "dispatch_id",
            "plaintext",
            "approved",
        ] {
            let mut bad = params.clone();
            bad[field] = true.into();
            assert!(
                serde_json::from_value::<Request>(
                    json!({"method":"workflow.action.send","params":bad})
                )
                .is_err()
            );
        }
        let mut bad = params.clone();
        bad["key"]["binding_digest"] = "AB".repeat(32).into();
        assert!(
            serde_json::from_value::<Request>(
                json!({"method":"workflow.action.send","params":bad})
            )
            .is_err()
        );
        let mut bad = params;
        bad["key"]["revision"] = 0.into();
        assert!(
            serde_json::from_value::<Request>(
                json!({"method":"workflow.action.send","params":bad})
            )
            .unwrap()
            .validate()
            .is_err()
        );
    }
    #[test]
    fn schedule_bounds_and_unknown_timezone_never_imply_execution_readiness() {
        let params = json!({"request_id":"aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa","series_id":"bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb","ordinal":0,"key":{"account_id":"aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa","action_id":"bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb","revision":1,"binding_digest":"ab".repeat(32)},"policy":{"timezone":null,"first_local_date":"2030-01-01","opens_minute":540,"closes_minute":600,"repeat_every_days":null,"max_occurrences":1,"pacing_seconds":60}});
        let request: Request =
            serde_json::from_value(json!({"method":"workflow.action.schedule","params":params}))
                .unwrap();
        request.validate().unwrap();
        assert_eq!(
            request.method().info().implementation,
            Implementation::LibraryCandidate
        );
        let mut bad = params.clone();
        bad["ordinal"] = 1.into();
        assert!(
            serde_json::from_value::<Request>(
                json!({"method":"workflow.action.schedule","params":bad})
            )
            .unwrap()
            .validate()
            .is_err()
        );
        let mut bad = params;
        bad["policy"]["approved"] = true.into();
        assert!(
            serde_json::from_value::<Request>(
                json!({"method":"workflow.action.schedule","params":bad})
            )
            .is_err()
        );
    }
    #[test]
    fn status_reads_current_head_and_proposals_reuse_canonical_descriptors() {
        let status = json!({"request_id":"aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa","context_id":"bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb","action_id":"cccccccc-cccc-4ccc-8ccc-cccccccccccc"});
        let request: Request =
            serde_json::from_value(json!({"method":"workflow.action.status","params":status}))
                .unwrap();
        request.validate().unwrap();
        assert_eq!(request.method().operation(), Operation::Status);
        let descriptor = json!({"account_id":"aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa","action_id":"bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb","revision":1,"line_id":"cccccccc-cccc-4ccc-8ccc-cccccccccccc","recipient_id":"dddddddd-dddd-4ddd-8ddd-dddddddddddd","purpose_id":"00000000-0000-0000-0000-000000000001","content_ref":"eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee","content_digest":"ab".repeat(32),"content_version":1,"not_before":1,"expires_at":2,"timezone":"UTC","window_id":format!("window-v1-{}", "ab".repeat(32)),"routine_id":"ffffffff-ffff-4fff-8fff-ffffffffffff","authority_generation":1,"commitment":"informational"});
        let params =
            json!({"request_id":"aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa","descriptor":descriptor});
        let request: Request =
            serde_json::from_value(json!({"method":"workflow.action.propose","params":params}))
                .unwrap();
        request.validate().unwrap();
        assert_eq!(request.method().operation(), Operation::Propose);
        let mut bad = params.clone();
        bad["descriptor"]["approved"] = true.into();
        assert!(
            serde_json::from_value::<Request>(
                json!({"method":"workflow.action.propose","params":bad})
            )
            .is_err()
        );
        let mut bad = params;
        bad["descriptor"]["revision"] = 0.into();
        assert!(
            serde_json::from_value::<Request>(
                json!({"method":"workflow.action.propose","params":bad})
            )
            .unwrap()
            .validate()
            .is_err()
        );
    }
    #[test]
    fn metadata_never_serializes_source_reader_or_content_proof_claims() {
        let value = serde_json::to_value(ContextMetadataResponse {
            context_id: Uuid::new_v4(),
            source_content_digest: "ab".repeat(32),
            revision: 1,
            kind: 1,
            expires_at_ms: 1,
            binding_generation: 1,
            trust_generation: 1,
            manifest_version: 1,
        })
        .unwrap();
        assert_eq!(value["source_content_digest"], "ab".repeat(32));
        for field in [
            "reader",
            "reader_key_id",
            "envelope",
            "envelope_digest",
            "content_digest",
            "plaintext",
        ] {
            assert!(value.get(field).is_none());
        }
    }
}

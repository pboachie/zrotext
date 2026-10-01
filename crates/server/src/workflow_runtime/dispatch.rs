// SPDX-License-Identifier: AGPL-3.0-only
//! Dormant client-neutral dispatch into the existing checked service functions.
use super::{
    IntegrationPrincipal,
    contracts::{
        ContactResponse, ContextContentResponse, ContextMetadataResponse, OccurrenceResponse,
        Request, Response,
    },
};
use crate::{
    auth::AuthError, encrypted_schedule::store::ScheduleRequest,
    http_owner_conversations::context::wire,
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use tokio_postgres::Client;

/// The caller supplies an actually authenticated service principal, not DTO
/// authority. This is not an HTTP mount or a background execution worker.
pub async fn call(
    client: &mut Client,
    principal: &IntegrationPrincipal,
    request: Request,
) -> Result<Response, AuthError> {
    request.validate().map_err(|_| AuthError::InvalidInput)?;
    match request {
        Request::ContactRead(v) => {
            let result = super::read_contact(client, principal, v.request_id, v.context_id).await?;
            Ok(Response::Contact(ContactResponse {
                contact_id: result.contact_id,
                purpose: result.purpose,
                peer_digest: digest_hex(&result.peer_digest),
            }))
        }
        Request::ContextMetadata(v) => {
            let (header, source_digest) = super::reads::read_context_metadata_binding(
                client,
                principal,
                v.request_id,
                v.context_id,
            )
            .await?;
            Ok(Response::ContextMetadata(metadata(&header, &source_digest)))
        }
        Request::ContextContent(v) => {
            let bytes =
                super::read_context_content(client, principal, v.request_id, v.context_id).await?;
            Ok(Response::ContextContent(content(&bytes)?))
        }
        Request::Propose(v) => Ok(Response::Action(
            super::propose_action(client, principal, v.request_id, v.descriptor).await?,
        )),
        Request::Status(v) => Ok(Response::Action(
            super::read_action_status(client, principal, v.request_id, v.context_id, v.action_id)
                .await?,
        )),
        Request::Schedule(v) => {
            let result = super::schedule_action(
                client,
                principal,
                v.key,
                ScheduleRequest {
                    request_id: v.request_id,
                    series_id: v.series_id,
                    ordinal: v.ordinal,
                },
                &v.policy,
            )
            .await?;
            Ok(Response::Occurrence(OccurrenceResponse {
                occurrence_id: result.id,
                series_id: result.series_id,
                ordinal: result.ordinal,
                phase: result.phase,
                opens_at_ms: result.opens_at_ms,
                closes_at_ms: result.closes_at_ms,
                expires_at_ms: result.expires_at_ms,
            }))
        }
        Request::Send(v) => Ok(Response::Send(
            super::send_action(client, principal, v.request_id, v.key, v.occurrence_id).await?,
        )),
    }
}
fn digest_hex(bytes: &[u8; 32]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    bytes
        .iter()
        .flat_map(|b| {
            [
                DIGITS[usize::from(b >> 4)] as char,
                DIGITS[usize::from(b & 15)] as char,
            ]
        })
        .collect()
}
fn metadata(header: &wire::Header, source_digest: &[u8; 32]) -> ContextMetadataResponse {
    ContextMetadataResponse {
        context_id: header.context,
        source_content_digest: digest_hex(source_digest),
        revision: header.revision,
        kind: header.kind,
        expires_at_ms: header.expires_ms,
        binding_generation: header.binding_generation,
        trust_generation: header.trust_generation,
        manifest_version: header.manifest_version,
    }
}
fn content(bytes: &[u8]) -> Result<ContextContentResponse, AuthError> {
    // Parse the actual returned role-3 projection; never reconstruct one from
    // archive metadata. Parsing is not a claim about plaintext authenticity.
    let header = wire::parse(bytes).map_err(|_| AuthError::Forbidden)?;
    Ok(ContextContentResponse {
        context_id: header.context,
        revision: header.revision,
        envelope_base64url: URL_SAFE_NO_PAD.encode(bytes),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn peer_digest_is_exact_lowercase_hex() {
        let mut bytes = [0xab; 32];
        bytes[0] = 0;
        bytes[31] = 255;
        assert_eq!(digest_hex(&bytes), format!("00{}ff", "ab".repeat(30)));
    }
    #[test]
    fn malformed_content_is_refused_instead_of_relabelled_as_a_projection() {
        assert!(matches!(
            content(b"not an envelope"),
            Err(AuthError::Forbidden)
        ));
    }
    #[test]
    fn content_identity_and_bytes_come_from_the_actual_projection() {
        use p256::elliptic_curve::sec1::ToSec1Point;
        let header = wire::Header {
            kind: 1,
            account: uuid::Uuid::from_u128(1),
            device: uuid::Uuid::from_u128(2),
            line: uuid::Uuid::from_u128(3),
            interval: uuid::Uuid::from_u128(4),
            context: uuid::Uuid::from_u128(5),
            binding_generation: 1,
            revision: 3,
            expires_ms: 1_893_500_000_000,
            trust_generation: 2,
            manifest_version: 4,
            peer_digest: [1; 32],
            reader: [2; 32],
            manifest_digest: [3; 32],
        };
        let mut bytes = header.aad().unwrap();
        let ephemeral = p256::SecretKey::from_slice(&[1; 32]).unwrap();
        bytes.extend(ephemeral.public_key().to_sec1_point(false).as_bytes());
        bytes.extend(17u32.to_be_bytes());
        bytes.extend([0; 17]);
        let result = content(&bytes).unwrap();
        assert_eq!(result.context_id, header.context);
        assert_eq!(result.revision, 3);
        assert_eq!(
            URL_SAFE_NO_PAD.decode(&result.envelope_base64url).unwrap(),
            bytes
        );
        assert!(!result.envelope_base64url.contains('='));
        let public = serde_json::to_value(metadata(&header, &[0xab; 32])).unwrap();
        assert_eq!(public["source_content_digest"], "ab".repeat(32));
        assert!(public.get("reader").is_none());
        assert!(public.get("envelope_base64url").is_none());
        // This synthetic shape test proves serialization, not authenticated decryption.
    }
}

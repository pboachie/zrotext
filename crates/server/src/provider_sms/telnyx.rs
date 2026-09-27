// SPDX-License-Identifier: AGPL-3.0-only
//! Outbound Telnyx SMS-v2 receipts only. Contract reference:
//! https://developers.telnyx.com/docs/messaging/messages/receiving-webhooks
//! Ignore unknown fields, but reject duplicate known fields and non-single SMS recipients.

use super::{ReceiptFact, Rejection, Request, VerifiedReceipt, e164};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use ring::signature::{ED25519, UnparsedPublicKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

const MAX_BODY: usize = 32 * 1024;
const REPLAY_WINDOW_SECONDS: u64 = 300;

#[derive(Deserialize)]
struct Envelope {
    data: Event,
}
#[derive(Deserialize, Serialize)]
struct Event {
    id: Uuid,
    event_type: String,
    record_type: String,
    payload: Payload,
}
#[derive(Deserialize, Serialize)]
struct Payload {
    id: Uuid,
    organization_id: Uuid,
    messaging_profile_id: Uuid,
    direction: String,
    #[serde(rename = "type")]
    kind: String,
    from: Sender,
    to: [Recipient; 1],
}
#[derive(Deserialize, Serialize)]
struct Sender {
    phone_number: String,
}
#[derive(Deserialize, Serialize)]
struct Recipient {
    phone_number: String,
    status: String,
}

/// The key and request must come from independently trusted route configuration.
/// The supplied current clock must be trustworthy. Verify original body bytes,
/// never parsed/re-serialized JSON. Key rotation policy belongs to the caller.
/// A valid signature is evidence, not a dispatch grant or a replay tombstone.
pub fn verify_receipt(
    request: &Request,
    public_key: &[u8; 32],
    timestamp: &str,
    signature: &str,
    body: &[u8],
    now_seconds: u64,
) -> Result<VerifiedReceipt, Rejection> {
    if body.is_empty() || body.len() > MAX_BODY || signature.len() != 88 {
        return Err(Rejection::InvalidCallback);
    }
    if timestamp.is_empty()
        || timestamp.len() > 19
        || timestamp.starts_with('0')
        || !timestamp.bytes().all(|b| b.is_ascii_digit())
    {
        return Err(Rejection::InvalidTimestamp);
    }
    let signed_seconds = timestamp
        .parse::<u64>()
        .map_err(|_| Rejection::InvalidTimestamp)?;
    if now_seconds > i64::MAX as u64
        || signed_seconds > i64::MAX as u64
        || signed_seconds.abs_diff(now_seconds) > REPLAY_WINDOW_SECONDS
    {
        return Err(Rejection::InvalidTimestamp);
    }
    let mut decoded = [0u8; 66];
    let len = STANDARD
        .decode_slice(signature, &mut decoded)
        .map_err(|_| Rejection::InvalidSignature)?;
    if len != 64 {
        return Err(Rejection::InvalidSignature);
    }
    let mut transcript = Vec::with_capacity(MAX_BODY + 20);
    transcript.extend_from_slice(timestamp.as_bytes());
    transcript.push(b'|');
    transcript.extend_from_slice(body);
    UnparsedPublicKey::new(&ED25519, public_key)
        .verify(&transcript, &decoded[..len])
        .map_err(|_| Rejection::InvalidSignature)?;
    let event = serde_json::from_slice::<Envelope>(body)
        .map_err(|_| Rejection::InvalidCallback)?
        .data;
    let payload = &event.payload;
    if event.id.is_nil()
        || payload.id.is_nil()
        || event.record_type != "event"
        || payload.direction != "outbound"
        || payload.kind != "SMS"
        || !e164(&payload.from.phone_number)
        || !e164(&payload.to[0].phone_number)
        || payload.to[0].status.len() > 64
    {
        return Err(Rejection::InvalidCallback);
    }
    let recipient: [u8; 32] = Sha256::digest(payload.to[0].phone_number.as_bytes()).into();
    if payload.organization_id != request.route.organization
        || payload.messaging_profile_id != request.route.profile
        || payload.from.phone_number != request.route.sender
        || recipient != request.recipient
    {
        return Err(Rejection::RouteMismatch);
    }
    let fact = match (event.event_type.as_str(), payload.to[0].status.as_str()) {
        ("message.sent", "sent") => ReceiptFact::CarrierSubmitted,
        ("message.finalized", "delivered") => ReceiptFact::Delivered,
        ("message.finalized", "delivery_unconfirmed") => ReceiptFact::DeliveryUnconfirmed,
        ("message.finalized", "sending_failed") => ReceiptFact::SendingFailed,
        ("message.finalized", "delivery_failed") => ReceiptFact::DeliveryFailed,
        ("message.finalized", _) => ReceiptFact::Unrecognized,
        _ => return Err(Rejection::InvalidCallback),
    };
    // Identity covers the validated semantic fields, excluding transport retry
    // metadata. Distinct status events for a message retain distinct event IDs.
    let identity =
        Sha256::digest(serde_json::to_vec(&event).map_err(|_| Rejection::InvalidCallback)?).into();
    Ok(VerifiedReceipt {
        event_id: event.id,
        message_id: payload.id,
        request: request.clone(),
        fact,
        identity,
    })
}

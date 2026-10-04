// SPDX-License-Identifier: AGPL-3.0-only
//! Synthetic fixtures only; this entire module is absent from non-test builds.
use crate::provider_sms::{Content, Request, Route, VerifiedReceipt, verify_receipt};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use ring::{
    rand::SystemRandom,
    signature::{Ed25519KeyPair, KeyPair},
};
use serde_json::Value;
use std::sync::OnceLock;
use tokio_postgres::Client;
use uuid::Uuid;

pub(crate) const PROPOSAL: &str =
    include_str!("../../../../../protocol/v1/provider-receipt-storage-proposal.sql");
pub(crate) const SITE: &str = "provider-receipt-test";
fn vector() -> Value {
    serde_json::from_str(include_str!("../telnyx-vector.json")).unwrap()
}
fn body() -> Value {
    serde_json::from_str(vector()["body"].as_str().unwrap()).unwrap()
}

pub(crate) fn request(account: Uuid) -> Request {
    let b = body();
    let payload = &b["data"]["payload"];
    Request::new(
        Route::telnyx(
            account,
            Uuid::from_u128(2),
            Uuid::from_u128(3),
            payload["from"]["phone_number"].as_str().unwrap(),
            1,
        )
        .unwrap(),
        payload["to"][0]["phone_number"].as_str().unwrap(),
        Content::ProviderPlaintext("synthetic fixture"),
    )
    .unwrap()
}

pub(crate) fn receipt(request: &Request, event: Uuid, status: &str) -> VerifiedReceipt {
    receipt_for_message(request, event, status, Uuid::from_u128(4))
}
pub(crate) fn receipt_for_message(
    request: &Request,
    event: Uuid,
    status: &str,
    message: Uuid,
) -> VerifiedReceipt {
    static KEY: OnceLock<Ed25519KeyPair> = OnceLock::new();
    let key = KEY.get_or_init(|| {
        let p = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).unwrap();
        Ed25519KeyPair::from_pkcs8(p.as_ref()).unwrap()
    });
    let mut b = body();
    b["data"]["id"] = serde_json::json!(event);
    b["data"]["payload"]["id"] = serde_json::json!(message);
    b["data"]["event_type"] = serde_json::json!(if status == "sent" {
        "message.sent"
    } else {
        "message.finalized"
    });
    b["data"]["payload"]["to"][0]["status"] = serde_json::json!(status);
    let bytes = serde_json::to_vec(&b).unwrap();
    let mut signed = b"1000|".to_vec();
    signed.extend_from_slice(&bytes);
    verify_receipt(
        request,
        key.public_key().as_ref().try_into().unwrap(),
        "1000",
        &STANDARD.encode(key.sign(&signed).as_ref()),
        &bytes,
        1000,
    )
    .unwrap()
}

/// Represents the future trusted committed-intent correlation, never an API.
pub(crate) async fn seed(client: &Client, account: Uuid, attempt: Uuid) {
    seed_for_message(client, account, attempt, Uuid::from_u128(4)).await;
}

pub(crate) async fn seed_for_message(client: &Client, account: Uuid, attempt: Uuid, message: Uuid) {
    let request = request(account);
    client
        .execute(
            "INSERT INTO sites(site_id) VALUES($1) ON CONFLICT DO NOTHING",
            &[&SITE],
        )
        .await
        .unwrap();
    client.execute("INSERT INTO provider_receipt_attempts(account_id,attempt_id,provider,route_fingerprint, \
        request_digest,provider_message_id,state,delivery_failed,accepted_at,updated_at,created_epoch) \
        VALUES($1,$2,'telnyx_sms_v2',$3,$4,$5,'submitting',false,clock_timestamp(),clock_timestamp(),1)",
        &[&account,&attempt,&super::route_fingerprint(&request).as_slice(),&request.digest().as_slice(),
        &message]).await.unwrap();
}

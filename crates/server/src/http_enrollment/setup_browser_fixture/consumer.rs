// SPDX-License-Identifier: AGPL-3.0-only
//! Autonomous HTTP/proof/recovery regression, not browser/Android acceptance.
use super::*;
use enrollment::binding::{BindingChallenge, challenge_bytes};
use p256::elliptic_curve::Generate;
use p256::{
    ecdsa::{Signature, SigningKey, signature::Signer},
    pkcs8::EncodePublicKey,
};
use reqwest::{Client, Method, RequestBuilder};
use serde_json::Value;
use sha2::{Digest, Sha256};

struct Http {
    client: Client,
    base: String,
    cookie: String,
    csrf: String,
    control: String,
}

impl Http {
    fn request(&self, method: Method, path: &str) -> RequestBuilder {
        self.client.request(method, format!("{}{path}", self.base))
    }
    fn owner(&self, method: Method, path: &str) -> RequestBuilder {
        self.request(method, path)
            .header("cookie", &self.cookie)
            .header("origin", ORIGIN)
            .header("x-zrotext-csrf", &self.csrf)
    }
    async fn control(&self, operation: &str) -> Value {
        value(
            self.request(Method::POST, "/__fixture/pairing-setup")
                .header("x-zrotext-fixture-token", &self.control),
            Some(json!({"version":1,"operation":operation})),
            200,
        )
        .await
    }
    async fn binding(
        &self,
        path: &str,
        account: Uuid,
        key: &SigningKey,
        fingerprint: [u8; 32],
        status: u16,
    ) -> Value {
        let text: String = fingerprint.iter().map(|b| format!("{b:02X}")).collect();
        let c = value(
            self.request(Method::POST, &format!("{path}/binding/challenge")),
            Some(json!({"key_fingerprint":text})),
            200,
        )
        .await;
        let challenge = BindingChallenge {
            account_id: account,
            pairing_id: path.rsplit('/').next().unwrap().parse().unwrap(),
            challenge_id: c["challenge_id"].as_str().unwrap().parse().unwrap(),
            nonce: decode_nonce(c["challenge_nonce"].as_str().unwrap()).unwrap(),
            fingerprint,
        };
        let signature: Signature = key.sign(&challenge_bytes(&challenge));
        value(
            self.request(Method::POST, &format!("{path}/binding")),
            Some(json!({
                "account_id":account,"challenge_id":challenge.challenge_id,
                "challenge_nonce":c["challenge_nonce"],
                "signature_der":URL_SAFE_NO_PAD.encode(signature.to_der().as_bytes())
            })),
            status,
        )
        .await
    }
}

async fn value(request: RequestBuilder, body: Option<Value>, status: u16) -> Value {
    let request = match body {
        Some(value) => request
            .header("content-type", "application/json")
            .body(value.to_string()),
        None => request,
    };
    let mut response = request
        .send()
        .await
        .expect("loopback fixture HTTP response");
    assert_eq!(
        response.status().as_u16(),
        status,
        "unexpected fixture HTTP status"
    );
    let mut bytes = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .expect("bounded fixture response body")
    {
        assert!(
            bytes.len() + chunk.len() <= 65536,
            "fixture response too large"
        );
        bytes.extend_from_slice(&chunk);
    }
    if bytes.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(&bytes).expect("fixture response JSON")
    }
}

pub(super) async fn run(port: u16, account: Uuid, session: String, csrf: String, control: String) {
    let http = Http {
        client: Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(std::time::Duration::from_secs(5))
            .timeout(std::time::Duration::from_secs(10))
            .build()
            .unwrap(),
        base: format!("http://127.0.0.1:{port}"),
        cookie: format!("__Host-zrotext_session={session}; __Host-zrotext_csrf={csrf}"),
        csrf,
        control,
    };
    let baseline = http.control("snapshot").await;
    assert_eq!(baseline["devices"], 0);
    assert_eq!(baseline["active_keys"], 0);
    assert_eq!(baseline["approved_pairings"], 0);
    let session = value(http.owner(Method::GET, "/v1/auth/session"), None, 200).await;
    assert_eq!(session["account_id"], account.to_string());
    assert_eq!(session["role"], "owner");
    // A cookie-only owner mutation must not create a pairing.
    value(
        http.request(Method::POST, "/v1/enrollment/pairings")
            .header("cookie", &http.cookie)
            .header("origin", ORIGIN),
        Some(json!({"display_name":"Synthetic phone"})),
        403,
    )
    .await;
    let empty = value(http.owner(Method::GET, "/v1/account/setup"), None, 200).await;
    assert!(empty["pairings"].as_array().unwrap().is_empty());
    let ticket = value(
        http.owner(Method::POST, "/v1/enrollment/pairings"),
        Some(json!({"display_name":"Synthetic phone"})),
        201,
    )
    .await;
    let pairing: Uuid = ticket["pairing_id"].as_str().unwrap().parse().unwrap();
    let path = format!("/v1/enrollment/pairings/{pairing}");
    let key = SigningKey::generate_from_rng(&mut rand::rng());
    let fingerprint: [u8; 32] =
        Sha256::digest(key.verifying_key().to_sec1_point(false).as_bytes()).into();
    let fingerprint_text: String = fingerprint.iter().map(|b| format!("{b:02X}")).collect();
    let spki = key.verifying_key().to_public_key_der().unwrap();
    let claim = value(
        http.request(Method::POST, &format!("{path}/claim")),
        Some(json!({
            "token":ticket["token"],"public_key_spki":URL_SAFE_NO_PAD.encode(spki.as_bytes())
        })),
        200,
    )
    .await;
    assert_eq!(claim["account_id"], account.to_string());
    assert_eq!(claim["pairing_id"], pairing.to_string());
    assert_eq!(claim["key_fingerprint"], fingerprint_text);
    let nonce = decode_nonce(claim["challenge_nonce"].as_str().unwrap()).unwrap();
    let bytes = enrollment::enrollment_challenge_bytes(account, pairing, &fingerprint, &nonce);
    let wrong_key = SigningKey::generate_from_rng(&mut rand::rng());
    // Wrong-key binding proof leaves the unproved candidate unapproved.
    let rejected = http
        .binding(&path, account, &wrong_key, fingerprint, 404)
        .await;
    assert!(rejected.is_null());
    assert_eq!(http.control("snapshot").await, baseline);
    let signature: Signature = key.sign(&bytes);
    let proved = value(
        http.request(Method::POST, &format!("{path}/prove")),
        Some(json!({
            "challenge_nonce":claim["challenge_nonce"],
            "signature_der":URL_SAFE_NO_PAD.encode(signature.to_der().as_bytes())
        })),
        200,
    )
    .await;
    assert_eq!(proved["proof_verified"], true);
    let owner = value(http.owner(Method::GET, &path), None, 200).await;
    assert_eq!(owner["comparison_code"], claim["comparison_code"]);
    assert_eq!(owner["key_fingerprint"], claim["key_fingerprint"]);
    assert_eq!(owner["proof_verified"], true);
    assert!(owner["approved_device_id"].is_null());
    let pending = http.binding(&path, account, &key, fingerprint, 200).await;
    assert_eq!(pending["status"], "pending");
    assert_eq!(pending["comparison_code"], claim["comparison_code"]);
    // Discard the approval response: recovery must discover authoritative state.
    drop(
        value(
            http.owner(Method::POST, &format!("{path}/approve")),
            Some(json!({
                "comparison_code":claim["comparison_code"],"key_fingerprint":fingerprint_text
            })),
            201,
        )
        .await,
    );
    let recovered = http.binding(&path, account, &key, fingerprint, 200).await;
    assert_eq!(recovered["status"], "approved");
    assert_eq!(recovered["key_fingerprint"], fingerprint_text);
    let device: Uuid = recovered["device_id"].as_str().unwrap().parse().unwrap();
    let repeated = http.binding(&path, account, &key, fingerprint, 200).await;
    assert_eq!(repeated["device_id"], device.to_string());
    let setup = value(http.owner(Method::GET, "/v1/account/setup"), None, 200).await;
    assert_eq!(setup["account_id"], account.to_string());
    let pairings = setup["pairings"].as_array().unwrap();
    assert_eq!(pairings.len(), 1);
    assert_eq!(pairings[0]["pairing_id"], pairing.to_string());
    assert_eq!(pairings[0]["approved_device_id"], device.to_string());
    assert_eq!(pairings[0]["status"], "approved");
    let devices = setup["devices"].as_array().unwrap();
    assert_eq!(devices.len(), 1);
    assert_eq!(devices[0]["device_id"], device.to_string());
    assert_eq!(devices[0]["key_fingerprint"], fingerprint_text);
    let approved = http.control("snapshot").await;
    assert_eq!(approved["devices"], 1);
    assert_eq!(approved["active_keys"], 1);
    assert_eq!(approved["approved_pairings"], 1);
    value(
        http.owner(Method::DELETE, &format!("/v1/enrollment/devices/{device}")),
        None,
        204,
    )
    .await;
    value(
        http.request(Method::POST, &format!("{path}/binding/challenge")),
        Some(json!({"key_fingerprint":fingerprint_text})),
        404,
    )
    .await;
    let final_state = http.control("snapshot").await;
    assert_eq!(final_state["devices"], 1);
    assert_eq!(final_state["active_keys"], 0);
    assert_eq!(final_state["approved_pairings"], 1);
    http.control("finish").await;
}

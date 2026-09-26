// SPDX-License-Identifier: AGPL-3.0-only
pub mod alpha_policy;
pub mod auth;
pub mod billing;
pub mod device_socket;
pub mod enrollment;
pub mod http_auth;
pub mod http_enrollment;
pub mod http_messages;
pub mod http_owner_messages;
pub mod http_owner_review;
pub mod http_webhooks;
pub mod inbound;
pub mod ingress;
pub mod owner_ui;
pub mod retention;
pub mod runtime_db;
pub mod sealed_inbound;
pub mod webhook_egress;
pub mod webhook_worker;

#[cfg(test)]
pub(crate) mod test_keys {
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
    use sha2::{Digest, Sha256};
    use std::sync::OnceLock;

    // A random master makes labeled fixture secrets stable within one test
    // process without embedding reusable authentication or vault keys in
    // source.
    fn master() -> [u8; 32] {
        static MASTER: OnceLock<[u8; 32]> = OnceLock::new();
        *MASTER.get_or_init(rand::random::<[u8; 32]>)
    }

    pub(crate) fn key(label: u8) -> Vec<u8> {
        let mut input = master();
        input[0] ^= label;
        Sha256::digest(input).to_vec()
    }

    // Fixture passwords ride the same random master, satisfy the 12..=1024
    // byte register/login policy, and labels keep accounts on distinct
    // credentials.
    pub(crate) fn password(label: u8) -> String {
        let mut input = master();
        input[1] ^= label;
        format!("fixture-{}", URL_SAFE_NO_PAD.encode(Sha256::digest(input)))
    }
}

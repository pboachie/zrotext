// SPDX-License-Identifier: AGPL-3.0-only
pub mod agent_authority;
pub mod alpha_policy;
pub mod api_json;
pub mod auth;
pub mod billing;
pub mod device_socket;
pub mod enrollment;
pub mod failover_adapters;
pub mod failover_executor;
pub mod http_auth;
pub mod http_enrollment;
pub mod http_message_summary;
pub mod http_messages;
pub mod http_observer;
pub mod http_owner_contacts;
pub mod http_owner_conversations;
pub mod http_owner_erasure;
pub mod http_owner_events;
pub mod http_owner_export;
pub mod http_owner_messages;
pub mod http_owner_review;
pub mod http_sealed;
pub mod http_webhooks;
pub mod inbound;
pub mod ingress;
pub mod maintenance;
pub mod owner_ui;
pub mod provider_sms;
pub mod readiness;
pub mod retention;
pub use zrotext_root_material::root_backup;
pub mod runtime_db;
pub mod sealed_body;
pub mod sealed_connector_registry;
pub mod sealed_dispatch;
pub mod sealed_envelope;
pub mod sealed_inbound;
pub mod sealed_manifest;
pub mod sealed_manifest_store;
pub mod sealed_outbound;
pub mod sealed_root_ceremony;
pub mod sealed_root_custody;
pub use zrotext_root_material::sealed_root_enrollment;
pub mod wakeups;
pub mod webhook_egress;
pub mod webhook_worker;

#[cfg(test)]
/// Synthetic recognizable plaintext markers for the sealed downgrade and
/// leakage acceptance harness (issue #632). A marker is planted in fixture
/// message content on the client side; every server-side surface the harness
/// can observe — database values, digests, HTTP responses — must never
/// contain it. The scan helper has its own positive controls so an all-clear
/// result can never pass vacuously.
pub(crate) mod sealed_marker {
    /// One per-run marker text, unique across tests and runs.
    pub(crate) struct Marker {
        text: String,
    }
    impl Marker {
        /// `ZTCANARY-<label>-<random hex>`: a synthetic string that cannot
        /// collide with protocol bytes, identifiers or error codes.
        pub(crate) fn generate(label: &str) -> Self {
            let entropy = rand::random::<[u8; 8]>();
            let suffix: String = entropy.iter().map(|b| format!("{b:02x}")).collect();
            Self {
                text: format!("ZTCANARY-{label}-{suffix}"),
            }
        }
        pub(crate) fn as_str(&self) -> &str {
            &self.text
        }
        pub(crate) fn as_bytes(&self) -> &[u8] {
            self.text.as_bytes()
        }
    }
    /// Byte-wise subslice scan over any observable surface. An empty needle
    /// detects nothing; a needle longer than the haystack detects nothing.
    pub(crate) fn present(haystack: &[u8], needle: &[u8]) -> bool {
        !needle.is_empty()
            && haystack
                .windows(needle.len())
                .any(|window| window == needle)
    }
    #[cfg(test)]
    mod tests {
        use super::*;
        #[test]
        fn scan_finds_a_planted_marker() {
            let marker = Marker::generate("self");
            let mut surface = vec![0u8; 64];
            let width = marker.as_bytes().len();
            surface[17..17 + width].copy_from_slice(marker.as_bytes());
            assert!(present(&surface, marker.as_bytes()));
            assert!(marker.as_str().starts_with("ZTCANARY-self-"));
        }
        #[test]
        fn scan_ignores_empty_needles_and_near_misses() {
            let marker = Marker::generate("self");
            let mut near_miss = marker.as_bytes().to_vec();
            let last = near_miss.len() - 1;
            near_miss[last] ^= 1;
            assert!(!present(&near_miss, marker.as_bytes()));
            assert!(!present(b"anything", b""));
            assert!(!present(b"short", marker.as_bytes()));
        }
    }
}

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

/// Outbox claims pick rows with `next_attempt_at <= now()`, and the runtime
/// queue paths insert that column with its `now()` default. PostgreSQL reads
/// `now()` from the host wall clock, which container and CI hosts step
/// backwards periodically, so a row queued in one transaction can be
/// not-yet-due for a claim a few statements later. Tests that queue mail
/// through the runtime paths and then immediately claim it backdate the
/// queued rows first, the same state a retry that is already due produces.
/// The claim still has to find, lock and lease the row, so the delivery
/// contract stays fully exercised and no assertion is weakened. Each test
/// schema runs only the migrations it needs, so callers backdate exactly the
/// outbox tables their schema contains.
#[cfg(test)]
pub(crate) mod outbox_test_support {
    pub(crate) async fn backdate_queued_reset_mail(client: &tokio_postgres::Client) {
        client
            .execute(
                "UPDATE password_reset_mail_outbox SET next_attempt_at=now()-interval '1 minute' WHERE delivered_at IS NULL AND canceled_at IS NULL AND dead_at IS NULL",
                &[],
            )
            .await
            .unwrap();
    }

    pub(crate) async fn backdate_queued_reset_notice(client: &tokio_postgres::Client) {
        client
            .execute(
                "UPDATE password_reset_notice_outbox SET next_attempt_at=now()-interval '1 minute' WHERE delivered_at IS NULL AND dead_at IS NULL",
                &[],
            )
            .await
            .unwrap();
    }

    pub(crate) async fn backdate_queued_verification_mail(client: &tokio_postgres::Client) {
        client
            .execute(
                "UPDATE verification_mail_outbox SET next_attempt_at=now()-interval '1 minute' WHERE delivered_at IS NULL AND canceled_at IS NULL AND dead_at IS NULL",
                &[],
            )
            .await
            .unwrap();
    }
}

#[cfg(test)]
mod sealed_root_roles_tests;

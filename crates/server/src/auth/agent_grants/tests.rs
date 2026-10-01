// SPDX-License-Identifier: AGPL-3.0-only
use super::*;

fn request() -> GrantRequest {
    GrantRequest {
        connector_id: Uuid::from_u128(1),
        connector_key_id: [1; 32],
        signer_key_id: [2; 32],
        device_id: Uuid::from_u128(2),
        line_id: Uuid::from_u128(3),
        binding_generation: 1,
        recipient: "+1".to_owned() + "00",
        metadata_allowed: true,
        content_allowed: false,
        draft_allowed: false,
        send_allowed: false,
        reader_identity: None,
        model_provider_identity: None,
        model_reads_content: false,
        owner_self_notification: true,
        expires_ms: 10_000,
        message_limit: 1,
        turn_limit: 1,
    }
}

#[test]
fn recipient_identity_is_account_peer_and_domain_bound() {
    let hasher = TokenHasher::new(crate::test_keys::key(77)).unwrap();
    let account = Uuid::from_u128(1);
    let peer = "+1".to_owned() + "00";
    let digest = hasher.agent_recipient_digest(account, &peer);
    assert_eq!(digest, hasher.agent_recipient_digest(account, &peer));
    assert_ne!(
        digest,
        hasher.agent_recipient_digest(Uuid::from_u128(2), &peer)
    );
    assert_ne!(
        digest,
        hasher.agent_recipient_digest(account, &(peer.clone() + "1"))
    );
    assert_ne!(digest, hasher.digest(b"api-key-v1", &peer));
}

#[test]
fn owner_attestation_model_and_reader_scope_cannot_be_inferred() {
    let mut r = request();
    assert!(r.validate(1_000).is_ok());
    r.owner_self_notification = false;
    assert!(r.validate(1_000).is_err());
    r.owner_self_notification = true;
    r.model_reads_content = true;
    assert!(r.validate(1_000).is_err());
    r.model_reads_content = false;
    r.model_provider_identity = Some(Uuid::from_u128(4));
    assert!(r.validate(1_000).is_err());
    r.model_provider_identity = None;
    r.content_allowed = true;
    assert!(r.validate(1_000).is_err());
    r.reader_identity = Some(Uuid::from_u128(5));
    assert!(r.validate(1_000).is_ok());
}

#[test]
fn grant_expiry_budgets_and_routing_are_bounded() {
    for invalid in [0, 101] {
        let mut r = request();
        r.message_limit = invalid;
        assert!(r.validate(1_000).is_err());
    }
    for invalid in [0, 4] {
        let mut r = request();
        r.turn_limit = invalid;
        assert!(r.validate(1_000).is_err());
    }
    for invalid in [1_000, 86_401_001, i64::MAX] {
        let mut r = request();
        r.expires_ms = invalid;
        assert!(r.validate(1_000).is_err());
    }
    for invalid in ["", "xx", "+0x", "+1x", "+100 "] {
        let mut r = request();
        r.recipient = invalid.to_owned();
        assert!(r.validate(1_000).is_err());
    }
    let mut r = request();
    r.metadata_allowed = false;
    assert!(r.validate(1_000).is_err());
}

#[test]
fn authenticated_permissions_are_independent_and_conversion_stays_scoped() {
    for selected in 0..4 {
        let p = AgentPrincipal {
            account: Uuid::from_u128(1),
            grant_id: Uuid::from_u128(2),
            key_id: Uuid::from_u128(3),
            device_id: Uuid::from_u128(4),
            permissions: Permissions {
                metadata: selected == 0,
                read_content: selected == 1,
                draft: selected == 2,
                send: selected == 3,
            },
            scopes: vec![Scope::MessagesSend],
        };
        for (index, op) in [
            Operation::Metadata,
            Operation::ReadContent,
            Operation::Draft,
            Operation::Send,
        ]
        .into_iter()
        .enumerate()
        {
            assert_eq!(p.require(op).is_ok(), selected == index);
        }
        let api = p.sealed_principal();
        assert!(api.require(Scope::MessagesSend, Some(p.device_id)).is_ok());
        assert!(
            api.require(Scope::MessagesSend, Some(Uuid::from_u128(5)))
                .is_err()
        );
        assert!(api.require(Scope::BillingRead, Some(p.device_id)).is_err());
    }
}

#[path = "db_tests.rs"]
mod db_tests;

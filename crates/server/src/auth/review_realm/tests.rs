// SPDX-License-Identifier: AGPL-3.0-only
use super::*;

fn deployment(seed: u8, label: &str) -> DeploymentIdentity {
    DeploymentIdentity {
        realm_id: Uuid::from_u128(u128::from(seed)),
        database_id: Uuid::from_u128(u128::from(seed) + 1),
        canonical_origin: format!("https://{label}.example.test"),
        deployment_fingerprint: [seed + 10; 32],
        key_fingerprints: std::array::from_fn(|i| [seed + i as u8; 32]),
    }
}

fn realm() -> UnactivatedReviewRealm {
    let identity = deployment(20, "review");
    UnactivatedReviewRealm::compare_supplied_observations(
        identity.clone(),
        identity,
        &[deployment(60, "ordinary")],
        1_000,
    )
    .unwrap()
}

fn request(realm: &UnactivatedReviewRealm) -> ReauthenticationRequest {
    ReauthenticationRequest {
        scope: WorkspaceScope {
            realm_id: realm.identity.realm_id,
            database_id: realm.identity.database_id,
            account_id: Uuid::from_u128(100),
            owner_user_id: Uuid::from_u128(101),
            owner_session_id: Uuid::from_u128(102),
            broker_authentication_event: Uuid::from_u128(103),
            broker_credential_id: Uuid::from_u128(104),
            credential_revision: 1,
        },
        operation: ReviewOperation::RootCustodyEnrollment,
        challenge_id: Uuid::from_u128(105),
        statement_digest: [7; 32],
        issued_at_ms: 1_000,
        expires_at_ms: 2_000,
    }
}

fn policy(request: &ReauthenticationRequest) -> IdentityPolicy {
    IdentityPolicy::ReviewWorkspace(request.scope.clone())
}

fn credential(
    realm: &UnactivatedReviewRealm,
    request: &ReauthenticationRequest,
    verifier: String,
) -> CredentialSnapshot {
    CredentialSnapshot::capture_supplied_verifier(
        realm,
        request.scope.broker_credential_id,
        request.scope.credential_revision,
        verifier,
    )
    .unwrap()
}

#[test]
fn supplied_containment_requires_exact_complete_canonical_observations() {
    let expected = deployment(20, "review");
    let production = [deployment(60, "ordinary")];
    for origin in [
        "http://review.example.test",
        "https://review.example.test/",
        "https://REVIEW.example.test",
        "https://review.example.test:443",
        "https://review.example.test/path",
        "https://user@review.example.test",
    ] {
        let mut bad = expected.clone();
        bad.canonical_origin = origin.to_owned();
        assert!(
            UnactivatedReviewRealm::compare_supplied_observations(
                bad.clone(),
                bad,
                &production,
                1_000
            )
            .is_err()
        );
    }
    for field in 0..9 {
        let mut bad = expected.clone();
        match field {
            0 => bad.realm_id = Uuid::nil(),
            1 => bad.database_id = Uuid::nil(),
            2 => bad.deployment_fingerprint.fill(0),
            3..=7 => bad.key_fingerprints[field - 3].fill(0),
            _ => bad.key_fingerprints[1] = bad.key_fingerprints[0],
        }
        assert!(
            UnactivatedReviewRealm::compare_supplied_observations(
                bad.clone(),
                bad,
                &production,
                1_000
            )
            .is_err()
        );
    }
    for field in 0..9 {
        let mut changed = expected.clone();
        match field {
            0 => changed.realm_id = Uuid::new_v4(),
            1 => changed.database_id = Uuid::new_v4(),
            2 => changed.canonical_origin = "https://other.example.test".to_owned(),
            3 => changed.deployment_fingerprint = [90; 32],
            _ => changed.key_fingerprints[field - 4] = [90; 32],
        }
        assert!(matches!(
            UnactivatedReviewRealm::compare_supplied_observations(
                expected.clone(),
                changed,
                &production,
                1_000
            ),
            Err(ComponentError::IsolationMismatch)
        ));
    }
    assert!(
        UnactivatedReviewRealm::compare_supplied_observations(
            expected.clone(),
            expected.clone(),
            &[],
            1_000
        )
        .is_err()
    );
    let mut missing_production_identity = production[0].clone();
    missing_production_identity.database_id = Uuid::nil();
    assert!(
        UnactivatedReviewRealm::compare_supplied_observations(
            expected.clone(),
            expected,
            &[missing_production_identity],
            1_000
        )
        .is_err()
    );
}

#[test]
fn every_production_identity_and_cross_slot_key_overlap_refuses() {
    let expected = deployment(20, "review");
    for field in 0..9 {
        let mut other = deployment(60, "ordinary");
        match field {
            0 => other.realm_id = expected.realm_id,
            1 => other.database_id = expected.database_id,
            2 => other.canonical_origin = expected.canonical_origin.clone(),
            3 => other.deployment_fingerprint = expected.deployment_fingerprint,
            _ => other.key_fingerprints[4] = expected.key_fingerprints[field - 4],
        }
        assert!(matches!(
            UnactivatedReviewRealm::compare_supplied_observations(
                expected.clone(),
                expected.clone(),
                &[deployment(80, "another"), other],
                1_000
            ),
            Err(ComponentError::ProductionOverlap)
        ));
    }
}

#[test]
fn null_workspace_fields_and_invalid_times_refuse_before_password_work() {
    let realm = realm();
    let original = request(&realm);
    for field in 0..10 {
        let mut bad = original.clone();
        match field {
            0 => bad.scope.realm_id = Uuid::nil(),
            1 => bad.scope.database_id = Uuid::nil(),
            2 => bad.scope.account_id = Uuid::nil(),
            3 => bad.scope.owner_user_id = Uuid::nil(),
            4 => bad.scope.owner_session_id = Uuid::nil(),
            5 => bad.scope.broker_authentication_event = Uuid::nil(),
            6 => bad.scope.broker_credential_id = Uuid::nil(),
            7 => bad.scope.credential_revision = 0,
            8 => bad.challenge_id = Uuid::nil(),
            _ => bad.statement_digest.fill(0),
        }
        assert!(realm.bind(&policy(&bad), &bad, 1_000).is_err());
    }
    for (issued, expiry, now) in [
        (0, 2_000, 1_000),
        (1_001, 2_000, 1_000),
        (1_000, 1_000, 1_000),
        (1_000, 999, 1_000),
        (999, 2_000, 999),
        (1_000, 2_000, 2_000),
        (1_000, u64::MAX, 1_000),
        (1_000, 2_000, u64::MAX),
    ] {
        let mut bad = original.clone();
        bad.issued_at_ms = issued;
        bad.expires_at_ms = expiry;
        assert!(realm.bind(&policy(&bad), &bad, now).is_err());
    }
    assert!(
        realm
            .bind(&IdentityPolicy::Ordinary, &original, 1_000)
            .is_err()
    );
    assert!(realm.bind(&policy(&original), &original, 1_000).is_ok());
    assert!(realm.bind(&policy(&original), &original, 1_999).is_ok());
}

#[tokio::test]
async fn real_password_work_is_required_and_never_manufactures_mfa() {
    let realm = realm();
    let request = request(&realm);
    let password = Uuid::new_v4().to_string();
    let verifier = password_work::hash(&password).await.unwrap();
    let proof = realm
        .check_password(
            policy(&request),
            request.clone(),
            credential(&realm, &request, verifier.clone()),
            &password,
            1_100,
        )
        .await
        .ok()
        .unwrap();
    // Component inspection is repeatable; there is deliberately no in-memory
    // consumed bit pretending to be durable one-use action acceptance.
    for _ in 0..2 {
        assert!(
            proof
                .check_exact_binding(&realm, &policy(&request), &request, 1_100)
                .is_ok()
        );
    }
    for (candidate, stored) in [
        (Uuid::new_v4().to_string(), verifier),
        (password.clone(), "invalid verifier".to_owned()),
        ("x".repeat(1025), "invalid verifier".to_owned()),
    ] {
        assert!(matches!(
            realm
                .check_password(
                    policy(&request),
                    request.clone(),
                    credential(&realm, &request, stored),
                    &candidate,
                    1_100
                )
                .await,
            Err(ComponentError::PasswordRejected)
        ));
    }
    assert!(matches!(
        realm
            .check_password(
                IdentityPolicy::Ordinary,
                request.clone(),
                credential(&realm, &request, "invalid verifier".to_owned()),
                &password,
                1_100
            )
            .await,
        Err(ComponentError::InvalidBinding)
    ));
}

#[tokio::test]
async fn proof_owns_exact_scope_challenge_operation_and_nonregressing_time() {
    let realm = realm();
    let request = request(&realm);
    let password = Uuid::new_v4().to_string();
    let verifier = password_work::hash(&password).await.unwrap();
    let proof = realm
        .check_password(
            policy(&request),
            request.clone(),
            credential(&realm, &request, verifier.clone()),
            &password,
            1_100,
        )
        .await
        .ok()
        .unwrap();
    for field in 0..14 {
        let mut changed = request.clone();
        match field {
            0 => changed.scope.realm_id = Uuid::new_v4(),
            1 => changed.scope.database_id = Uuid::new_v4(),
            2 => changed.scope.account_id = Uuid::new_v4(),
            3 => changed.scope.owner_user_id = Uuid::new_v4(),
            4 => changed.scope.owner_session_id = Uuid::new_v4(),
            5 => changed.scope.broker_authentication_event = Uuid::new_v4(),
            6 => changed.scope.broker_credential_id = Uuid::new_v4(),
            7 => changed.scope.credential_revision += 1,
            8 => changed.operation = ReviewOperation::LineOwnerKeyRegistration,
            9 => changed.challenge_id = Uuid::new_v4(),
            10 => changed.statement_digest[0] ^= 1,
            11 => changed.issued_at_ms -= 1,
            12 => changed.expires_at_ms += 1,
            _ => changed.scope.credential_revision = u64::MAX,
        }
        assert!(
            proof
                .check_exact_binding(&realm, &policy(&changed), &changed, 1_100)
                .is_err()
        );
    }
    assert!(
        proof
            .check_exact_binding(&realm, &IdentityPolicy::Ordinary, &request, 1_100)
            .is_err()
    );
    assert!(
        proof
            .check_exact_binding(&realm, &policy(&request), &request, 1_099)
            .is_err()
    );
    assert!(
        proof
            .check_exact_binding(&realm, &policy(&request), &request, 1_999)
            .is_ok()
    );
    assert!(
        proof
            .check_exact_binding(&realm, &policy(&request), &request, 2_000)
            .is_err()
    );
    let mut changed_deployment = realm.identity.clone();
    changed_deployment.key_fingerprints[0] = [99; 32];
    let changed_realm = UnactivatedReviewRealm::compare_supplied_observations(
        changed_deployment.clone(),
        changed_deployment,
        &[deployment(60, "ordinary")],
        1_000,
    )
    .unwrap();
    assert!(
        proof
            .check_exact_binding(&changed_realm, &policy(&request), &request, 1_100)
            .is_err()
    );
    let mut later_realm = realm.identity.clone();
    let old = later_realm.clone();
    let later = UnactivatedReviewRealm::compare_supplied_observations(
        later_realm.clone(),
        old,
        &[deployment(60, "ordinary")],
        1_101,
    )
    .unwrap();
    later_realm.canonical_origin.clear();
    assert!(
        proof
            .check_exact_binding(&later, &policy(&request), &request, 1_100)
            .is_err()
    );
    assert!(
        proof
            .check_exact_binding(&realm, &policy(&request), &request, 1_100)
            .is_ok()
    );
    let mut different_revision = credential(&realm, &request, verifier);
    different_revision.revision += 1;
    assert!(matches!(
        realm
            .check_password(
                policy(&request),
                request,
                different_revision,
                &password,
                1_100
            )
            .await,
        Err(ComponentError::InvalidBinding)
    ));
}

#[test]
fn supplied_credential_requires_complete_identity_and_bounded_owned_verifier() {
    let realm = realm();
    for (id, revision, verifier) in [
        (Uuid::nil(), 1, "invalid verifier".to_owned()),
        (Uuid::new_v4(), 0, "invalid verifier".to_owned()),
        (Uuid::new_v4(), u64::MAX, "invalid verifier".to_owned()),
        (Uuid::new_v4(), 1, String::new()),
        (Uuid::new_v4(), 1, "x".repeat(1025)),
    ] {
        assert!(
            CredentialSnapshot::capture_supplied_verifier(&realm, id, revision, verifier).is_err()
        );
    }
}

#[test]
fn integer_boundaries_are_checked_without_inventing_a_challenge_ttl() {
    let original = deployment(20, "review");
    for clock in [0, u64::MAX] {
        assert!(
            UnactivatedReviewRealm::compare_supplied_observations(
                original.clone(),
                original.clone(),
                &[deployment(60, "ordinary")],
                clock
            )
            .is_err()
        );
    }
    let realm = realm();
    let mut request = request(&realm);
    request.expires_at_ms = i64::MAX as u64;
    assert!(
        realm
            .bind(&policy(&request), &request, request.expires_at_ms - 1)
            .is_ok()
    );
    assert!(
        realm
            .bind(&policy(&request), &request, request.expires_at_ms)
            .is_err()
    );
    request.scope.credential_revision = i64::MAX as u64;
    assert!(realm.bind(&policy(&request), &request, 1_000).is_ok());
    request.scope.credential_revision += 1;
    assert!(realm.bind(&policy(&request), &request, 1_000).is_err());
}

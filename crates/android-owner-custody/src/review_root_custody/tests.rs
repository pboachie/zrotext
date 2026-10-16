// SPDX-License-Identifier: AGPL-3.0-only
use super::*;
use crate::custody::{CreatedKit, create};
use p256::ecdsa::{Signature, VerifyingKey, signature::Verifier};
use sha2::{Digest, Sha256};
type Change = Box<dyn Fn(&mut ReviewAuthority)>;

struct Fixture {
    kit: CreatedKit,
    unsigned: Vec<u8>,
    challenge: Challenge,
    authority: ReviewAuthority,
    anchor: TimeAnchor,
}

impl Fixture {
    fn new() -> Self {
        let kit = create([1; 16], "https://owner.example.test").unwrap();
        let authority = ReviewAuthority {
            realm: [10; 16],
            database_commitment: [11; 32],
            config_commitment: [16; 32],
            config_revision: 1,
            origin: kit.identity.origin.clone(),
            account_id: [1; 16],
            owner_user_id: [2; 16],
            review_owner_session_id: [3; 16],
            broker_principal_id: [12; 16],
            credential_id: [13; 16],
            credential_revision: 1,
            broker_session_id: [14; 16],
            authentication_event_id: [15; 16],
            issued_ms: 98_000,
            absolute_expiry_ms: 130_000,
            idle_deadline_ms: 125_000,
            context_epoch: 1,
        };
        let challenge = Challenge {
            account_id: authority.account_id,
            user_id: authority.owner_user_id,
            session_id: authority.review_owner_session_id,
            challenge_id: [4; 16],
            nonce: [5; 32],
            root_fingerprint: kit.identity.root_fingerprint,
            issued_ms: 99_000,
            expires_ms: 120_000,
            origin: kit.identity.origin.clone(),
        };
        let unsigned = sealed_root_enrollment::encode(&challenge).unwrap();
        let anchor = TimeAnchor {
            authenticated_server_ms: 100_000,
            authenticated_elapsed_ms: 1_000,
            uncertainty_ms: 10,
        };
        Self {
            kit,
            unsigned,
            challenge,
            authority,
            anchor,
        }
    }

    fn open(&self, service: &ReviewSigningService) -> ReviewHandle {
        service
            .open_custody(
                &self.unsigned,
                &self.kit.encrypted_backup,
                &self.kit.public_card,
                &self.kit.identity,
                &self.kit.encrypted_backup[6..22].try_into().unwrap(),
                self.authority.clone(),
                self.anchor,
                1_001,
            )
            .unwrap()
    }
}

#[test]
fn exact_enrollment_and_custody_signatures_verify_in_existing_formats() {
    let fixture = Fixture::new();
    let service = ReviewSigningService::default();
    let handle = fixture.open(&service);
    let signatures = service
        .sign(
            handle,
            &fixture.kit.recovery_token,
            &fixture.authority,
            || Ok(1_010),
        )
        .unwrap();
    sealed_root_enrollment::verify(
        &fixture.kit.root_pin,
        &fixture.unsigned,
        &signatures.enrollment,
        &fixture.challenge,
        100_010,
    )
    .unwrap();
    let statement = [
        b"ZTSE/root-custody/v1\0".as_slice(),
        &(fixture.unsigned.len() as u32).to_be_bytes(),
        &fixture.unsigned,
        &Sha256::digest(&fixture.kit.encrypted_backup),
        &Sha256::digest(&fixture.kit.public_card),
        &fixture.kit.identity.root_fingerprint,
    ]
    .concat();
    VerifyingKey::from_sec1_bytes(&fixture.kit.root_pin[29..])
        .unwrap()
        .verify(
            &statement,
            &Signature::from_slice(&signatures.custody).unwrap(),
        )
        .unwrap();
    assert!(service.review(handle).is_err());
    assert!(
        service
            .sign(
                handle,
                &fixture.kit.recovery_token,
                &fixture.authority,
                || Ok(1_010)
            )
            .is_err()
    );
}

#[test]
fn opened_review_copies_exact_public_artifacts() {
    let mut fixture = Fixture::new();
    let service = ReviewSigningService::default();
    let original = fixture.unsigned.clone();
    let handle = fixture.open(&service);
    fixture.unsigned.fill(0);
    fixture.kit.encrypted_backup.fill(0);
    fixture.kit.public_card.fill(0);
    assert_eq!(service.review(handle).unwrap(), original);
    assert!(
        service
            .sign(
                handle,
                &fixture.kit.recovery_token,
                &fixture.authority,
                || Ok(1_010)
            )
            .is_ok()
    );
}

#[test]
fn independent_identity_and_authenticated_session_reject_substitution() {
    let fixture = Fixture::new();
    let service = ReviewSigningService::default();
    let mut expected = fixture.kit.identity.clone();
    expected.root_fingerprint[0] ^= 1;
    assert!(
        service
            .open_custody(
                &fixture.unsigned,
                &fixture.kit.encrypted_backup,
                &fixture.kit.public_card,
                &expected,
                &fixture.kit.encrypted_backup[6..22].try_into().unwrap(),
                fixture.authority.clone(),
                fixture.anchor,
                1_001,
            )
            .is_err()
    );
    let mut authority = fixture.authority.clone();
    authority.review_owner_session_id = [8; 16];
    assert!(
        service
            .open_custody(
                &fixture.unsigned,
                &fixture.kit.encrypted_backup,
                &fixture.kit.public_card,
                &fixture.kit.identity,
                &fixture.kit.encrypted_backup[6..22].try_into().unwrap(),
                authority.clone(),
                fixture.anchor,
                1_001,
            )
            .is_err()
    );
    let handle = fixture.open(&service);
    assert!(
        service
            .sign(handle, &fixture.kit.recovery_token, &authority, || Ok(
                1_010
            ))
            .is_err()
    );
    assert!(
        service
            .sign(
                handle,
                &fixture.kit.recovery_token,
                &fixture.authority,
                || Ok(1_010)
            )
            .is_err()
    );
}

#[test]
fn wrong_token_consumes_approval_and_cancel_cannot_reopen_challenge() {
    let fixture = Fixture::new();
    let service = ReviewSigningService::default();
    let handle = fixture.open(&service);
    assert!(
        service
            .sign(handle, b"invalid", &fixture.authority, || Ok(1_010))
            .is_err()
    );
    assert!(
        service
            .sign(
                handle,
                &fixture.kit.recovery_token,
                &fixture.authority,
                || Ok(1_010)
            )
            .is_err()
    );
    assert!(
        service
            .open_custody(
                &fixture.unsigned,
                &fixture.kit.encrypted_backup,
                &fixture.kit.public_card,
                &fixture.kit.identity,
                &fixture.kit.encrypted_backup[6..22].try_into().unwrap(),
                fixture.authority.clone(),
                fixture.anchor,
                1_010,
            )
            .is_err()
    );
    let fresh_service = ReviewSigningService::default();
    let handle = fixture.open(&fresh_service);
    fresh_service.close(handle);
    fresh_service.close_all();
    assert!(fresh_service.review(handle).is_err());
    assert!(
        fresh_service
            .open_custody(
                &fixture.unsigned,
                &fixture.kit.encrypted_backup,
                &fixture.kit.public_card,
                &fixture.kit.identity,
                &fixture.kit.encrypted_backup[6..22].try_into().unwrap(),
                fixture.authority.clone(),
                fixture.anchor,
                1_010,
            )
            .is_err()
    );
}

#[test]
fn lifecycle_cancellation_during_signing_prevents_signature_publication() {
    let fixture = Fixture::new();
    let service = ReviewSigningService::default();
    let handle = fixture.open(&service);
    let mut samples = 0;
    let result = service.sign_with_public_output(
        handle,
        &fixture.kit.recovery_token,
        &fixture.authority,
        &mut (),
        |_| {
            samples += 1;
            Ok(1_010)
        },
        |_, signatures| {
            // Cancel after recovery/signing and before publication. The clock
            // callback supplies only elapsed time and must not reenter the registry.
            service.close_all();
            Ok(signatures)
        },
    );
    assert!(result.is_err());
    assert_eq!(samples, 2);
    assert!(service.review(handle).is_err());
}

#[test]
fn sleep_elapsed_time_and_uncertainty_upper_bound_prevent_expired_output() {
    let fixture = Fixture::new();
    let service = ReviewSigningService::default();
    let handle = fixture.open(&service);
    let mut samples = 0;
    assert!(
        service
            .sign(
                handle,
                &fixture.kit.recovery_token,
                &fixture.authority,
                || {
                    samples += 1;
                    Ok(if samples == 1 { 1_010 } else { 20_990 })
                }
            )
            .is_err()
    );
    let service = ReviewSigningService::default();
    assert!(
        service
            .open_custody(
                &fixture.unsigned,
                &fixture.kit.encrypted_backup,
                &fixture.kit.public_card,
                &fixture.kit.identity,
                &fixture.kit.encrypted_backup[6..22].try_into().unwrap(),
                fixture.authority.clone(),
                fixture.anchor,
                20_990,
            )
            .is_err()
    );
}

#[test]
fn public_output_allocation_delay_and_cancellation_remain_inside_approval() {
    let fixture = Fixture::new();
    let service = ReviewSigningService::default();
    let handle = fixture.open(&service);
    let mut clock = 1_010;
    let result = service.sign_with_public_output(
        handle,
        &fixture.kit.recovery_token,
        &fixture.authority,
        &mut clock,
        |clock| Ok(*clock),
        |clock, signatures| {
            *clock = 20_990;
            Ok(signatures)
        },
    );
    assert!(result.is_err());
    let service = ReviewSigningService::default();
    let handle = fixture.open(&service);
    let result = service.sign_with_public_output(
        handle,
        &fixture.kit.recovery_token,
        &fixture.authority,
        &mut (),
        |_| Ok(1_010),
        |_, signatures| {
            service.close(handle);
            Ok(signatures)
        },
    );
    assert!(result.is_err());
}

#[test]
fn stale_or_regressing_monotonic_anchor_and_not_yet_valid_challenges_fail_closed() {
    let fixture = Fixture::new();
    assert!(fixture.anchor.bounds(999).is_err());
    assert!(fixture.anchor.bounds(301_001).is_err());
    let uncertain = TimeAnchor {
        uncertainty_ms: 5_001,
        ..fixture.anchor
    };
    assert!(uncertain.bounds(1_001).is_err());
    let service = ReviewSigningService::default();
    let handle = fixture.open(&service);
    assert!(
        service
            .sign(
                handle,
                &fixture.kit.recovery_token,
                &fixture.authority,
                || Ok(1_000)
            )
            .is_err()
    );
    let mut challenge = fixture.challenge.clone();
    challenge.issued_ms = 100_001;
    assert!(
        service
            .open_custody(
                &sealed_root_enrollment::encode(&challenge).unwrap(),
                &fixture.kit.encrypted_backup,
                &fixture.kit.public_card,
                &fixture.kit.identity,
                &fixture.kit.encrypted_backup[6..22].try_into().unwrap(),
                fixture.authority.clone(),
                fixture.anchor,
                1_001,
            )
            .is_err()
    );
}

#[test]
fn unsupported_transcript_types_and_unknown_restart_handles_are_rejected() {
    let fixture = Fixture::new();
    let service = ReviewSigningService::default();
    let handle = fixture.open(&service);
    let restarted = ReviewSigningService::default();
    assert!(
        restarted
            .sign(
                handle,
                &fixture.kit.recovery_token,
                &fixture.authority,
                || Ok(1_010)
            )
            .is_err()
    );
    for magic in [b"ZTRC\x01", b"ZTRB\x01", b"ZTRE\x02"] {
        let mut unsigned = fixture.unsigned.clone();
        unsigned[..5].copy_from_slice(magic);
        assert!(
            restarted
                .open_custody(
                    &unsigned,
                    &fixture.kit.encrypted_backup,
                    &fixture.kit.public_card,
                    &fixture.kit.identity,
                    &fixture.kit.encrypted_backup[6..22].try_into().unwrap(),
                    fixture.authority.clone(),
                    fixture.anchor,
                    1_001,
                )
                .is_err()
        );
    }
    service.close_all();
    assert!(service.review(handle).is_err());
}

#[test]
fn final_registry_wait_crossing_expiry_denies_output() {
    use std::sync::{atomic::AtomicU64, mpsc};
    use std::time::Duration;
    let fixture = Fixture::new();
    let service = ReviewSigningService::default();
    let handle = fixture.open(&service);
    let clock = AtomicU64::new(1_010);
    let (release_tx, release_rx) = mpsc::channel();
    let release_rx = Mutex::new(release_rx);
    let (ready_tx, ready_rx) = mpsc::channel();
    let (sample_tx, sample_rx) = mpsc::channel();
    let (result, pre_release_sample, published_while_locked) = std::thread::scope(|scope| {
        let worker = scope.spawn(|| {
            let mut samples = 0;
            service.sign_with_public_output(
                handle,
                &fixture.kit.recovery_token,
                &fixture.authority,
                &mut (),
                |_| {
                    samples += 1;
                    let elapsed = clock.load(Ordering::SeqCst);
                    if samples == 2 {
                        sample_tx.send(elapsed).unwrap();
                    }
                    Ok(elapsed)
                },
                |_, _| {
                    ready_tx.send(()).unwrap();
                    // A setup timeout cannot leave a scoped worker parked forever.
                    release_rx
                        .lock()
                        .unwrap()
                        .recv_timeout(Duration::from_secs(5))
                        .map_err(|_| SigningError::Unavailable)?;
                    Ok(())
                },
            )
        });
        ready_rx.recv_timeout(Duration::from_secs(5)).unwrap();
        // Recovery and public allocation completed. Hold the actual final mutex
        // before allowing the worker to leave its output callback.
        let registry = service.registry.lock().unwrap();
        release_tx.send(()).unwrap();
        let sample = sample_rx.recv_timeout(Duration::from_millis(500)).ok();
        let finished = worker.is_finished();
        clock.store(20_990, Ordering::SeqCst);
        drop(registry);
        (worker.join().unwrap(), sample, finished)
    });
    assert!(!published_while_locked);
    assert_eq!(result, Err(SigningError::TimeRejected));
    assert!(
        pre_release_sample.is_none(),
        "final time must be sampled after acquiring the mutex"
    );
    assert!(service.review(handle).is_err());
    assert!(matches!(
        service.sign(
            handle,
            &fixture.kit.recovery_token,
            &fixture.authority,
            || Ok(1_010)
        ),
        Err(SigningError::Unavailable)
    ));
}

#[test]
fn every_review_identity_and_epoch_is_rechecked_and_failure_burns_handle() {
    let f = Fixture::new();
    let variants: Vec<Change> = vec![
        Box::new(|a| a.realm[0] ^= 1),
        Box::new(|a| a.database_commitment[0] ^= 1),
        Box::new(|a| a.config_commitment[0] ^= 1),
        Box::new(|a| a.config_revision += 1),
        Box::new(|a| a.origin = "https://other.example.test".into()),
        Box::new(|a| a.account_id[0] ^= 1),
        Box::new(|a| a.owner_user_id[0] ^= 1),
        Box::new(|a| a.review_owner_session_id[0] ^= 1),
        Box::new(|a| a.broker_principal_id[0] ^= 1),
        Box::new(|a| a.credential_id[0] ^= 1),
        Box::new(|a| a.credential_revision += 1),
        Box::new(|a| a.broker_session_id[0] ^= 1),
        Box::new(|a| a.authentication_event_id[0] ^= 1),
        Box::new(|a| a.context_epoch += 1),
        Box::new(|a| a.absolute_expiry_ms += 1),
    ];
    for change in variants {
        let service = ReviewSigningService::default();
        let handle = f.open(&service);
        let mut switched = f.authority.clone();
        change(&mut switched);
        assert!(
            service
                .sign(handle, &f.kit.recovery_token, &switched, || Ok(1_010))
                .is_err()
        );
        assert!(
            service
                .sign(handle, &f.kit.recovery_token, &f.authority, || Ok(1_010))
                .is_err()
        );
    }
}

#[test]
fn original_typed_session_expiry_caps_longer_root_challenge_at_output_boundary() {
    let mut f = Fixture::new();
    f.authority.idle_deadline_ms = 100_020;
    let service = ReviewSigningService::default();
    let handle = f.open(&service);
    let mut clock = 1_005;
    assert!(
        service
            .sign_with_public_output(
                handle,
                &f.kit.recovery_token,
                &f.authority,
                &mut clock,
                |c| Ok(*c),
                |c, out| {
                    *c = 1_010;
                    Ok(out)
                }
            )
            .is_err()
    );
}

#[test]
fn malformed_review_context_cannot_open_even_with_valid_ordinary_shaped_challenge() {
    let f = Fixture::new();
    let variants: Vec<Change> = vec![
        Box::new(|a| a.realm = [0; 16]),
        Box::new(|a| a.database_commitment = [0; 32]),
        Box::new(|a| a.config_commitment = [0; 32]),
        Box::new(|a| a.config_revision = 0),
        Box::new(|a| a.broker_principal_id = [0; 16]),
        Box::new(|a| a.credential_id = [0; 16]),
        Box::new(|a| a.credential_revision = 0),
        Box::new(|a| a.context_epoch = 0),
        Box::new(|a| a.issued_ms = 100_001),
        Box::new(|a| a.idle_deadline_ms = 100_000),
        Box::new(|a| a.absolute_expiry_ms = i64::MAX as u64 + 1),
    ];
    for change in variants {
        let mut a = f.authority.clone();
        change(&mut a);
        assert!(
            ReviewSigningService::default()
                .open_custody(
                    &f.unsigned,
                    &f.kit.encrypted_backup,
                    &f.kit.public_card,
                    &f.kit.identity,
                    &f.kit.encrypted_backup[6..22].try_into().unwrap(),
                    a,
                    f.anchor,
                    1_001
                )
                .is_err()
        );
    }
}

// SPDX-License-Identifier: AGPL-3.0-only
use super::*;
use crate::sealed_manifest_store::tests::Fixture;
use axum::{body::Body, http::Request};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use hmac::{Hmac, KeyInit, Mac};
use p256::ecdsa::{Signature, signature::Signer};
use sha2::{Digest, Sha256};
use tower::ServiceExt;

fn consent(device_id: Uuid, line_id: Uuid) -> ConversationConsent {
    ConversationConsent {
        device_id,
        line_id,
        binding_generation: 1,
        peer: "+12".into(),
        disclosure_version: DISCLOSURE_VERSION.into(),
        content_transfer_confirmed: true,
    }
}

#[test]
fn content_transfer_requires_explicit_current_disclosure_and_line_identity() {
    let mut selected = consent(Uuid::new_v4(), Uuid::new_v4());
    assert!(selected.valid());
    selected.content_transfer_confirmed = false;
    assert!(!selected.valid());
    selected.content_transfer_confirmed = true;
    selected.disclosure_version = "metadata-only".into();
    assert!(!selected.valid());
    selected.disclosure_version = DISCLOSURE_VERSION.into();
    selected.binding_generation = 0;
    assert!(!selected.valid());
    selected.binding_generation = 1;
    selected.device_id = Uuid::nil();
    assert!(!selected.valid());
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; isolated synthetic schema"]
async fn inventory_is_bounded_account_scoped_and_preserves_purged_identities() {
    let (f, owner) = prepared().await;
    enable_conversation(&mut f.connect().await, &owner, &consent(f.device, f.line))
        .await
        .unwrap();
    let event = Uuid::new_v4();
    capture(&f, event, 1, b"+12", 0).await;
    // Cloning synthetic verified storage identities exercises cursor bounds;
    // these rows are never used as device/ciphertext evidence.
    for sequence in 2..=102i64 {
        f.db.execute("INSERT INTO sealed_inbound_events(id,account_id,device_id,line_id,binding_generation,device_sequence,unsigned_digest,observed_at,received_at,envelope_profile,envelope) \
            SELECT $1,account_id,device_id,line_id,binding_generation,$2,unsigned_digest,observed_at,received_at,envelope_profile,envelope FROM sealed_inbound_events WHERE id=$3",
            &[&Uuid::new_v4(), &sequence, &event]).await.unwrap();
    }
    f.db.execute(
        "UPDATE sealed_inbound_events SET envelope=NULL WHERE id=$1",
        &[&event],
    )
    .await
    .unwrap();
    let mut client = f.connect().await;
    let first = lifecycle::inventory(&mut client, &owner, None, None)
        .await
        .unwrap();
    assert_eq!(first.consent.unwrap().peer.as_deref(), Some("+12"));
    assert_eq!(first.sealed_events.len(), lifecycle::INVENTORY_LIMIT);
    assert!(first.sealed_events_truncated);
    let second = lifecycle::inventory(&mut client, &owner, first.sealed_events_next_cursor, None)
        .await
        .unwrap();
    assert_eq!(second.sealed_events.len(), 2);
    assert!(!second.sealed_events_truncated);
    assert!(second.sealed_events_next_cursor.is_none());
    let all: Vec<_> = first
        .sealed_events
        .iter()
        .chain(&second.sealed_events)
        .collect();
    assert_eq!(
        all.iter()
            .filter(|e| e.event_id == event && !e.content_retained)
            .count(),
        1
    );
    let other = Uuid::new_v4();
    f.db.execute("INSERT INTO accounts(id) VALUES($1)", &[&other])
        .await
        .unwrap();
    let other_owner = owner_for(&f, other).await;
    let other_view = lifecycle::inventory(&mut client, &other_owner, None, None)
        .await
        .unwrap();
    assert!(other_view.consent.is_none());
    assert!(other_view.sealed_events.is_empty());
    assert!(matches!(
        lifecycle::inventory(&mut client, &other_owner, Some(event), None).await,
        Err(ConversationError::NotFound)
    ));
    revoke_conversation(&mut client, &owner).await.unwrap();
    let withdrawn = lifecycle::inventory(&mut client, &owner, None, None)
        .await
        .unwrap()
        .consent
        .unwrap();
    assert!(withdrawn.peer.is_none());
    assert!(withdrawn.revoked_at_ms.is_some());
    f.db.execute(
        "UPDATE sessions SET revoked_at=clock_timestamp() WHERE id=$1",
        &[&owner.session_id],
    )
    .await
    .unwrap();
    assert!(matches!(
        lifecycle::inventory(&mut client, &owner, None, None).await,
        Err(ConversationError::Forbidden)
    ));
    f.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; isolated synthetic schema"]
async fn withdrawn_metadata_cleanup_respects_cutoff_row_locks_and_new_consent() {
    let (f, owner) = prepared().await;
    let mut client = f.connect().await;
    enable_conversation(&mut client, &owner, &consent(f.device, f.line))
        .await
        .unwrap();
    assert_eq!(lifecycle::prune_withdrawn(&client, 30, 1).await.unwrap(), 0);
    revoke_conversation(&mut client, &owner).await.unwrap();
    assert_eq!(lifecycle::prune_withdrawn(&client, 30, 1).await.unwrap(), 0);
    f.db.execute("UPDATE owner_conversation_consents SET revoked_at=clock_timestamp()-interval '31 days' WHERE account_id=$1", &[&f.account]).await.unwrap();
    let mut blocker = f.connect().await;
    let tx = blocker.transaction().await.unwrap();
    tx.query_one(
        "SELECT account_id FROM owner_conversation_consents WHERE account_id=$1 FOR UPDATE",
        &[&f.account],
    )
    .await
    .unwrap();
    assert_eq!(lifecycle::prune_withdrawn(&client, 30, 1).await.unwrap(), 0);
    tx.commit().await.unwrap();
    let counts =
        crate::retention::prune(&mut client, crate::retention::RetentionPolicy::default(), 1)
            .await
            .unwrap();
    assert_eq!(counts.conversation_consents, 1);
    assert!(counts.any_full(1));
    assert!(
        lifecycle::inventory(&mut client, &owner, None, None)
            .await
            .unwrap()
            .consent
            .is_none()
    );
    enable_conversation(&mut client, &owner, &consent(f.device, f.line))
        .await
        .unwrap();
    assert_eq!(lifecycle::prune_withdrawn(&client, 30, 1).await.unwrap(), 0);
    f.cleanup().await;
}

#[test]
fn conversation_selectors_refuse_ambiguous_or_noncanonical_peers() {
    let mut selected = consent(Uuid::new_v4(), Uuid::new_v4());
    for invalid in [
        "",
        "+1",
        "+01",
        "+1 2",
        "+1\n2",
        "12",
        "+∩╝æ∩╝Æ",
        "+1234567890123456",
    ] {
        selected.peer = invalid.into();
        assert!(!selected.valid());
    }
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; isolated synthetic schema"]
async fn reader_requires_exact_current_manifest_and_refuses_revoked_root_authority() {
    let (mut f, owner) = prepared().await;
    let mut client = f.connect().await;
    enable_conversation(&mut client, &owner, &consent(f.device, f.line))
        .await
        .unwrap();
    let old = Uuid::new_v4();
    capture(&f, old, 1, b"+12", 0).await;
    assert!(read_event(&mut client, &owner, old).await.is_ok());
    f.advance();
    let current = Uuid::new_v4();
    let bytes = capture(&f, current, 2, b"+12", 0).await;
    // Even unchanged reader key bytes do not substitute for the exact epoch.
    assert!(matches!(
        read_event(&mut client, &owner, old).await,
        Err(ConversationError::Forbidden)
    ));
    assert_eq!(
        read_event(&mut client, &owner, current).await.unwrap(),
        bytes
    );
    f.db.execute(
        "UPDATE sealed_manifest_authorities SET revoked_at=clock_timestamp() WHERE account_id=$1",
        &[&f.account],
    )
    .await
    .unwrap();
    assert!(matches!(
        read_event(&mut client, &owner, current).await,
        Err(ConversationError::Forbidden)
    ));
    // Persisted ciphertext remains opaque; revocation is an access fence.
    assert!(
        f.db.query_one(
            "SELECT envelope IS NOT NULL FROM sealed_inbound_events WHERE id=$1",
            &[&current]
        )
        .await
        .unwrap()
        .get::<_, bool>(0)
    );
    f.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; isolated synthetic schema"]
async fn reader_waits_for_manifest_before_account_and_observes_withdrawal() {
    let (f, owner) = prepared().await;
    enable_conversation(&mut f.connect().await, &owner, &consent(f.device, f.line))
        .await
        .unwrap();
    let event = Uuid::new_v4();
    capture(&f, event, 1, b"+12", 0).await;
    let mut blocker = f.connect().await;
    let blocker_pid: i32 = blocker
        .query_one("SELECT pg_backend_pid()", &[])
        .await
        .unwrap()
        .get(0);
    let tx = blocker.transaction().await.unwrap();
    tx.query_one(
        "SELECT account_id FROM sealed_manifest_authorities WHERE account_id=$1 FOR UPDATE",
        &[&f.account],
    )
    .await
    .unwrap();
    let mut reader = f.connect().await;
    let reader_pid: i32 = reader
        .query_one("SELECT pg_backend_pid()", &[])
        .await
        .unwrap()
        .get(0);
    let pending = read_event(&mut reader, &owner, event);
    tokio::pin!(pending);
    blocked(&f.db, pending.as_mut(), reader_pid, blocker_pid).await;
    // NOWAIT proves the blocked reader did not hold account while requesting
    // manifest authority. Account-only withdrawal can therefore finish.
    let mut withdrawal = f.connect().await;
    let proof = withdrawal.transaction().await.unwrap();
    proof
        .query_one(
            "SELECT id FROM accounts WHERE id=$1 FOR UPDATE NOWAIT",
            &[&f.account],
        )
        .await
        .unwrap();
    proof.rollback().await.unwrap();
    revoke_conversation(&mut withdrawal, &owner).await.unwrap();
    tx.commit().await.unwrap();
    assert!(matches!(pending.await, Err(ConversationError::NotFound)));
    f.cleanup().await;
}

async fn expiry_during_event_wait(expire_reader: bool) {
    let (mut f, owner) = prepared().await;
    enable_conversation(&mut f.connect().await, &owner, &consent(f.device, f.line))
        .await
        .unwrap();
    // Prepare every connection before signing the short lease. The initial
    // verified capture must complete while this authority is genuinely live.
    let mut capture_client = f.connect().await;
    let mut blocker = f.connect().await;
    let blocker_pid: i32 = blocker
        .query_one("SELECT pg_backend_pid()", &[])
        .await
        .unwrap()
        .get(0);
    let mut reader = f.connect().await;
    let reader_pid: i32 = reader
        .query_one("SELECT pg_backend_pid()", &[])
        .await
        .unwrap()
        .get(0);
    let observed: i64 =
        f.db.query_one(
            "SELECT floor(extract(epoch FROM clock_timestamp())*1000)::bigint",
            &[],
        )
        .await
        .unwrap()
        .get(0);
    let expires = observed + 9000;
    if expire_reader {
        // Keep manifest/version/digest unchanged during the wait. Only the
        // archive reader's validity ends; manifest expiry remains in the future.
        f.bytes[151 + 140..151 + 148].copy_from_slice(&(expires as u64).to_be_bytes());
    } else {
        f.bytes[45..53].copy_from_slice(&(expires as u64).to_be_bytes());
    }
    f.resign();
    let event = Uuid::new_v4();
    let bytes = envelope(&f, event, 1, (observed + 1) as u64, b"+12");
    crate::sealed_inbound::ingest::ingest_candidate02(
        &mut capture_client,
        f.session(),
        f.line,
        1,
        &f.bytes,
        &bytes,
    )
    .await
    .unwrap();
    let tx = blocker.transaction().await.unwrap();
    tx.query_one(
        "SELECT id FROM sealed_inbound_events WHERE id=$1 FOR UPDATE",
        &[&event],
    )
    .await
    .unwrap();
    let pending = read_event(&mut reader, &owner, event);
    tokio::pin!(pending);
    blocked(&f.db, pending.as_mut(), reader_pid, blocker_pid).await;
    assert!(
        f.db.query_one(
            "SELECT floor(extract(epoch FROM clock_timestamp())*1000)::bigint<$1",
            &[&expires]
        )
        .await
        .unwrap()
        .get::<_, bool>(0),
        "signed authority must remain live when the known event blocker is observed"
    );
    // The signed lease and therefore the remaining event lock wait are shorter
    // than the fixture's ten-second statement deadline. A timeout cannot pass.
    tokio::time::timeout(std::time::Duration::from_secs(9), async {
        while f
            .db
            .query_one(
                "SELECT floor(extract(epoch FROM clock_timestamp())*1000)::bigint<$1",
                &[&expires],
            )
            .await
            .unwrap()
            .get::<_, bool>(0)
        {
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    tx.commit().await.unwrap();
    assert!(matches!(pending.await, Err(ConversationError::Forbidden)));
    assert_eq!(
        f.db.query_one(
            "SELECT envelope FROM sealed_inbound_events WHERE id=$1",
            &[&event]
        )
        .await
        .unwrap()
        .get::<_, Vec<u8>>(0),
        bytes
    );
    f.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; isolated synthetic schema"]
async fn manifest_expiry_during_event_wait_never_returns_content() {
    expiry_during_event_wait(false).await;
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; isolated synthetic schema"]
async fn archive_reader_expiry_during_event_wait_never_returns_content() {
    expiry_during_event_wait(true).await;
}

fn app() -> Router {
    router(OwnerConversationsState {
        database_url: "postgres://unused".into(),
        auth_hasher: Arc::new(TokenHasher::new(crate::test_keys::key(83)).unwrap()),
        canonical_origin: "https://zrotext.example".into(),
    })
}

#[tokio::test]
async fn anonymous_and_bearer_calls_fail_before_body_or_database_access() {
    for method in ["GET", "POST", "DELETE"] {
        let path = if method == "GET" {
            format!("/v1/owner/conversation/events/{}", Uuid::new_v4())
        } else {
            "/v1/owner/conversation".into()
        };
        for bearer in [false, true] {
            let mut request = Request::builder().method(method).uri(&path);
            if bearer {
                request = request.header(header::AUTHORIZATION, "Bearer synthetic");
            }
            let response = app()
                .oneshot(request.body(Body::empty()).unwrap())
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
            assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
            assert_eq!(
                response.headers()[header::X_CONTENT_TYPE_OPTIONS],
                "nosniff"
            );
        }
    }
}

#[tokio::test]
async fn content_read_requires_csrf_proof_before_database_access() {
    let response = app()
        .oneshot(
            Request::builder()
                .uri(format!("/v1/owner/conversation/events/{}", Uuid::new_v4()))
                .header(header::COOKIE, "__Host-zrotext_session=synthetic")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

async fn owner(f: &Fixture) -> SessionPrincipal {
    owner_for(f, f.account).await
}

pub(super) async fn owner_for(f: &Fixture, account: Uuid) -> SessionPrincipal {
    principal_for(f, account, "owner").await
}

async fn principal_for(f: &Fixture, account: Uuid, role: &str) -> SessionPrincipal {
    let user = Uuid::new_v4();
    let session = Uuid::new_v4();
    let hasher = TokenHasher::new(crate::test_keys::key(84)).unwrap();
    let token = format!("zts_{}", URL_SAFE_NO_PAD.encode(rand::random::<[u8; 32]>()));
    f.db.execute(
        "INSERT INTO users(id,email,password_hash,email_verified_at) VALUES($1,$2,'unused',now())",
        &[&user, &format!("{}@example.test", user.simple())],
    )
    .await
    .unwrap();
    f.db.execute(
        "INSERT INTO memberships(account_id,user_id,role) VALUES($1,$2,$3)",
        &[&account, &user, &role],
    )
    .await
    .unwrap();
    let mut mac = Hmac::<Sha256>::new_from_slice(&crate::test_keys::key(84)).unwrap();
    mac.update(b"session-v1\0");
    mac.update(token.as_bytes());
    let hash = mac.finalize().into_bytes();
    f.db.execute("INSERT INTO sessions(id,account_id,user_id,token_hash,csrf_hash,expires_at) VALUES($1,$2,$3,$4,$5,clock_timestamp()+interval '1 hour')",
        &[&session,&account,&user,&hash.as_slice(),&vec![4u8;32]]).await.unwrap();
    auth::authenticate_session(&f.db, &hasher, &token)
        .await
        .unwrap()
}

pub(super) async fn prepared() -> (Fixture, SessionPrincipal) {
    let f = Fixture::new().await;
    f.db.batch_execute(include_str!(
        "../../../../deploy/compose/migrations/064_owner_conversation_consent.sql"
    ))
    .await
    .unwrap();
    f.db.batch_execute(include_str!(
        "../../../../deploy/compose/migrations/065_conversation_activation.sql"
    ))
    .await
    .unwrap();
    f.db.batch_execute(include_str!(
        "../../../../deploy/compose/migrations/072_conversation_confirmation_records.sql"
    ))
    .await
    .unwrap();
    f.db.batch_execute(include_str!(
        "../../../../deploy/compose/migrations/075_workflow_context.sql"
    ))
    .await
    .unwrap();
    f.db.batch_execute(include_str!(
        "../../../../deploy/compose/migrations/067_contacts_consent.sql"
    ))
    .await
    .unwrap();
    f.db.batch_execute(include_str!(
        "../../../../deploy/compose/migrations/076_workflow_decisions.sql"
    ))
    .await
    .unwrap();
    for migration in [
        include_str!("../../../../deploy/compose/migrations/068_connector_registration.sql"),
        include_str!("../../../../deploy/compose/migrations/073_collaboration_drafts.sql"),
        include_str!("../../../../deploy/compose/migrations/074_agent_authority.sql"),
        include_str!("../../../../deploy/compose/migrations/077_encrypted_schedule.sql"),
    ] {
        f.db.batch_execute(migration).await.unwrap();
    }
    let owner = owner(&f).await;
    (f, owner)
}

// Exact signed candidate envelope with opaque synthetic ciphertext. These
// tests exercise verified ingest and reader isolation, not HPKE/device proof.
pub(super) fn envelope(
    f: &Fixture,
    event: Uuid,
    sequence: u64,
    observed: u64,
    peer: &[u8],
) -> Vec<u8> {
    let mut bytes = b"ZTSE\x02\x02\0\0".to_vec();
    bytes.extend(172u16.to_be_bytes());
    bytes.extend(f.account.as_bytes());
    bytes.extend(event.as_bytes());
    bytes.extend(f.device.as_bytes());
    bytes.extend(f.line.as_bytes());
    bytes.extend(&f.bytes[29..37]);
    bytes.extend(Sha256::digest(&f.bytes[..f.bytes.len() - 64]));
    bytes.extend(f.signer);
    bytes.extend(observed.to_be_bytes());
    bytes.extend(event.as_bytes());
    bytes.extend(sequence.to_be_bytes());
    bytes.push(peer.len() as u8);
    bytes.extend(peer);
    bytes.extend([3; 12]);
    bytes.extend(20u32.to_be_bytes());
    bytes.extend([7; 20]);
    bytes.push(1);
    bytes.push(2);
    bytes.extend(f.readers[0].key_id);
    bytes.extend(f.root.verifying_key().to_sec1_point(false).as_bytes());
    bytes.extend([9; 48]);
    let signature: Signature = f.event_signer.sign(
        &[
            b"ZTSE/sign/v2\0".as_slice(),
            &(bytes.len() as u32).to_be_bytes(),
            &bytes,
        ]
        .concat(),
    );
    bytes.extend(signature.normalize_s().to_bytes());
    bytes
}

async fn capture(f: &Fixture, event: Uuid, sequence: u64, peer: &[u8], offset_ms: i64) -> Vec<u8> {
    let now: i64 =
        f.db.query_one(
            "SELECT floor(extract(epoch FROM clock_timestamp())*1000)::bigint",
            &[],
        )
        .await
        .unwrap()
        .get(0);
    // Recorded time deliberately rounds upward so a post-enable fixture never
    // precedes the consent row's microsecond timestamp in the same millisecond.
    let bytes = envelope(f, event, sequence, (now + 1 + offset_ms) as u64, peer);
    crate::sealed_inbound::ingest::ingest_candidate02(
        &mut f.connect().await,
        f.session(),
        f.line,
        1,
        &f.bytes,
        &bytes,
    )
    .await
    .unwrap();
    bytes
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; isolated synthetic schema"]
async fn selected_conversation_reads_exact_verified_bytes_and_withdrawal_fences_reads() {
    let (f, owner) = prepared().await;
    let selected = consent(f.device, f.line);
    enable_conversation(&mut f.connect().await, &owner, &selected)
        .await
        .unwrap();
    assert!(matches!(
        enable_conversation(&mut f.connect().await, &owner, &selected).await,
        Err(ConversationError::Conflict)
    ));
    let event = Uuid::new_v4();
    let bytes = capture(&f, event, 1, b"+12", 0).await;
    assert_eq!(
        read_event(&mut f.connect().await, &owner, event)
            .await
            .unwrap(),
        bytes
    );
    revoke_conversation(&mut f.connect().await, &owner)
        .await
        .unwrap();
    let retained_peer: Option<String> =
        f.db.query_one(
            "SELECT peer FROM owner_conversation_consents WHERE account_id=$1",
            &[&f.account],
        )
        .await
        .unwrap()
        .get(0);
    assert!(retained_peer.is_none());
    assert!(matches!(
        read_event(&mut f.connect().await, &owner, event).await,
        Err(ConversationError::NotFound)
    ));
    enable_conversation(&mut f.connect().await, &owner, &selected)
        .await
        .unwrap();
    assert!(matches!(
        read_event(&mut f.connect().await, &owner, event).await,
        Err(ConversationError::NotFound)
    ));
    f.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; isolated synthetic schema"]
async fn reader_refuses_other_peer_preconsent_content_purge_and_revoked_session() {
    let (f, owner) = prepared().await;
    enable_conversation(&mut f.connect().await, &owner, &consent(f.device, f.line))
        .await
        .unwrap();
    let old = Uuid::new_v4();
    capture(&f, old, 1, b"+12", -60_000).await;
    let other = Uuid::new_v4();
    capture(&f, other, 2, b"+13", 0).await;
    for event in [old, other] {
        assert!(matches!(
            read_event(&mut f.connect().await, &owner, event).await,
            Err(ConversationError::NotFound)
        ));
    }
    let fresh = Uuid::new_v4();
    capture(&f, fresh, 3, b"+12", 0).await;
    f.db.execute(
        "UPDATE sealed_inbound_events SET envelope=NULL WHERE id=$1",
        &[&fresh],
    )
    .await
    .unwrap();
    assert!(matches!(
        read_event(&mut f.connect().await, &owner, fresh).await,
        Err(ConversationError::NotFound)
    ));
    f.db.execute(
        "UPDATE sessions SET revoked_at=clock_timestamp() WHERE id=$1",
        &[&owner.session_id],
    )
    .await
    .unwrap();
    assert!(matches!(
        read_event(&mut f.connect().await, &owner, fresh).await,
        Err(ConversationError::Forbidden)
    ));
    f.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; isolated synthetic schema"]
async fn stale_generation_device_revocation_and_observer_role_fail_closed() {
    let (f, owner) = prepared().await;
    let mut selected = consent(f.device, f.line);
    selected.binding_generation = 2;
    assert!(matches!(
        enable_conversation(&mut f.connect().await, &owner, &selected).await,
        Err(ConversationError::Forbidden)
    ));
    selected.binding_generation = 1;
    enable_conversation(&mut f.connect().await, &owner, &selected)
        .await
        .unwrap();
    let event = Uuid::new_v4();
    capture(&f, event, 1, b"+12", 0).await;
    let foreign_account = Uuid::new_v4();
    f.db.execute("INSERT INTO accounts(id) VALUES($1)", &[&foreign_account])
        .await
        .unwrap();
    let outsider = owner_for(&f, foreign_account).await;
    assert!(matches!(
        read_event(&mut f.connect().await, &outsider, event).await,
        Err(ConversationError::Forbidden)
    ));
    // Independent verified account B shares this schema with its own root,
    // approved device/line and active selection. Missing-authority rejection
    // alone would not exercise event isolation after manifest admission.
    let other = Fixture::new().await;
    capture(&other, Uuid::new_v4(), 1, b"+12", 0).await;
    f.db.execute("INSERT INTO accounts(id) VALUES($1)", &[&other.account])
        .await
        .unwrap();
    let authorized_other = owner_for(&f, other.account).await;
    for table in [
        "devices",
        "device_keys",
        "phone_lines",
        "device_line_bindings",
        "sealed_manifest_authorities",
    ] {
        f.db.batch_execute(&format!(
            "INSERT INTO {table} SELECT * FROM {}.{table}",
            other.schema
        ))
        .await
        .unwrap();
    }
    enable_conversation(
        &mut f.connect().await,
        &authorized_other,
        &consent(other.device, other.line),
    )
    .await
    .unwrap();
    assert!(matches!(
        read_event(&mut f.connect().await, &authorized_other, event).await,
        Err(ConversationError::NotFound)
    ));
    // Capture a new signed fixture event after B's selection; do not retime
    // immutable historical bytes just to make a consent assertion pass.
    let new_event = Uuid::new_v4();
    capture(&other, new_event, 2, b"+12", 0).await;
    f.db.batch_execute(&format!("INSERT INTO sealed_inbound_events SELECT * FROM {}.sealed_inbound_events WHERE id='{new_event}'", other.schema)).await.unwrap();
    assert!(
        read_event(&mut f.connect().await, &authorized_other, new_event)
            .await
            .is_ok()
    );
    other.cleanup().await;
    f.db.execute(
        "UPDATE devices SET revoked_at=clock_timestamp() WHERE id=$1",
        &[&f.device],
    )
    .await
    .unwrap();
    assert!(matches!(
        read_event(&mut f.connect().await, &owner, event).await,
        Err(ConversationError::Forbidden)
    ));
    revoke_conversation(&mut f.connect().await, &owner)
        .await
        .unwrap();
    let observer = principal_for(&f, f.account, "observer").await;
    assert!(matches!(
        enable_conversation(&mut f.connect().await, &observer, &selected).await,
        Err(ConversationError::Forbidden)
    ));
    f.cleanup().await;
}

async fn blocked<T>(
    observer: &Client,
    mut pending: std::pin::Pin<&mut impl std::future::Future<Output = T>>,
    waiter: i32,
    blocker: i32,
) {
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        tokio::select! {
            _ = &mut pending => panic!("read completed before the expected lock wait"),
            _ = async {
                loop {
                    let waiting: bool = observer.query_one(
                        "SELECT $2=ANY(pg_blocking_pids($1))", &[&waiter,&blocker],
                    ).await.unwrap().get(0);
                    if waiting { return; }
                    tokio::time::sleep(std::time::Duration::from_millis(10)).await;
                }
            } => {}
        }
    })
    .await
    .expect("expected lock wait was not observed");
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; isolated synthetic schema"]
async fn session_expiry_during_event_lock_wait_never_returns_content() {
    let (f, owner) = prepared().await;
    enable_conversation(&mut f.connect().await, &owner, &consent(f.device, f.line))
        .await
        .unwrap();
    let event = Uuid::new_v4();
    capture(&f, event, 1, b"+12", 0).await;
    let mut blocker = f.connect().await;
    let blocker_pid: i32 = blocker
        .query_one("SELECT pg_backend_pid()", &[])
        .await
        .unwrap()
        .get(0);
    let tx = blocker.transaction().await.unwrap();
    tx.query_one(
        "SELECT id FROM sealed_inbound_events WHERE id=$1 FOR UPDATE",
        &[&event],
    )
    .await
    .unwrap();
    let mut reader = f.connect().await;
    let reader_pid: i32 = reader
        .query_one("SELECT pg_backend_pid()", &[])
        .await
        .unwrap()
        .get(0);
    f.db.execute(
        "UPDATE sessions SET expires_at=clock_timestamp()+interval '1 second' WHERE id=$1",
        &[&owner.session_id],
    )
    .await
    .unwrap();
    let pending = read_event(&mut reader, &owner, event);
    tokio::pin!(pending);
    blocked(&f.db, pending.as_mut(), reader_pid, blocker_pid).await;
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        loop {
            let expired: bool =
                f.db.query_one(
                    "SELECT expires_at<=clock_timestamp() FROM sessions WHERE id=$1",
                    &[&owner.session_id],
                )
                .await
                .unwrap()
                .get(0);
            if expired {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    tx.commit().await.unwrap();
    assert!(matches!(pending.await, Err(ConversationError::Forbidden)));
    f.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; isolated synthetic schema"]
async fn withdrawal_committed_while_reader_waits_fences_content() {
    let (f, owner) = prepared().await;
    enable_conversation(&mut f.connect().await, &owner, &consent(f.device, f.line))
        .await
        .unwrap();
    let event = Uuid::new_v4();
    capture(&f, event, 1, b"+12", 0).await;
    let mut blocker = f.connect().await;
    let blocker_pid: i32 = blocker
        .query_one("SELECT pg_backend_pid()", &[])
        .await
        .unwrap()
        .get(0);
    let tx = blocker.transaction().await.unwrap();
    tx.query_one(
        "SELECT id FROM accounts WHERE id=$1 FOR UPDATE",
        &[&f.account],
    )
    .await
    .unwrap();
    let mut reader = f.connect().await;
    let reader_pid: i32 = reader
        .query_one("SELECT pg_backend_pid()", &[])
        .await
        .unwrap()
        .get(0);
    let pending = read_event(&mut reader, &owner, event);
    tokio::pin!(pending);
    blocked(&f.db, pending.as_mut(), reader_pid, blocker_pid).await;
    tx.execute("UPDATE owner_conversation_consents SET revoked_at=clock_timestamp(),peer=NULL WHERE account_id=$1",&[&f.account]).await.unwrap();
    tx.commit().await.unwrap();
    assert!(matches!(pending.await, Err(ConversationError::NotFound)));
    f.cleanup().await;
}

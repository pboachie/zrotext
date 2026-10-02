// SPDX-License-Identifier: AGPL-3.0-only
use super::*;
use crate::sealed_manifest_store::tests::Fixture;
use axum::{body::Body, http::Request};
use p256::{ecdsa::SigningKey, elliptic_curve::Generate};
use sha2::{Digest, Sha256};
use tower::ServiceExt;

fn selected(f: &Fixture) -> Selection {
    Selection {
        device_id: f.device,
        line_id: f.line,
        binding_generation: 1,
        peer: "+12".into(),
    }
}
async fn case() -> (Fixture, SessionPrincipal, InstallRequest) {
    let (mut f, owner) = super::super::tests::prepared().await;
    let phone = SigningKey::generate_from_rng(&mut rand::rng());
    let point = phone.verifying_key().to_sec1_point(false);
    let id = Sha256::digest([b"ZTSE/key/v1\0".as_slice(), &[0, 16], point.as_bytes()].concat());
    let mut record = vec![1];
    record.extend(id);
    record.extend(point.as_bytes());
    record.extend(f.device.as_bytes());
    record.extend(f.line.as_bytes());
    record.extend(4u16.to_be_bytes());
    record.extend(&f.bytes[37..53]);
    record.push(1);
    f.bytes.splice(151..151, record);
    f.bytes[150] = 4;
    let validity: [u8; 16] = f.bytes[37..53].try_into().unwrap();
    for i in 0..4 {
        f.bytes[151 + i * 149 + 132..151 + i * 149 + 148].copy_from_slice(&validity);
    }
    f.resign();
    let signer_point = f
        .event_signer
        .verifying_key()
        .to_sec1_point(false)
        .as_bytes()
        .to_vec();
    let signer_fingerprint = Sha256::digest(&signer_point).to_vec();
    f.db.execute(
        "UPDATE device_keys SET signing_key_sec1=$1,fingerprint=$2 WHERE device_id=$3",
        &[&signer_point, &signer_fingerprint, &f.device],
    )
    .await
    .unwrap();
    let r = |i: usize| STANDARD.encode(&f.bytes[151 + i * 149 + 33..151 + i * 149 + 98]);
    let request = InstallRequest {
        expected_session_id: owner.session_id,
        device_id: f.device,
        line_id: f.line,
        binding_generation: 1,
        peer: "+12".into(),
        current_device_signing_fingerprint: STANDARD.encode(&signer_fingerprint),
        expected_root_fingerprint: STANDARD.encode(Sha256::digest(
            [b"ZTSE/root-pin/v2\0".as_slice(), &f.pin].concat(),
        )),
        phone_reader_point: r(0),
        archive_reader_point: r(1),
        phone_signer_point: r(2),
        owner_signer_point: r(3),
        signed_manifest: STANDARD.encode(&f.bytes),
    };
    (f, owner, request)
}
fn app() -> axum::Router {
    super::super::owner_host::router(OwnerConversationsState {
        database_url: "invalid".into(),
        auth_hasher: Arc::new(crate::auth::TokenHasher::new(crate::test_keys::key(84)).unwrap()),
        canonical_origin: "https://test.example".into(),
    })
}

#[test]
fn genesis_rejects_unbounded_noncanonical_and_caller_account_fields() {
    for text in ["YQ", "YR==", "YQ==\n", "YQ==="] {
        assert!(decode(text, 1).is_err());
    }
    assert_eq!(decode("YQ==", 1).unwrap(), b"a");
    assert!(
        serde_json::from_value::<Selection>(
            serde_json::json!({"account_id":Uuid::new_v4(),"device_id":Uuid::new_v4(),
        "line_id":Uuid::new_v4(),"binding_generation":1,"peer":"+12"})
        )
        .is_err()
    );
}

#[tokio::test]
async fn genesis_routes_authenticate_before_body_and_remain_absent_from_default_router() {
    for path in [
        "/v1/owner/conversation/genesis/bootstrap",
        "/v1/owner/conversation/genesis/install",
    ] {
        let response = app()
            .oneshot(Request::post(path).body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(response.headers().get("cache-control").unwrap(), "no-store");
        let response = app()
            .oneshot(
                Request::post(path)
                    .header("authorization", "Bearer synthetic")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        let response = super::super::router(OwnerConversationsState {
            database_url: "invalid".into(),
            auth_hasher: Arc::new(
                crate::auth::TokenHasher::new(crate::test_keys::key(84)).unwrap(),
            ),
            canonical_origin: "https://test.example".into(),
        })
        .oneshot(Request::post(path).body(Body::empty()).unwrap())
        .await
        .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; isolated synthetic schema"]
async fn genesis_installs_once_replays_exact_bytes_and_creates_no_consent_or_activation() {
    let (f, owner, request) = case().await;
    let before = bootstrap_manifest(&mut f.connect().await, &owner, &selected(&f))
        .await
        .unwrap();
    assert_eq!(before["manifest_version"], "0");
    assert!(before["current_manifest"].is_null());
    assert!(before["manifest_digest"].is_null());
    assert_eq!(
        before["current_device_signing_fingerprint"],
        request.current_device_signing_fingerprint
    );
    install_manifest(&mut f.connect().await, &owner, &request)
        .await
        .unwrap();
    let accepted: i64 =
        f.db.query_one(
            "SELECT accepted_at_ms FROM sealed_manifest_authorities",
            &[],
        )
        .await
        .unwrap()
        .get(0);
    install_manifest(&mut f.connect().await, &owner, &request)
        .await
        .unwrap();
    assert_eq!(
        f.db.query_one(
            "SELECT accepted_at_ms FROM sealed_manifest_authorities",
            &[]
        )
        .await
        .unwrap()
        .get::<_, i64>(0),
        accepted
    );
    let after = bootstrap_manifest(&mut f.connect().await, &owner, &selected(&f))
        .await
        .unwrap();
    assert_eq!(after["manifest_version"], "1");
    assert_eq!(after["current_manifest"], request.signed_manifest);
    for table in ["owner_conversation_consents", "conversation_intervals"] {
        assert_eq!(
            f.db.query_one(&format!("SELECT count(*) FROM {table}"), &[])
                .await
                .unwrap()
                .get::<_, i64>(0),
            0
        );
    }
    f.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; isolated synthetic schema"]
async fn genesis_rejects_changed_comparison_scope_key_and_signed_fork() {
    let (mut f, owner, mut request) = case().await;
    let original = request.expected_root_fingerprint.clone();
    request.expected_root_fingerprint = STANDARD.encode([0u8; 32]);
    assert!(
        install_manifest(&mut f.connect().await, &owner, &request)
            .await
            .is_err()
    );
    request.expected_root_fingerprint = original;
    let point = request.phone_reader_point.clone();
    request.phone_reader_point = request.archive_reader_point.clone();
    assert!(
        install_manifest(&mut f.connect().await, &owner, &request)
            .await
            .is_err()
    );
    request.phone_reader_point = point;
    request.binding_generation = 2;
    assert!(
        install_manifest(&mut f.connect().await, &owner, &request)
            .await
            .is_err()
    );
    request.binding_generation = 1;
    let key = request.current_device_signing_fingerprint.clone();
    request.current_device_signing_fingerprint = STANDARD.encode([0u8; 32]);
    assert!(
        install_manifest(&mut f.connect().await, &owner, &request)
            .await
            .is_err()
    );
    request.current_device_signing_fingerprint = key;
    install_manifest(&mut f.connect().await, &owner, &request)
        .await
        .unwrap();
    let issued = u64::from_be_bytes(f.bytes[37..45].try_into().unwrap());
    f.bytes[37..45].copy_from_slice(&(issued + 1).to_be_bytes());
    for i in 0..4 {
        f.bytes[151 + i * 149 + 132..151 + i * 149 + 140]
            .copy_from_slice(&(issued + 1).to_be_bytes());
    }
    f.resign();
    request.signed_manifest = STANDARD.encode(&f.bytes);
    assert!(matches!(
        install_manifest(&mut f.connect().await, &owner, &request).await,
        Err(ConversationError::Conflict)
    ));
    f.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; isolated synthetic schema"]
async fn genesis_rejects_signed_role_windows_that_differ_from_manifest_validity() {
    let (mut f, owner, mut request) = case().await;
    let original = f.bytes.clone();
    let issued = u64::from_be_bytes(original[37..45].try_into().unwrap());
    let expires = u64::from_be_bytes(original[45..53].try_into().unwrap());
    for i in 0..4 {
        for (offset, value) in [(132, issued - 1), (140, expires + 1)] {
            f.bytes = original.clone();
            let at = 151 + i * 149 + offset;
            f.bytes[at..at + 8].copy_from_slice(&value.to_be_bytes());
            f.resign();
            let now: i64 =
                f.db.query_one(
                    "SELECT floor(extract(epoch FROM clock_timestamp())*1000)::bigint",
                    &[],
                )
                .await
                .unwrap()
                .get(0);
            // The generic manifest protocol permits wider role windows. This
            // owner-signed input must be rejected by the strict genesis profile.
            sealed_manifest::verify(
                &f.pin,
                &f.bytes,
                &ManifestTrust {
                    account_id: *f.account.as_bytes(),
                    root_fingerprint: decode(&request.expected_root_fingerprint, 32)
                        .unwrap()
                        .try_into()
                        .unwrap(),
                    generation: 1,
                    position: ChainPosition::Genesis {
                        anchor_digest: [0; 32],
                    },
                },
                now as u64,
            )
            .unwrap();
            request.signed_manifest = STANDARD.encode(&f.bytes);
            assert!(matches!(
                install_manifest(&mut f.connect().await, &owner, &request).await,
                Err(ConversationError::Forbidden)
            ));
            assert_eq!(
                f.db.query_one("SELECT version FROM sealed_manifest_authorities", &[])
                    .await
                    .unwrap()
                    .get::<_, i64>(0),
                0
            );
        }
    }
    f.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; isolated synthetic schema"]
async fn genesis_rejects_signed_lifetime_exceeding_twenty_four_hours() {
    let (mut f, owner, mut request) = case().await;
    let issued = u64::from_be_bytes(f.bytes[37..45].try_into().unwrap());
    let expires = issued + 86_400_001;
    f.bytes[45..53].copy_from_slice(&expires.to_be_bytes());
    for i in 0..4 {
        f.bytes[151 + i * 149 + 140..151 + i * 149 + 148].copy_from_slice(&expires.to_be_bytes());
    }
    f.resign();
    request.signed_manifest = STANDARD.encode(&f.bytes);
    assert!(matches!(
        install_manifest(&mut f.connect().await, &owner, &request).await,
        Err(ConversationError::Forbidden)
    ));
    assert_eq!(
        f.db.query_one("SELECT version FROM sealed_manifest_authorities", &[])
            .await
            .unwrap()
            .get::<_, i64>(0),
        0
    );
    f.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; isolated synthetic schema"]
async fn genesis_rejects_revoked_key_expired_device_session_disabled_and_foreign_owner() {
    let (f, owner, request) = case().await;
    for sql in [
        "UPDATE device_keys SET revoked_at=clock_timestamp()",
        "UPDATE device_keys SET revoked_at=NULL; UPDATE device_sessions SET lease_until=clock_timestamp()-interval '1 second'",
        "UPDATE accounts SET disabled_at=clock_timestamp()",
    ] {
        f.db.batch_execute(sql).await.unwrap();
        assert!(
            bootstrap_manifest(&mut f.connect().await, &owner, &selected(&f))
                .await
                .is_err()
        );
        assert!(
            install_manifest(&mut f.connect().await, &owner, &request)
                .await
                .is_err()
        );
    }
    f.db.batch_execute("UPDATE accounts SET disabled_at=NULL; UPDATE device_keys SET revoked_at=NULL; UPDATE device_sessions SET lease_until=clock_timestamp()+interval '10 minutes'").await.unwrap();
    let other = Uuid::new_v4();
    f.db.execute("INSERT INTO accounts(id) VALUES($1)", &[&other])
        .await
        .unwrap();
    let foreign = super::super::tests::owner_for(&f, other).await;
    assert!(
        install_manifest(&mut f.connect().await, &foreign, &request)
            .await
            .is_err()
    );
    f.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; isolated synthetic schema"]
async fn genesis_rechecks_owner_expiry_after_authority_lock_wait() {
    let (f, owner, request) = case().await;
    f.db.execute(
        "UPDATE sessions SET expires_at=clock_timestamp()+interval '300 milliseconds' WHERE id=$1",
        &[&owner.session_id],
    )
    .await
    .unwrap();
    let mut blocker = f.connect().await;
    let tx = blocker.transaction().await.unwrap();
    tx.query_one(
        "SELECT account_id FROM sealed_manifest_authorities WHERE account_id=$1 FOR UPDATE",
        &[&f.account],
    )
    .await
    .unwrap();
    let mut db = f.connect().await;
    let pending = tokio::spawn(async move { install_manifest(&mut db, &owner, &request).await });
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    tx.commit().await.unwrap();
    assert!(pending.await.unwrap().is_err());
    assert_eq!(
        f.db.query_one("SELECT version FROM sealed_manifest_authorities", &[])
            .await
            .unwrap()
            .get::<_, i64>(0),
        0
    );
    f.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; isolated synthetic schema"]
async fn genesis_bootstrap_rechecks_device_lease_after_session_lock_wait() {
    let (f, owner, _) = case().await;
    f.db.execute("UPDATE device_sessions SET lease_until=clock_timestamp()+interval '300 milliseconds' WHERE device_id=$1",&[&f.device]).await.unwrap();
    let mut blocker = f.connect().await;
    let tx = blocker.transaction().await.unwrap();
    tx.query_one(
        "SELECT device_id FROM device_sessions WHERE device_id=$1 FOR UPDATE",
        &[&f.device],
    )
    .await
    .unwrap();
    let mut db = f.connect().await;
    let selection = selected(&f);
    let pending =
        tokio::spawn(async move { bootstrap_manifest(&mut db, &owner, &selection).await });
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    tx.commit().await.unwrap();
    assert!(pending.await.unwrap().is_err());
    f.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; isolated synthetic schema"]
async fn genesis_rejects_expired_manifest_and_database_time_regression() {
    let (mut f, owner, mut request) = case().await;
    let original = f.bytes.clone();
    let issued = u64::from_be_bytes(f.bytes[37..45].try_into().unwrap());
    f.bytes[45..53].copy_from_slice(&(issued + 1).to_be_bytes());
    f.resign();
    request.signed_manifest = STANDARD.encode(&f.bytes);
    assert!(
        install_manifest(&mut f.connect().await, &owner, &request)
            .await
            .is_err()
    );
    f.bytes = original;
    request.signed_manifest = STANDARD.encode(&f.bytes);
    install_manifest(&mut f.connect().await, &owner, &request)
        .await
        .unwrap();
    f.db.batch_execute(
        "UPDATE sealed_manifest_authorities SET last_verified_ms=last_verified_ms+86400000",
    )
    .await
    .unwrap();
    assert!(
        install_manifest(&mut f.connect().await, &owner, &request)
            .await
            .is_err()
    );
    assert!(
        bootstrap_manifest(&mut f.connect().await, &owner, &selected(&f))
            .await
            .is_err()
    );
    f.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; isolated synthetic schema"]
async fn genesis_http_requires_matching_origin_and_csrf_before_body() {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use hmac::{Hmac, KeyInit, Mac};
    let (f, owner, _) = case().await;
    let token = format!("zts_{}", URL_SAFE_NO_PAD.encode(rand::random::<[u8; 32]>()));
    let csrf = format!("ztc_{}", URL_SAFE_NO_PAD.encode(rand::random::<[u8; 32]>()));
    let hash = |domain: &[u8], value: &str| {
        let mut mac = Hmac::<Sha256>::new_from_slice(&crate::test_keys::key(84)).unwrap();
        mac.update(domain);
        mac.update(value.as_bytes());
        mac.finalize().into_bytes().to_vec()
    };
    f.db.execute(
        "UPDATE sessions SET token_hash=$1,csrf_hash=$2 WHERE id=$3",
        &[
            &hash(b"session-v1\0", &token),
            &hash(b"csrf-v1\0", &csrf),
            &owner.session_id,
        ],
    )
    .await
    .unwrap();
    let sep = if f.url.contains('?') { '&' } else { '?' };
    let url = format!("{}{sep}options=-csearch_path%3D{}", f.url, f.schema);
    for path in [
        "/v1/owner/conversation/genesis/bootstrap",
        "/v1/owner/conversation/genesis/install",
    ] {
        for (origin, header_csrf) in [
            ("https://other.example", csrf.as_str()),
            ("https://test.example", "ztc_wrong"),
        ] {
            let app = super::super::owner_host::router(OwnerConversationsState {
                database_url: url.clone(),
                auth_hasher: Arc::new(
                    crate::auth::TokenHasher::new(crate::test_keys::key(84)).unwrap(),
                ),
                canonical_origin: "https://test.example".into(),
            });
            let body = Body::from_stream(futures_util::stream::pending::<
                Result<axum::body::Bytes, std::io::Error>,
            >());
            let response = tokio::time::timeout(
                std::time::Duration::from_secs(2),
                app.oneshot(
                    Request::post(path)
                        .header("origin", origin)
                        .header(
                            "cookie",
                            format!("__Host-zrotext_session={token}; __Host-zrotext_csrf={csrf}"),
                        )
                        .header("x-zrotext-csrf", header_csrf)
                        .body(body)
                        .unwrap(),
                ),
            )
            .await
            .unwrap()
            .unwrap();
            assert_eq!(response.status(), StatusCode::FORBIDDEN);
        }
    }
    f.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; isolated synthetic schema"]
async fn genesis_final_write_wait_cannot_outlive_owner_or_phone_authority() {
    for expire_owner in [true, false] {
        let (f, owner, request) = case().await;
        bootstrap_manifest(&mut f.connect().await, &owner, &selected(&f))
            .await
            .unwrap();
        f.db.batch_execute(
            "CREATE FUNCTION genesis_final_write_wait() RETURNS trigger LANGUAGE plpgsql AS $$
             BEGIN PERFORM pg_advisory_xact_lock(737, 1); RETURN NEW; END $$;
             CREATE TRIGGER genesis_final_write_wait BEFORE UPDATE ON sealed_manifest_authorities
             FOR EACH ROW WHEN (NEW.version=OLD.version)
             EXECUTE FUNCTION genesis_final_write_wait();",
        )
        .await
        .unwrap();
        let mut blocker = f.connect().await;
        let held = blocker.transaction().await.unwrap();
        held.query_one("SELECT pg_advisory_xact_lock(737, 1)", &[])
            .await
            .unwrap();
        let blocker_pid: i32 = held
            .query_one("SELECT pg_backend_pid()", &[])
            .await
            .unwrap()
            .get(0);
        let sql = if expire_owner {
            "UPDATE sessions SET expires_at=clock_timestamp()+interval '4 seconds' WHERE id=$1 RETURNING expires_at>clock_timestamp()"
        } else {
            "UPDATE device_sessions SET lease_until=clock_timestamp()+interval '4 seconds' WHERE device_id=$1 RETURNING lease_until>clock_timestamp()"
        };
        let identity = if expire_owner {
            owner.session_id
        } else {
            f.device
        };
        assert!(
            f.db.query_one(sql, &[&identity])
                .await
                .unwrap()
                .get::<_, bool>(0)
        );
        let mut db = f.connect().await;
        let writer_pid: i32 = db
            .query_one("SELECT pg_backend_pid()", &[])
            .await
            .unwrap()
            .get(0);
        let pending =
            tokio::spawn(async move { install_manifest(&mut db, &owner, &request).await });
        let observed = tokio::time::timeout(std::time::Duration::from_secs(6), async {
            loop {
                if f.db
                    .query_one(
                        "SELECT $1=ANY(pg_blocking_pids($2))",
                        &[&blocker_pid, &writer_pid],
                    )
                    .await
                    .unwrap()
                    .get::<_, bool>(0)
                {
                    break;
                }
                assert!(
                    !pending.is_finished(),
                    "installation ended before its final-write wait"
                );
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
        })
        .await;
        assert!(
            observed.is_ok(),
            "installation never reached its final-write barrier"
        );
        let expiry_query = if expire_owner {
            "SELECT expires_at<=clock_timestamp() FROM sessions WHERE id=$1"
        } else {
            "SELECT lease_until<=clock_timestamp() FROM device_sessions WHERE device_id=$1"
        };
        tokio::time::timeout(std::time::Duration::from_secs(6), async {
            while !f
                .db
                .query_one(expiry_query, &[&identity])
                .await
                .unwrap()
                .get::<_, bool>(0)
            {
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();
        held.commit().await.unwrap();
        let result = pending.await.unwrap();
        let row = f.db.query_one(
            "SELECT version,manifest IS NULL,accepted_at_ms IS NULL,last_verified_ms FROM sealed_manifest_authorities", &[]
        ).await.unwrap();
        let state = (
            row.get::<_, i64>(0),
            row.get::<_, bool>(1),
            row.get::<_, bool>(2),
            row.get::<_, i64>(3),
        );
        f.db.batch_execute("DROP TRIGGER genesis_final_write_wait ON sealed_manifest_authorities; DROP FUNCTION genesis_final_write_wait();").await.unwrap();
        f.cleanup().await;
        assert!(
            matches!(result, Err(ConversationError::Forbidden)),
            "expired authority committed after final write: {result:?}"
        );
        assert_eq!(state, (0, true, true, 0));
    }
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; isolated synthetic schema"]
async fn genesis_install_rejects_a_different_live_owner_session_before_mutation() {
    let (f, owner, request) = case().await;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use hmac::{Hmac, KeyInit, Mac};
    let token = format!("zts_{}", URL_SAFE_NO_PAD.encode(rand::random::<[u8; 32]>()));
    let hasher = crate::auth::TokenHasher::new(crate::test_keys::key(84)).unwrap();
    let mut mac = Hmac::<Sha256>::new_from_slice(&crate::test_keys::key(84)).unwrap();
    mac.update(b"session-v1\0");
    mac.update(token.as_bytes());
    let hash = mac.finalize().into_bytes().to_vec();
    f.db.execute(
        "INSERT INTO sessions(id,account_id,user_id,token_hash,csrf_hash,expires_at) VALUES($1,$2,$3,$4,$5,clock_timestamp()+interval '1 hour')",
        &[&Uuid::new_v4(), &f.account, &owner.user_id, &hash, &vec![4u8;32]],
    ).await.unwrap();
    let replacement = crate::auth::authenticate_session(&f.db, &hasher, &token)
        .await
        .unwrap();
    bootstrap_manifest(&mut f.connect().await, &replacement, &selected(&f))
        .await
        .unwrap();
    let result = install_manifest(&mut f.connect().await, &replacement, &request).await;
    let row = f.db.query_one(
        "SELECT version,manifest IS NULL,accepted_at_ms IS NULL,last_verified_ms FROM sealed_manifest_authorities", &[]
    ).await.unwrap();
    let state = (
        row.get::<_, i64>(0),
        row.get::<_, bool>(1),
        row.get::<_, bool>(2),
        row.get::<_, i64>(3),
    );
    if matches!(result, Err(ConversationError::Forbidden)) {
        install_manifest(&mut f.connect().await, &owner, &request)
            .await
            .unwrap();
    }
    f.cleanup().await;
    assert!(
        matches!(result, Err(ConversationError::Forbidden)),
        "another live session installed the original ceremony: {result:?}"
    );
    assert_eq!(state, (0, true, true, 0));
}

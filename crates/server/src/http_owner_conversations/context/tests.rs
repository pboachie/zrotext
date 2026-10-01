// SPDX-License-Identifier: AGPL-3.0-only
use super::*;
use crate::{
    http_owner_conversations::activation::tests::{activate, capture, pending},
    sealed_manifest_store::tests::Fixture,
};

pub(crate) struct Case {
    pub(crate) f: Fixture,
    pub(crate) owner: SessionPrincipal,
    pub(crate) s: activation::Statement,
    pub(crate) h: wire::Header,
}
impl Case {
    pub(crate) async fn new() -> Self {
        let (f, owner, s) = pending().await;
        activate(&f, &s).await;
        let r=f.db.query_one("SELECT generation,version,semantic_digest FROM sealed_manifest_authorities WHERE account_id=$1",&[&f.account]).await.unwrap();
        let now = activation::now(&f.connect().await.transaction().await.unwrap())
            .await
            .unwrap();
        let h = wire::Header {
            kind: 1,
            account: f.account,
            device: f.device,
            line: f.line,
            interval: s.interval,
            context: Uuid::new_v4(),
            binding_generation: 1,
            revision: 1,
            expires_ms: now + 600000,
            trust_generation: r.get(0),
            manifest_version: r.get(1),
            peer_digest: Sha256::digest(s.peer.as_bytes()).into(),
            reader: s.reader,
            manifest_digest: r.get::<_, Vec<u8>>(2).try_into().unwrap(),
        };
        Self { f, owner, s, h }
    }
    pub(crate) fn bytes(&self) -> Vec<u8> {
        Self::envelope(&self.h, 88)
    }
    pub(crate) fn envelope(h: &wire::Header, value: u8) -> Vec<u8> {
        let mut b = h.aad().unwrap();
        let key = p256::SecretKey::from_slice(&[1; 32]).unwrap();
        b.extend(key.public_key().to_sec1_bytes());
        b.extend(33u32.to_be_bytes());
        b.extend([value; 33]);
        b
    }
    async fn write(
        &self,
        request: Uuid,
        expected: i64,
        bytes: &[u8],
    ) -> Result<i64, ConversationError> {
        write(
            &mut self.f.connect().await,
            &self.owner,
            request,
            expected,
            bytes,
        )
        .await
    }
    async fn insert_message(&self, state: &str, peer: &str) -> Uuid {
        let id = Uuid::new_v4();
        // Synthetic opaque body; this fixture tests metadata source binding,
        // while the SDK separately exercises real client encryption.
        let mut payload = vec![88u8; 426];
        payload[..6].copy_from_slice(b"ZTSE\x02\x01");
        let payload = Some(payload);
        self.f.db.execute("INSERT INTO messages(id,account_id,device_id,recipient_e164,recipient_digest,transport_mode,transport_payload,request_digest,state,expires_at,sealed_line_id,sealed_binding_generation,sealed_manifest_generation,sealed_manifest_version,sealed_manifest_digest,sealed_signer_key_id) VALUES($1,$2,$3,$4,$5,'sealed_candidate02',$6,$5,$7,clock_timestamp()+interval '1 hour',$8,1,$9,$10,$11,$12)",
            &[&id,&self.f.account,&self.f.device,&peer,&vec![1u8;32],&payload,&state,&self.f.line,&self.h.trust_generation,&self.h.manifest_version,&self.h.manifest_digest.as_slice(),&self.s.signer.as_slice()]).await.unwrap();
        id
    }
    pub(crate) async fn cleanup(self) {
        self.f.cleanup().await;
    }
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; isolated synthetic schema"]
async fn encrypted_versions_replay_exactly_and_concurrent_compare_and_swap_has_one_winner() {
    let c = Case::new().await;
    let bytes = c.bytes();
    let request = Uuid::new_v4();
    assert_eq!(c.write(request, 0, &bytes).await.unwrap(), 1);
    assert_eq!(c.write(request, 0, &bytes).await.unwrap(), 1);
    assert!(
        c.write(request, 0, &Case::envelope(&c.h, 89))
            .await
            .is_err()
    );
    assert_eq!(
        read(&mut c.f.connect().await, &c.owner, c.h.context, None)
            .await
            .unwrap(),
        bytes
    );
    let mut next = c.h.clone();
    next.revision = 2;
    let a = Case::envelope(&next, 90);
    let b = Case::envelope(&next, 91);
    let (ra, rb) = tokio::join!(
        c.write(Uuid::new_v4(), 1, &a),
        c.write(Uuid::new_v4(), 1, &b)
    );
    assert_eq!(usize::from(ra.is_ok()) + usize::from(rb.is_ok()), 1);
    assert_eq!(
        read(&mut c.f.connect().await, &c.owner, c.h.context, Some(1))
            .await
            .unwrap(),
        bytes
    );
    let row=c.f.db.query_one("SELECT (SELECT count(*) FROM workflow_context_versions),(SELECT count(*) FROM workflow_context_audit),revision FROM workflow_contexts",&[]).await.unwrap();
    assert_eq!(row.get::<_, i64>(0), 2);
    assert_eq!(row.get::<_, i64>(1), 2);
    assert_eq!(row.get::<_, i64>(2), 2);
    assert!(
        c.f.db
            .execute(
                "UPDATE workflow_contexts SET peer_digest=$1",
                &[&vec![9u8; 32]]
            )
            .await
            .is_err()
    );
    assert!(
        c.f.db
            .execute("UPDATE workflow_context_versions SET envelope=$1", &[&a])
            .await
            .is_err()
    );
    c.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; isolated synthetic schema"]
async fn foreign_context_binding_reader_manifest_and_owner_revocation_are_refused() {
    let c = Case::new().await;
    let bytes = c.bytes();
    c.write(Uuid::new_v4(), 0, &bytes).await.unwrap();
    assert!(
        read(&mut c.f.connect().await, &c.owner, Uuid::new_v4(), None)
            .await
            .is_err()
    );
    let mut variants = Vec::new();
    for field in 0..8 {
        let mut h = c.h.clone();
        h.context = Uuid::new_v4();
        match field {
            0 => h.account = Uuid::new_v4(),
            1 => h.device = Uuid::new_v4(),
            2 => h.line = Uuid::new_v4(),
            3 => h.interval = Uuid::new_v4(),
            4 => h.reader = [8; 32],
            5 => h.peer_digest = [8; 32],
            6 => h.trust_generation += 1,
            _ => h.manifest_digest = [8; 32],
        };
        variants.push(h);
    }
    for h in variants {
        assert!(
            c.write(Uuid::new_v4(), 0, &Case::envelope(&h, 88))
                .await
                .is_err()
        );
    }
    c.f.db
        .execute(
            "UPDATE sessions SET revoked_at=clock_timestamp() WHERE account_id=$1",
            &[&c.f.account],
        )
        .await
        .unwrap();
    assert!(
        read(&mut c.f.connect().await, &c.owner, c.h.context, None)
            .await
            .is_err()
    );
    assert_eq!(
        c.f.db
            .query_one("SELECT count(*) FROM workflow_contexts", &[])
            .await
            .unwrap()
            .get::<_, i64>(0),
        1
    );
    c.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; isolated synthetic schema"]
async fn deterministic_exceptions_validate_provenance_state_and_versioned_resolution() {
    let c = Case::new().await;
    c.write(Uuid::new_v4(), 0, &c.bytes()).await.unwrap();
    let event = Uuid::new_v4();
    capture(&c.f, &c.s, event, 1, b"+12").await.unwrap();
    let base = ExceptionInput {
        context_id: c.h.context,
        context_revision: 1,
        source_kind: 1,
        source_id: event,
        reason: 1,
    };
    let id = exception(&mut c.f.connect().await, &c.owner, base)
        .await
        .unwrap();
    let mut left = c.f.connect().await;
    let mut right = c.f.connect().await;
    let (ra, rb) = tokio::join!(
        exception(&mut left, &c.owner, base),
        exception(&mut right, &c.owner, base)
    );
    assert_eq!(ra.unwrap(), id);
    assert_eq!(rb.unwrap(), id);
    assert!(
        exception(
            &mut c.f.connect().await,
            &c.owner,
            ExceptionInput {
                source_id: Uuid::new_v4(),
                ..base
            }
        )
        .await
        .is_err()
    );
    assert!(
        exception(
            &mut c.f.connect().await,
            &c.owner,
            ExceptionInput {
                context_revision: 2,
                ..base
            }
        )
        .await
        .is_err()
    );
    let mismatch = exception(
        &mut c.f.connect().await,
        &c.owner,
        ExceptionInput { reason: 5, ..base },
    )
    .await
    .unwrap();
    assert_ne!(id, mismatch);
    for (state, reason) in [("expired", 3), ("cancelled", 4)] {
        let source = c.insert_message(state, "+12").await;
        let input = ExceptionInput {
            source_kind: 2,
            source_id: source,
            reason,
            ..base
        };
        let created = exception(&mut c.f.connect().await, &c.owner, input)
            .await
            .unwrap();
        assert_eq!(
            exception(&mut c.f.connect().await, &c.owner, input)
                .await
                .unwrap(),
            created
        );
        assert!(
            exception(
                &mut c.f.connect().await,
                &c.owner,
                ExceptionInput { reason: 2, ..input }
            )
            .await
            .is_err()
        );
    }
    let other_peer = c.insert_message("cancelled", "+13").await;
    assert!(
        exception(
            &mut c.f.connect().await,
            &c.owner,
            ExceptionInput {
                source_kind: 2,
                source_id: other_peer,
                reason: 4,
                ..base
            }
        )
        .await
        .is_err()
    );
    let request = Uuid::new_v4();
    assert_eq!(
        resolve(&mut c.f.connect().await, &c.owner, id, request, 1)
            .await
            .unwrap(),
        2
    );
    assert_eq!(
        resolve(&mut c.f.connect().await, &c.owner, id, request, 1)
            .await
            .unwrap(),
        2
    );
    assert!(
        resolve(&mut c.f.connect().await, &c.owner, id, Uuid::new_v4(), 1)
            .await
            .is_err()
    );
    let page = lifecycle::exceptions(&mut c.f.connect().await, &c.owner, c.h.context, None)
        .await
        .unwrap();
    assert_eq!(page.items.len(), 4);
    assert!(
        lifecycle::exceptions(
            &mut c.f.connect().await,
            &c.owner,
            c.h.context,
            Some(Uuid::new_v4())
        )
        .await
        .is_err()
    );
    assert_eq!(
        c.f.db
            .query_one("SELECT count(*) FROM workflow_exceptions", &[])
            .await
            .unwrap()
            .get::<_, i64>(0),
        4
    );
    c.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; isolated synthetic schema"]
async fn withdrawal_revokes_read_then_bounded_retention_purges_without_rehydration() {
    let c = Case::new().await;
    let bytes = c.bytes();
    c.write(Uuid::new_v4(), 0, &bytes).await.unwrap();
    activation::close(&mut c.f.connect().await, &c.owner, c.s.interval, true)
        .await
        .unwrap();
    assert!(
        read(&mut c.f.connect().await, &c.owner, c.h.context, None)
            .await
            .is_err()
    );
    assert_eq!(
        lifecycle::prune(&mut c.f.connect().await, 0, 1)
            .await
            .unwrap(),
        1
    );
    let r =
        c.f.db
            .query_one(
                "SELECT envelope IS NULL,request_digest FROM workflow_context_versions",
                &[],
            )
            .await
            .unwrap();
    assert!(r.get::<_, bool>(0));
    assert_eq!(r.get::<_, Vec<u8>>(1), Sha256::digest(&bytes).to_vec());
    assert!(c.write(Uuid::new_v4(), 0, &bytes).await.is_err());
    assert_eq!(
        lifecycle::prune(&mut c.f.connect().await, 0, 1)
            .await
            .unwrap(),
        1
    );
    assert_eq!(
        c.f.db
            .query_one("SELECT count(*) FROM workflow_contexts", &[])
            .await
            .unwrap()
            .get::<_, i64>(0),
        0
    );
    c.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; isolated synthetic schema"]
async fn current_reader_revocation_blocks_content_but_owner_takeout_remains_opaque() {
    let c = Case::new().await;
    c.write(Uuid::new_v4(), 0, &c.bytes()).await.unwrap();
    c.f.db.execute("UPDATE sealed_manifest_authorities SET revoked_at=clock_timestamp() WHERE account_id=$1",&[&c.f.account]).await.unwrap();
    assert!(
        read(&mut c.f.connect().await, &c.owner, c.h.context, None)
            .await
            .is_err()
    );
    let exported = lifecycle::export(&mut c.f.connect().await, &c.owner, [None; 4])
        .await
        .unwrap();
    assert_eq!(exported.contexts.items.len(), 1);
    assert_eq!(exported.versions.items.len(), 1);
    assert_eq!(exported.audit.items.len(), 1);
    let json = serde_json::to_string(&exported).unwrap();
    assert!(!json.contains("synthetic workflow private canary"));
    assert!(json.contains("envelope_hex"));
    assert!(
        lifecycle::export(
            &mut c.f.connect().await,
            &c.owner,
            [Some(Uuid::new_v4()), None, None, None]
        )
        .await
        .is_err()
    );
    c.cleanup().await;
}

#[test]
fn exception_identity_is_stable_across_replay_but_not_sources_or_reasons() {
    let account = Uuid::from_u128(1);
    let input = ExceptionInput {
        context_id: Uuid::from_u128(2),
        context_revision: 1,
        source_kind: 1,
        source_id: Uuid::from_u128(3),
        reason: 1,
    };
    assert_eq!(
        exception_id(account, input),
        exception_id(
            account,
            ExceptionInput {
                context_revision: 2,
                ..input
            }
        )
    );
    assert_ne!(
        input.digest(account).unwrap(),
        ExceptionInput {
            context_revision: 2,
            ..input
        }
        .digest(account)
        .unwrap()
    );
    assert_ne!(
        exception_id(account, input),
        exception_id(account, ExceptionInput { reason: 5, ..input })
    );
    assert!(
        ExceptionInput {
            source_kind: 1,
            reason: 2,
            ..input
        }
        .digest(account)
        .is_err()
    );
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; isolated synthetic schema"]
async fn audit_cap_rolls_back_new_head_and_export_cursors_are_bounded() {
    let c = Case::new().await;
    c.write(Uuid::new_v4(), 0, &c.bytes()).await.unwrap();
    c.f.db.execute("INSERT INTO workflow_context_audit(account_id,context_id,id,operation,subject_id,revision,request_id,request_digest,actor_user_id) SELECT $1,$2,gen_random_uuid(),1,$2,1,gen_random_uuid(),$3,$4 FROM generate_series(1,8191)",&[&c.f.account,&c.h.context,&vec![1u8;32],&c.owner.user_id]).await.unwrap();
    let mut next = c.h.clone();
    next.revision = 2;
    assert!(
        c.write(Uuid::new_v4(), 1, &Case::envelope(&next, 99))
            .await
            .is_err()
    );
    let row=c.f.db.query_one("SELECT revision,(SELECT count(*) FROM workflow_context_versions),(SELECT count(*) FROM workflow_context_audit) FROM workflow_contexts",&[]).await.unwrap();
    assert_eq!(row.get::<_, i64>(0), 1);
    assert_eq!(row.get::<_, i64>(1), 1);
    assert_eq!(row.get::<_, i64>(2), 8192);
    let page = lifecycle::export(&mut c.f.connect().await, &c.owner, [None; 4])
        .await
        .unwrap();
    assert_eq!(page.audit.items.len(), 20);
    let cursor = page.audit.next_cursor.unwrap();
    let next = lifecycle::export(
        &mut c.f.connect().await,
        &c.owner,
        [None, None, None, Some(cursor)],
    )
    .await
    .unwrap();
    assert_eq!(next.audit.items.len(), 20);
    assert!(
        !next
            .audit
            .items
            .iter()
            .any(|r| page.audit.items.contains(r))
    );
    assert!(
        c.f.db
            .execute("UPDATE workflow_context_audit SET revision=2", &[])
            .await
            .is_err()
    );
    c.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; isolated synthetic schema"]
async fn expiry_removes_reader_access_and_cannot_extend_an_expired_context() {
    let mut c = Case::new().await;
    let now: i64 =
        c.f.db
            .query_one(
                "SELECT floor(extract(epoch FROM clock_timestamp())*1000)::bigint",
                &[],
            )
            .await
            .unwrap()
            .get(0);
    c.h.expires_ms = now + 30_000;
    let bytes = c.bytes();
    c.write(Uuid::new_v4(), 0, &bytes).await.unwrap();
    let remaining: i64 = c.f.db.query_one("SELECT GREATEST($1::bigint-floor(extract(epoch FROM clock_timestamp())*1000)::bigint,0)", &[&c.h.expires_ms]).await.unwrap().get(0);
    tokio::time::sleep(std::time::Duration::from_millis(
        remaining.clamp(0, 30_000) as u64 + 100,
    ))
    .await;
    assert!(
        read(&mut c.f.connect().await, &c.owner, c.h.context, None)
            .await
            .is_err()
    );
    let mut next = c.h.clone();
    next.revision = 2;
    next.expires_ms += 600000;
    assert!(
        c.write(Uuid::new_v4(), 1, &Case::envelope(&next, 99))
            .await
            .is_err()
    );
    assert_eq!(
        lifecycle::prune(&mut c.f.connect().await, 30, 1)
            .await
            .unwrap(),
        1
    );
    c.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; isolated synthetic schema"]
async fn erasure_plan_removes_all_introduced_records_before_conversation_parents() {
    let c = Case::new().await;
    c.write(Uuid::new_v4(), 0, &c.bytes()).await.unwrap();
    let event = Uuid::new_v4();
    capture(&c.f, &c.s, event, 1, b"+12").await.unwrap();
    exception(
        &mut c.f.connect().await,
        &c.owner,
        ExceptionInput {
            context_id: c.h.context,
            context_revision: 1,
            source_kind: 1,
            source_id: event,
            reason: 1,
        },
    )
    .await
    .unwrap();
    let mut client = c.f.connect().await;
    let tx = client.transaction().await.unwrap();
    let mut names = Vec::new();
    for (table, sql) in crate::http_owner_erasure::DELETE_PLAN {
        if table.starts_with("workflow_") {
            assert!(tx.execute(*sql, &[&c.f.account]).await.unwrap() > 0);
            names.push(*table);
        }
    }
    assert_eq!(
        names,
        [
            "workflow_context_audit",
            "workflow_exceptions",
            "workflow_context_versions",
            "workflow_contexts"
        ]
    );
    tx.commit().await.unwrap();
    assert!(
        read(&mut c.f.connect().await, &c.owner, c.h.context, None)
            .await
            .is_err()
    );
    c.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; isolated synthetic schema"]
async fn expiry_during_version_insert_rolls_back_context_ciphertext_and_audit() {
    let mut c = Case::new().await;
    c.f.db.batch_execute("CREATE SEQUENCE context_delay_calls; CREATE FUNCTION delay_context_version() RETURNS trigger LANGUAGE plpgsql AS $$ DECLARE remaining double precision; BEGIN PERFORM nextval('context_delay_calls'); SELECT LEAST(GREATEST((expires_at_ms-floor(extract(epoch FROM clock_timestamp())*1000)::bigint)::double precision/1000,0),30) INTO remaining FROM workflow_contexts WHERE account_id=NEW.account_id AND id=NEW.context_id; PERFORM pg_sleep(remaining+0.1); RETURN NEW; END $$; CREATE TRIGGER delay_context_version BEFORE INSERT ON workflow_context_versions FOR EACH ROW EXECUTE FUNCTION delay_context_version()").await.unwrap();
    let now: i64 =
        c.f.db
            .query_one(
                "SELECT floor(extract(epoch FROM clock_timestamp())*1000)::bigint",
                &[],
            )
            .await
            .unwrap()
            .get(0);
    c.h.expires_ms = now + 30_000;
    assert!(c.write(Uuid::new_v4(), 0, &c.bytes()).await.is_err());
    assert!(
        c.f.db
            .query_one("SELECT is_called FROM context_delay_calls", &[])
            .await
            .unwrap()
            .get::<_, bool>(0),
        "the expiry test must reach its blocking insert before refusal"
    );
    let row=c.f.db.query_one("SELECT (SELECT count(*) FROM workflow_contexts),(SELECT count(*) FROM workflow_context_versions),(SELECT count(*) FROM workflow_context_audit)",&[]).await.unwrap();
    for index in 0..3 {
        assert_eq!(row.get::<_, i64>(index), 0);
    }
    c.cleanup().await;
}

#[tokio::test]
async fn unmounted_candidate_rejects_anonymous_and_bearer_requests_without_database_access() {
    use axum::{
        body::Body,
        http::{Request, StatusCode, header},
    };
    use tower::ServiceExt;
    for (method, path) in [
        (
            "GET",
            "/v1/owner/workflow/contexts/00000000-0000-0000-0000-000000000001",
        ),
        ("POST", "/v1/owner/workflow/contexts"),
        ("POST", "/v1/owner/workflow/exceptions"),
    ] {
        for bearer in [false, true] {
            let app = http::router(crate::http_owner_conversations::OwnerConversationsState {
                database_url: "postgres://unused".into(),
                auth_hasher: std::sync::Arc::new(
                    crate::http_owner_conversations::TokenHasher::new(crate::test_keys::key(83))
                        .unwrap(),
                ),
                canonical_origin: "https://zrotext.example".into(),
            });
            let mut request = Request::builder().method(method).uri(path);
            if bearer {
                request = request.header(header::AUTHORIZATION, "Bearer synthetic");
            }
            let response = app
                .oneshot(
                    request
                        .body(Body::from(vec![0; wire::MAX_ENVELOPE + 1]))
                        .unwrap(),
                )
                .await
                .unwrap();
            // Anonymous read proof maps to the existing conversation Forbidden error;
            // bearer middleware and mutation session extraction reject with Unauthorized.
            let expected = if method == "GET" && !bearer {
                StatusCode::FORBIDDEN
            } else {
                StatusCode::UNAUTHORIZED
            };
            assert_eq!(response.status(), expected, "{method} bearer={bearer}");
            assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
            assert_eq!(
                response.headers()[header::X_CONTENT_TYPE_OPTIONS],
                "nosniff"
            );
        }
    }
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; isolated synthetic schema"]
async fn retained_ciphertext_budget_refuses_creation_without_partial_context_or_audit() {
    let mut c = Case::new().await;
    let first = c.h.context;
    c.write(Uuid::new_v4(), 0, &c.bytes()).await.unwrap();
    c.h.context = Uuid::new_v4();
    let second = c.h.context;
    c.write(Uuid::new_v4(), 0, &c.bytes()).await.unwrap();
    // Fixture-only opaque retained versions fill the documented byte budget.
    for (id, last) in [(first, 128i64), (second, 127i64)] {
        c.f.db.execute("INSERT INTO workflow_context_versions(account_id,context_id,id,revision,request_id,request_digest,envelope) SELECT $1,$2,gen_random_uuid(),n,gen_random_uuid(),decode(repeat('ab',32),'hex'),decode(repeat('ab',33075),'hex') FROM generate_series(2,$3::bigint) n",&[&c.f.account,&id,&last]).await.unwrap();
    }
    c.h.context = Uuid::new_v4();
    let candidate = c.h.context;
    let mut bytes = c.h.aad().unwrap();
    let key = p256::SecretKey::from_slice(&[1; 32]).unwrap();
    bytes.extend(key.public_key().to_sec1_bytes());
    bytes.extend(32784u32.to_be_bytes());
    bytes.extend(vec![55; 32784]);
    assert!(matches!(
        c.write(Uuid::new_v4(), 0, &bytes).await,
        Err(ConversationError::Conflict)
    ));
    let row=c.f.db.query_one("SELECT (SELECT count(*) FROM workflow_contexts WHERE id=$1),(SELECT count(*) FROM workflow_context_versions WHERE context_id=$1),(SELECT count(*) FROM workflow_context_audit)",&[&candidate]).await.unwrap();
    assert_eq!(row.get::<_, i64>(0), 0);
    assert_eq!(row.get::<_, i64>(1), 0);
    assert_eq!(row.get::<_, i64>(2), 2);
    c.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; isolated synthetic schema"]
async fn retained_workflow_identity_does_not_extend_closed_interval_peer_statement() {
    let c = Case::new().await;
    c.write(Uuid::new_v4(), 0, &c.bytes()).await.unwrap();
    c.f.db.execute("UPDATE conversation_intervals SET phase='history',closed_at=clock_timestamp()-interval '40 days' WHERE account_id=$1 AND id=$2", &[&c.f.account,&c.s.interval]).await.unwrap();
    super::super::lifecycle::activation::prune(&mut c.f.connect().await, 30, 100)
        .await
        .unwrap();
    let row=c.f.db.query_one("SELECT phase,statement IS NULL FROM conversation_intervals WHERE account_id=$1 AND id=$2", &[&c.f.account,&c.s.interval]).await.unwrap();
    assert_eq!(row.get::<_, String>(0), "withdrawn");
    assert!(row.get::<_, bool>(1));
    assert_eq!(
        c.f.db
            .query_one(
                "SELECT count(*) FROM workflow_contexts WHERE account_id=$1 AND id=$2",
                &[&c.f.account, &c.h.context]
            )
            .await
            .unwrap()
            .get::<_, i64>(0),
        1
    );
    assert_eq!(
        lifecycle::prune(&mut c.f.connect().await, 30, 100)
            .await
            .unwrap(),
        1
    );
    assert!(c.f.db.query_one("SELECT envelope IS NULL FROM workflow_context_versions WHERE account_id=$1 AND context_id=$2", &[&c.f.account,&c.h.context]).await.unwrap().get::<_,bool>(0));
    c.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; isolated synthetic schema"]
async fn another_live_owner_session_cannot_extend_a_revoked_origin_interval() {
    let c = Case::new().await;
    let owner = activation::tests::fresh_session(&c.f, &c.owner).await;
    write(
        &mut c.f.connect().await,
        &owner,
        Uuid::new_v4(),
        0,
        &c.bytes(),
    )
    .await
    .unwrap();
    c.f.db
        .execute(
            "UPDATE sessions SET revoked_at=clock_timestamp() WHERE id=$1",
            &[&c.owner.session_id],
        )
        .await
        .unwrap();
    assert_eq!(
        c.f.db
            .query_one(
                "SELECT phase FROM conversation_intervals WHERE account_id=$1 AND id=$2",
                &[&c.f.account, &c.s.interval]
            )
            .await
            .unwrap()
            .get::<_, String>(0),
        "active",
        "the background closer has not run"
    );
    let mut db = c.f.connect().await;
    let tx = db.transaction().await.unwrap();
    fresh_owner(&tx, &owner).await.unwrap();
    tx.commit().await.unwrap();
    let mut next = c.h.clone();
    next.revision = 2;
    assert!(matches!(
        write(
            &mut c.f.connect().await,
            &owner,
            Uuid::new_v4(),
            1,
            &Case::envelope(&next, 99)
        )
        .await,
        Err(ConversationError::Forbidden)
    ));
    let row=c.f.db.query_one("SELECT (SELECT revision FROM workflow_contexts),(SELECT count(*) FROM workflow_context_versions),(SELECT count(*) FROM workflow_context_audit)", &[]).await.unwrap();
    for i in 0..3 {
        assert_eq!(row.get::<_, i64>(i), 1);
    }
    c.cleanup().await;
}

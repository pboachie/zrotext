// SPDX-License-Identifier: AGPL-3.0-only
use super::*;
use crate::http_owner_conversations::send::Confirmation;
use crate::{
    http_owner_conversations::activation, sealed_envelope::ExpectedRecipient,
    sealed_manifest_store::tests::Fixture,
};
use p256::{
    ecdsa::{Signature, SigningKey, signature::Signer},
    elliptic_curve::Generate,
};

// Allocated proof schema, exercised only in isolated fixtures here. No runtime
// creates this table. Production integration also needs export/retention/erasure
// coordination: proof redaction preserves these immutable identity tombstones.
const SCHEMA: &str = include_str!(
    "../../../../../../deploy/compose/migration-candidates/NNN_conversation_confirmation_records.sql"
);

#[path = "../../channel/execution/tests.rs"]
mod execution_tests;

struct Case {
    f: Fixture,
    owner: SessionPrincipal,
    interval: activation::Statement,
    browser: SigningKey,
    browser_id: [u8; 32],
    phone_reader: ExpectedRecipient,
}

// Independently build the negotiated wire bytes; do not call private production codecs.
fn delivery_frame(
    session: &crate::http_owner_conversations::channel::AuthenticatedChannelSession<'_>,
    statement: &activation::Statement,
    message: Uuid,
    challenge: Uuid,
) -> Vec<u8> {
    let mut bytes = b"ZTCW\x01\x0e".to_vec();
    for id in [
        session.device.account_id,
        session.device.device_id,
        session.phone_session,
    ] {
        bytes.extend(id.as_bytes());
    }
    bytes.extend(session.device.connection_epoch.to_be_bytes());
    bytes.extend(session.device.deployment_epoch.to_be_bytes());
    bytes.extend(session.origin_hash);
    bytes.extend(challenge.as_bytes());
    assert_eq!(bytes.len(), 118);
    for id in [
        statement.account,
        statement.device,
        statement.line,
        statement.interval,
        statement.receipt,
        statement.originating_session,
    ] {
        bytes.extend(id.as_bytes());
    }
    for n in [
        statement.generation,
        statement.trust_generation,
        statement.activation_version,
    ] {
        bytes.extend(n.to_be_bytes());
    }
    bytes.extend(Sha256::digest(
        activation::statement::DISCLOSURE_TEXT.as_bytes(),
    ));
    bytes.extend(statement.reader);
    bytes.extend(statement.activation_digest);
    bytes.extend(statement.digest().unwrap());
    bytes.push(statement.peer.len() as u8);
    bytes.extend(statement.peer.as_bytes());
    bytes.extend(message.as_bytes());
    bytes
}

fn delivery_identity(
    case: &Case,
) -> crate::http_owner_conversations::channel::AuthenticatedChannelSession<'static> {
    crate::http_owner_conversations::channel::AuthenticatedChannelSession {
        device: case.f.session(),
        phone_session: Uuid::new_v4(),
        origin_hash: [9; 32],
    }
}

async fn dispatch_snapshot(case: &Case) -> String {
    case.f
        .db
        .query_one("SELECT to_jsonb(j)::text FROM dispatch_jobs j", &[])
        .await
        .unwrap()
        .get(0)
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; isolated synthetic schema"]
async fn authenticated_delivery_returns_exact_confirmed_bytes_and_retry_never_claims_job() {
    let case = Case::new().await;
    let (envelope, confirmation, signature) = case.packet(Uuid::new_v4(), 30_000).await;
    assert!(
        case.enqueue(&envelope, &confirmation, &signature)
            .await
            .unwrap()
            .created
    );
    let session = delivery_identity(&case);
    let challenge = Uuid::new_v4();
    let frame = delivery_frame(&session, &case.interval, confirmation.message, challenge);
    let encoded = confirmation.encode().unwrap();
    let mut expected = b"ZTCR\x01".to_vec();
    expected.extend((envelope.len() as u32).to_be_bytes());
    expected.extend(&envelope);
    expected.extend((encoded.len() as u16).to_be_bytes());
    expected.extend(&encoded);
    expected.extend(&signature);
    let before = dispatch_snapshot(&case).await;
    let mut first = None;
    for _ in 0..2 {
        let reply = crate::http_owner_conversations::channel::handle(
            &mut case.f.connect().await,
            &session,
            &frame,
        )
        .await
        .unwrap();
        assert_eq!(&reply[..5], b"ZTCW\x01");
        assert_eq!(reply[5], 15);
        assert_eq!(&reply[6..118], &frame[6..118]);
        assert_eq!(
            u32::from_be_bytes(reply[118..122].try_into().unwrap()) as usize,
            expected.len()
        );
        assert_eq!(&reply[122..], expected);
        if let Some(previous) = &first {
            assert_eq!(&reply, previous);
        }
        first = Some(reply);
        assert_eq!(dispatch_snapshot(&case).await, before);
        assert_eq!(case.counts().await, (1, 1, 1, 1));
    }
    case.f.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; isolated synthetic schema"]
async fn authenticated_delivery_rejects_header_scope_and_foreign_selectors_without_claim() {
    let case = Case::new().await;
    let (b, c, sig) = case.packet(Uuid::new_v4(), 30_000).await;
    case.enqueue(&b, &c, &sig).await.unwrap();
    let session = delivery_identity(&case);
    let frame = delivery_frame(&session, &case.interval, c.message, Uuid::new_v4());
    let before = dispatch_snapshot(&case).await;
    // Authenticated account/device/session/origin and each immutable scope field.
    for offset in [
        6, 22, 38, 54, 62, 70, 118, 134, 150, 166, 182, 198, 214, 222, 230, 238, 270, 302, 334, 370,
    ] {
        let mut changed = frame.clone();
        changed[offset] ^= 1;
        assert!(
            crate::http_owner_conversations::channel::handle(
                &mut case.f.connect().await,
                &session,
                &changed
            )
            .await
            .is_err(),
            "offset {offset}"
        );
        assert_eq!(dispatch_snapshot(&case).await, before);
    }
    for offset in [166, frame.len() - 16] {
        let mut changed = frame.clone();
        changed[offset..offset + 16].copy_from_slice(Uuid::new_v4().as_bytes());
        assert!(
            crate::http_owner_conversations::channel::handle(
                &mut case.f.connect().await,
                &session,
                &changed
            )
            .await
            .is_err()
        );
    }
    let mut rebound = delivery_identity(&case);
    rebound.phone_session = Uuid::new_v4();
    assert!(
        crate::http_owner_conversations::channel::handle(
            &mut case.f.connect().await,
            &rebound,
            &frame
        )
        .await
        .is_err()
    );
    assert_eq!(dispatch_snapshot(&case).await, before);
    assert_eq!(case.counts().await, (1, 1, 1, 1));
    case.f.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; isolated synthetic schema"]
async fn authenticated_delivery_rechecks_owner_phone_origin_and_withdrawal_without_claim() {
    for cause in 0..5 {
        let case = Case::new().await;
        let (b, c, sig) = case.packet(Uuid::new_v4(), 30_000).await;
        case.enqueue(&b, &c, &sig).await.unwrap();
        let session = delivery_identity(&case);
        let frame = delivery_frame(&session, &case.interval, c.message, Uuid::new_v4());
        let before = dispatch_snapshot(&case).await;
        match cause {
            0 => {
                case.f
                    .db
                    .execute(
                        "UPDATE sessions SET revoked_at=clock_timestamp() WHERE id=$1",
                        &[&case.owner.session_id],
                    )
                    .await
                    .unwrap();
            }
            1 => {
                case.f.db.execute("UPDATE device_sessions SET lease_until=clock_timestamp()-interval '1 second'", &[]).await.unwrap();
            }
            2 => {
                case.f
                    .db
                    .execute("UPDATE devices SET revoked_at=clock_timestamp()", &[])
                    .await
                    .unwrap();
            }
            3 => {
                activation::close(&mut case.f.connect().await, &case.owner, c.interval, true)
                    .await
                    .unwrap();
            }
            _ => {
                case.f
                    .db
                    .execute(
                        "UPDATE device_sessions SET connection_epoch=connection_epoch+1",
                        &[],
                    )
                    .await
                    .unwrap();
            }
        }
        assert!(
            crate::http_owner_conversations::channel::handle(
                &mut case.f.connect().await,
                &session,
                &frame
            )
            .await
            .is_err(),
            "cause {cause}"
        );
        assert_eq!(dispatch_snapshot(&case).await, before);
        assert_eq!(case.counts().await, (1, 1, 1, 1));
        case.f.cleanup().await;
    }
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; isolated synthetic schema"]
async fn authenticated_delivery_rejects_missing_redacted_and_expired_proof_without_claim() {
    for cause in 0..4 {
        let case = Case::new().await;
        let (b, c, sig) = case
            .packet(Uuid::new_v4(), if cause == 3 { 5_000 } else { 30_000 })
            .await;
        case.enqueue(&b, &c, &sig).await.unwrap();
        let session = delivery_identity(&case);
        let frame = delivery_frame(&session, &case.interval, c.message, Uuid::new_v4());
        let before = dispatch_snapshot(&case).await;
        match cause {
            0 => {
                case.f
                    .db
                    .execute("DELETE FROM conversation_confirmation_records", &[])
                    .await
                    .unwrap();
            }
            1 => {
                case.f.db.execute("UPDATE conversation_confirmation_records SET confirmation=NULL,signature=NULL", &[]).await.unwrap();
            }
            2 => {
                case.f
                    .db
                    .execute(
                        "UPDATE messages SET transport_payload=NULL,recipient_e164=NULL",
                        &[],
                    )
                    .await
                    .unwrap();
            }
            _ => {
                tokio::time::timeout(std::time::Duration::from_secs(8), async {
                    loop {
                        let now: i64 = case
                            .f
                            .db
                            .query_one(
                                "SELECT floor(extract(epoch FROM clock_timestamp())*1000)::bigint",
                                &[],
                            )
                            .await
                            .unwrap()
                            .get(0);
                        if now >= c.expires_ms {
                            break;
                        }
                        tokio::time::sleep(std::time::Duration::from_millis(25)).await;
                    }
                })
                .await
                .expect("database clock must reach fixture expiry");
            }
        }
        assert!(
            crate::http_owner_conversations::channel::handle(
                &mut case.f.connect().await,
                &session,
                &frame
            )
            .await
            .is_err(),
            "cause {cause}"
        );
        assert_eq!(dispatch_snapshot(&case).await, before);
        let counts = case.counts().await;
        assert_eq!((counts.0, counts.1, counts.3), (1, 1, 1));
        assert_eq!(counts.2, if cause == 0 { 0 } else { 1 });
        case.f.cleanup().await;
    }
}
impl Case {
    async fn new() -> Self {
        let (mut f, owner, interval) = activation::tests::pending().await;
        activation::tests::activate(&f, &interval).await;
        f.advance();
        let old_entries = f.bytes[151..f.bytes.len() - 64].to_vec();
        let browser = SigningKey::generate_from_rng(&mut rand::rng());
        let kem = SigningKey::generate_from_rng(&mut rand::rng());
        let now: i64 =
            f.db.query_one(
                "SELECT floor(extract(epoch FROM clock_timestamp())*1000)::bigint",
                &[],
            )
            .await
            .unwrap()
            .get(0);
        let entry = |role: u8, key: &SigningKey| {
            let point = key.verifying_key().to_sec1_point(false);
            let algorithm = if role == 1 { [0, 16] } else { [1, 1] };
            let id: [u8; 32] = Sha256::digest(
                [b"ZTSE/key/v1\0".as_slice(), &algorithm, point.as_bytes()].concat(),
            )
            .into();
            let mut bytes = vec![role];
            bytes.extend(id);
            bytes.extend(point.as_bytes());
            bytes.extend(if role == 1 {
                *f.device.as_bytes()
            } else {
                [0; 16]
            });
            bytes.extend(f.line.as_bytes());
            bytes.extend(if role == 1 { 4u16 } else { 1u16 }.to_be_bytes());
            bytes.extend((now - 1000).to_be_bytes());
            bytes.extend((now + 240_000).to_be_bytes());
            bytes.push(1);
            (bytes, id)
        };
        let (phone, phone_id) = entry(1, &kem);
        let (signer, browser_id) = entry(5, &browser);
        f.bytes.truncate(150);
        f.bytes.push(5);
        f.bytes.extend(phone);
        f.bytes.extend(&old_entries[..298]);
        f.bytes.extend(signer);
        f.bytes.extend(&old_entries[298..]);
        f.bytes.extend([0; 64]);
        f.resign();
        let mut db = f.connect().await;
        let tx = db.transaction().await.unwrap();
        let mut admitted =
            crate::sealed_manifest_store::admit(&tx, f.session(), f.line, 1, &f.bytes)
                .await
                .unwrap();
        admitted.context(&f.wanted()).await.unwrap();
        drop(admitted);
        tx.commit().await.unwrap();
        if !lifecycle::installed(&f.db).await.unwrap() {
            f.db.batch_execute(SCHEMA).await.unwrap();
        }
        f.db.execute("INSERT INTO usage_quota_policies(account_id,metric,limit_units) VALUES($1,'outbound_message',1000)",&[&f.account]).await.unwrap();
        Self {
            f,
            owner,
            interval,
            browser,
            browser_id,
            phone_reader: ExpectedRecipient {
                role: 1,
                key_id: phone_id,
            },
        }
    }
    async fn packet(&self, message: Uuid, lifetime: i64) -> (Vec<u8>, Confirmation, Vec<u8>) {
        let now: i64 = self
            .f
            .db
            .query_one(
                "SELECT floor(extract(epoch FROM clock_timestamp())*1000)::bigint",
                &[],
            )
            .await
            .unwrap()
            .get(0);
        let digest: [u8; 32] = Sha256::digest(&self.f.bytes[..self.f.bytes.len() - 64]).into();
        let mut b = b"ZTSE\x02\x01\0\0".to_vec();
        b.extend(157u16.to_be_bytes());
        for id in [self.f.account, message, self.f.device, self.f.line] {
            b.extend(id.as_bytes());
        }
        b.extend(3u64.to_be_bytes());
        b.extend(digest);
        b.extend(self.browser_id);
        b.extend(now.to_be_bytes());
        b.extend((now + lifetime).to_be_bytes());
        b.extend([1, 3]);
        b.extend(b"+12");
        b.extend([4; 12]);
        b.extend(17u32.to_be_bytes());
        b.extend([7; 17]);
        b.push(2);
        for reader in [&self.phone_reader, &self.f.readers[0]] {
            b.push(reader.role);
            b.extend(reader.key_id);
            b.extend(self.f.root.verifying_key().to_sec1_point(false).as_bytes());
            b.extend([9; 48]);
        }
        let signature: Signature = self.browser.sign(
            &[
                b"ZTSE/sign/v2\0".as_slice(),
                &(b.len() as u32).to_be_bytes(),
                &b,
            ]
            .concat(),
        );
        b.extend(signature.normalize_s().to_bytes());
        let c = Confirmation {
            account: self.f.account,
            device: self.f.device,
            line: self.f.line,
            interval: self.interval.interval,
            session: self.owner.session_id,
            message,
            generation: 1,
            trust_generation: 1,
            version: 3,
            expires_ms: now + lifetime,
            peer: "+12".into(),
            signer: self.browser_id,
            reader: self.interval.reader,
            manifest: digest,
            envelope_digest: Sha256::digest(&b).into(),
            body_digest: [8; 32],
        };
        let signature: Signature = self.browser.sign(&c.transcript().unwrap());
        (b, c, signature.normalize_s().to_bytes().to_vec())
    }
    async fn enqueue(
        &self,
        b: &[u8],
        c: &Confirmation,
        sig: &[u8],
    ) -> Result<AcceptOutcome, QueueError> {
        enqueue_confirmed_send(
            &mut self.f.connect().await,
            &self.owner,
            self.f.session(),
            true,
            ConfirmedPacket {
                envelope: b,
                confirmation: &c.encode().unwrap(),
                signature: sig,
            },
        )
        .await
    }
    async fn counts(&self) -> (i64, i64, i64, i64) {
        let r=self.f.db.query_one("SELECT (SELECT count(*) FROM messages),(SELECT count(*) FROM dispatch_jobs), \
        (SELECT count(*) FROM conversation_confirmation_records),(SELECT count(*) FROM usage_ledger WHERE entry_kind='reserve')",&[]).await.unwrap();
        (r.get(0), r.get(1), r.get(2), r.get(3))
    }
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; isolated synthetic schema"]
async fn confirmed_queue_commits_exact_proof_once_and_never_rehydrates_redacted_evidence() {
    let case = Case::new().await;
    let (b, c, sig) = case.packet(Uuid::new_v4(), 30_000).await;
    assert!(case.enqueue(&b, &c, &sig).await.unwrap().created);
    assert!(!case.enqueue(&b, &c, &sig).await.unwrap().created);
    assert_eq!(case.counts().await, (1, 1, 1, 1));
    let row = case
        .f
        .db
        .query_one(
            "SELECT confirmation,signature FROM conversation_confirmation_records",
            &[],
        )
        .await
        .unwrap();
    assert_eq!(row.get::<_, Vec<u8>>(0), c.encode().unwrap());
    assert_eq!(row.get::<_, Vec<u8>>(1), sig);
    let mut changed = c.clone();
    changed.body_digest[0] ^= 1;
    let altered: Signature = case.browser.sign(&changed.transcript().unwrap());
    assert!(
        case.enqueue(&b, &changed, &altered.normalize_s().to_bytes())
            .await
            .is_err()
    );
    assert!(
        case.f
            .db
            .execute(
                "UPDATE conversation_confirmation_records SET body_digest=$1",
                &[&vec![3u8; 32]]
            )
            .await
            .is_err()
    );
    case.f
        .db
        .execute(
            "UPDATE conversation_confirmation_records SET confirmation=NULL,signature=NULL",
            &[],
        )
        .await
        .unwrap();
    case.f
        .db
        .execute(
            "UPDATE messages SET transport_payload=NULL,recipient_e164=NULL",
            &[],
        )
        .await
        .unwrap();
    assert!(!case.enqueue(&b, &c, &sig).await.unwrap().created);
    assert_eq!(case.counts().await, (1, 1, 1, 1));
    let row = case
        .f
        .db
        .query_one(
            "SELECT confirmation,signature FROM conversation_confirmation_records",
            &[],
        )
        .await
        .unwrap();
    assert!(row.get::<_, Option<Vec<u8>>>(0).is_none());
    assert!(row.get::<_, Option<Vec<u8>>>(1).is_none());
    assert!(
        case.f
            .db
            .execute(
                "UPDATE conversation_confirmation_records SET confirmation=$1,signature=$2",
                &[&c.encode().unwrap(), &sig]
            )
            .await
            .is_err()
    );
    case.f.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; isolated synthetic schema"]
async fn confirmed_queue_rejects_revoked_expired_and_wrong_scope_without_any_acceptance() {
    let case = Case::new().await;
    let (b, c, sig) = case.packet(Uuid::new_v4(), 30_000).await;
    let mut altered = c.clone();
    altered.peer = "+13".into();
    assert!(case.enqueue(&b, &altered, &sig).await.is_err());
    let mut bad = sig.clone();
    bad[0] ^= 1;
    assert!(case.enqueue(&b, &c, &bad).await.is_err());
    let (expired, proof, signature) = case.packet(Uuid::new_v4(), 1).await;
    tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    assert!(case.enqueue(&expired, &proof, &signature).await.is_err());
    assert_eq!(case.counts().await, (0, 0, 0, 0));
    case.f
        .db
        .execute(
            "UPDATE sessions SET revoked_at=clock_timestamp() WHERE id=$1",
            &[&case.owner.session_id],
        )
        .await
        .unwrap();
    assert!(case.enqueue(&b, &c, &sig).await.is_err());
    assert_eq!(case.counts().await, (0, 0, 0, 0));
    case.f.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; isolated synthetic schema"]
async fn confirmed_queue_rolls_back_queue_and_reservation_when_proof_insert_fails() {
    let case = Case::new().await;
    let (b, c, sig) = case.packet(Uuid::new_v4(), 30_000).await;
    case.f.db.batch_execute("CREATE FUNCTION reject_confirmation() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'fixture rejection'; END $$; \
        CREATE TRIGGER reject_confirmation BEFORE INSERT ON conversation_confirmation_records FOR EACH ROW EXECUTE FUNCTION reject_confirmation()").await.unwrap();
    assert!(case.enqueue(&b, &c, &sig).await.is_err());
    assert_eq!(case.counts().await, (0, 0, 0, 0));
    case.f.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; isolated synthetic schema"]
async fn confirmed_queue_never_exposes_staged_acceptance_and_expiry_after_insert_wait_rolls_back() {
    let case = Case::new().await;
    let (b, c, sig) = case.packet(Uuid::new_v4(), 9_000).await;
    let lock = i64::from_be_bytes(c.message.as_bytes()[..8].try_into().unwrap());
    let mut blocker = case.f.connect().await;
    let blocked = blocker.transaction().await.unwrap();
    blocked
        .query_one("SELECT pg_advisory_xact_lock($1)", &[&lock])
        .await
        .unwrap();
    case.f.db.batch_execute(&format!("CREATE FUNCTION wait_confirmation() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN PERFORM pg_advisory_xact_lock({lock}); RETURN NEW; END $$; \
        CREATE TRIGGER wait_confirmation BEFORE INSERT ON conversation_confirmation_records FOR EACH ROW EXECUTE FUNCTION wait_confirmation()")).await.unwrap();
    let mut sender = case.f.connect().await;
    let pid: i32 = sender
        .query_one("SELECT pg_backend_pid()", &[])
        .await
        .unwrap()
        .get(0);
    let proof = c.encode().unwrap();
    let send = enqueue_confirmed_send(
        &mut sender,
        &case.owner,
        case.f.session(),
        true,
        ConfirmedPacket {
            envelope: &b,
            confirmation: &proof,
            signature: &sig,
        },
    );
    let release = async {
        let start = std::time::Instant::now();
        loop {
            let waiting: bool = case
                .f
                .db
                .query_one("SELECT cardinality(pg_blocking_pids($1))>0", &[&pid])
                .await
                .unwrap()
                .get(0);
            if waiting {
                break;
            }
            assert!(start.elapsed() < std::time::Duration::from_secs(10));
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        assert_eq!(case.counts().await, (0, 0, 0, 0));
        loop {
            let now: i64 = case
                .f
                .db
                .query_one(
                    "SELECT floor(extract(epoch FROM clock_timestamp())*1000)::bigint",
                    &[],
                )
                .await
                .unwrap()
                .get(0);
            if now >= c.expires_ms {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        blocked.commit().await.unwrap();
    };
    let (result, ()) = tokio::join!(send, release);
    assert!(matches!(
        result,
        Err(QueueError::Authorization(ConversationError::Forbidden))
    ));
    assert_eq!(case.counts().await, (0, 0, 0, 0));
    case.f.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; isolated synthetic schema"]
async fn confirmed_queue_requires_live_phone_active_interval_and_current_root_even_on_replay() {
    for cause in 0..3 {
        let case = Case::new().await;
        let (b, c, sig) = case.packet(Uuid::new_v4(), 30_000).await;
        assert!(case.enqueue(&b, &c, &sig).await.unwrap().created);
        match cause {
            0 => {
                case.f.db.execute("UPDATE device_sessions SET lease_until=clock_timestamp()-interval '1 second'",&[]).await.unwrap();
            }
            1 => {
                activation::close(&mut case.f.connect().await, &case.owner, c.interval, false)
                    .await
                    .unwrap();
            }
            _ => {
                case.f
                    .db
                    .execute(
                        "UPDATE sealed_manifest_authorities SET revoked_at=clock_timestamp()",
                        &[],
                    )
                    .await
                    .unwrap();
            }
        }
        assert!(case.enqueue(&b, &c, &sig).await.is_err());
        assert_eq!(case.counts().await, (1, 1, 1, 1));
        case.f.cleanup().await;
    }
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; isolated synthetic schema"]
async fn confirmed_proof_lifecycle_redacts_bounded_content_and_exports_only_metadata() {
    let case = Case::new().await;
    let (b, c, sig) = case.packet(Uuid::new_v4(), 30_000).await;
    assert!(case.enqueue(&b, &c, &sig).await.unwrap().created);
    // Synthetic retained identities exercise pagination independently of signing cost.
    // Admission and proof binding are tested separately with real signed packets.
    case.f.db.batch_execute("WITH added AS (INSERT INTO messages SELECT (jsonb_populate_record(NULL::messages,to_jsonb(m)||jsonb_build_object('id',gen_random_uuid()))).* FROM messages m CROSS JOIN generate_series(1,100) RETURNING id) INSERT INTO conversation_confirmation_records SELECT (jsonb_populate_record(NULL::conversation_confirmation_records,to_jsonb(c)||jsonb_build_object('message_id',a.id))).* FROM conversation_confirmation_records c CROSS JOIN added a").await.unwrap();
    let mut db = case.f.connect().await;
    let first = lifecycle::inventory(&mut db, &case.owner, None)
        .await
        .unwrap();
    assert_eq!(first.records.len(), 100);
    assert!(first.truncated);
    let last = lifecycle::inventory(&mut db, &case.owner, first.next_cursor)
        .await
        .unwrap();
    assert_eq!(last.records.len(), 1);
    assert!(!last.truncated);
    assert!(
        lifecycle::inventory(&mut db, &case.owner, Some(Uuid::new_v4()))
            .await
            .is_err()
    );
    let serialized = serde_json::to_string(&first).unwrap();
    for forbidden in [
        "peer",
        "signature",
        "body_digest",
        "envelope",
        "confirmation_digest",
    ] {
        assert!(!serialized.contains(forbidden));
    }
    activation::close(&mut db, &case.owner, case.interval.interval, false)
        .await
        .unwrap();
    assert_eq!(lifecycle::redact(&db, 1).await.unwrap(), 1);
    assert_eq!(lifecycle::redact(&db, 100).await.unwrap(), 100);
    assert_eq!(lifecycle::redact(&db, 100).await.unwrap(), 0);
    let inventory = lifecycle::inventory(&mut db, &case.owner, None)
        .await
        .unwrap();
    assert!(inventory.records.iter().all(|p| !p.proof_retained));
    let hashes: i64 = db.query_one("SELECT count(*) FROM conversation_confirmation_records WHERE octet_length(confirmation_digest)=32 AND signature IS NULL AND confirmation IS NULL",&[]).await.unwrap().get(0);
    assert_eq!(hashes, 101);
    // Referenced interval metadata survives content cleanup and retains replay identity.
    let result = crate::http_owner_conversations::lifecycle::activation::prune(&mut db, 0, 100)
        .await
        .unwrap();
    assert_eq!(result.2, 0);
    let retained = db
        .query_one(
            "SELECT phase,statement IS NULL FROM conversation_intervals WHERE id=$1",
            &[&case.interval.interval],
        )
        .await
        .unwrap();
    assert_eq!(retained.get::<_, String>(0), "withdrawn");
    assert!(retained.get::<_, bool>(1));
    db.execute(
        "UPDATE sessions SET revoked_at=clock_timestamp() WHERE account_id=$1 AND id=$2",
        &[&case.f.account, &case.owner.session_id],
    )
    .await
    .unwrap();
    assert!(
        lifecycle::inventory(&mut db, &case.owner, None)
            .await
            .is_err()
    );
    case.f.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; isolated synthetic schema"]
async fn confirmed_proof_retention_session_revocation_and_schema_absence_are_explicit() {
    let case = Case::new().await;
    let (b, c, sig) = case.packet(Uuid::new_v4(), 30_000).await;
    assert!(case.enqueue(&b, &c, &sig).await.unwrap().created);
    case.f
        .db
        .execute(
            "UPDATE sessions SET revoked_at=clock_timestamp() WHERE account_id=$1 AND id=$2",
            &[&case.f.account, &case.owner.session_id],
        )
        .await
        .unwrap();
    let mut db = case.f.connect().await;
    let counts =
        crate::retention::prune(&mut db, crate::retention::RetentionPolicy::default(), 100)
            .await
            .unwrap();
    assert_eq!(counts.conversation_confirmations, 1);
    db.batch_execute("DROP TABLE conversation_confirmation_records")
        .await
        .unwrap();
    assert!(!lifecycle::installed(&db).await.unwrap());
    assert_eq!(lifecycle::redact(&db, 100).await.unwrap(), 0);
    assert!(case.enqueue(&b, &c, &sig).await.is_err());
    case.f.cleanup().await;
}

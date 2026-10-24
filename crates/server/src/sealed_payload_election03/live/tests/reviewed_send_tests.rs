// SPDX-License-Identifier: AGPL-3.0-only
//! Genuine ordinary-runtime capture and real billing queue admission. The
//! synthetic encrypted payload is opaque to the server; no decrypt/radio claim.
use super::interval_queue_tests::{lease, prepared, request};
use super::*;
use crate::sealed_payload_election03::adapter_contract;
use crate::{
    conversation_interval03::{self as consent, live as intervals},
    reviewed_intent03::live as reviewed,
};

pub(super) struct Packet {
    pub(super) intent: Vec<u8>,
    pub(super) signature: Vec<u8>,
    pub(super) envelope: Vec<u8>,
    pub(super) message: Uuid,
}
pub(super) async fn active() -> (Case, SigningKey, consent::Statement03) {
    let (mut c, browser, signed) = prepared().await;
    let p = request(&mut c, &browser, &signed, b"+12", 300_000, 5).await;
    let statement = consent::Statement03::decode(&p.bytes).unwrap();
    let phone = sign(
        &c.phone_key,
        b"zrotext/conversation/approve03/v1\0",
        &[p.bytes.as_slice(), &crypto::sha(&p.signature)].concat(),
    );
    let installed = sign(
        &c.phone_key,
        b"zrotext/conversation/install03/v1\0",
        &[
            p.bytes.as_slice(),
            &crypto::sha(&p.signature),
            &crypto::sha(&phone),
        ]
        .concat(),
    );
    let actual = lease(&c);
    let tx = c.db.reader.transaction().await.unwrap();
    intervals::device_approve(&tx, actual, p.id, &statement.digest(), &phone)
        .await
        .unwrap();
    tx.commit().await.unwrap();
    let tx = c.db.reader.transaction().await.unwrap();
    intervals::device_install(&tx, actual, p.id, &statement.digest(), &installed)
        .await
        .unwrap();
    tx.commit().await.unwrap();
    (c, browser, statement)
}
pub(super) async fn packet(c: &mut Case, key: &SigningKey, s: &consent::Statement03) -> Packet {
    packet_with_lifetime(c, key, s, 60_000).await
}
pub(super) async fn packet_with_lifetime(
    c: &mut Case,
    key: &SigningKey,
    s: &consent::Statement03,
    lifetime_ms: u64,
) -> Packet {
    let tx = c.db.reader.transaction().await.unwrap();
    let mut owner = ordinary_owner03::authenticate(&tx, &c.hasher, ORIGIN, source(&c.credentials))
        .await
        .unwrap();
    let mut held = hold_owner_selection(&tx, &mut owner, c.line, ORIGIN)
        .await
        .unwrap();
    let interval = intervals::StoredInterval03::active(&tx, &mut held, s.interval_id())
        .await
        .unwrap();
    let deadline = interval.admission_deadline(&mut held).await.unwrap();
    let now = held.now_ms();
    let expires = (now + lifetime_ms).min(deadline - 1);
    assert!(expires > now + 1000);
    let review_end = (now + 30_000).min(expires);
    let a = held.authority();
    let message = Uuid::new_v4();
    let (_, _, signer) = s.keys();
    let readers = s.recipients(true);
    let mut protected = Vec::new();
    for id in [a.account_id, *message.as_bytes(), a.device_id, a.line_id] {
        protected.extend(id);
    }
    protected.extend(a.manifest_version.to_be_bytes());
    protected.extend(a.manifest_digest);
    protected.extend(signer);
    protected.extend(now.to_be_bytes());
    protected.extend(expires.to_be_bytes());
    protected.push(1);
    protected.push(s.peer().len() as u8);
    protected.extend(s.peer());
    let mut envelope = b"ZTSE\x03\x01\0\0".to_vec();
    envelope.extend(u16::try_from(protected.len()).unwrap().to_be_bytes());
    envelope.extend(protected);
    envelope.extend([7; 12]);
    envelope.extend(17_u32.to_be_bytes());
    envelope.extend([8; 17]);
    envelope.push(readers.len() as u8);
    let ephemeral = SigningKey::generate_from_rng(&mut rand::rng());
    for (role, id) in &readers {
        envelope.push(*role);
        envelope.extend(id);
        envelope.extend(ephemeral.verifying_key().to_sec1_point(false).as_bytes());
        envelope.extend([9; 48]);
    }
    envelope.extend(sign(key, b"ZTSE/sign/v3\0", &envelope));
    let unsigned = crypto::sha(&envelope[..envelope.len() - 64]);
    let owner_digest = crate::sealed_payload_election03::adapter_contract::OwnerSessionIdentity03 {
        account_id: a.account_id,
        user_id: *held.selected().user.as_bytes(),
        session_id: *held.selected().session.as_bytes(),
    }
    .digest()
    .unwrap();
    let mut intent = b"ZTRI\x02\x03\x03\0".to_vec();
    for id in [
        a.account_id,
        a.device_id,
        a.line_id,
        a.binding_id,
        *held.selected().user.as_bytes(),
        *held.selected().session.as_bytes(),
        *s.interval_id().as_bytes(),
        *message.as_bytes(),
    ] {
        intent.extend(id);
    }
    for n in [
        a.binding_generation,
        1,
        a.manifest_version,
        1,
        now,
        expires,
        now,
        review_end,
    ] {
        intent.extend(n.to_be_bytes());
    }
    for d in [
        a.selected_reader_key_id,
        a.root_fingerprint,
        a.manifest_digest,
        a.election_commitment,
        a.election_bundle_sha256,
        owner_digest,
        adapter_contract::origin_digest(ORIGIN).unwrap(),
        *signer,
        crypto::sha(&envelope),
        unsigned,
    ] {
        intent.extend(d);
    }
    intent.push(s.peer().len() as u8);
    intent.extend(s.peer());
    intent.push(readers.len() as u8);
    for (role, id) in &readers {
        intent.push(*role);
        intent.extend(id);
    }
    intent.push(1);
    let signature = sign(key, b"zrotext/conversation/reviewed-send03/v2\0", &intent);
    drop(held);
    drop(owner);
    tx.rollback().await.unwrap();
    Packet {
        intent,
        signature,
        envelope,
        message,
    }
}
#[tokio::test]
#[ignore = "requires disposable ZT_AUTH_TEST_DATABASE_URL administrator; genuine installed consent and finite quota queue"]
async fn genuine_review_queues_once_reserves_once_and_signout_preserves_only_historical_identity() {
    let (mut c, browser, statement) = active().await;
    let account = c.principal.tenant.account_id();
    c.db.owner.execute("INSERT INTO public.usage_quota_policies(account_id,metric,limit_units,source) VALUES($1,'outbound_message',10,'operator')",&[&account]).await.unwrap();
    let p = packet(&mut c, &browser, &statement).await;
    // These real temporary shadows must not replace the stock public account,
    // quota or queue. The explicit legacy bridge places pg_temp last.
    c.db.reader.batch_execute("CREATE TEMP TABLE accounts(id uuid,disabled_at timestamptz); CREATE TEMP TABLE messages(id uuid,account_id uuid); CREATE TEMP TABLE usage_quota_policies(account_id uuid,metric text,limit_units bigint,source text)").await.unwrap();
    let tx = c.db.reader.transaction().await.unwrap();
    let mut owner = ordinary_owner03::authenticate(&tx, &c.hasher, ORIGIN, source(&c.credentials))
        .await
        .unwrap();
    let (new, original) = reviewed::admit(
        &tx,
        &mut owner,
        &p.intent,
        &p.signature,
        &p.envelope,
        ORIGIN,
    )
    .await
    .unwrap();
    assert!(new);
    assert_eq!(
        tx.query_one("SHOW search_path", &[])
            .await
            .unwrap()
            .get::<_, String>(0),
        "pg_catalog"
    );
    drop(owner);
    tx.commit().await.unwrap();
    let tx = c.db.reader.transaction().await.unwrap();
    let mut owner = ordinary_owner03::authenticate(&tx, &c.hasher, ORIGIN, source(&c.credentials))
        .await
        .unwrap();
    let (new, repeated) = reviewed::admit(
        &tx,
        &mut owner,
        &p.intent,
        &p.signature,
        &p.envelope,
        ORIGIN,
    )
    .await
    .unwrap();
    assert!(!new);
    assert_eq!(repeated, original);
    drop(owner);
    tx.commit().await.unwrap();
    let row=c.db.reader.query_one("SELECT m.transport_mode,m.transport_payload,m.sealed_segment_limit,(SELECT count(*) FROM public.dispatch_jobs j WHERE j.account_id=m.account_id AND j.message_id=m.id),(SELECT count(*) FROM public.usage_ledger u WHERE u.account_id=m.account_id AND u.message_id=m.id AND u.entry_kind='reserve'),(SELECT count(*) FROM public.message_attempts a WHERE a.account_id=m.account_id AND a.message_id=m.id) FROM public.messages m WHERE m.account_id=$1 AND m.id=$2",&[&account,&p.message]).await.unwrap();
    assert_eq!(row.get::<_, String>(0), "sealed_profile03");
    assert_eq!(row.get::<_, Vec<u8>>(1), p.envelope);
    assert_eq!(row.get::<_, Option<i16>>(2), Some(1));
    assert_eq!(row.get::<_, i64>(3), 1);
    assert_eq!(row.get::<_, i64>(4), 1);
    assert_eq!(row.get::<_, i64>(5), 0);
    assert_eq!(
        c.db.reader
            .query_one("SELECT count(*) FROM pg_temp.messages", &[])
            .await
            .unwrap()
            .get::<_, i64>(0),
        0
    );
    let tx = c.db.reader.transaction().await.unwrap();
    let mut owner = ordinary_owner03::authenticate(&tx, &c.hasher, ORIGIN, source(&c.credentials))
        .await
        .unwrap();
    let mut changed = p.envelope.clone();
    changed[200] ^= 1;
    assert!(matches!(
        reviewed::admit(&tx, &mut owner, &p.intent, &p.signature, &changed, ORIGIN).await,
        Err(Error::Conflict)
    ));
    drop(owner);
    tx.rollback().await.unwrap();
    // Real ordinary sign-out revokes the original admission owner. It never
    // changes the retained review or creates a dispatch attempt.
    assert!(
        crate::auth::revoke_session(&c.db.reader, &c.principal, c.principal.session_id)
            .await
            .unwrap()
    );
    let tx = c.db.reader.transaction().await.unwrap();
    assert!(
        ordinary_owner03::authenticate(&tx, &c.hasher, ORIGIN, source(&c.credentials))
            .await
            .is_err()
    );
    tx.rollback().await.unwrap();
    let row=c.db.reader.query_one("SELECT intent,signature,envelope_sha256,intent_version,body_digest FROM public.conversation_reviewed_sends03 WHERE account_id=$1 AND message_id=$2",&[&account,&p.message]).await.unwrap();
    assert_eq!(row.get::<_, Vec<u8>>(0), p.intent);
    assert_eq!(row.get::<_, Vec<u8>>(1), p.signature);
    assert_eq!(row.get::<_, Vec<u8>>(2), crypto::sha(&p.envelope));
    assert_eq!(row.get::<_, i16>(3), 2);
    assert!(row.get::<_, Option<Vec<u8>>>(4).is_none());
    c.db.finish().await;
}

#[tokio::test]
#[ignore = "requires disposable ZT_AUTH_TEST_DATABASE_URL administrator; actual owner and valid historical format refuse new effects"]
async fn genuine_owner_cannot_admit_signed_v1_into_the_corrected_v2_composition() {
    let (mut c, browser, statement) = active().await;
    let account = c.principal.tenant.account_id();
    c.db.owner.execute("INSERT INTO public.usage_quota_policies(account_id,metric,limit_units,source) VALUES($1,'outbound_message',10,'operator')",&[&account]).await.unwrap();
    let p = packet(&mut c, &browser, &statement).await;
    // This is an independently signed obsolete-format negative control, never
    // a conversion of retained history or an alternate new V2 producer.
    let mut legacy = b"ZTRI\x01\x03\x03\0".to_vec();
    legacy.extend(&p.intent[8..520]);
    legacy.extend([42; 32]);
    legacy.extend(&p.intent[520..]);
    let parsed = crate::reviewed_intent03::Intent03::decode(&legacy).unwrap();
    let signature = sign(
        &browser,
        b"zrotext/conversation/reviewed-send03/v1\0",
        &legacy,
    );
    crypto::signature(
        browser.verifying_key().to_sec1_point(false).as_bytes(),
        &signature,
        &parsed.transcript(),
    )
    .unwrap();
    let tx = c.db.reader.transaction().await.unwrap();
    let mut owner = ordinary_owner03::authenticate(&tx, &c.hasher, ORIGIN, source(&c.credentials))
        .await
        .unwrap();
    assert!(matches!(
        reviewed::admit(&tx, &mut owner, &legacy, &signature, &p.envelope, ORIGIN).await,
        Err(Error::Unsupported)
    ));
    for table in [
        "conversation_reviewed_sends03",
        "messages",
        "dispatch_jobs",
        "usage_ledger",
    ] {
        assert_eq!(
            tx.query_one(
                &format!("SELECT count(*) FROM public.{table} WHERE account_id=$1"),
                &[&account]
            )
            .await
            .unwrap()
            .get::<_, i64>(0),
            0,
            "{table}"
        );
    }
    drop(owner);
    tx.rollback().await.unwrap();
    c.db.finish().await;
}

#[tokio::test]
#[ignore = "requires disposable ZT_AUTH_TEST_DATABASE_URL administrator; actual stock-runtime public namespace privilege refusal"]
async fn operator_widened_public_creation_refuses_before_billing_queue() {
    let (mut c, browser, statement) = active().await;
    let account = c.principal.tenant.account_id();
    c.db.owner.execute("INSERT INTO public.usage_quota_policies(account_id,metric,limit_units,source) VALUES($1,'outbound_message',10,'operator')",&[&account]).await.unwrap();
    let p = packet(&mut c, &browser, &statement).await;
    let tx = c.db.reader.transaction().await.unwrap();
    let mut owner = ordinary_owner03::authenticate(&tx, &c.hasher, ORIGIN, source(&c.credentials))
        .await
        .unwrap();
    let role = postgres_protocol::escape::escape_identifier(&c.db.read_role);
    c.db.owner
        .batch_execute(&format!("GRANT CREATE ON SCHEMA public TO {role}"))
        .await
        .unwrap();
    assert!(
        reviewed::admit(
            &tx,
            &mut owner,
            &p.intent,
            &p.signature,
            &p.envelope,
            ORIGIN
        )
        .await
        .is_err()
    );
    drop(owner);
    tx.rollback().await.unwrap();
    c.db.owner
        .batch_execute(&format!("REVOKE CREATE ON SCHEMA public FROM {role}"))
        .await
        .unwrap();
    let row=c.db.reader.query_one("SELECT (SELECT count(*) FROM public.messages WHERE account_id=$1),(SELECT count(*) FROM public.conversation_reviewed_sends03 WHERE account_id=$1)",&[&account]).await.unwrap();
    assert_eq!(row.get::<_, i64>(0), 0);
    assert_eq!(row.get::<_, i64>(1), 0);
    c.db.finish().await;
}
#[tokio::test]
#[ignore = "requires disposable ZT_AUTH_TEST_DATABASE_URL administrator; additive configured quota requirement"]
async fn unconfigured_selfhosted_review_refuses_without_partial_sidecar_message_job_or_reserve() {
    let (mut c, browser, statement) = active().await;
    let account = c.principal.tenant.account_id();
    let p = packet(&mut c, &browser, &statement).await;
    // A favorable operator-owned schema is not this installation. Its actual
    // quota row must never satisfy the real public account's missing policy.
    let role = postgres_protocol::escape::escape_identifier(&c.db.read_role);
    c.db.owner
        .batch_execute(&format!(
            "CREATE SCHEMA billing_shadow; CREATE TABLE billing_shadow.usage_quota_policies (LIKE public.usage_quota_policies INCLUDING ALL); GRANT USAGE ON SCHEMA billing_shadow TO {role}; GRANT SELECT ON billing_shadow.usage_quota_policies TO {role}"
        ))
        .await
        .unwrap();
    c.db.owner.execute("INSERT INTO billing_shadow.usage_quota_policies(account_id,metric,limit_units,source) VALUES($1,'outbound_message',10,'operator')",&[&account]).await.unwrap();
    c.db.reader
        .batch_execute("SET search_path TO billing_shadow,pg_temp,public")
        .await
        .unwrap();
    assert_eq!(
        c.db.reader
            .query_one(
                "SELECT count(*) FROM billing_shadow.usage_quota_policies WHERE account_id=$1",
                &[&account]
            )
            .await
            .unwrap()
            .get::<_, i64>(0),
        1
    );
    let tx = c.db.reader.transaction().await.unwrap();
    let mut owner = ordinary_owner03::authenticate(&tx, &c.hasher, ORIGIN, source(&c.credentials))
        .await
        .unwrap();
    assert!(
        reviewed::admit(
            &tx,
            &mut owner,
            &p.intent,
            &p.signature,
            &p.envelope,
            ORIGIN
        )
        .await
        .is_err()
    );
    drop(owner);
    tx.rollback().await.unwrap();
    let row=c.db.reader.query_one("SELECT (SELECT count(*) FROM public.messages WHERE account_id=$1),(SELECT count(*) FROM public.conversation_reviewed_sends03 WHERE account_id=$1),(SELECT count(*) FROM public.dispatch_jobs WHERE account_id=$1),(SELECT count(*) FROM public.usage_ledger WHERE account_id=$1)",&[&account]).await.unwrap();
    for i in 0..4 {
        assert_eq!(row.get::<_, i64>(i), 0);
    }
    c.db.finish().await;
}

// SPDX-License-Identifier: AGPL-3.0-only
//! Actual independently signed originals, ordinary runtime and one real quota
//! reservation. Opaque synthetic ciphertext proves no HPKE open or radio send.
use super::interval_queue_tests::{lease, request};
use super::reviewed_send_tests::{Packet, active_claimed as active, packet_with_lifetime};
use super::*;
use crate::conversation_grant03::{self as grants, FetchServing03};
use crate::sealed_dispatch::wire03::{Fetch03, GrantFrame03, ReadyFrame03};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD as B};

pub(super) async fn queue(
    c: &mut Case,
    browser: &SigningKey,
    statement: &crate::conversation_interval03::Statement03,
) -> Packet {
    // Sign once with ample initial message time for the positive grant flow;
    // the helper still caps it at the genuine current/interval authority and
    // leaves the signed review window and SQL grant window unchanged.
    queue_with_lifetime(c, browser, statement, 180_000).await
}
async fn queue_with_lifetime(
    c: &mut Case,
    browser: &SigningKey,
    statement: &crate::conversation_interval03::Statement03,
    lifetime_ms: u64,
) -> Packet {
    c.heartbeat().await;
    let p = packet_with_lifetime(c, browser, statement, lifetime_ms).await;
    let tx = c.db.reader.transaction().await.unwrap();
    let mut owner = ordinary_owner03::authenticate(&tx, &c.hasher, ORIGIN, source(&c.credentials))
        .await
        .unwrap();
    assert!(
        crate::reviewed_intent03::live::admit(
            &tx,
            &mut owner,
            &p.intent,
            &p.signature,
            &p.envelope,
            ORIGIN
        )
        .await
        .unwrap()
        .0
    );
    drop(owner);
    tx.commit().await.unwrap();
    p
}
pub(super) async fn ready(c: &mut Case) -> ReadyFrame03 {
    c.heartbeat().await;
    let tx = c.db.reader.transaction().await.unwrap();
    let mut owner = ordinary_owner03::authenticate(&tx, &c.hasher, ORIGIN, source(&c.credentials))
        .await
        .unwrap();
    let held = hold_owner_selection(&tx, &mut owner, c.line, ORIGIN)
        .await
        .unwrap();
    let a = held.authority();
    let raw = serde_json::json!({"v":1,"type":"sealed_ready","grant_version":3,"envelope_profile":3,"manifest_profile":3,
        "connection_epoch":1,"deployment_epoch":1,"binding_generation":a.binding_generation,
        "trust_generation":1,"manifest_version":a.manifest_version,"line_id":Uuid::from_bytes(a.line_id),
        "reader_key_id":B.encode(a.selected_reader_key_id),"manifest_digest":B.encode(a.manifest_digest),
        "root_fingerprint":B.encode(a.root_fingerprint),"election_digest":B.encode(a.election_commitment)});
    let value = ReadyFrame03::parse(&serde_json::to_vec(&raw).unwrap()).unwrap();
    drop(held);
    drop(owner);
    tx.rollback().await.unwrap();
    value
}
fn fetch(c: &Case, frame: &GrantFrame03) -> Fetch03 {
    let signature: Signature = c.phone_key.sign(&frame.fetch_transcript());
    let raw = serde_json::json!({"grant":serde_json::from_slice::<serde_json::Value>(&frame.to_json().unwrap()).unwrap(),
        "signature_der":B.encode(signature.normalize_s().to_der().as_bytes())});
    Fetch03::parse(&serde_json::to_vec(&raw).unwrap()).unwrap()
}
fn serving() -> FetchServing03<'static> {
    FetchServing03 {
        site: "activation-test",
        deployment: 1,
        origin: ORIGIN,
    }
}

async fn assert_original_grant_bounds(
    c: &Case,
    packet: &Packet,
    statement: &crate::conversation_interval03::Statement03,
    frame: &GrantFrame03,
    expect_full_mint_window: bool,
) {
    let claims = frame.claims();
    let signed = crate::reviewed_intent03::v2::Intent03V2::decode(&packet.intent).unwrap();
    let row = c.db.reader.query_one(
        "SELECT g.issued_ms,g.expires_at_ms,g.authority_deadline_ms,a.minted_ms,floor(extract(epoch FROM clock_timestamp())*1000)::bigint,floor(extract(epoch FROM m.expires_at)*1000)::bigint FROM public.conversation_profile03_grants g JOIN public.conversation_profile03_effect_actors a USING(account_id,attempt_id) JOIN public.messages m ON(m.account_id,m.id)=(g.account_id,g.message_id) WHERE g.account_id=$1 AND g.attempt_id=$2",
        &[&claims.account_id, &claims.attempt_id],
    ).await.unwrap();
    let issued: i64 = row.get(0);
    let expiry: i64 = row.get(1);
    let authority_deadline: i64 = row.get(2);
    let primary: i64 = row.get(4);
    let message_expiry: i64 = row.get(5);
    assert_eq!(row.get::<_, i64>(3), issued);
    assert!(issued <= primary);
    assert!(expiry > issued && expiry - issued <= 30_000);
    if expect_full_mint_window {
        assert_eq!(expiry - issued, 30_000);
    }
    assert_eq!(expiry, (issued + 30_000).min(authority_deadline));
    assert_eq!(expiry, claims.expires_at_ms);
    assert_eq!(message_expiry as u64, signed.message_expires_ms());
    assert!(expiry <= message_expiry);
    assert!(expiry as u64 <= statement.times().3);
}

#[tokio::test]
#[ignore = "requires disposable ZT_AUTH_TEST_DATABASE_URL administrator; genuine typed grant and signed full-current fetch"]
async fn actual_grant_fetch_preserves_originals_one_attempt_and_refuses_owner_withdrawal() {
    let (mut c, browser, statement) = active().await;
    let account = c.principal.tenant.account_id();
    c.db.owner.execute("INSERT INTO public.usage_quota_policies(account_id,metric,limit_units,source) VALUES($1,'outbound_message',10,'operator')",&[&account]).await.unwrap();
    let p = queue(&mut c, &browser, &statement).await;
    let ready = ready(&mut c).await;
    let actor = lease(&c);
    let socket = c.socket_actor();
    let mut other_epoch = actor;
    other_epoch.session.connection_epoch += 1;
    assert!(matches!(
        grants::issue_next(&mut c.db.reader, socket, other_epoch, &ready).await,
        Err(Error::Authentication)
    ));
    let grant = grants::issue_next(&mut c.db.reader, socket, actor, &ready)
        .await
        .unwrap()
        .unwrap();
    assert_original_grant_bounds(&c, &p, &statement, grant.frame(), true).await;
    let claims = grant.frame().claims();
    assert_eq!(claims.message_id, p.message);
    assert_eq!(claims.segment_count, 1);
    let original = c.db.reader.query_one(
        "SELECT original_enrolled_point,original_enrolled_key_id,fetch_transcript_sha256,original_device_session_digest,minted_ms FROM public.conversation_profile03_effect_actors WHERE account_id=$1 AND attempt_id=$2",
        &[&account,&claims.attempt_id],
    ).await.unwrap();
    assert_eq!(
        original.get::<_, Vec<u8>>(0).as_slice(),
        socket.proof().signing_point().as_slice()
    );
    assert_eq!(
        original.get::<_, Vec<u8>>(1).as_slice(),
        socket.proof().signing_key_id().as_slice()
    );
    assert_eq!(
        original.get::<_, Vec<u8>>(2).as_slice(),
        crypto::sha(grant.frame().fetch_transcript().as_slice()).as_slice()
    );
    let clock_and_session = c.db.reader.query_one(
        "SELECT g.issued_ms,a.minted_ms,a.original_device_session_digest=g.device_session_digest FROM public.conversation_profile03_grants g JOIN public.conversation_profile03_effect_actors a USING(account_id,attempt_id) WHERE g.account_id=$1 AND g.attempt_id=$2",
        &[&account, &claims.attempt_id],
    ).await.unwrap();
    assert_eq!(
        clock_and_session.get::<_, i64>(0),
        original.get::<_, i64>(4)
    );
    assert_eq!(
        clock_and_session.get::<_, i64>(1),
        original.get::<_, i64>(4)
    );
    assert!(clock_and_session.get::<_, bool>(2));
    let request = fetch(&c, grant.frame());
    let first = grants::fetch(&mut c.db.reader, serving(), &request)
        .await
        .unwrap();
    assert_eq!(first.as_object().unwrap().len(), 10);
    assert_eq!(
        B.decode(first["envelope"].as_str().unwrap()).unwrap(),
        p.envelope
    );
    let original_review = B
        .decode(first["reviewed_intent"].as_str().unwrap())
        .unwrap();
    assert_eq!(&original_review[..8], b"ZTRI\x02\x03\x03\0");
    assert_eq!(original_review, p.intent);
    assert_eq!(first["current"]["kind"], "message_manifest_permission03");
    assert_eq!(
        first["current"]["request_id"],
        claims.attempt_id.to_string()
    );
    assert_eq!(
        first["current"]["fetch_transcript_sha256"],
        B.encode(crypto::sha(grant.frame().fetch_transcript().as_slice()))
    );
    assert_eq!(
        first["current"]["permission_expires_ms"],
        claims.expires_at_ms.to_string()
    );
    assert_eq!(
        first["interval_permission"]["permission_expires_ms"],
        claims.expires_at_ms.to_string()
    );
    assert_eq!(
        first["current"]["compared_ms"],
        first["interval_permission"]["compared_ms"]
    );
    let repeat = grants::fetch(&mut c.db.reader, serving(), &request)
        .await
        .unwrap();
    assert_eq!(repeat["envelope"], first["envelope"]);
    assert_eq!(repeat["accepted_ms"], first["accepted_ms"]);
    assert!(
        grants::issue_next(&mut c.db.reader, socket, actor, &ready)
            .await
            .unwrap()
            .is_none()
    );
    let original=c.db.reader.query_one("SELECT(SELECT count(*) FROM public.message_attempts WHERE account_id=$1),(SELECT count(*) FROM public.usage_ledger WHERE account_id=$1 AND entry_kind='reserve'),(SELECT expires_at_ms FROM public.conversation_profile03_grants WHERE account_id=$1 AND message_id=$2)",&[&account,&p.message]).await.unwrap();
    assert_eq!(original.get::<_, i64>(0), 1);
    assert_eq!(original.get::<_, i64>(1), 1);
    assert_eq!(original.get::<_, i64>(2), claims.expires_at_ms);
    assert!(
        crate::auth::revoke_session(&c.db.reader, &c.principal, c.principal.session_id)
            .await
            .unwrap()
    );
    assert!(
        grants::fetch(&mut c.db.reader, serving(), &request)
            .await
            .is_err()
    );
    let row=c.db.reader.query_one("SELECT expires_at_ms FROM public.conversation_profile03_grants WHERE account_id=$1 AND message_id=$2",&[&account,&p.message]).await.unwrap();
    assert_eq!(row.get::<_, i64>(0), claims.expires_at_ms);
    c.db.finish().await;
}

#[tokio::test]
#[ignore = "requires disposable ZT_AUTH_TEST_DATABASE_URL administrator; genuine fresh-owner pending grant selection"]
async fn old_revoked_owner_message_cannot_starve_fresh_owner_queue_or_gain_an_attempt() {
    let (mut c, browser, statement) = active().await;
    let account = c.principal.tenant.account_id();
    c.db.owner.execute("INSERT INTO public.usage_quota_policies(account_id,metric,limit_units,source) VALUES($1,'outbound_message',10,'operator')",&[&account]).await.unwrap();
    let old = queue(&mut c, &browser, &statement).await;
    assert!(
        crate::auth::revoke_session(&c.db.reader, &c.principal, c.principal.session_id)
            .await
            .unwrap()
    );
    let challenge = crate::auth::mfa::begin_login_challenge(
        &c.db.reader,
        &c.hasher,
        account,
        c.principal.user_id,
        &c.password,
    )
    .await
    .unwrap();
    c.credentials = crate::auth::mfa::complete_login(
        &mut c.db.reader,
        Some(&c.cipher),
        &c.hasher,
        &challenge,
        &c.recovery[6],
    )
    .await
    .unwrap();
    c.principal = crate::auth::authenticate_session(&c.db.reader, &c.hasher, &c.credentials.token)
        .await
        .unwrap();
    let signed: Vec<u8> =
        c.db.reader
            .query_one(
                "SELECT manifest FROM public.sealed_manifest_authorities WHERE account_id=$1",
                &[&account],
            )
            .await
            .unwrap()
            .get(0);
    let pending = request(&mut c, &browser, &signed, b"+13", 300_000, 7).await;
    let s = crate::conversation_interval03::Statement03::decode(&pending.bytes).unwrap();
    let phone = sign(
        &c.phone_key,
        b"zrotext/conversation/approve03/v1\0",
        &[pending.bytes.as_slice(), &crypto::sha(&pending.signature)].concat(),
    );
    let installed = sign(
        &c.phone_key,
        b"zrotext/conversation/install03/v1\0",
        &[
            pending.bytes.as_slice(),
            &crypto::sha(&pending.signature),
            &crypto::sha(&phone),
        ]
        .concat(),
    );
    let actor = lease(&c);
    let socket = c.socket_actor();
    let tx = c.db.reader.transaction().await.unwrap();
    crate::conversation_interval03::live::device_approve(
        &tx,
        actor,
        pending.id,
        &s.digest(),
        &phone,
    )
    .await
    .unwrap();
    tx.commit().await.unwrap();
    let tx = c.db.reader.transaction().await.unwrap();
    crate::conversation_interval03::live::device_install(
        &tx,
        actor,
        pending.id,
        &s.digest(),
        &installed,
    )
    .await
    .unwrap();
    tx.commit().await.unwrap();
    let fresh = queue(&mut c, &browser, &s).await;
    let ready = ready(&mut c).await;
    let grant = grants::issue_next(&mut c.db.reader, socket, actor, &ready)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(grant.frame().claims().message_id, fresh.message);
    let row=c.db.reader.query_one("SELECT m.state,(SELECT count(*) FROM public.message_attempts a WHERE a.account_id=m.account_id AND a.message_id=m.id) FROM public.messages m WHERE m.account_id=$1 AND m.id=$2",&[&account,&old.message]).await.unwrap();
    assert_eq!(row.get::<_, String>(0), "queued");
    assert_eq!(row.get::<_, i64>(1), 0);
    c.db.finish().await;
}

#[tokio::test]
#[ignore = "requires disposable ZT_AUTH_TEST_DATABASE_URL administrator; actual SQL mint clips a narrower caller permission"]
async fn sql_mint_clips_original_grant_to_fresh_narrower_caller_permission() {
    let (mut c, browser, statement) = active().await;
    let account = c.principal.tenant.account_id();
    c.db.owner.execute("INSERT INTO public.usage_quota_policies(account_id,metric,limit_units,source) VALUES($1,'outbound_message',10,'operator')", &[&account]).await.unwrap();
    // Genuine signed admission precedes this storage-boundary regression. This
    // does not claim to issue a Rust-verified content permission or exercise
    // the complete issue_next path; its full-window/expiry tests remain above
    // and below. The independent V2 test covers the signed message boundary.
    let packet = queue(&mut c, &browser, &statement).await;
    let signed = crate::reviewed_intent03::v2::Intent03V2::decode(&packet.intent).unwrap();
    c.heartbeat().await;
    let actor = lease(&c);
    let attempt = Uuid::new_v4();
    let tx = crate::runtime_db::begin_native(&mut c.db.reader)
        .await
        .unwrap();
    tx.batch_execute("SET LOCAL search_path TO pg_catalog; SET LOCAL lock_timeout='3s'; SET LOCAL statement_timeout='5s'").await.unwrap();
    crate::conversation_profile03_effect_storage::require(&tx)
        .await
        .unwrap();
    assert!(
        tx.query(
            "SELECT * FROM public.conversation_profile03_grant_lock($1,$2,$3,$4,$5,$6,$7)",
            &[
                &account,
                &attempt,
                &actor.session.device_id,
                &actor.site,
                &actor.instance,
                &actor.session.connection_epoch,
                &(actor.deployment as i64)
            ],
        )
        .await
        .unwrap()
        .is_empty()
    );
    // Sample a NEW caller-requested bound only after readiness and locking.
    // It narrows existing authority; no signed, stored or production deadline
    // is rewritten. MATERIALIZED ensures one real primary clock sample.
    let signed_expiry = i64::try_from(signed.message_expires_ms()).unwrap();
    let row = tx.query_one(
        "WITH bound AS MATERIALIZED (SELECT least($9::bigint,floor(extract(epoch FROM clock_timestamp())*1000)::bigint+29000) AS deadline) SELECT g.issued_ms,g.expires_at_ms,g.authority_deadline_ms,b.deadline FROM bound b CROSS JOIN LATERAL public.conversation_profile03_grant_issue($1,$2,$3,$4,$5,$6,$7,$8,b.deadline) g",
        &[&account, &packet.message, &attempt, &actor.session.device_id, &actor.site, &actor.instance, &actor.session.connection_epoch, &(actor.deployment as i64), &signed_expiry],
    ).await.unwrap();
    let issued: i64 = row.get(0);
    let expiry: i64 = row.get(1);
    let authority_deadline: i64 = row.get(2);
    let caller_deadline: i64 = row.get(3);
    assert!(caller_deadline < signed_expiry);
    assert!(issued < expiry && expiry < issued + 30_000);
    assert_eq!(expiry, caller_deadline);
    assert_eq!(authority_deadline, caller_deadline);
    tx.commit().await.unwrap();
    let retained = c.db.reader.query_one(
        "SELECT g.expires_at_ms,a.minted_ms,floor(extract(epoch FROM m.expires_at)*1000)::bigint,(SELECT count(*) FROM public.message_attempts WHERE account_id=$1 AND message_id=$2),(SELECT count(*) FROM public.usage_ledger WHERE account_id=$1 AND message_id=$2 AND entry_kind='reserve') FROM public.conversation_profile03_grants g JOIN public.conversation_profile03_effect_actors a USING(account_id,attempt_id) JOIN public.messages m ON(m.account_id,m.id)=(g.account_id,g.message_id) WHERE g.account_id=$1 AND g.message_id=$2",
        &[&account, &packet.message],
    ).await.unwrap();
    assert_eq!(retained.get::<_, i64>(0), expiry);
    assert_eq!(retained.get::<_, i64>(1), issued);
    assert_eq!(retained.get::<_, i64>(2), signed_expiry);
    assert_eq!(retained.get::<_, i64>(3), 1);
    assert_eq!(retained.get::<_, i64>(4), 1);
    c.db.finish().await;
}

#[tokio::test]
#[ignore = "requires disposable ZT_AUTH_TEST_DATABASE_URL administrator; genuine grant expiry cannot remint original actor or permission"]
async fn naturally_expired_grant_refuses_fetch_without_remint_extension_or_another_attempt() {
    let (mut c, browser, statement) = active().await;
    let account = c.principal.tenant.account_id();
    c.db.owner.execute("INSERT INTO public.usage_quota_policies(account_id,metric,limit_units,source) VALUES($1,'outbound_message',10,'operator')", &[&account]).await.unwrap();
    // Retain the shorter original fixture for the natural-expiry control;
    // this original is never renewed or replaced.
    let packet = queue_with_lifetime(&mut c, &browser, &statement, 60_000).await;
    let published = ready(&mut c).await;
    let actor = lease(&c);
    let socket = c.socket_actor();
    let grant = grants::issue_next(&mut c.db.reader, socket, actor, &published)
        .await
        .unwrap()
        .unwrap();
    assert_original_grant_bounds(&c, &packet, &statement, grant.frame(), false).await;
    let claims = grant.frame().claims();
    let request = fetch(&c, grant.frame());
    let original: String = c.db.reader.query_one(
        "SELECT jsonb_build_array(g.xmin::text,to_jsonb(g),a.xmin::text,to_jsonb(a))::text FROM public.conversation_profile03_grants g JOIN public.conversation_profile03_effect_actors a USING(account_id,attempt_id) WHERE g.account_id=$1 AND g.attempt_id=$2 AND a.minted_ms=g.issued_ms AND a.original_device_session_digest=g.device_session_digest",
        &[&account, &claims.attempt_id],
    ).await.unwrap().get(0);
    tokio::time::timeout(std::time::Duration::from_secs(45), async {
        loop {
            let now: i64 =
                c.db.reader
                    .query_one(
                        "SELECT floor(extract(epoch FROM clock_timestamp())*1000)::bigint",
                        &[],
                    )
                    .await
                    .unwrap()
                    .get(0);
            if now >= claims.expires_at_ms {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(25)).await;
        }
    })
    .await
    .expect("actual primary grant expiry");
    // Renew only the actual still-current socket lease, never the retained
    // grant deadline. Current owner/physical selection must remain available.
    let current_ready = ready(&mut c).await;
    assert!(
        grants::fetch(&mut c.db.reader, serving(), &request)
            .await
            .is_err()
    );
    assert!(
        grants::issue_next(&mut c.db.reader, socket, actor, &current_ready)
            .await
            .unwrap()
            .is_none()
    );
    let unchanged: String = c.db.reader.query_one(
        "SELECT jsonb_build_array(g.xmin::text,to_jsonb(g),a.xmin::text,to_jsonb(a))::text FROM public.conversation_profile03_grants g JOIN public.conversation_profile03_effect_actors a USING(account_id,attempt_id) WHERE g.account_id=$1 AND g.attempt_id=$2",
        &[&account, &claims.attempt_id],
    ).await.unwrap().get(0);
    assert_eq!(unchanged, original);
    let counts = c.db.reader.query_one(
        "SELECT (SELECT count(*) FROM public.message_attempts WHERE account_id=$1 AND message_id=$2),(SELECT count(*) FROM public.usage_ledger WHERE account_id=$1 AND message_id=$2 AND entry_kind='reserve'),(SELECT count(*) FROM public.conversation_profile03_grants WHERE account_id=$1 AND message_id=$2)",
        &[&account, &packet.message],
    ).await.unwrap();
    assert_eq!(
        (
            counts.get::<_, i64>(0),
            counts.get::<_, i64>(1),
            counts.get::<_, i64>(2)
        ),
        (1, 1, 1)
    );
    c.db.finish().await;
}

#[tokio::test]
#[ignore = "requires disposable ZT_AUTH_TEST_DATABASE_URL administrator; complete current Mode guards refuse before business mutation"]
async fn mode_readiness_drift_refuses_issue_fetch_and_submit_and_restoration_is_not_cached() {
    use crate::conversation_effect03::wire;
    use crate::conversation_grant03::effects;
    use postgres_protocol::escape::escape_identifier;
    let (mut c, browser, statement) = active().await;
    let account = c.principal.tenant.account_id();
    c.db.owner.execute("INSERT INTO public.usage_quota_policies(account_id,metric,limit_units,source) VALUES($1,'outbound_message',10,'operator')", &[&account]).await.unwrap();
    let packet = queue(&mut c, &browser, &statement).await;
    let ready = ready(&mut c).await;
    let actor = lease(&c);
    let socket = c.socket_actor();
    let grant = grants::issue_next(&mut c.db.reader, socket, actor, &ready)
        .await
        .unwrap()
        .unwrap();
    let request = fetch(&c, grant.frame());
    let claims = grant.frame().claims();
    let observed: i64 =
        c.db.reader
            .query_one(
                "SELECT floor(extract(epoch FROM clock_timestamp())*1000)::bigint",
                &[],
            )
            .await
            .unwrap()
            .get(0);
    let raw = serde_json::json!({"v":1,"type":"payload_profile_submit03",
        "connection_epoch":socket.session().connection_epoch,"event_id":Uuid::new_v4(),
        "message_id":packet.message,"attempt_id":claims.attempt_id,
        "fetch_transcript_sha256":B.encode(crypto::sha(grant.frame().fetch_transcript().as_slice())),
        "segment_count":1,"observed_ms":observed.to_string()});
    let database = escape_identifier(c.db.reader_config.get_dbname().unwrap());
    let role = escape_identifier(c.db.reader_config.get_user().unwrap());
    let initial = c.db.reader.query_one("SELECT pg_catalog.has_database_privilege(CURRENT_USER,current_database(),'TEMP'),pg_catalog.has_column_privilege(CURRENT_USER,'public.conversation_reviewed_sends03','intent_version','UPDATE'),(SELECT count(*) FROM pg_catalog.pg_attrdef d JOIN pg_catalog.pg_attribute a ON(a.attrelid,a.attnum)=(d.adrelid,d.adnum) WHERE a.attrelid='public.conversation_reviewed_sends03'::regclass AND a.attname='intent_version')", &[]).await.unwrap();
    assert!(!initial.get::<_, bool>(0));
    assert!(!initial.get::<_, bool>(1));
    assert_eq!(initial.get::<_, i64>(2), 0);
    let mut controls = Vec::new();
    for name in [
        "conversation_profile03_grant_ready",
        "conversation_reviewed_send03_v2_ready",
        "hosted_runtime_identity_ready",
        "conversation_profile03_effect_ready",
    ] {
        let original: String =
            c.db.owner
                .query_one(
                    "SELECT pg_catalog.pg_get_functiondef(pg_catalog.to_regprocedure($1::text))",
                    &[&format!("public.{name}()")],
                )
                .await
                .unwrap()
                .get(0);
        controls.push((format!("CREATE OR REPLACE FUNCTION public.{name}() RETURNS boolean LANGUAGE sql STABLE SET search_path TO pg_catalog AS 'SELECT true'"), original));
    }
    controls.push(("ALTER TABLE public.conversation_reviewed_sends03 ALTER COLUMN intent_version SET DEFAULT 2".into(), "ALTER TABLE public.conversation_reviewed_sends03 ALTER COLUMN intent_version DROP DEFAULT".into()));
    controls.push((
        format!("GRANT TEMP ON DATABASE {database} TO {role}"),
        format!("REVOKE TEMP ON DATABASE {database} FROM {role}"),
    ));
    controls.push((
        format!("GRANT UPDATE(intent_version) ON public.conversation_reviewed_sends03 TO {role}"),
        format!(
            "REVOKE UPDATE(intent_version) ON public.conversation_reviewed_sends03 FROM {role}"
        ),
    ));
    let original = super::typed_submit_tests::retained(&c).await;
    for (change, restore) in controls {
        // Genuine independent admission precedes this isolated operator drift;
        // no manufactured receipt can reach the submit application path.
        c.heartbeat().await;
        let state = c.socket_state();
        let submit = wire::Request03::parse(&raw.to_string()).unwrap().unwrap();
        let admitted = effects::admit(&mut c.db.reader, socket, &state, submit.kind().admission())
            .await
            .unwrap();
        c.db.owner.batch_execute(&change).await.unwrap();
        assert!(matches!(
            grants::issue_next(&mut c.db.reader, socket, actor, &ready).await,
            Err(Error::Unavailable)
        ));
        assert!(matches!(
            grants::fetch(&mut c.db.reader, serving(), &request).await,
            Err(Error::Unavailable)
        ));
        assert!(matches!(
            effects::apply(&mut c.db.reader, admitted, &state, Some(ORIGIN), submit).await,
            Err(Error::Unavailable)
        ));
        assert_eq!(super::typed_submit_tests::retained(&c).await, original);
        c.db.owner.batch_execute(&restore).await.unwrap();
        let tx = crate::runtime_db::begin_native(&mut c.db.reader)
            .await
            .unwrap();
        crate::conversation_profile03_effect_storage::require(&tx)
            .await
            .unwrap();
        tx.rollback().await.unwrap();
        assert_eq!(super::typed_submit_tests::retained(&c).await, original);
    }
    // Restored structural readiness is not renewed content permission: these
    // slow negative controls never rewrite or extend the original grant.
    tokio::time::timeout(std::time::Duration::from_secs(35), async {
        loop {
            let primary: i64 =
                c.db.reader
                    .query_one(
                        "SELECT floor(extract(epoch FROM clock_timestamp())*1000)::bigint",
                        &[],
                    )
                    .await
                    .unwrap()
                    .get(0);
            if primary >= claims.expires_at_ms {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(25)).await;
        }
    })
    .await
    .expect("unchanged original grant expires naturally");
    c.heartbeat().await;
    assert!(
        grants::fetch(&mut c.db.reader, serving(), &request)
            .await
            .is_err()
    );
    assert_eq!(super::typed_submit_tests::retained(&c).await, original);
    c.db.finish().await;
}

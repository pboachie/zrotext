// SPDX-License-Identifier: AGPL-3.0-only
//! Genuine stock-runtime read/recovery, not an asserted owner or fake session.
use super::*;
use crate::conversation_interval03::live as intervals;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD as B};

async fn unsigned() -> (Case, Uuid, Uuid, serde_json::Value) {
    let (mut c, _browser, signed) = super::interval_queue_tests::prepared().await;
    let key = |role| -> [u8; 32] {
        signed[153..signed.len() - 64]
            .chunks_exact(149)
            .find(|r| r[0] == role && r[148] == 1)
            .unwrap()[1..33]
            .try_into()
            .unwrap()
    };
    let opening = Uuid::new_v4();
    let tx = c.db.reader.transaction().await.unwrap();
    let now:i64=tx.query_one("SELECT pg_catalog.floor(extract(epoch FROM pg_catalog.clock_timestamp())*1000)::bigint",&[]).await.unwrap().get(0);
    let mut owner = ordinary_owner03::authenticate(&tx, &c.hasher, ORIGIN, source(&c.credentials))
        .await
        .unwrap();
    let (new, receipt) = intervals::reserve(
        &tx,
        &mut owner,
        intervals::Reserve03 {
            opening,
            line: c.line,
            peer: b"+12",
            archive: key(2),
            phone: key(4),
            browser: key(5),
            expires_ms: now as u64 + 480_000,
            integrations: &[],
        },
        ORIGIN,
    )
    .await
    .unwrap();
    assert!(new);
    let interval = Uuid::parse_str(receipt["interval_id"].as_str().unwrap()).unwrap();
    assert_eq!(receipt["phase"], "reserved");
    drop(owner);
    tx.commit().await.unwrap();
    (c, opening, interval, receipt)
}
#[tokio::test]
#[ignore = "requires disposable ZT_AUTH_TEST_DATABASE_URL administrator; genuine retained unsigned consent and same-held context"]
async fn unsigned_context_uses_one_current_selection_and_stop_keeps_only_history() {
    let (mut c, opening, interval, receipt) = unsigned().await;
    let bytes = B.decode(receipt["statement"].as_str().unwrap()).unwrap();
    let statement = crate::conversation_interval03::Statement03::decode(&bytes).unwrap();
    let (_, setup, _, end) = statement.times();
    assert!(setup < end);
    // Renew actual metadata for this same synthetic connection after reserve.
    // Its unchanged full-session identity must not extend the signed setup.
    assert_eq!(c.db.reader.execute("UPDATE public.device_sessions SET lease_until=pg_catalog.clock_timestamp()+interval '10 minutes' WHERE account_id=$1 AND device_id=$2 AND site_id='activation-test' AND instance_id='fixture' AND connection_epoch=1 AND deployment_epoch=1",&[&c.principal.tenant.account_id(),&c.device]).await.unwrap(),1);
    let request = Uuid::new_v4();
    let tx = c.db.reader.transaction().await.unwrap();
    let mut owner = ordinary_owner03::authenticate(&tx, &c.hasher, ORIGIN, source(&c.credentials))
        .await
        .unwrap();
    let owner_deadline = owner.session_deadline_ms();
    let context = intervals::owner_context(
        &tx,
        &mut owner,
        intervals::ContextRead03 {
            request,
            opening,
            interval,
        },
        ORIGIN,
    )
    .await
    .unwrap();
    assert_eq!(context["kind"], "owner_conversation_context03");
    assert_eq!(context["request_id"], request.to_string());
    assert_eq!(context["selection"]["kind"], "owner_manifest_selection03");
    assert_eq!(context["selection"]["compared_ms"], context["compared_ms"]);
    assert_eq!(
        context["selection"]["permission_expires_ms"],
        context["permission_expires_ms"]
    );
    assert_eq!(context["permission_expires_ms"], setup.to_string());
    assert_eq!(
        context["owner_session_expires_ms"],
        owner_deadline.to_string()
    );
    assert_eq!(
        context["selection"]["owner_session_id"],
        c.principal.session_id.to_string()
    );
    assert_eq!(
        context["selection"]["physical_selection"]["kind"],
        "original_v2"
    );
    assert_eq!(context["readers"], serde_json::json!([]));
    assert!(
        owner_deadline
            > context["permission_expires_ms"]
                .as_str()
                .unwrap()
                .parse::<u64>()
                .unwrap()
    );
    assert_eq!(context["statement_sha256"], B.encode(crypto::sha(&bytes)));
    assert_eq!(
        intervals::opening_status(&tx, &mut owner, opening)
            .await
            .unwrap(),
        receipt
    );
    drop(owner);
    tx.rollback().await.unwrap();
    let tx = c.db.reader.transaction().await.unwrap();
    let mut owner = ordinary_owner03::authenticate(&tx, &c.hasher, ORIGIN, source(&c.credentials))
        .await
        .unwrap();
    assert!(
        intervals::owner_context(
            &tx,
            &mut owner,
            intervals::ContextRead03 {
                request: Uuid::new_v4(),
                opening: Uuid::new_v4(),
                interval
            },
            ORIGIN
        )
        .await
        .is_err()
    );
    drop(owner);
    tx.rollback().await.unwrap();
    let tx = c.db.reader.transaction().await.unwrap();
    let mut owner = ordinary_owner03::authenticate(&tx, &c.hasher, ORIGIN, source(&c.credentials))
        .await
        .unwrap();
    intervals::stop(&tx, &mut owner, interval).await.unwrap();
    drop(owner);
    tx.commit().await.unwrap();
    let tx = c.db.reader.transaction().await.unwrap();
    let mut owner = ordinary_owner03::authenticate(&tx, &c.hasher, ORIGIN, source(&c.credentials))
        .await
        .unwrap();
    assert!(
        intervals::owner_context(
            &tx,
            &mut owner,
            intervals::ContextRead03 {
                request: Uuid::new_v4(),
                opening,
                interval
            },
            ORIGIN
        )
        .await
        .is_err()
    );
    let stopped = intervals::opening_status(&tx, &mut owner, opening)
        .await
        .unwrap();
    assert_eq!(stopped["phase"], "stopped");
    assert_eq!(stopped["statement"], receipt["statement"]);
    assert!(stopped.get("selection").is_none());
    drop(owner);
    tx.rollback().await.unwrap();
    c.db.finish().await;
}
#[tokio::test]
#[ignore = "requires disposable ZT_AUTH_TEST_DATABASE_URL administrator; genuine sign-in interrupted reserve reconciliation"]
async fn opening_only_recovery_after_fresh_signin_cannot_adopt_old_session_or_create_another_interval()
 {
    let (mut c, opening, interval, receipt) = unsigned().await;
    let old = c.principal.session_id;
    assert!(
        crate::auth::revoke_session(&c.db.reader, &c.principal, old)
            .await
            .unwrap()
    );
    let challenge = crate::auth::mfa::begin_login_challenge(
        &c.db.reader,
        &c.hasher,
        c.principal.tenant.account_id(),
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
    assert_ne!(c.principal.session_id, old);
    let tx = c.db.reader.transaction().await.unwrap();
    let mut owner = ordinary_owner03::authenticate(&tx, &c.hasher, ORIGIN, source(&c.credentials))
        .await
        .unwrap();
    assert_eq!(
        intervals::opening_status(&tx, &mut owner, opening)
            .await
            .unwrap(),
        receipt
    );
    assert!(
        intervals::owner_context(
            &tx,
            &mut owner,
            intervals::ContextRead03 {
                request: Uuid::new_v4(),
                opening,
                interval
            },
            ORIGIN
        )
        .await
        .is_err()
    );
    drop(owner);
    tx.rollback().await.unwrap();
    let row=c.db.reader.query_one("SELECT initiating_session_id,(SELECT count(*) FROM public.conversation_profile03_intervals WHERE account_id=$1) FROM public.conversation_profile03_intervals WHERE account_id=$1 AND opening_id=$2",&[&c.principal.tenant.account_id(),&opening]).await.unwrap();
    assert_eq!(row.get::<_, Uuid>(0), old);
    assert_eq!(row.get::<_, i64>(1), 1);
    c.db.finish().await;
}

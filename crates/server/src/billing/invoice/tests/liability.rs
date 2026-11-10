// SPDX-License-Identifier: AGPL-3.0-only
use super::*;

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL with CREATEDB/CREATEROLE; disposable current public database"]
async fn catalog_only_terminal_projection_closes_original_invoice_liability_once() {
    let mut case = Case::new().await;
    let paid = case.observation("active", "paid", "subscription_cycle");
    case.observe(&paid).await.unwrap();
    let first = case.send("terminal-liability").await.unwrap().message_id;
    let cancelled = case.send("refunded-liability").await.unwrap().message_id;
    assert_eq!(accounting(&case).await, (2, 0, 2, 2, 2));

    // The typed effect helper deliberately inherits only pg_catalog. Exercise
    // its real public.messages trigger without widening that trusted path.
    catalog_state(&mut case, first, "failed").await;
    assert_eq!(accounting(&case).await, (2, 0, 1, 2, 2));
    assert_eq!(liability(&case, first).await, (true, false));
    for state in ["failed", "delivered", "cancelled", "expired"] {
        catalog_state(&mut case, first, state).await;
        assert_eq!(accounting(&case).await, (2, 0, 1, 2, 2));
        assert_eq!(liability(&case, first).await, (true, false));
    }

    // A legitimate pre-grant cancellation already refunded the other unit.
    // Later terminal projections must not release another unit or add credit.
    assert!(
        zrotext_delivery_store::DeliveryStore::new(&mut case.db)
            .cancel(case.account, cancelled)
            .await
            .unwrap()
    );
    assert_eq!(accounting(&case).await, (2, 1, 0, 2, 3));
    for state in ["cancelled", "failed"] {
        catalog_state(&mut case, cancelled, state).await;
        assert_eq!(accounting(&case).await, (2, 1, 0, 2, 3));
        assert_eq!(liability(&case, cancelled).await, (true, true));
    }

    // The documented unmetered Store API supplies a genuine message without
    // an invoice attribution; terminal projection must leave billing alone.
    let unmetered = Uuid::new_v4();
    assert!(
        zrotext_delivery_store::DeliveryStore::new(&mut case.db)
            .accept(zrotext_delivery_store::NewMessage {
                account_id: case.account,
                device_id: case.device,
                client_message_id: unmetered,
                idempotency_key: "unmetered-liability",
                recipient_e164: "+15551234567",
                synthetic_payload: b"synthetic invoice trigger fixture",
                expires_at_ms: case.end * 1000,
                line_label: None,
                no_fallback: false,
            })
            .await
            .unwrap()
            .created
    );
    catalog_state(&mut case, unmetered, "failed").await;
    assert_eq!(accounting(&case).await, (2, 1, 0, 2, 3));
    assert!(!case.db.query_one(
        "SELECT EXISTS(SELECT FROM public.billing_invoice_usage WHERE account_id=$1 AND message_id=$2)",
        &[&case.account, &unmetered],
    ).await.unwrap().get::<_, bool>(0));
    assert!(case.db.query_one(
        "SELECT NOT p.prosecdef AND p.proconfig IS NULL AND p.proowner=c.relowner AND p.prorettype='pg_catalog.trigger'::regtype AND p.pronargs=0 AND l.lanname='plpgsql' AND t.tgenabled IN('O','A') FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_language l ON l.oid=p.prolang JOIN pg_catalog.pg_class c ON c.oid='public.accounts'::regclass JOIN pg_catalog.pg_trigger t ON t.tgrelid='public.messages'::regclass AND t.tgname='billing_invoice_liability' AND t.tgfoid=p.oid WHERE p.oid='public.close_billing_invoice_liability()'::regprocedure",
        &[],
    ).await.unwrap().get::<_, bool>(0));
    case.current.as_ref().unwrap().verify().await;
    case.cleanup().await;
}

async fn catalog_state(case: &mut Case, message: Uuid, state: &str) {
    let tx = case.db.transaction().await.unwrap();
    // Use the unchanged current-schema/manual-namespace entry, not an owner
    // connection or a fabricated hosted identity.
    assert_eq!(
        zrotext_delivery_store::enter_hosted_transaction(&tx, None)
            .await
            .unwrap(),
        None
    );
    tx.batch_execute("SET LOCAL search_path TO pg_catalog")
        .await
        .unwrap();
    assert_eq!(
        tx.query_one("SELECT pg_catalog.current_setting('search_path')", &[])
            .await
            .unwrap()
            .get::<_, String>(0),
        "pg_catalog"
    );
    assert_eq!(tx.execute(
        "UPDATE public.messages SET state=$3,state_version=state_version+1,updated_at=pg_catalog.clock_timestamp() WHERE account_id=$1 AND id=$2",
        &[&case.account, &message, &state],
    ).await.unwrap(), 1);
    tx.commit().await.unwrap();
}

async fn accounting(case: &Case) -> (i64, i64, i64, i64, i64) {
    let row = case.db.query_one(
        "SELECT reserved_units,refunded_units,open_units,(SELECT count(*) FROM public.billing_invoice_usage WHERE account_id=$1),(SELECT count(*) FROM public.usage_ledger WHERE account_id=$1) FROM public.billing_invoice_periods WHERE account_id=$1",
        &[&case.account],
    ).await.unwrap();
    (row.get(0), row.get(1), row.get(2), row.get(3), row.get(4))
}

async fn liability(case: &Case, message: Uuid) -> (bool, bool) {
    let row = case.db.query_one(
        "SELECT terminal,refunded FROM public.billing_invoice_usage WHERE account_id=$1 AND message_id=$2",
        &[&case.account, &message],
    ).await.unwrap();
    (row.get(0), row.get(1))
}

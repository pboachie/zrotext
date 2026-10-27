// SPDX-License-Identifier: AGPL-3.0-only
//! Genuine physical readers retain schema refusal before material is returned.
use super::*;
use crate::manifest_install03::SelectedManifest03;
use postgres_protocol::escape::escape_identifier;

async fn physical(c: &mut Case) -> [u8; 32] {
    c.heartbeat().await;
    let tx = c.db.reader.transaction().await.unwrap();
    let selected = SelectedManifest03::lock(&tx, c.principal.tenant.account_id(), c.line, ORIGIN)
        .await
        .unwrap();
    let context = selected.device_context(&tx).await.unwrap();
    let result = selected.physical(&tx, &context).await.unwrap();
    assert_eq!(result.identity(), ("original_v2", None));
    let digest = *result.digest();
    drop(context);
    drop(selected);
    tx.rollback().await.unwrap();
    digest
}

#[tokio::test]
#[ignore = "requires disposable ZT_AUTH_TEST_DATABASE_URL administrator; actual ordinary physical reader"]
async fn selected_physical_rechecks_schema_and_missing_family_cannot_construct_authority() {
    let (mut c, _) = elected().await;
    let original = physical(&mut c).await;
    let role = escape_identifier(&c.db.read_role);
    let declaration: String = c.db.reader.query_one("SELECT pg_catalog.pg_get_functiondef(oid)||coalesce(proacl::text,'') FROM pg_catalog.pg_proc WHERE oid='public.payload_profile_selection_ready()'::pg_catalog.regprocedure", &[]).await.unwrap().get(0);
    for (change, restore) in [
        (
            "ALTER FUNCTION public.payload_profile_selection_ready() VOLATILE".to_owned(),
            "ALTER FUNCTION public.payload_profile_selection_ready() STABLE".to_owned(),
        ),
        (
            format!(
                "REVOKE EXECUTE ON FUNCTION public.payload_profile_selection_ready() FROM {role}"
            ),
            format!("GRANT EXECUTE ON FUNCTION public.payload_profile_selection_ready() TO {role}"),
        ),
    ] {
        c.heartbeat().await;
        let tx = c.db.reader.transaction().await.unwrap();
        let selected =
            SelectedManifest03::lock(&tx, c.principal.tenant.account_id(), c.line, ORIGIN)
                .await
                .unwrap();
        let context = selected.device_context(&tx).await.unwrap();
        assert_eq!(
            *selected.physical(&tx, &context).await.unwrap().digest(),
            original
        );
        tx.batch_execute("SAVEPOINT physical_schema_refusal")
            .await
            .unwrap();
        c.db.owner.batch_execute(&change).await.unwrap();
        let refused = matches!(
            selected.physical(&tx, &context).await,
            Err(Error::Unavailable)
        );
        c.db.owner.batch_execute(&restore).await.unwrap();
        tx.batch_execute("ROLLBACK TO SAVEPOINT physical_schema_refusal; RELEASE SAVEPOINT physical_schema_refusal").await.unwrap();
        assert!(refused);
        assert_eq!(
            *selected.physical(&tx, &context).await.unwrap().digest(),
            original
        );
        drop(context);
        drop(selected);
        tx.rollback().await.unwrap();
        let restored: String = c.db.reader.query_one("SELECT pg_catalog.pg_get_functiondef(oid)||coalesce(proacl::text,'') FROM pg_catalog.pg_proc WHERE oid='public.payload_profile_selection_ready()'::pg_catalog.regprocedure", &[]).await.unwrap().get(0);
        assert_eq!(restored, declaration);
        assert_eq!(physical(&mut c).await, original);
    }
    // Missing schema is tested before taking relation locks: no fabricated held
    // value or role switch is used to get around ordinary lock/permission rules.
    c.db.owner.batch_execute("ALTER TABLE public.payload_profile_selection_receipts RENAME TO synthetic_hidden_selection_receipts").await.unwrap();
    let tx = c.db.reader.transaction().await.unwrap();
    let partial_refused =
        SelectedManifest03::lock(&tx, c.principal.tenant.account_id(), c.line, ORIGIN)
            .await
            .is_err();
    tx.rollback().await.unwrap();
    c.db.owner.batch_execute("ALTER TABLE public.synthetic_hidden_selection_receipts RENAME TO payload_profile_selection_receipts").await.unwrap();
    assert!(partial_refused);
    assert_eq!(physical(&mut c).await, original);

    let functions: Vec<(String, String)> = c.db.reader.query("SELECT proname::text,pg_catalog.format('public.%I(%s)',proname,pg_catalog.pg_get_function_identity_arguments(oid)) FROM pg_catalog.pg_proc WHERE pronamespace='public'::pg_catalog.regnamespace AND proname LIKE 'payload_profile_selection_%' ORDER BY proname", &[]).await.unwrap().iter().map(|row| (row.get(0), row.get(1))).collect();
    assert_eq!(functions.len(), 11);
    let tx = c.db.owner.transaction().await.unwrap();
    for (index, (_, signature)) in functions.iter().enumerate() {
        tx.batch_execute(&format!(
            "ALTER FUNCTION {signature} RENAME TO synthetic_hidden_selection_{index}"
        ))
        .await
        .unwrap();
    }
    tx.batch_execute("ALTER TABLE public.payload_profile_selection_challenges RENAME TO synthetic_hidden_selection_challenges; ALTER TABLE public.payload_profile_selection_receipts RENAME TO synthetic_hidden_selection_receipts").await.unwrap();
    tx.commit().await.unwrap();
    let absent: bool = c.db.reader.query_one("SELECT pg_catalog.to_regclass('public.payload_profile_selection_challenges') IS NULL AND pg_catalog.to_regclass('public.payload_profile_selection_receipts') IS NULL AND NOT EXISTS(SELECT FROM pg_catalog.pg_proc WHERE pronamespace='public'::pg_catalog.regnamespace AND proname LIKE 'payload_profile_selection_%')", &[]).await.unwrap().get(0);
    assert!(absent);
    let tx = c.db.reader.transaction().await.unwrap();
    let absent_refused =
        SelectedManifest03::lock(&tx, c.principal.tenant.account_id(), c.line, ORIGIN)
            .await
            .is_err();
    tx.rollback().await.unwrap();
    let tx = c.db.owner.transaction().await.unwrap();
    tx.batch_execute("ALTER TABLE public.synthetic_hidden_selection_challenges RENAME TO payload_profile_selection_challenges; ALTER TABLE public.synthetic_hidden_selection_receipts RENAME TO payload_profile_selection_receipts").await.unwrap();
    for (index, (name, signature)) in functions.iter().enumerate() {
        let hidden = signature.replacen(
            &format!("public.{name}"),
            &format!("public.synthetic_hidden_selection_{index}"),
            1,
        );
        tx.batch_execute(&format!(
            "ALTER FUNCTION {hidden} RENAME TO {}",
            escape_identifier(name)
        ))
        .await
        .unwrap();
    }
    tx.commit().await.unwrap();
    assert!(absent_refused);
    assert_eq!(physical(&mut c).await, original);
    c.db.finish().await;
}

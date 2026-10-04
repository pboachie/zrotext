// SPDX-License-Identifier: AGPL-3.0-only
use super::*;

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; disposable concurrent consent and workflow schema"]
async fn owner_session_revocation_during_consent_wait_rolls_back_every_change() {
    let (mut case, input, _, _) = prepared().await;
    let route = OwnerRoute::new(&case).await;
    let application = route.application.clone();
    let session = route.session;
    let observer = case.f.connect().await;
    let tx = case.f.db.transaction().await.unwrap();
    tx.query_one(
        "SELECT id FROM accounts WHERE id=$1 FOR UPDATE",
        &[&case.f.account],
    )
    .await
    .unwrap();
    let withdrawal = tokio::spawn(async move { route.consent("withdraw").await });
    let started = tokio::time::Instant::now();
    loop {
        let waiting = observer.query_one("SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE application_name=$1 AND wait_event_type='Lock' AND query LIKE '%FOR NO KEY UPDATE%')", &[&application]).await.unwrap().get::<_,bool>(0);
        if waiting {
            break;
        }
        assert!(
            started.elapsed() < std::time::Duration::from_secs(2),
            "withdrawal must reach the observed account lock"
        );
        tokio::task::yield_now().await;
    }
    observer
        .execute(
            "UPDATE sessions SET revoked_at=clock_timestamp() WHERE id=$1",
            &[&session],
        )
        .await
        .unwrap();
    tx.commit().await.unwrap();
    assert_eq!(withdrawal.await.unwrap(), StatusCode::UNAUTHORIZED);
    let row=case.f.db.query_one("SELECT (SELECT count(*) FROM contact_consent_records WHERE action='withdraw'),(SELECT count(*) FROM workflow_integration_grants WHERE revoked_ms IS NOT NULL),(SELECT count(*) FROM workflow_routine_policies WHERE withdrawn_ms IS NOT NULL)",&[]).await.unwrap();
    assert_eq!(
        (
            row.get::<_, i64>(0),
            row.get::<_, i64>(1),
            row.get::<_, i64>(2)
        ),
        (0, 0, 0)
    );
    assert!(
        super::super::super::super::read_context_content(
            &mut case.f.connect().await,
            &input,
            Uuid::new_v4(),
            case.header.context
        )
        .await
        .is_ok()
    );
    case.f.cleanup().await;
}

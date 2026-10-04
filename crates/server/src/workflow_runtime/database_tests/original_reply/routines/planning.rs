// SPDX-License-Identifier: AGPL-3.0-only
use super::*;

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; genuine original routine authority"]
async fn routine_join_order_setting_is_local_after_commit_and_refusal() {
    let f = RoutineCase::new().await;
    let mut client = f.f.case.f.connect().await;
    // An explicit noncandidate baseline makes a mistaken SET SESSION visible
    // even when the test launcher itself supplies join_collapse_limit=1.
    client
        .batch_execute("SET join_collapse_limit=8")
        .await
        .map_err(|_| ())
        .expect("fixture setting unavailable");
    let initial: String = client
        .query_one("SELECT current_setting('join_collapse_limit')", &[])
        .await
        .map_err(|_| ())
        .expect("fixture setting unavailable")
        .get(0);
    assert_eq!(initial, "8");
    let original = service::authenticate(&client, &f.f.case.hasher, &f.read.token)
        .await
        .map_err(|_| ())
        .expect("original authority unavailable");
    let policy = routines::current_with_original(
        &mut client,
        &f.input,
        Some(&original),
        f.policy.context_id,
        f.policy.policy_id,
    )
    .await
    .map_err(|_| ())
    .expect("genuine current policy refused");
    assert_eq!(policy.policy_id, f.policy.policy_id);
    let committed: String = client
        .query_one("SELECT current_setting('join_collapse_limit')", &[])
        .await
        .map_err(|_| ())
        .expect("fixture setting unavailable")
        .get(0);
    assert_eq!(
        committed, initial,
        "successful transaction leaked join setting"
    );
    let refused = routines::current_with_original(
        &mut client,
        &f.input,
        Some(&original),
        f.policy.context_id,
        Uuid::new_v4(),
    )
    .await;
    assert!(
        matches!(refused, Err(AuthError::Forbidden)),
        "missing policy did not refuse"
    );
    let rolled_back: String = client
        .query_one("SELECT current_setting('join_collapse_limit')", &[])
        .await
        .map_err(|_| ())
        .expect("fixture setting unavailable")
        .get(0);
    assert_eq!(
        rolled_back, initial,
        "refused transaction leaked join setting"
    );
    drop(client);
    f.finish().await;
}

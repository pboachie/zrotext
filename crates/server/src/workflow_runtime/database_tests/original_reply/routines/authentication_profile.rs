// SPDX-License-Identifier: AGPL-3.0-only
use super::*;
use std::time::Instant;
use tokio_postgres::Client;

async fn setting(client: &Client) -> String {
    client
        .query_one("SELECT current_setting('join_collapse_limit')", &[])
        .await
        .map_err(|_| ())
        .expect("fixture setting unavailable")
        .get(0)
}

async fn profile_authentication(
    client: &Client,
    f: &RoutineCase,
    local_order: bool,
) -> Result<(IntegrationPrincipal, u128), AuthError> {
    client
        .batch_execute("BEGIN")
        .await
        .map_err(|_| AuthError::Crypto)?;
    // No assertion or early return may strand this test-owned connection in a
    // transaction. Preserve the real authentication result until rollback.
    let result = async {
        if local_order {
            client
                .batch_execute("SET LOCAL join_collapse_limit=1")
                .await?;
        }
        let observed = client
            .query_one("SELECT current_setting('join_collapse_limit')", &[])
            .await?;
        let active: String = observed.get(0);
        if active != if local_order { "1" } else { "8" } {
            return Err(AuthError::Crypto);
        }
        let start = Instant::now();
        let principal = authenticate(client, &f.f.case.hasher, &f.input_token).await?;
        Ok((principal, start.elapsed().as_millis()))
    }
    .await;
    let rollback = client.batch_execute("ROLLBACK").await;
    rollback.map_err(|_| AuthError::Crypto)?;
    result
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; genuine original routine authentication profile"]
async fn genuine_workflow_authentication_matches_with_local_join_order_and_restores_settings() {
    let f = RoutineCase::new().await;
    let client = f.f.case.f.connect().await;
    client
        .batch_execute("SET join_collapse_limit=8")
        .await
        .map_err(|_| ())
        .expect("fixture setting unavailable");
    assert_eq!(setting(&client).await, "8");
    let mut samples = Vec::new();
    // Alternate order on identical live authority rows; elapsed values are
    // observations, not a hardware-dependent speed assertion or a permit.
    for local in [false, true, true, false] {
        let result = profile_authentication(&client, &f, local).await;
        assert_eq!(
            setting(&client).await,
            "8",
            "authentication profile leaked setting"
        );
        let (principal, elapsed) = result
            .map_err(|_| ())
            .expect("genuine authentication refused");
        assert_eq!(principal.account_id(), f.input.account_id());
        assert_eq!(principal.grant_id(), f.input.grant_id());
        assert_eq!(principal.credential_hash(), f.input.credential_hash());
        for operation in [
            Operation::ContactRead,
            Operation::ContextMetadata,
            Operation::ContextContent,
            Operation::Propose,
            Operation::Status,
            Operation::Schedule,
            Operation::Send,
        ] {
            assert_eq!(
                principal.require(operation).is_ok(),
                f.input.require(operation).is_ok()
            );
        }
        samples.push((local, elapsed));
    }
    for (local, elapsed) in samples {
        eprintln!("workflow authentication profile local_order={local} elapsed_ms={elapsed}");
    }
    drop(client);
    f.finish().await;
}

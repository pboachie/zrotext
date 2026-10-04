// SPDX-License-Identifier: AGPL-3.0-only
use super::*;

async fn issuance_respects_conversation_key(role: u8) {
    let mut f = OriginalCase::with_conversation_key_deadline(Some(role)).await;
    let at = (0..usize::from(f.case.f.bytes[150]))
        .map(|index| 151 + 149 * index)
        .find(|at| f.case.f.bytes[*at] == role)
        .unwrap();
    let until = i64::try_from(u64::from_be_bytes(
        f.case.f.bytes[at + 140..at + 148].try_into().unwrap(),
    ))
    .unwrap();
    let mut caller = f.case.f.connect().await;
    let factor = f.case.fresh_factor().await;
    let unused = f.case.f.db.query_one(
        "SELECT count(*) FROM owner_mfa_recovery_codes WHERE account_id=$1 AND user_id=$2 AND used_at IS NULL",
        &[&f.case.f.account, &f.case.owner.user_id],
    ).await.unwrap().get::<_, i64>(0);
    let mut request = service::GrantRequest {
        interval_id: f.statement.interval,
        connector_id: f.case.request.connector,
        read_grant_id: f.read_grant,
        reader_key_id: f.statement.integration_readers[0].key_id,
        expires_at_ms: until + 1,
    };
    let now: i64 = caller
        .query_one(
            "SELECT floor(extract(epoch FROM clock_timestamp())*1000)::bigint",
            &[],
        )
        .await
        .unwrap()
        .get(0);
    assert!(now < until);
    assert!(matches!(
        service::issue(
            &mut caller,
            &f.case.owner,
            &f.case.hasher,
            &f.case.cipher,
            &f.case.password,
            &factor,
            &request
        )
        .await,
        Err(auth::AuthError::InvalidInput)
    ));
    let after = f.case.f.db.query_one(
        "SELECT (SELECT count(*) FROM original_reply_grants WHERE account_id=$1), (SELECT count(*) FROM owner_mfa_recovery_codes WHERE account_id=$1 AND user_id=$2 AND used_at IS NULL)",
        &[&f.case.f.account, &f.case.owner.user_id],
    ).await.unwrap();
    assert_eq!(after.get::<_, i64>(0), 0);
    assert_eq!(after.get::<_, i64>(1), unused);
    request.expires_at_ms = until;
    let issued = service::issue(
        &mut caller,
        &f.case.owner,
        &f.case.hasher,
        &f.case.cipher,
        &f.case.password,
        &factor,
        &request,
    )
    .await
    .unwrap();
    let principal = service::authenticate(&caller, &f.case.hasher, &issued.token)
        .await
        .unwrap();
    let proof = service::current(&mut caller, &principal, f.statement.activation_version)
        .await
        .unwrap();
    assert_eq!(proof.expires_at_ms, until);
    assert!(proof.observed_at_ms < until);
    let row = caller.query_one(
        "SELECT expires_ms, original_reply_grant_deadline(account_id,grant_id), original_reply_grant_current(account_id,grant_id) FROM original_reply_grants WHERE account_id=$1 AND grant_id=$2",
        &[&f.case.f.account, &issued.grant_id],
    ).await.unwrap();
    assert_eq!(row.get::<_, i64>(0), until);
    assert_eq!(row.get::<_, i64>(1), until);
    assert!(row.get::<_, bool>(2));
    assert!(caller.execute(
        "UPDATE original_reply_grants SET expires_ms=$3 WHERE account_id=$1 AND grant_id=$2",
        &[&f.case.f.account, &issued.grant_id, &(until + 1)],
    ).await.is_err());
    f.case.f.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; genuine original grant archive-key deadline"]
async fn original_grant_cannot_outlive_archive_reader_or_consume_factor_on_refusal() {
    issuance_respects_conversation_key(2).await;
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; genuine original grant phone-signer deadline"]
async fn original_grant_cannot_outlive_phone_signer_or_consume_factor_on_refusal() {
    issuance_respects_conversation_key(4).await;
}

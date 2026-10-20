// SPDX-License-Identifier: AGPL-3.0-only
use super::super::test_database::Fixture;
use super::*;
use crate::sealed_inbound::line_activation::{v2, v2_runtime as run};
use tokio_postgres::error::SqlState;
pub(crate) mod fixture;
use fixture::Case;
const ORIGIN: &str = "https://activation.example";

#[tokio::test]
#[ignore = "requires disposable ZT_AUTH_TEST_DATABASE_URL administrator; ordinary runtime genuine ceremonies"]
async fn fresh_registered_activation_captures_exact_originals_and_survives_nonce_clear_and_owner_signout()
 {
    let mut c = Case::new().await;
    c.approve().await;
    let locator = c.locator().await;
    let before = read(&mut c.db.reader, locator, ORIGIN).await.unwrap();
    assert_eq!(before.identity().registration, c.registration);
    assert_eq!(before.activation_challenge_id(), c.challenge.id);
    assert_ne!(before.binding_id(), c.challenge.id);
    let decoded = ActivationEvidence03::decode(before.canonical_evidence()).unwrap();
    assert_eq!(decoded.device_statement.as_slice(), c.device_statement);
    assert_eq!(decoded.owner_statement.as_slice(), c.owner_statement);
    assert_eq!(decoded.device_signature_der, c.device_der);
    assert_eq!(decoded.owner_signature_der, c.owner_der);
    assert_eq!(before.original_proof_lease().site_id(), "activation-test");
    assert_eq!(before.original_proof_lease().connection_epoch(), 1);
    let lease = c.lease();
    let ack = run::next_ack(&mut c.db.reader, lease, run::Purpose::Sealed, &[])
        .await
        .unwrap()
        .unwrap();
    assert!(
        run::confirm_sealed_install(&mut c.db.reader, lease, ack)
            .await
            .unwrap()
    );
    assert!(c.db.reader.query_one("SELECT nonce IS NULL AND installed_at IS NOT NULL FROM public.line_activation_v2_pending WHERE challenge_id=$1", &[&c.challenge.id]).await.unwrap().get::<_,bool>(0));
    c.approve().await;
    c.db.reader
        .execute(
            "UPDATE public.sessions SET revoked_at=clock_timestamp() WHERE id=$1",
            &[&c.principal.session_id],
        )
        .await
        .unwrap();
    let after = read(&mut c.db.reader, locator, ORIGIN).await.unwrap();
    assert_eq!(after.canonical_evidence(), before.canonical_evidence());
    assert_eq!(after.accepted_ms(), before.accepted_ms());
    assert!(after.identity() == before.identity());
    assert_eq!(
        after.old_binding_proof_digest(),
        before.old_binding_proof_digest()
    );
    c.db.finish().await;
}

#[tokio::test]
#[ignore = "requires disposable ZT_AUTH_TEST_DATABASE_URL administrator; ordinary runtime genuine ceremonies"]
async fn wrong_owner_proof_cannot_capture_or_activate_and_exact_valid_proof_still_works() {
    let mut c = Case::new().await;
    let mut wrong = c.owner_der.clone();
    *wrong.last_mut().unwrap() ^= 1;
    assert!(
        run::approve(
            &mut c.db.reader,
            &c.principal,
            c.line,
            c.challenge.id,
            run::Purpose::Sealed,
            &wrong
        )
        .await
        .is_err()
    );
    assert_eq!(c.db.reader.query_one("SELECT count(*) FROM public.payload_profile_v2_activation_receipts WHERE account_id=$1", &[&c.principal.tenant.account_id()]).await.unwrap().get::<_,i64>(0),0);
    assert!(c.db.reader.query_one("SELECT approved_at IS NULL FROM public.line_activation_v2_pending WHERE challenge_id=$1", &[&c.challenge.id]).await.unwrap().get::<_,bool>(0));
    c.approve().await;
    let locator = c.locator().await;
    assert!(read(&mut c.db.reader, locator, ORIGIN).await.is_ok());
    c.db.finish().await;
}

#[tokio::test]
#[ignore = "requires disposable ZT_AUTH_TEST_DATABASE_URL administrator; ordinary runtime genuine ceremonies"]
async fn runtime_cannot_rewrite_original_receipts_and_current_root_or_origin_substitution_refuses()
{
    let mut c = Case::new().await;
    c.approve().await;
    let locator = c.locator().await;
    let error = c.db.reader.execute("UPDATE public.payload_profile_v2_activation_receipts SET accepted_ms=accepted_ms+1 WHERE account_id=$1", &[&locator.account]).await.unwrap_err();
    assert_eq!(error.code(), Some(&SqlState::INSUFFICIENT_PRIVILEGE));
    assert!(matches!(
        read(&mut c.db.reader, locator, "https://different.example").await,
        Err(ReadError::Refused)
    ));
    let mut absent = locator;
    absent.binding = Uuid::new_v4();
    assert!(matches!(
        read(&mut c.db.reader, absent, ORIGIN).await,
        Err(ReadError::Refused)
    ));
    c.db.reader.execute("UPDATE public.sealed_manifest_authorities SET revoked_at=clock_timestamp() WHERE account_id=$1", &[&locator.account]).await.unwrap();
    assert!(matches!(
        read(&mut c.db.reader, locator, ORIGIN).await,
        Err(ReadError::Refused)
    ));
    c.db.finish().await;
}

#[tokio::test]
#[ignore = "requires disposable ZT_AUTH_TEST_DATABASE_URL administrator; observed ordinary-runtime account fence"]
async fn original_reader_holds_account_until_transaction_end_without_serializing_another_account() {
    let mut c = Case::new().await;
    c.approve().await;
    let locator = c.locator().await;
    let (writer, connection) =
        c.db.reader_config
            .connect(tokio_postgres::NoTls)
            .await
            .unwrap();
    let driver = tokio::spawn(connection);
    writer
        .batch_execute("SET lock_timeout='100ms'; SET statement_timeout='2s'")
        .await
        .unwrap();
    let tx = c.db.reader.transaction().await.unwrap();
    let historical = read_locked(&tx, locator, ORIGIN).await.unwrap();
    let blocked = writer
        .execute(
            "UPDATE public.accounts SET disabled_at=clock_timestamp() WHERE id=$1",
            &[&locator.account],
        )
        .await
        .unwrap_err();
    assert_eq!(blocked.code(), Some(&SqlState::LOCK_NOT_AVAILABLE));
    let other = Uuid::new_v4();
    writer
        .execute("INSERT INTO public.accounts(id) VALUES($1)", &[&other])
        .await
        .unwrap();
    writer
        .execute(
            "UPDATE public.accounts SET disabled_at=clock_timestamp() WHERE id=$1",
            &[&other],
        )
        .await
        .unwrap();
    tx.rollback().await.unwrap();
    writer
        .execute(
            "UPDATE public.accounts SET disabled_at=clock_timestamp() WHERE id=$1",
            &[&locator.account],
        )
        .await
        .unwrap();
    assert!(matches!(
        read(&mut c.db.reader, locator, ORIGIN).await,
        Err(ReadError::Refused)
    ));
    // The retained object remains historical bytes, never current permission.
    assert!(!historical.canonical_evidence().is_empty());
    drop(writer);
    driver.await.unwrap().unwrap();
    c.db.finish().await;
}

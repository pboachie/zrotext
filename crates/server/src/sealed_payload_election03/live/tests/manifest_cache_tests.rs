// SPDX-License-Identifier: AGPL-3.0-only
//! Privileged-negative corruption is rolled back before fixture cleanup.
use super::manifest_tests::{elected, packet};
use super::*;
use crate::manifest_install03::live as service;

#[tokio::test]
#[ignore = "requires disposable ZT_AUTH_TEST_DATABASE_URL administrator; actual ordinary runtime manifest schema"]
async fn warm_history_refuses_changed_intermediate_signature_and_rollback_restores_originals() {
    let (mut c, _) = elected().await;
    let browser = SigningKey::generate_from_rng(&mut rand::rng());
    let mut openings = Vec::new();
    for step in 0..2 {
        let (opening, statement, successor, signature) = packet(&mut c, &browser, false).await;
        let tx = c.db.reader.transaction().await.unwrap();
        let owner = ordinary_owner03::authenticate(&tx, &c.hasher, ORIGIN, source(&c.credentials))
            .await
            .unwrap();
        let step_up::Outcome::Verified(mut proof) = step_up::verify(
            owner,
            &c.hasher,
            &c.cipher,
            &c.password,
            &c.recovery[4 + step],
        )
        .await
        .unwrap() else {
            panic!("fresh manifest factor")
        };
        service::install(
            &tx,
            &mut proof,
            service::InstallCommand03 {
                opening,
                statement: &statement,
                successor: &successor,
                signature: &signature,
            },
            ORIGIN,
        )
        .await
        .unwrap();
        drop(proof);
        tx.commit().await.unwrap();
        openings.push(opening);
    }
    // This genuine ordinary current read verifies the full committed chain and
    // populates its private crypto cache at the second successor.
    let tx = c.db.reader.transaction().await.unwrap();
    let mut owner = ordinary_owner03::authenticate(&tx, &c.hasher, ORIGIN, source(&c.credentials))
        .await
        .unwrap();
    let current = service::current_owner(&tx, &mut owner, c.line, ORIGIN)
        .await
        .unwrap();
    drop(owner);
    tx.rollback().await.unwrap();
    let account = c.principal.tenant.account_id();
    let original_signature: Vec<u8> = c.db.reader.query_one(
        "SELECT signature FROM public.payload_profile_manifest_successors WHERE account_id=$1 AND opening_id=$2",
        &[&account, &openings[0]],
    ).await.unwrap().get(0);
    let tip_original: String = c.db.reader.query_one(
        "SELECT row_to_json(r)::text FROM public.payload_profile_manifest_successors r WHERE account_id=$1 AND opening_id=$2",
        &[&account, &openings[1]],
    ).await.unwrap().get(0);
    c.db.enable_negative_runtime_role_switch().await;
    let tx = c.db.owner.transaction().await.unwrap();
    // Privileged corruption changes only a received intermediate signature.
    // Restore the closed trigger graph before running the real runtime reader;
    // the tip row, unsigned semantics and stored prefix hashes remain untouched.
    tx.batch_execute("ALTER TABLE public.payload_profile_manifest_successors DISABLE TRIGGER USER")
        .await
        .unwrap();
    assert_eq!(tx.execute(
        "UPDATE public.payload_profile_manifest_successors SET signature=pg_catalog.set_byte(signature,0,pg_catalog.get_byte(signature,0)#1) WHERE account_id=$1 AND opening_id=$2",
        &[&account, &openings[0]],
    ).await.unwrap(), 1);
    tx.batch_execute("ALTER TABLE public.payload_profile_manifest_successors ENABLE TRIGGER USER")
        .await
        .unwrap();
    tx.batch_execute(&format!(
        "SET LOCAL ROLE {}",
        postgres_protocol::escape::escape_identifier(&c.db.read_role)
    ))
    .await
    .unwrap();
    assert_eq!(
        tx.query_one("SELECT current_user::text", &[])
            .await
            .unwrap()
            .get::<_, String>(0),
        c.db.read_role
    );
    crate::payload_profile_manifests::require(&tx)
        .await
        .unwrap();
    assert_eq!(tx.query_one(
        "SELECT row_to_json(r)::text FROM public.payload_profile_manifest_successors r WHERE account_id=$1 AND opening_id=$2",
        &[&account, &openings[1]],
    ).await.unwrap().get::<_, String>(0), tip_original);
    let mut owner = ordinary_owner03::authenticate(&tx, &c.hasher, ORIGIN, source(&c.credentials))
        .await
        .unwrap();
    assert!(matches!(
        service::current_owner(&tx, &mut owner, c.line, ORIGIN).await,
        Err(Error::Conflict)
    ));
    drop(owner);
    tx.rollback().await.unwrap();
    assert_eq!(c.db.reader.query_one(
        "SELECT signature FROM public.payload_profile_manifest_successors WHERE account_id=$1 AND opening_id=$2",
        &[&account, &openings[0]],
    ).await.unwrap().get::<_, Vec<u8>>(0), original_signature);
    let tx = c.db.reader.transaction().await.unwrap();
    let mut owner = ordinary_owner03::authenticate(&tx, &c.hasher, ORIGIN, source(&c.credentials))
        .await
        .unwrap();
    let restored = service::current_owner(&tx, &mut owner, c.line, ORIGIN)
        .await
        .unwrap();
    for field in ["current_manifest03", "manifest_ancestry_sha256", "evidence"] {
        assert_eq!(restored[field], current[field]);
    }
    drop(owner);
    tx.rollback().await.unwrap();
    c.db.finish().await;
}

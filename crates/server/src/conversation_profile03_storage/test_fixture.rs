// SPDX-License-Identifier: AGPL-3.0-only
use crate::test_database::Fixture;

// Current storage capabilities must use the unchanged stock runtime ACLs, not
// a hand-maintained list of entry points from an earlier migration. Retain the
// shared writer fixture's idempotent-migration and owner/runtime controls.
pub(crate) async fn new() -> Fixture {
    let mut fixture = Fixture::new("ZT_AUTH_TEST_DATABASE_URL").await;
    fixture.verify().await;
    let snapshot: Vec<u8> = fixture
        .owner
        .query_one("SELECT public.payload_profile_writer_graph()", &[])
        .await
        .unwrap()
        .get(0);
    let directory =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../deploy/compose/migrations");
    assert!(
        zrotext_migrator::apply(&mut fixture.owner, &directory, false)
            .await
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        snapshot,
        fixture
            .owner
            .query_one("SELECT public.payload_profile_writer_graph()", &[])
            .await
            .unwrap()
            .get::<_, Vec<u8>>(0)
    );
    fixture
        .runtime
        .batch_execute("SET lock_timeout='2s'; SET statement_timeout='10s'")
        .await
        .unwrap();
    crate::payload_profile_writer::require(&fixture.runtime)
        .await
        .unwrap();
    assert!(matches!(
        crate::payload_profile_writer::require(&fixture.owner).await,
        Err(crate::payload_profile_writer::WriterSchemaError::Invalid)
    ));
    fixture
}

// SPDX-License-Identifier: AGPL-3.0-only
use super::*;

#[test]
fn alpha_message_id_is_stable_per_account_and_never_the_client_id() {
    let account_a = Uuid::from_u128(0xa);
    let account_b = Uuid::from_u128(0xb);
    let client_id = Uuid::from_u128(0x413);
    let for_a = alpha_message_id(account_a, client_id);
    assert_eq!(for_a, alpha_message_id(account_a, client_id));
    assert_ne!(for_a, alpha_message_id(account_b, client_id));
    assert_ne!(for_a, client_id);
    // Submitting another account's server ID as a client ID maps elsewhere.
    assert_ne!(alpha_message_id(account_b, for_a), for_a);
    assert_eq!(for_a.get_version_num(), 8);
    assert_eq!(for_a.get_variant(), uuid::Variant::RFC4122);
}

#[tokio::test]
#[ignore = "requires ZT_DELIVERY_TEST_DATABASE_URL; run the documented PostgreSQL test command"]
async fn alpha_client_message_ids_are_scoped_per_account() {
    let url = std::env::var("ZT_DELIVERY_TEST_DATABASE_URL")
        .expect("set ZT_DELIVERY_TEST_DATABASE_URL for PostgreSQL-backed tests");
    let (mut client, connection) = tokio_postgres::connect(&url, tokio_postgres::NoTls)
        .await
        .unwrap();
    tokio::spawn(async move { connection.await.unwrap() });
    let schema = format!("alpha_ids_{}", Uuid::new_v4().simple());
    client
        .batch_execute(&format!(
            "CREATE SCHEMA {schema}; SET search_path TO {schema}"
        ))
        .await
        .unwrap();
    crate::tests::apply_test_migrations(&client).await;
    let (account_a, device_a) = (Uuid::new_v4(), Uuid::new_v4());
    let (account_b, device_b) = (Uuid::new_v4(), Uuid::new_v4());
    for (account, device) in [(account_a, device_a), (account_b, device_b)] {
        client
            .execute("INSERT INTO accounts(id) VALUES($1)", &[&account])
            .await
            .unwrap();
        client
            .execute(
                "INSERT INTO devices(id,account_id,display_name) VALUES($1,$2,'virtual phone')",
                &[&device, &account],
            )
            .await
            .unwrap();
    }
    let shared = Uuid::new_v4();
    let expiry = now_ms() + 300_000;
    let input = |account_id, device_id, client_message_id, idempotency_key| NewMessage {
        account_id,
        client_message_id,
        device_id,
        idempotency_key,
        recipient_e164: "+15551234567",
        synthetic_payload: b"fixture",
        expires_at_ms: expiry,
    };

    let first_a = DeliveryStore::new(&mut client)
        .accept_alpha(input(account_a, device_a, shared, "shared-key"), false)
        .await
        .unwrap();
    assert!(first_a.created);
    assert_ne!(first_a.message_id, shared);

    // Another account reusing the same client ID and key is ordinary new work,
    // not a conflict that would reveal account A's message.
    let first_b = DeliveryStore::new(&mut client)
        .accept_alpha(input(account_b, device_b, shared, "shared-key"), false)
        .await
        .unwrap();
    assert!(first_b.created);
    assert_ne!(first_b.message_id, first_a.message_id);
    assert_ne!(first_b.message_id, shared);

    // Probing with account A's returned server ID is also just new work.
    let probe = DeliveryStore::new(&mut client)
        .accept_alpha(
            input(account_b, device_b, first_a.message_id, "probe-key"),
            false,
        )
        .await
        .unwrap();
    assert!(probe.created);
    assert_ne!(probe.message_id, first_a.message_id);

    // Within one account the client ID still names one message.
    let replay_a = DeliveryStore::new(&mut client)
        .accept_alpha(input(account_a, device_a, shared, "shared-key"), false)
        .await
        .unwrap();
    assert_eq!(replay_a.message_id, first_a.message_id);
    assert!(!replay_a.created);
    assert!(matches!(
        DeliveryStore::new(&mut client)
            .accept_alpha(input(account_a, device_a, shared, "other-key"), false)
            .await,
        Err(StoreError::MessageIdConflict)
    ));

    let store = DeliveryStore::new(&mut client);
    assert!(
        store
            .status(account_a, first_a.message_id)
            .await
            .unwrap()
            .is_some()
    );
    assert!(
        store
            .status(account_b, first_a.message_id)
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        store
            .status(account_b, first_b.message_id)
            .await
            .unwrap()
            .is_some()
    );
    let counts: Vec<i64> = client
        .query_one(
            "SELECT (SELECT count(*) FROM messages WHERE account_id=$1), \
                    (SELECT count(*) FROM messages WHERE account_id=$2), \
                    (SELECT count(*) FROM messages WHERE id=$3)",
            &[&account_a, &account_b, &shared],
        )
        .await
        .map(|row| (0..3).map(|index| row.get(index)).collect())
        .unwrap();
    assert_eq!(counts, vec![1, 2, 0]);
    client
        .batch_execute(&format!(
            "SET search_path TO public; DROP SCHEMA {schema} CASCADE"
        ))
        .await
        .unwrap();
}

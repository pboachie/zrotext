// SPDX-License-Identifier: AGPL-3.0-only
//! ADR 0004 submit-path acceptance against disposable SQL. No Android radio,
//! SMS, provider, or external webhook is involved. Every scenario names lines
//! by owner-chosen label only; no SIM slot, subscription identifier, ICCID,
//! IMSI or phone number appears in any fixture or assertion.

use crate::{DeliveryStore, NewMessage, StoreError};

/// One fixed expiry for the whole test so exact replays keep their digest.
const EXPIRY_OFFSET_MS: i64 = 10 * 60 * 1000;
use uuid::Uuid;

fn input<'a>(account: Uuid, device: Uuid, key: &'a str, expires_at_ms: i64) -> NewMessage<'a> {
    NewMessage {
        account_id: account,
        client_message_id: Uuid::new_v4(),
        device_id: device,
        idempotency_key: key,
        recipient_e164: "+15551234567",
        synthetic_payload: b"line admission test",
        expires_at_ms,
        line_label: None,
        no_fallback: false,
    }
}

#[tokio::test]
#[ignore = "requires ZT_DELIVERY_TEST_DATABASE_URL; run the documented PostgreSQL test command"]
async fn line_labels_resolve_route_and_hold_across_every_not_ready_mode() {
    let url = std::env::var("ZT_DELIVERY_TEST_DATABASE_URL")
        .expect("set ZT_DELIVERY_TEST_DATABASE_URL for PostgreSQL-backed tests");
    let (mut client, connection) = tokio_postgres::connect(&url, tokio_postgres::NoTls)
        .await
        .unwrap();
    tokio::spawn(async move { connection.await.unwrap() });
    let schema = format!("line_admission_{}", Uuid::new_v4().simple());
    client
        .batch_execute(&format!(
            "CREATE SCHEMA {schema}; SET search_path TO {schema}"
        ))
        .await
        .unwrap();
    // The curated in-schema subset the line admission path needs; the
    // concurrent-index migrations are skipped exactly like the other
    // in-schema fixtures, and 098/099/120 supply the line policy, the
    // observations and the recorded line identity.
    let needed = [
        "001_foundation.sql",
        "002_auth.sql",
        "003_delivery.sql",
        "004_enrollment.sql",
        "005_verification_outbox.sql",
        "006_usage_metering.sql",
        "007_inbound_webhook_foundation.sql",
        "008_stripe_billing_foundation.sql",
        "009_webhook_manual_replay.sql",
        "010_billing_test_entitlement.sql",
        "011_billing_payment_holds.sql",
        "012_auth_abuse_limits.sql",
        "013_owner_mfa.sql",
        "014_owner_mfa_failure_budget.sql",
        "015_webhook_kek_commitments.sql",
        "016_auth_abuse_atomic.sql",
        "017_billing_device_caps.sql",
        "018_sealed_inbound_identity.sql",
        "019_line_activation_contract.sql",
        "030_terminal_dispatch_jobs.sql",
        "031_recipient_suppression.sql",
        "032_line_opt_out_events.sql",
        "033_sms_line_binding_scope.sql",
        "035_sms_owner_key_ceremony.sql",
        "036_owner_opt_out_holds.sql",
        "038_owner_opt_out_hold_guards.sql",
        "039_inbound_device_clock_offset.sql",
        "048_observer_memberships.sql",
        "095_device_session_line_activation_version.sql",
        "098_line_labels_and_not_ready_policy.sql",
        "099_line_readiness_observations.sql",
        "120_messages_line.sql",
    ];
    for (_, migration) in crate::tests::TEST_MIGRATIONS
        .iter()
        .filter(|(name, _)| needed.contains(name))
    {
        client.batch_execute(migration).await.unwrap();
    }
    let expires_at_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as i64
        + EXPIRY_OFFSET_MS;
    let account = Uuid::new_v4();
    let other_account = Uuid::new_v4();
    let device = Uuid::new_v4();
    let other_device = Uuid::new_v4();
    let primary = Uuid::new_v4();
    let backup = Uuid::new_v4();
    let foreign = Uuid::new_v4();
    let elsewhere = Uuid::new_v4();
    for id in [account, other_account] {
        client
            .execute("INSERT INTO accounts(id) VALUES($1)", &[&id])
            .await
            .unwrap();
    }
    for (id, owner) in [(device, account), (other_device, other_account)] {
        client
            .execute(
                "INSERT INTO devices(id,account_id,display_name) VALUES($1,$2,'virtual phone')",
                &[&id, &owner],
            )
            .await
            .unwrap();
    }
    // second_device shares the account so fallback routing can move a send.
    let second_device = Uuid::new_v4();
    client
        .execute(
            "INSERT INTO devices(id,account_id,display_name) VALUES($1,$2,'virtual fallback phone')",
            &[&second_device, &account],
        )
        .await
        .unwrap();
    async fn make_line(
        client: &tokio_postgres::Client,
        line: Uuid,
        owner: Uuid,
        bound: Uuid,
        label: &str,
        mode: &str,
    ) {
        client
            .execute(
                "INSERT INTO phone_lines(id,account_id,state,approved_at,current_binding_generation,last_issued_generation,label,not_ready_mode) \
                 VALUES($1,$2,'active',clock_timestamp(),1,1,$3,$4)",
                &[&line, &owner, &label, &mode],
            )
            .await
            .unwrap();
        client
            .execute(
                "INSERT INTO device_line_bindings(account_id,line_id,device_id,generation,state,purpose,owner_approval_digest,device_confirmation_digest,activated_at) \
                 VALUES($1,$2,$3,1,'active','sms',$4,$5,clock_timestamp()-interval '1 second')",
                &[&owner, &line, &bound, &vec![1_u8; 32], &vec![2_u8; 32]],
            )
            .await
            .unwrap();
    }
    async fn observe(client: &tokio_postgres::Client, owner: Uuid, line: Uuid, kind: &str) {
        client
            .execute(
                "INSERT INTO line_readiness_observations \
                 (account_id,line_id,device_id,binding_generation,kind,since_observation_ms,observed_at_ms,digest) \
                 VALUES($1,$2,(SELECT device_id FROM device_line_bindings WHERE account_id=$1 AND line_id=$2 AND state='active'), \
                   (SELECT current_binding_generation FROM phone_lines WHERE account_id=$1 AND id=$2), \
                   $3,$4,$5,'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA') \
                 ON CONFLICT (account_id,line_id) DO UPDATE SET kind=EXCLUDED.kind, \
                   since_observation_ms=EXCLUDED.since_observation_ms, \
                   observed_at_ms=EXCLUDED.observed_at_ms, hub_received_at=now()",
                &[&owner, &line, &kind, &1200_i64, &1_700_000_000_000_i64],
            )
            .await
            .unwrap();
    }
    async fn recorded_line(client: &tokio_postgres::Client, message: Uuid) -> tokio_postgres::Row {
        client
            .query_one(
                "SELECT m.line_id, l.label, m.device_id FROM messages m \
                 LEFT JOIN phone_lines l ON l.account_id=m.account_id AND l.id=m.line_id \
                 WHERE m.id=$1",
                &[&message],
            )
            .await
            .unwrap()
    }
    make_line(&client, primary, account, device, "primary", "ignore").await;
    make_line(&client, backup, account, second_device, "backup", "ignore").await;
    make_line(
        &client,
        foreign,
        other_account,
        other_device,
        "primary",
        "ignore",
    )
    .await;
    make_line(
        &client,
        elsewhere,
        account,
        second_device,
        "elsewhere",
        "ignore",
    )
    .await;

    // A ready line admits with its identity recorded and its label answered.
    observe(&client, account, primary, "ready").await;
    let ready_client_id = Uuid::new_v4();
    let accepted = DeliveryStore::new(&mut client)
        .accept_alpha(
            NewMessage {
                client_message_id: ready_client_id,
                line_label: Some("primary"),
                ..input(account, device, "ready-line", expires_at_ms)
            },
            false,
            None,
        )
        .await
        .unwrap();
    assert_eq!(accepted.line_label.as_deref(), Some("primary"));
    let row = recorded_line(&client, accepted.message_id).await;
    let recorded: Uuid = row.get(0);
    assert_eq!(recorded, primary);
    let label: Option<String> = row.get(1);
    assert_eq!(label.as_deref(), Some("primary"));
    let sending_device: Uuid = row.get(2);
    assert_eq!(sending_device, device);

    // An exact replay keeps its outcome and label even after the policy and
    // the observation change underneath it.
    observe(&client, account, primary, "card_changed").await;
    let replay = DeliveryStore::new(&mut client)
        .accept_alpha(
            NewMessage {
                client_message_id: ready_client_id,
                line_label: Some("primary"),
                ..input(account, device, "ready-line", expires_at_ms)
            },
            false,
            None,
        )
        .await
        .unwrap();
    assert!(!replay.created);
    assert_eq!(replay.message_id, accepted.message_id);
    assert_eq!(replay.line_label.as_deref(), Some("primary"));

    // The same key with a different line label is a different request.
    assert!(matches!(
        DeliveryStore::new(&mut client)
            .accept_alpha(
                NewMessage {
                    line_label: Some("elsewhere"),
                    ..input(account, device, "ready-line", expires_at_ms)
                },
                false,
                None,
            )
            .await,
        Err(StoreError::IdempotencyConflict)
    ));

    // A not-ready line under the default ignore policy refuses before
    // acceptance with the stable card-changed code: no message, job, or
    // idempotency row survives the rollback.
    assert!(matches!(
        DeliveryStore::new(&mut client)
            .accept_alpha(
                NewMessage {
                    line_label: Some("primary"),
                    ..input(account, device, "card-changed-refusal", expires_at_ms)
                },
                false,
                None,
            )
            .await,
        Err(StoreError::LineNotReady { code: "line_not_ready_card_changed", ref label })
            if label.as_deref() == Some("primary")
    ));
    let leftovers: i64 = client
        .query_one(
            "SELECT (SELECT count(*) FROM idempotency_keys WHERE key='card-changed-refusal') \
             + (SELECT count(*) FROM messages)",
            &[],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(leftovers, 1, "only the ready-line message may exist");

    // A foreign label never resolves, and a label whose binding belongs to
    // another device of the account does not redirect onto that device.
    assert!(matches!(
        DeliveryStore::new(&mut client)
            .accept_alpha(
                NewMessage {
                    line_label: Some("foreign-same-name"),
                    ..input(account, device, "unknown-label", expires_at_ms)
                },
                false,
                None,
            )
            .await,
        Err(StoreError::NotFound)
    ));
    assert!(matches!(
        DeliveryStore::new(&mut client)
            .accept_alpha(
                NewMessage {
                    line_label: Some("elsewhere"),
                    ..input(account, device, "wrong-device", expires_at_ms)
                },
                false,
                None,
            )
            .await,
        Err(StoreError::NotFound)
    ));

    // Queue mode holds the message on the addressed line: no observation, no
    // claim; a fresh current-generation ready observation releases it.
    client
        .execute(
            "UPDATE phone_lines SET not_ready_mode='queue' WHERE id=$1",
            &[&backup],
        )
        .await
        .unwrap();
    let queued = DeliveryStore::new(&mut client)
        .accept_alpha(
            NewMessage {
                line_label: Some("backup"),
                ..input(account, second_device, "queued-line", expires_at_ms)
            },
            false,
            None,
        )
        .await
        .unwrap();
    assert_eq!(queued.line_label.as_deref(), Some("backup"));
    assert!(
        DeliveryStore::new(&mut client)
            .claim_due("worker-hold")
            .await
            .unwrap()
            .is_none(),
        "an unobserved line must not release its queued message"
    );
    observe(&client, account, backup, "ready").await;
    client.execute(
        "UPDATE line_readiness_observations SET since_observation_ms=300000 WHERE account_id=$1 AND line_id=$2",
        &[&account, &backup],
    ).await.unwrap();
    assert!(
        DeliveryStore::new(&mut client)
            .claim_due("worker-old-evidence")
            .await
            .unwrap()
            .is_none(),
        "a fresh report with stale underlying evidence must not release the queue"
    );
    observe(&client, account, backup, "ready").await;
    client
        .execute(
            "UPDATE phone_lines SET offline_not_ready_after_seconds=0 WHERE id=$1",
            &[&backup],
        )
        .await
        .unwrap();
    assert!(
        DeliveryStore::new(&mut client)
            .claim_due("worker-zero-threshold")
            .await
            .unwrap()
            .is_none()
    );
    client
        .execute(
            "UPDATE phone_lines SET offline_not_ready_after_seconds=300 WHERE id=$1",
            &[&backup],
        )
        .await
        .unwrap();
    let claimed = DeliveryStore::new(&mut client)
        .claim_due("worker-release")
        .await
        .unwrap()
        .expect("a ready current-generation observation releases the queue");
    assert_eq!(claimed.message_id, queued.message_id);

    // A stale-generation observation is not evidence: bump the generation and
    // the released queue closes again.
    client
        .execute(
            "UPDATE phone_lines SET current_binding_generation=2, last_issued_generation=2 WHERE id=$1",
            &[&backup],
        )
        .await
        .unwrap();
    let held = DeliveryStore::new(&mut client)
        .accept_alpha(
            NewMessage {
                line_label: Some("backup"),
                ..input(account, second_device, "queued-stale", expires_at_ms)
            },
            false,
            None,
        )
        .await
        .unwrap();
    assert_eq!(held.line_label.as_deref(), Some("backup"));
    assert!(
        DeliveryStore::new(&mut client)
            .claim_due("worker-stale")
            .await
            .unwrap()
            .is_none(),
        "a stale-generation observation must not release the queue"
    );

    // Fallback mode sends from the fallback line's own bound device when that
    // line is itself ready, and records the fallback line's identity.
    client
        .execute(
            "UPDATE phone_lines SET not_ready_mode='fallback', fallback_line_id=$2 WHERE id=$1",
            &[&primary, &backup],
        )
        .await
        .unwrap();
    // Rebind the backup line to a fresh generation, retiring the old active
    // binding first exactly like a real re-approval would.
    client
        .execute(
            "UPDATE device_line_bindings SET state='revoked' WHERE account_id=$1 AND line_id=$2 AND state='active'",
            &[&account, &backup],
        )
        .await
        .unwrap();
    client
        .execute(
            "INSERT INTO device_line_bindings(account_id,line_id,device_id,generation,state,purpose,owner_approval_digest,device_confirmation_digest,activated_at) \
             VALUES($1,$2,$3,2,'active','sms',$4,$5,clock_timestamp()-interval '1 second')",
            &[&account, &backup, &second_device, &vec![3_u8; 32], &vec![4_u8; 32]],
        )
        .await
        .unwrap();
    client
        .execute(
            "UPDATE line_readiness_observations SET binding_generation=2 WHERE line_id=$1",
            &[&backup],
        )
        .await
        .unwrap();
    let fell_back = DeliveryStore::new(&mut client)
        .accept_alpha(
            NewMessage {
                line_label: Some("primary"),
                ..input(account, device, "fallback-send", expires_at_ms)
            },
            false,
            None,
        )
        .await
        .unwrap();
    assert_eq!(fell_back.line_label.as_deref(), Some("backup"));
    let row = recorded_line(&client, fell_back.message_id).await;
    let recorded: Uuid = row.get(0);
    assert_eq!(recorded, backup, "the fallback line identity is recorded");
    let sending_device: Uuid = row.get(2);
    assert_eq!(
        sending_device, second_device,
        "the send actually moves to the fallback line's bound device"
    );

    // The per-request opt-out refuses instead of falling back.
    assert!(matches!(
        DeliveryStore::new(&mut client)
            .accept_alpha(
                NewMessage {
                    line_label: Some("primary"),
                    no_fallback: true,
                    ..input(account, device, "fallback-forbidden", expires_at_ms)
                },
                false,
                None,
            )
            .await,
        Err(StoreError::LineNotReady {
            code: "line_not_ready_fallback_forbidden",
            ..
        })
    ));

    // A device-bound key may not be routed onto the fallback device.
    assert!(matches!(
        DeliveryStore::new(&mut client)
            .accept_alpha(
                NewMessage {
                    line_label: Some("primary"),
                    ..input(account, device, "fallback-scoped", expires_at_ms)
                },
                false,
                Some(device),
            )
            .await,
        Err(StoreError::LineNotReady {
            code: "line_not_ready_no_eligible_fallback",
            ..
        })
    ));

    // A retained ready report cannot authorize a revoked binding.
    client.execute(
        "UPDATE device_line_bindings SET state='revoked' WHERE account_id=$1 AND line_id=$2 AND state='active'",
        &[&account, &backup],
    ).await.unwrap();
    assert!(
        DeliveryStore::new(&mut client)
            .claim_due("worker-revoked")
            .await
            .unwrap()
            .is_none()
    );

    // Account-wide suppression still refuses before any line routing: an
    // unreleased owner hold blocks exactly like a signed suppression.
    let hold_author = Uuid::new_v4();
    client
        .execute(
            "INSERT INTO users(id,email,password_hash) VALUES($1,$2,'unused')",
            &[
                &hold_author,
                &format!("line-admission-{}@example.test", hold_author.simple()),
            ],
        )
        .await
        .unwrap();
    client
        .execute(
            "INSERT INTO memberships(account_id,user_id,role) VALUES($1,$2,'owner')",
            &[&account, &hold_author],
        )
        .await
        .unwrap();
    client
        .execute(
            "INSERT INTO owner_recipient_holds(id,account_id,recipient_e164,channel,reason,reported_at,created_by) \
             VALUES($1,$2,'+15551234567','other','opt_out',clock_timestamp(),$3)",
            &[&Uuid::new_v4(), &account, &hold_author],
        )
        .await
        .unwrap();
    assert!(matches!(
        DeliveryStore::new(&mut client)
            .accept_alpha(
                NewMessage {
                    line_label: Some("elsewhere"),
                    ..input(account, second_device, "suppressed", expires_at_ms)
                },
                false,
                None,
            )
            .await,
        Err(StoreError::RecipientSuppressed)
    ));

    client
        .batch_execute(&format!("DROP SCHEMA {schema} CASCADE"))
        .await
        .unwrap();
}

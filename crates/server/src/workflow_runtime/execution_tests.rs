// SPDX-License-Identifier: AGPL-3.0-only
use super::database_tests::Case;
use super::*;
use crate::{
    encrypted_schedule::{policy::WindowPolicy, store::ScheduleRequest},
    http_owner_conversations::context::decisions::{self, ActionState, model::Decision},
};
use uuid::Uuid;

struct Flow {
    case: Case,
    principal: IntegrationPrincipal,
    action: ActionState,
    policy: WindowPolicy,
}
async fn prepared(permissions: &[Operation], approve: bool) -> Flow {
    prepared_window(permissions, approve, false).await
}
async fn prepared_window(permissions: &[Operation], approve: bool, future: bool) -> Flow {
    prepared_bounded(permissions, approve, future, false).await
}
async fn prepared_bounded(
    permissions: &[Operation],
    approve: bool,
    future: bool,
    short: bool,
) -> Flow {
    let mut case = Case::with_signer(Some(120000)).await;
    case.request.permissions = Permissions::new(permissions).unwrap();
    let issued = case.issue().await.unwrap();
    let principal = authenticate(&case.f.db, &case.hasher, &issued.token)
        .await
        .unwrap();
    let offset = if future { 1i32 } else { -2i32 };
    let row = case.f.db.query_one("SELECT to_char(t,'YYYY-MM-DD'),extract(hour FROM t)::int*60+extract(minute FROM t)::int FROM (SELECT (clock_timestamp() AT TIME ZONE 'UTC')+$1::integer*interval '1 minute' t) v", &[&offset]).await.unwrap();
    let opens: i32 = row.get(1);
    let policy = WindowPolicy {
        timezone: Some("UTC".into()),
        first_local_date: row.get(0),
        opens_minute: opens as u16,
        closes_minute: ((opens + 60) % 1440) as u16,
        repeat_every_days: None,
        max_occurrences: 1,
        pacing_seconds: 60,
    };
    let mut descriptor = case.descriptor().await;
    descriptor.window_id = if !future && !permissions.contains(&Operation::Schedule) {
        IMMEDIATE_WINDOW_ID.into()
    } else {
        policy.identity().unwrap()
    };
    if short {
        descriptor.expires_at = case
            .f
            .db
            .query_one(
                "SELECT floor(extract(epoch FROM clock_timestamp()))::bigint+8",
                &[],
            )
            .await
            .unwrap()
            .get(0);
    }
    let proposed = if principal.require(Operation::Propose).is_ok() {
        propose_action(
            &mut case.f.connect().await,
            &principal,
            Uuid::new_v4(),
            descriptor,
        )
        .await
        .unwrap()
    } else {
        decisions::register(
            &mut case.f.connect().await,
            &case.owner,
            Uuid::new_v4(),
            descriptor,
        )
        .await
        .unwrap()
    };
    let action = if approve {
        decisions::decide(
            &mut case.f.connect().await,
            &case.owner,
            Uuid::new_v4(),
            proposed.record_version,
            proposed.key,
            Decision::Approve,
        )
        .await
        .unwrap()
    } else {
        proposed
    };
    Flow {
        case,
        principal,
        action,
        policy,
    }
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; disposable workflow schema"]
async fn expired_exact_action_cannot_use_its_still_live_owner_binding_and_integration_grant() {
    let mut flow = prepared_bounded(&[Operation::Send], true, false, true).await;
    let (bound, _) = flow.case.bind_message(flow.action, Uuid::new_v4()).await;
    loop {
        let expired: bool = flow.case.f.db.query_one("SELECT expires_at_ms<=floor(extract(epoch FROM clock_timestamp())*1000)::bigint FROM workflow_action_versions WHERE account_id=$1 AND action_id=$2 AND revision=$3", &[&bound.key.account_id,&bound.key.action_id,&bound.key.revision]).await.unwrap().get(0);
        if expired {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    let live: bool = flow.case.f.db.query_one("SELECT g.expires_ms>floor(extract(epoch FROM clock_timestamp())*1000)::bigint AND c.expires_at_ms>floor(extract(epoch FROM clock_timestamp())*1000)::bigint FROM workflow_integration_grants g JOIN workflow_contexts c ON (c.account_id,c.id)=(g.account_id,g.context_id)", &[]).await.unwrap().get(0);
    assert!(
        live,
        "the rejection must concern the action deadline, not fixture authority expiry"
    );
    assert!(
        send_action(
            &mut flow.case.f.connect().await,
            &flow.principal,
            Uuid::new_v4(),
            bound.key,
            None
        )
        .await
        .is_err()
    );
    assert_eq!(counts(&flow.case).await, (0, 1, 0));
    flow.case.f.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; disposable workflow schema"]
async fn exact_owner_binding_does_not_bypass_a_future_recipient_window() {
    // Establish a bounded actual-clock precondition before the signed fixture
    // starts its 60-second lifetime. This leaves time for owner step-up while
    // keeping the next civil-minute opening strictly inside the action bound.
    let url = std::env::var("ZT_INBOUND_TEST_DATABASE_URL").unwrap();
    let (clock, connection) = tokio_postgres::connect(&url, tokio_postgres::NoTls)
        .await
        .unwrap();
    tokio::spawn(async move {
        connection.await.unwrap();
    });
    let started = tokio::time::Instant::now();
    loop {
        let second: i32 = clock
            .query_one(
                "SELECT floor(extract(second FROM clock_timestamp() AT TIME ZONE 'UTC'))::integer",
                &[],
            )
            .await
            .unwrap()
            .get(0);
        if (5..=35).contains(&second) {
            break;
        }
        assert!(started.elapsed() < std::time::Duration::from_secs(31));
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    drop(clock);
    let mut flow = prepared_window(
        &[Operation::Propose, Operation::Schedule, Operation::Send],
        true,
        true,
    )
    .await;
    let occurrence = schedule_action(
        &mut flow.case.f.connect().await,
        &flow.principal,
        flow.action.key,
        request(),
        &flow.policy,
    )
    .await
    .unwrap();
    let (bound, _) = flow
        .case
        .bind_message(flow.action, occurrence.dispatch_id)
        .await;
    let row = flow.case.f.db.query_one("SELECT floor(extract(epoch FROM clock_timestamp())*1000)::bigint,expires_at_ms FROM workflow_action_versions WHERE account_id=$1 AND action_id=$2 AND revision=$3", &[&bound.key.account_id,&bound.key.action_id,&bound.key.revision]).await.unwrap();
    assert!(occurrence.opens_at_ms.unwrap() > row.get::<_, i64>(0));
    assert!(occurrence.opens_at_ms.unwrap() < row.get::<_, i64>(1));
    let id = Uuid::new_v4();
    assert!(
        send_action(
            &mut flow.case.f.connect().await,
            &flow.principal,
            Uuid::new_v4(),
            bound.key,
            None
        )
        .await
        .is_err()
    );
    for _ in 0..2 {
        assert!(matches!(
            send_action(
                &mut flow.case.f.connect().await,
                &flow.principal,
                id,
                bound.key,
                Some(occurrence.id)
            )
            .await
            .unwrap(),
            SendOutcome::WaitingWindow
        ));
    }
    assert_eq!(counts(&flow.case).await, (1, 1, 0));
    let count: i64 = flow
        .case
        .f
        .db
        .query_one("SELECT count(*) FROM message_attempts", &[])
        .await
        .unwrap()
        .get(0);
    assert_eq!(count, 0);
    flow.case.f.cleanup().await;
}
fn request() -> ScheduleRequest {
    ScheduleRequest {
        request_id: Uuid::new_v4(),
        series_id: Uuid::new_v4(),
        ordinal: 0,
    }
}
async fn counts(case: &Case) -> (i64, i64, i64) {
    let row = case.f.db.query_one("SELECT (SELECT count(*) FROM workflow_schedule_occurrences),(SELECT count(*) FROM messages),(SELECT count(*) FROM workflow_actions WHERE phase='dispatching')", &[]).await.unwrap();
    (row.get(0), row.get(1), row.get(2))
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; disposable workflow schema"]
async fn integration_schedule_and_send_require_separate_bits_and_actual_owner_approval() {
    for permissions in [
        vec![Operation::Propose],
        vec![Operation::Schedule],
        vec![Operation::Send],
    ] {
        let flow = prepared(&permissions, true).await;
        let result = schedule_action(
            &mut flow.case.f.connect().await,
            &flow.principal,
            flow.action.key,
            request(),
            &flow.policy,
        )
        .await;
        assert_eq!(result.is_ok(), permissions.contains(&Operation::Schedule));
        let sent = send_action(
            &mut flow.case.f.connect().await,
            &flow.principal,
            Uuid::new_v4(),
            flow.action.key,
            None,
        )
        .await;
        if permissions.contains(&Operation::Send) {
            assert!(matches!(sent.unwrap(), SendOutcome::WaitingOwnerBinding));
        } else {
            assert!(sent.is_err());
        }
        let (_, messages, attempts) = counts(&flow.case).await;
        assert_eq!((messages, attempts), (0, 0));
        flow.case.f.cleanup().await;
    }
    let flow = prepared(
        &[Operation::Propose, Operation::Schedule, Operation::Send],
        false,
    )
    .await;
    assert!(
        schedule_action(
            &mut flow.case.f.connect().await,
            &flow.principal,
            flow.action.key,
            request(),
            &flow.policy
        )
        .await
        .is_err()
    );
    assert!(
        send_action(
            &mut flow.case.f.connect().await,
            &flow.principal,
            Uuid::new_v4(),
            flow.action.key,
            None
        )
        .await
        .is_err()
    );
    assert_eq!(counts(&flow.case).await, (0, 0, 0));
    flow.case.f.cleanup().await;
    let flow = prepared(&[Operation::Send], false).await;
    assert!(
        send_action(
            &mut flow.case.f.connect().await,
            &flow.principal,
            Uuid::new_v4(),
            flow.action.key,
            None
        )
        .await
        .is_err()
    );
    assert_eq!(counts(&flow.case).await, (0, 0, 0));
    flow.case.f.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; disposable workflow schema"]
async fn integration_schedule_waits_for_exact_owner_binding_then_prepares_once_without_radio() {
    let mut flow = prepared(
        &[Operation::Propose, Operation::Schedule, Operation::Send],
        true,
    )
    .await;
    let input = request();
    let occurrence = schedule_action(
        &mut flow.case.f.connect().await,
        &flow.principal,
        flow.action.key,
        input,
        &flow.policy,
    )
    .await
    .unwrap();
    let replay = schedule_action(
        &mut flow.case.f.connect().await,
        &flow.principal,
        flow.action.key,
        input,
        &flow.policy,
    )
    .await
    .unwrap();
    assert_eq!(occurrence, replay);
    assert_eq!(counts(&flow.case).await, (1, 0, 0));
    let waiting = Uuid::new_v4();
    assert!(matches!(
        send_action(
            &mut flow.case.f.connect().await,
            &flow.principal,
            waiting,
            flow.action.key,
            Some(occurrence.id)
        )
        .await
        .unwrap(),
        SendOutcome::WaitingOwnerBinding
    ));
    let (bound, message) = flow
        .case
        .bind_message(flow.action, occurrence.dispatch_id)
        .await;
    assert!(matches!(
        send_action(
            &mut flow.case.f.connect().await,
            &flow.principal,
            waiting,
            bound.key,
            Some(occurrence.id)
        )
        .await
        .unwrap(),
        SendOutcome::WaitingOwnerBinding
    ));
    let issued = flow.case.issue_another().await;
    let other = authenticate(&flow.case.f.db, &flow.case.hasher, &issued.token)
        .await
        .unwrap();
    assert!(
        schedule_action(
            &mut flow.case.f.connect().await,
            &other,
            bound.key,
            input,
            &flow.policy
        )
        .await
        .is_err()
    );
    assert!(
        send_action(
            &mut flow.case.f.connect().await,
            &other,
            Uuid::new_v4(),
            bound.key,
            Some(occurrence.id)
        )
        .await
        .is_err()
    );
    let id = Uuid::new_v4();
    for _ in 0..2 {
        assert!(
            matches!(send_action(&mut flow.case.f.connect().await, &flow.principal, id, bound.key, Some(occurrence.id)).await.unwrap(), SendOutcome::Prepared { message_id, dispatch_id } if message_id==message && dispatch_id==occurrence.dispatch_id)
        );
    }
    assert_eq!(counts(&flow.case).await, (1, 1, 1));
    let row = flow.case.f.db.query_one("SELECT (SELECT count(*) FROM message_attempts),(SELECT count(*) FROM message_events),(SELECT count(*) FROM usage_ledger WHERE entry_kind='reserve')", &[]).await.unwrap();
    assert_eq!(row.get::<_, i64>(0), 0);
    assert_eq!(row.get::<_, i64>(1), 0);
    assert_eq!(row.get::<_, i64>(2), 1);
    let original: Uuid = flow
        .case
        .f
        .db
        .query_one(
            "SELECT actor_id FROM workflow_schedule_occurrences WHERE id=$1",
            &[&occurrence.id],
        )
        .await
        .unwrap()
        .get(0);
    revoke_grant(&mut flow.case.f.connect().await, &flow.case.owner, original)
        .await
        .unwrap();
    assert!(
        send_action(
            &mut flow.case.f.connect().await,
            &flow.principal,
            id,
            bound.key,
            Some(occurrence.id)
        )
        .await
        .is_err()
    );
    flow.case.f.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; disposable workflow schema"]
async fn immediate_send_only_uses_a_real_owner_binding_and_cannot_replay_after_revocation() {
    let mut flow = prepared(&[Operation::Send], true).await;
    let dispatch = Uuid::new_v4();
    let (bound, message) = flow.case.bind_message(flow.action, dispatch).await;
    let id = Uuid::new_v4();
    for _ in 0..2 {
        assert!(
            matches!(send_action(&mut flow.case.f.connect().await, &flow.principal, id, bound.key, None).await.unwrap(), SendOutcome::Prepared { message_id, dispatch_id } if message_id==message && dispatch_id==dispatch)
        );
    }
    assert_eq!(counts(&flow.case).await, (0, 1, 1));
    let grant: Uuid = flow
        .case
        .f
        .db
        .query_one("SELECT grant_id FROM workflow_integration_grants", &[])
        .await
        .unwrap()
        .get(0);
    revoke_grant(&mut flow.case.f.connect().await, &flow.case.owner, grant)
        .await
        .unwrap();
    assert!(
        send_action(
            &mut flow.case.f.connect().await,
            &flow.principal,
            id,
            bound.key,
            None
        )
        .await
        .is_err()
    );
    let row = flow.case.f.db.query_one("SELECT (SELECT count(*) FROM messages),(SELECT count(*) FROM message_attempts),(SELECT count(*) FROM usage_ledger WHERE entry_kind='reserve')", &[]).await.unwrap();
    assert_eq!(row.get::<_, i64>(0), 1);
    assert_eq!(row.get::<_, i64>(1), 0);
    assert_eq!(row.get::<_, i64>(2), 1);
    flow.case.f.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; disposable workflow schema"]
async fn send_only_cannot_omit_the_occurrence_for_an_owner_approved_canonical_window() {
    let mut flow = prepared_window(&[Operation::Send], true, true).await;
    let (bound, _) = flow.case.bind_message(flow.action, Uuid::new_v4()).await;
    assert_eq!(counts(&flow.case).await, (0, 1, 0));
    assert!(
        send_action(
            &mut flow.case.f.connect().await,
            &flow.principal,
            Uuid::new_v4(),
            bound.key,
            None
        )
        .await
        .is_err()
    );
    assert_eq!(counts(&flow.case).await, (0, 1, 0));
    flow.case.f.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; disposable workflow schema"]
async fn exhausted_normal_admission_keeps_the_next_workflow_waiting_for_owner_binding() {
    let mut flow = prepared(&[Operation::Send], true).await;
    flow.case.f.db.execute("INSERT INTO usage_quota_policies(account_id,metric,limit_units) VALUES($1,'outbound_message',1)", &[&flow.case.f.account]).await.unwrap();
    flow.case.bind_message(flow.action, Uuid::new_v4()).await;
    let mut descriptor = flow.case.descriptor().await;
    descriptor.window_id = IMMEDIATE_WINDOW_ID.into();
    let proposed = decisions::register(
        &mut flow.case.f.connect().await,
        &flow.case.owner,
        Uuid::new_v4(),
        descriptor,
    )
    .await
    .unwrap();
    let approved = decisions::decide(
        &mut flow.case.f.connect().await,
        &flow.case.owner,
        Uuid::new_v4(),
        proposed.record_version,
        proposed.key,
        Decision::Approve,
    )
    .await
    .unwrap();
    assert!(matches!(
        flow.case
            .try_bind_message(approved.clone(), Uuid::new_v4())
            .await,
        Err(crate::sealed_outbound::AdmitError::Queue(
            zrotext_delivery_store::StoreError::QuotaExceeded
        ))
    ));
    assert!(matches!(
        send_action(
            &mut flow.case.f.connect().await,
            &flow.principal,
            Uuid::new_v4(),
            approved.key,
            None
        )
        .await
        .unwrap(),
        SendOutcome::WaitingOwnerBinding
    ));
    assert_eq!(counts(&flow.case).await, (0, 1, 0));
    let row = flow.case.f.db.query_one("SELECT (SELECT count(*) FROM usage_ledger WHERE entry_kind='reserve'),(SELECT count(*) FROM workflow_message_links)", &[]).await.unwrap();
    assert_eq!(row.get::<_, i64>(0), 1);
    assert_eq!(row.get::<_, i64>(1), 1);
    flow.case.f.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; disposable workflow schema"]
async fn cached_integration_authority_cannot_schedule_or_prepare_after_withdrawal_or_foreign_scope()
{
    for withdrawal in ["grant", "consent", "owner", "takeover", "foreign"] {
        let mut flow = prepared(
            &[Operation::Propose, Operation::Schedule, Operation::Send],
            true,
        )
        .await;
        let occurrence = schedule_action(
            &mut flow.case.f.connect().await,
            &flow.principal,
            flow.action.key,
            request(),
            &flow.policy,
        )
        .await
        .unwrap();
        let (bound, _) = flow
            .case
            .bind_message(flow.action, occurrence.dispatch_id)
            .await;
        let mut key = bound.key;
        match withdrawal {
            "grant" => {
                let id: Uuid = flow
                    .case
                    .f
                    .db
                    .query_one("SELECT grant_id FROM workflow_integration_grants", &[])
                    .await
                    .unwrap()
                    .get(0);
                revoke_grant(&mut flow.case.f.connect().await, &flow.case.owner, id)
                    .await
                    .unwrap();
            }
            "consent" => {
                flow.case.f.db.execute("INSERT INTO contact_consent_records(id,account_id,contact_id,purpose,action,source,effective_at,recorded_by) VALUES($1,$2,$3,'operational','withdraw','manual_entry',clock_timestamp(),$4)", &[&Uuid::new_v4(),&flow.case.f.account,&flow.case.request.contact,&flow.case.owner.user_id]).await.unwrap();
            }
            "owner" => {
                flow.case
                    .f
                    .db
                    .execute(
                        "UPDATE sessions SET revoked_at=clock_timestamp() WHERE id=$1",
                        &[&flow.case.owner.session_id],
                    )
                    .await
                    .unwrap();
            }
            "takeover" => {
                decisions::takeover(
                    &mut flow.case.f.connect().await,
                    &flow.case.owner,
                    Uuid::new_v4(),
                    flow.case.header.context,
                )
                .await
                .unwrap();
            }
            "foreign" => {
                key.account_id = Uuid::new_v4();
            }
            _ => unreachable!(),
        }
        assert!(
            schedule_action(
                &mut flow.case.f.connect().await,
                &flow.principal,
                key,
                request(),
                &flow.policy
            )
            .await
            .is_err(),
            "{withdrawal}"
        );
        assert!(
            send_action(
                &mut flow.case.f.connect().await,
                &flow.principal,
                Uuid::new_v4(),
                key,
                Some(occurrence.id)
            )
            .await
            .is_err(),
            "{withdrawal}"
        );
        let (_, messages, attempts) = counts(&flow.case).await;
        assert_eq!((messages, attempts), (1, 0), "{withdrawal}");
        flow.case.f.cleanup().await;
    }
}

mod cancellation;
mod status;

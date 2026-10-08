// SPDX-License-Identifier: AGPL-3.0-only
use super::super::activation;
use super::*;
use model::{Decision, Phase};
use sha2::{Digest, Sha256};
use uuid::Uuid;
mod dispatch;
mod http;
mod lifecycle;
mod provider_profile;
mod replies;
mod safety;
mod support;
pub(crate) use support::Case;

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; isolated synthetic schema"]
async fn concurrent_exact_decisions_have_one_winner_and_replays_cannot_reapply_after_edit() {
    let c = Case::new().await;
    let proposal = c.propose(c.descriptor.clone()).await;
    let key = proposal.key;
    let request = Uuid::new_v4();
    let mut approve_connection = c.base.f.connect().await;
    let mut cancel_connection = c.base.f.connect().await;
    let (a, b) = tokio::join!(
        decide(
            &mut approve_connection,
            &c.base.owner,
            request,
            1,
            key,
            Decision::Approve
        ),
        decide(
            &mut cancel_connection,
            &c.base.owner,
            Uuid::new_v4(),
            1,
            key,
            Decision::Cancel
        )
    );
    assert_eq!(usize::from(a.is_ok()) + usize::from(b.is_ok()), 1);
    if let Ok(approved) = a {
        let mut next = c.descriptor.clone();
        next.revision = 2;
        next.window_id = "changed-window".into();
        let changed = edit(
            &mut c.base.f.connect().await,
            &c.base.owner,
            Uuid::new_v4(),
            2,
            key,
            next,
        )
        .await
        .unwrap();
        assert_eq!(changed.phase, Phase::Invalidated);
        assert_eq!(
            decide(
                &mut c.base.f.connect().await,
                &c.base.owner,
                request,
                1,
                key,
                Decision::Approve
            )
            .await
            .unwrap()
            .record_version,
            approved.record_version
        );
        assert_eq!(
            read(&mut c.base.f.connect().await, &c.base.owner, changed.key)
                .await
                .unwrap()
                .phase,
            Phase::Invalidated
        );
        assert!(
            lock_approved(
                &c.base.f.connect().await.transaction().await.unwrap(),
                &c.base.owner,
                key
            )
            .await
            .is_err()
        );
    }
    c.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; isolated synthetic schema"]
async fn takeover_stops_only_the_context_and_rejects_new_proposals_and_dispatch() {
    let c = Case::new().await;
    let approved = c.approved().await;
    let request = Uuid::new_v4();
    let result = takeover(
        &mut c.base.f.connect().await,
        &c.base.owner,
        request,
        c.base.h.context,
    )
    .await
    .unwrap();
    assert_eq!(result.stopped_routines, 1);
    assert_eq!(
        takeover(
            &mut c.base.f.connect().await,
            &c.base.owner,
            request,
            c.base.h.context
        )
        .await
        .unwrap()
        .stopped_routines,
        1
    );
    assert!(
        lock_approved(
            &c.base.f.connect().await.transaction().await.unwrap(),
            &c.base.owner,
            approved.key
        )
        .await
        .is_err()
    );
    let mut next = c.descriptor.clone();
    next.action_id = Uuid::new_v4().to_string();
    assert!(
        register(
            &mut c.base.f.connect().await,
            &c.base.owner,
            Uuid::new_v4(),
            next
        )
        .await
        .is_err()
    );
    assert_eq!(
        read(&mut c.base.f.connect().await, &c.base.owner, approved.key)
            .await
            .unwrap()
            .phase,
        Phase::Cancelled
    );
    assert!(
        takeover(
            &mut c.base.f.connect().await,
            &c.base.owner,
            Uuid::new_v4(),
            Uuid::new_v4()
        )
        .await
        .is_err()
    );
    c.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; isolated synthetic schema"]
async fn purpose_and_peer_substitution_withdrawal_and_owner_revocation_refuse_approval() {
    let c = Case::new().await;
    let other_peer = Uuid::new_v4();
    c.base
        .f
        .db
        .execute(
            "INSERT INTO contacts(id,account_id,recipient_e164) VALUES($1,$2,'+13')",
            &[&other_peer, &c.base.f.account],
        )
        .await
        .unwrap();
    let mut wrong_peer = c.descriptor.clone();
    wrong_peer.recipient_id = other_peer.to_string();
    assert!(
        register(
            &mut c.base.f.connect().await,
            &c.base.owner,
            Uuid::new_v4(),
            wrong_peer
        )
        .await
        .is_err()
    );
    let mut bad = c.descriptor.clone();
    bad.purpose_id = Uuid::new_v4().to_string();
    assert!(
        register(
            &mut c.base.f.connect().await,
            &c.base.owner,
            Uuid::new_v4(),
            bad
        )
        .await
        .is_err()
    );
    let proposal = c.propose(c.descriptor.clone()).await;
    c.base.f.db.execute("INSERT INTO contact_consent_records(id,account_id,contact_id,purpose,action,source,effective_at,recorded_by) VALUES($1,$2,$3,'transactional','withdraw','manual_entry',clock_timestamp(),$4)",
        &[&Uuid::new_v4(),&c.base.f.account,&c.contact,&c.base.owner.user_id]).await.unwrap();
    assert!(
        decide(
            &mut c.base.f.connect().await,
            &c.base.owner,
            Uuid::new_v4(),
            1,
            proposal.key,
            Decision::Approve
        )
        .await
        .is_err()
    );
    c.base
        .f
        .db
        .execute(
            "UPDATE sessions SET revoked_at=clock_timestamp() WHERE id=$1",
            &[&c.base.owner.session_id],
        )
        .await
        .unwrap();
    assert!(
        read(&mut c.base.f.connect().await, &c.base.owner, proposal.key)
            .await
            .is_err()
    );
    assert_eq!(
        c.base
            .f
            .db
            .query_one("SELECT phase FROM workflow_actions", &[])
            .await
            .unwrap()
            .get::<_, String>(0),
        "proposed"
    );
    c.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; isolated synthetic schema"]
async fn signed_ambiguous_reply_is_deduplicated_without_approving_either_request() {
    let c = Case::new().await;
    let a = c.approved().await;
    let mut second = c.descriptor.clone();
    second.action_id = Uuid::new_v4().to_string();
    second.routine_id = Uuid::new_v4().to_string();
    let b = c.propose(second).await;
    let event = c.capture(1).await;
    let input = Correlation {
        context_id: c.base.h.context,
        context_revision: 1,
        event_id: event,
        request_action: None,
    };
    let result = correlate_reply(
        &mut c.base.f.connect().await,
        &c.base.owner,
        Uuid::new_v4(),
        input.clone(),
    )
    .await
    .unwrap();
    assert_eq!(result.disposition, "ambiguous");
    assert_eq!(
        correlate_reply(
            &mut c.base.f.connect().await,
            &c.base.owner,
            Uuid::new_v4(),
            input
        )
        .await
        .unwrap()
        .disposition,
        "ambiguous"
    );
    assert_eq!(
        read(&mut c.base.f.connect().await, &c.base.owner, a.key)
            .await
            .unwrap()
            .phase,
        Phase::Approved
    );
    assert_eq!(
        read(&mut c.base.f.connect().await, &c.base.owner, b.key)
            .await
            .unwrap()
            .phase,
        Phase::Proposed
    );
    let counts=c.base.f.db.query_one("SELECT (SELECT count(*) FROM workflow_reply_correlations),(SELECT count(*) FROM workflow_exceptions)",&[]).await.unwrap();
    assert_eq!(counts.get::<_, i64>(0), 1);
    assert_eq!(counts.get::<_, i64>(1), 1);
    let wrong = Correlation {
        context_id: c.base.h.context,
        context_revision: 1,
        event_id: event,
        request_action: Some(a.key),
    };
    assert!(
        correlate_reply(
            &mut c.base.f.connect().await,
            &c.base.owner,
            Uuid::new_v4(),
            wrong
        )
        .await
        .is_err()
    );
    c.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; isolated synthetic schema"]
async fn expiry_during_audit_write_rolls_back_approval_and_its_mutation() {
    let c = Case::new().await;
    let mut d = c.descriptor.clone();
    let now = activation::now(&c.base.f.connect().await.transaction().await.unwrap())
        .await
        .unwrap();
    d.expires_at = (now / 1000) + 2;
    let proposed = c.propose(d).await;
    c.base.f.db.batch_execute("CREATE FUNCTION delay_workflow_audit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN PERFORM pg_sleep(2.1); RETURN NEW; END $$; CREATE TRIGGER delay_workflow_audit BEFORE INSERT ON workflow_action_mutations FOR EACH ROW EXECUTE FUNCTION delay_workflow_audit();").await.unwrap();
    assert!(
        decide(
            &mut c.base.f.connect().await,
            &c.base.owner,
            Uuid::new_v4(),
            1,
            proposed.key,
            Decision::Approve
        )
        .await
        .is_err()
    );
    let row=c.base.f.db.query_one("SELECT phase,record_version,(SELECT count(*) FROM workflow_action_mutations) FROM workflow_actions",&[]).await.unwrap();
    assert_eq!(row.get::<_, String>(0), "proposed");
    assert_eq!(row.get::<_, i64>(1), 1);
    assert_eq!(row.get::<_, i64>(2), 1);
    c.cleanup().await;
}

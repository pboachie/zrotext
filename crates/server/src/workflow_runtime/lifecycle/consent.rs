// SPDX-License-Identifier: AGPL-3.0-only
use tokio_postgres::Transaction;
use uuid::Uuid;

/// The caller holds the contact and account locks used by the consent writer
/// and workflow admission. Withdrawal reduces existing authority in that same
/// transaction; a later grant must issue fresh credentials and policies.
pub(crate) async fn withdraw(
    tx: &Transaction<'_>,
    account: Uuid,
    contact: Uuid,
    purpose: &str,
) -> Result<(), tokio_postgres::Error> {
    crate::managed_ai::lifecycle::withdraw(tx, account, contact, purpose).await?;
    crate::workflow_runtime::openings::lifecycle::withdraw_contact(tx, account, contact, purpose)
        .await?;
    if !super::installed(tx).await? {
        return Ok(());
    }
    if crate::workflow_runtime::routines::lifecycle::installed(tx).await? {
        let policies = tx
            .query(
                "SELECT p.id FROM workflow_routine_policies p \
                 JOIN workflow_integration_grants g \
                 ON (g.account_id,g.grant_id)=(p.account_id,p.input_grant_id) \
                 WHERE g.account_id=$1 AND g.contact_id=$2 AND g.purpose=$3 \
                 ORDER BY p.id FOR UPDATE OF p",
                &[&account, &contact, &purpose],
            )
            .await?;
        for policy in policies {
            let policy: Uuid = policy.get(0);
            crate::workflow_runtime::routines::lifecycle::stop_outputs(tx, account, policy).await?;
            tx.execute(
                "UPDATE workflow_routine_policies SET withdrawn_ms=COALESCE(withdrawn_ms, \
                 floor(extract(epoch FROM clock_timestamp())*1000)::bigint) \
                 WHERE account_id=$1 AND id=$2",
                &[&account, &policy],
            )
            .await?;
        }
    }
    tx.execute(
        "UPDATE workflow_integration_grants SET revoked_ms=COALESCE(revoked_ms, \
         floor(extract(epoch FROM clock_timestamp())*1000)::bigint) \
         WHERE account_id=$1 AND contact_id=$2 AND purpose=$3",
        &[&account, &contact, &purpose],
    )
    .await?;
    tx.execute(
        "UPDATE workflow_connector_context_envelopes e SET envelope=NULL \
         FROM workflow_integration_grants g \
         WHERE (e.account_id,e.grant_id)=(g.account_id,g.grant_id) \
         AND g.account_id=$1 AND g.contact_id=$2 AND g.purpose=$3 AND e.envelope IS NOT NULL",
        &[&account, &contact, &purpose],
    )
    .await?;
    // Existing calls, admission tombstones and debits remain. In-flight or
    // unknown submissions are never relabeled as successful or refunded.
    Ok(())
}

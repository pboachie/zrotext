// SPDX-License-Identifier: AGPL-3.0-only
use super::{Error, Runtime};
use crate::{
    auth::SessionPrincipal,
    billing::hosted::namespace::{Marker, Mode, Namespace},
};
use tokio_postgres::{Client, Transaction};
use uuid::Uuid;

pub(super) fn ns(r: &Runtime) -> Uuid {
    Uuid::from_bytes(r.options.namespace.id())
}
pub(super) async fn now(tx: &Transaction<'_>) -> Result<i64, Error> {
    Ok(tx
        .query_one(
            "SELECT floor(extract(epoch FROM clock_timestamp()))::bigint",
            &[],
        )
        .await?
        .get(0))
}
pub(super) async fn marker(db: &mut Client) -> Result<Marker, Error> {
    let tx = db.transaction().await?;
    let rows=tx.query("SELECT namespace_id,mode,provider_account,policy_revision,enabled,old_binary_fenced FROM hosted_billing_namespaces FOR SHARE",&[]).await?;
    if rows.len() != 1 || !rows[0].get::<_, bool>(5) {
        return Err(Error::Identity);
    }
    let row = &rows[0];
    let id: Uuid = row.get(0);
    let mode = match row.get::<_, String>(1).as_str() {
        "test" => Mode::Test,
        "live" => Mode::Live,
        _ => return Err(Error::Identity),
    };
    let n = Namespace::new(id.into_bytes(), mode, &row.get::<_, String>(2))
        .map_err(|_| Error::Identity)?;
    let revision = u64::try_from(row.get::<_, i64>(3)).map_err(|_| Error::Identity)?;
    let result = Marker {
        namespace: n,
        policy_revision: revision,
        enabled: row.get(4),
    };
    tx.commit().await?;
    Ok(result)
}
pub(super) async fn lock(tx: &Transaction<'_>, r: &Runtime, account: Uuid) -> Result<(), Error> {
    let row=tx.query_one("SELECT namespace_id,mode,provider_account,policy_revision,enabled,old_binary_fenced FROM hosted_billing_namespaces FOR SHARE",&[]).await?;
    if row.get::<_, Uuid>(0) != ns(r)
        || row.get::<_, String>(1) != super::mode_name(r.options.namespace.mode())
        || row.get::<_, String>(2) != r.options.namespace.provider_account()
        || row.get::<_, i64>(3) != r.options.policy_revision as i64
        || !row.get::<_, bool>(4)
        || !row.get::<_, bool>(5)
    {
        return Err(Error::Identity);
    }
    if tx
        .query_one("SELECT pg_is_in_recovery()", &[])
        .await?
        .get::<_, bool>(0)
    {
        return Err(Error::Database);
    }
    tx.query_opt(
        "SELECT id FROM accounts WHERE id=$1 AND disabled_at IS NULL FOR NO KEY UPDATE",
        &[&account],
    )
    .await?
    .ok_or(Error::Session)?;
    Ok(())
}
pub(super) async fn owner(
    tx: &Transaction<'_>,
    r: &Runtime,
    p: &SessionPrincipal,
) -> Result<(), Error> {
    lock(tx, r, p.tenant.account_id()).await?;
    tx.query_opt("SELECT 1 FROM sessions s JOIN users u ON u.id=s.user_id JOIN memberships m ON (m.account_id,m.user_id)=(s.account_id,s.user_id) WHERE s.id=$1 AND s.account_id=$2 AND s.user_id=$3 AND s.revoked_at IS NULL AND s.expires_at>clock_timestamp() AND u.email_verified_at IS NOT NULL AND m.role='owner' AND m.revoked_at IS NULL FOR SHARE OF s,u,m",&[&p.session_id,&p.tenant.account_id(),&p.user_id]).await?.ok_or(Error::Session)?;
    Ok(())
}
pub(super) async fn final_owner(tx: &Transaction<'_>, p: &SessionPrincipal) -> Result<(), Error> {
    tx.query_opt("SELECT 1 FROM sessions WHERE id=$1 AND revoked_at IS NULL AND expires_at>clock_timestamp()",&[&p.session_id]).await?.ok_or(Error::Session)?;
    Ok(())
}
pub(super) async fn connect(r: &Runtime) -> Result<crate::runtime_db::PooledClient, Error> {
    crate::runtime_db::connect(&r.auth.database_url)
        .await
        .map_err(|_| Error::Database)
}

pub(super) struct Customer {
    pub id: Option<String>,
    pub operation: Uuid,
    pub started: i64,
    pub checkout: Option<Uuid>,
    pub checkout_started: Option<i64>,
    pub checkout_id: Option<String>,
    pub checkout_url: Option<String>,
    pub checkout_expires: Option<i64>,
    pub checkout_state: String,
    pub queued: i64,
    pub processed: i64,
    pub hold: bool,
    pub review: bool,
    pub complete: bool,
    pub nonterminal: i64,
}
pub(super) async fn customer(
    tx: &Transaction<'_>,
    r: &Runtime,
    account: Uuid,
    ensure: bool,
) -> Result<Option<Customer>, Error> {
    if ensure {
        tx.execute("INSERT INTO hosted_billing_customers(namespace_id,account_id) VALUES($1,$2) ON CONFLICT DO NOTHING",&[&ns(r),&account]).await?;
    }
    let Some(row)=tx.query_opt("SELECT customer_id,customer_operation,customer_started_at,checkout_operation,checkout_started_at,checkout_id,checkout_url,checkout_expires_at,checkout_state,queue_generation,processed_generation,payment_hold,review_required,last_observation_complete,last_nonterminal_count FROM hosted_billing_customers WHERE namespace_id=$1 AND account_id=$2 FOR UPDATE",&[&ns(r),&account]).await? else{return Ok(None)};
    Ok(Some(Customer {
        id: row.get(0),
        operation: row.get(1),
        started: row.get(2),
        checkout: row.get(3),
        checkout_started: row.get(4),
        checkout_id: row.get(5),
        checkout_url: row.get(6),
        checkout_expires: row.get(7),
        checkout_state: row.get(8),
        queued: row.get(9),
        processed: row.get(10),
        hold: row.get(11),
        review: row.get(12),
        complete: row.get(13),
        nonterminal: row.get(14),
    }))
}
pub(super) async fn queue(tx: &Transaction<'_>, r: &Runtime, account: Uuid) -> Result<(), Error> {
    tx.execute("UPDATE hosted_billing_customers SET queue_generation=queue_generation+1,next_attempt_at=0 WHERE namespace_id=$1 AND account_id=$2",&[&ns(r),&account]).await?;
    // Events invalidate an in-flight provider claim immediately. A checkout
    // return can neither grant a projection nor clear either risk latch.
    tx.execute("UPDATE hosted_billing_projections SET dirty_generation=dirty_generation+1,per_read_sequence=per_read_sequence+1,read_token=gen_random_uuid() WHERE namespace_id=$1 AND account_id=$2",&[&ns(r),&account]).await?;
    Ok(())
}
pub(super) async fn require_no_global_review(
    tx: &Transaction<'_>,
    r: &Runtime,
) -> Result<(), Error> {
    if tx
        .query_one(
            "SELECT review_required FROM hosted_billing_namespaces WHERE namespace_id=$1 FOR SHARE",
            &[&ns(r)],
        )
        .await?
        .get::<_, bool>(0)
    {
        return Err(Error::Pending);
    }
    Ok(())
}
pub(super) async fn audit(
    tx: &Transaction<'_>,
    r: &Runtime,
    account: Uuid,
    generation: i64,
    reason: &str,
) -> Result<(), Error> {
    tx.execute("INSERT INTO hosted_billing_audit(namespace_id,account_id,generation,reason) VALUES($1,$2,$3,$4)",&[&ns(r),&account,&generation,&reason]).await?;
    Ok(())
}

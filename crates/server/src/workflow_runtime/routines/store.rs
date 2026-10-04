// SPDX-License-Identifier: AGPL-3.0-only
use super::*;
use tokio_postgres::Row;

pub(super) async fn configure(
    tx: &Transaction<'_>,
    owner: &SessionPrincipal,
    input: &IntegrationPrincipal,
    p: &Policy,
    revision: i64,
    source: &[u8; 32],
    hash: &[u8],
) -> Result<(), AuthError> {
    let account = input.account_id();
    if let Some(row)=tx.query_opt("SELECT policy_digest,withdrawn_ms FROM workflow_routine_policies WHERE account_id=$1 AND id=$2 FOR UPDATE",&[&account,&p.policy_id]).await?{
        if row.get::<_,Vec<u8>>(0)!=hash || row.get::<_,Option<i64>>(1).is_some(){return Err(AuthError::Conflict)}
        return Ok(())
    }
    if tx
        .query_one(
            "SELECT count(*) FROM workflow_routine_policies WHERE account_id=$1",
            &[&account],
        )
        .await?
        .get::<_, i64>(0)
        >= 256
    {
        return Err(AuthError::RateLimited);
    }
    tx.execute("INSERT INTO workflow_routine_policies(account_id,id,input_grant_id,context_id,input_revision,input_digest,routine_id,generation,policy,policy_digest,created_by_user,created_session,expires_ms) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9::text::jsonb,$10,$11,$12,$13)",
        &[&account,&p.policy_id,&input.grant_id(),&p.context_id,&revision,&source.as_slice(),&p.routine_id,&p.generation,&serde_json::to_string(p).map_err(|_|AuthError::InvalidInput)?,&hash,&owner.user_id,&owner.session_id,&p.expires_ms]).await?;
    Ok(())
}
pub(super) async fn policy(
    tx: &Transaction<'_>,
    input: &IntegrationPrincipal,
    id: Uuid,
) -> Result<Policy, AuthError> {
    let row=tx.query_opt("SELECT p.policy::text,p.input_revision,p.input_digest,p.expires_ms,floor(extract(epoch FROM s.expires_at)*1000)::bigint FROM workflow_routine_policies p JOIN memberships m ON (m.account_id,m.user_id)=(p.account_id,p.created_by_user) JOIN users u ON u.id=m.user_id JOIN sessions s ON (s.account_id,s.user_id,s.id)=(p.account_id,p.created_by_user,p.created_session) WHERE p.account_id=$1 AND p.id=$2 AND p.input_grant_id=$3 AND p.withdrawn_ms IS NULL AND p.expires_ms>floor(extract(epoch FROM clock_timestamp())*1000)::bigint AND m.role='owner' AND m.revoked_at IS NULL AND u.email_verified_at IS NOT NULL AND u.mfa_enabled AND s.revoked_at IS NULL AND s.expires_at>clock_timestamp() AND EXISTS(SELECT 1 FROM workflow_contexts c JOIN workflow_context_versions v ON (v.account_id,v.context_id,v.revision)=(c.account_id,c.id,c.revision) WHERE c.account_id=p.account_id AND c.id=p.context_id AND c.revision=p.input_revision AND c.purged_at IS NULL AND v.envelope IS NOT NULL AND sha256(v.envelope)=p.input_digest) FOR UPDATE OF p FOR SHARE OF m,u,s",
        &[&input.account_id(),&id,&input.grant_id()]).await?.ok_or(AuthError::Forbidden)?;
    // WHERE may have been evaluated before waiting for the row locks. Recheck
    // the locked policy and issuing owner session against a fresh DB clock.
    let now = activation::now(tx).await.map_err(error)?;
    if row.get::<_, i64>(3) <= now || row.get::<_, i64>(4) <= now {
        return Err(AuthError::Forbidden);
    }
    let policy: Policy =
        serde_json::from_str(row.get::<_, String>(0).as_str()).map_err(|_| AuthError::Forbidden)?;
    if !policy.validate() {
        return Err(AuthError::Forbidden);
    }
    Ok(policy)
}
pub(super) async fn call_policy(
    tx: &Transaction<'_>,
    input: &IntegrationPrincipal,
    id: Uuid,
) -> Result<Policy, AuthError> {
    let policy_id = tx
        .query_opt(
            "SELECT policy_id FROM workflow_routine_calls WHERE account_id=$1 AND id=$2",
            &[&input.account_id(), &id],
        )
        .await?
        .ok_or(AuthError::Forbidden)?
        .get(0);
    policy(tx, input, policy_id).await
}
pub(super) async fn load(tx: &Transaction<'_>, account: Uuid, id: Uuid) -> Result<Row, AuthError> {
    tx.query_opt("SELECT id,policy_id,phase,output_context_id,output_revision,action_id,binding_digest,request_digest,produced_digest,output_grant_id,output_digest,publication_request,publication_digest FROM workflow_routine_calls WHERE account_id=$1 AND id=$2 FOR UPDATE",&[&account,&id]).await?.ok_or(AuthError::Forbidden)
}
pub(super) fn response(row: &Row) -> Result<Call, AuthError> {
    Ok(Call {
        call_id: row.get(0),
        assigned_output_context_id: row.get(0),
        execute_once: false,
        policy_id: row.get(1),
        phase: match row.get::<_, String>(2).as_str() {
            "unknown" => Phase::Unknown,
            "produced" => Phase::Produced,
            "published" => Phase::Published,
            "proposed" => Phase::Proposed,
            _ => return Err(AuthError::Forbidden),
        },
        output_context_id: row.get(3),
        output_revision: row.get(4),
        action_id: row.get(5),
        binding_digest: row.get::<_, Option<Vec<u8>>>(6).map(|h| hex(&h)),
    })
}
pub(super) async fn admit(
    tx: &Transaction<'_>,
    input: &IntegrationPrincipal,
    p: &Policy,
    request_id: Uuid,
    hash: &[u8],
) -> Result<Call, AuthError> {
    let account = input.account_id();
    if tx
        .query_one(
            "SELECT EXISTS(SELECT 1 FROM workflow_routine_calls WHERE account_id=$1 AND id=$2)",
            &[&account, &request_id],
        )
        .await?
        .get::<_, bool>(0)
    {
        let row = load(tx, account, request_id).await?;
        if row.get::<_, Uuid>(1) != p.policy_id || row.get::<_, Vec<u8>>(7) != hash {
            return Err(AuthError::Conflict);
        }
        return response(&row);
    }
    // Account lock serializes independent policy generations. Minimal debits
    // and tombstones survive removal of call metadata; no erasure refund.
    // The 1000-record replay ceiling is account-lifetime, not a daily allowance.
    // Exhaustion refuses new calls until full account erasure; no silent pruning.
    if tx.query_one("SELECT EXISTS(SELECT 1 FROM workflow_routine_admission_tombstones WHERE account_id=$1 AND call_id=$2)",&[&account,&request_id]).await?.get::<_,bool>(0){return Err(AuthError::Conflict)}
    let day = activation::now(tx).await.map_err(error)? / 86_400_000;
    tx.execute("INSERT INTO workflow_routine_period_debits(account_id,utc_day,calls,units) VALUES($1,$2,0,0) ON CONFLICT DO NOTHING",&[&account,&day]).await?;
    tx.execute("INSERT INTO workflow_routine_turn_debits(account_id,context_id,turns) VALUES($1,$2,0) ON CONFLICT DO NOTHING",&[&account,&p.context_id]).await?;
    let totals=tx.query_one("SELECT calls,units FROM workflow_routine_period_debits WHERE account_id=$1 AND utc_day=$2 FOR UPDATE",&[&account,&day]).await?;
    let turns=tx.query_one("SELECT turns FROM workflow_routine_turn_debits WHERE account_id=$1 AND context_id=$2 FOR UPDATE",&[&account,&p.context_id]).await?.get::<_,i64>(0);
    if totals.get::<_, i64>(0) >= i64::from(p.call_limit)
        || totals.get::<_, i64>(1) + i64::from(p.units_per_call) > i64::from(p.unit_limit)
        || turns >= i64::from(p.turn_limit)
    {
        return Err(AuthError::RateLimited);
    }
    if tx
        .query_one(
            "SELECT count(*) FROM workflow_routine_admission_tombstones WHERE account_id=$1",
            &[&account],
        )
        .await?
        .get::<_, i64>(0)
        >= 1000
    {
        return Err(AuthError::RateLimited);
    }
    tx.execute("INSERT INTO workflow_routine_admission_tombstones(account_id,call_id,request_digest) VALUES($1,$2,$3)",&[&account,&request_id,&hash]).await?;
    tx.execute("UPDATE workflow_routine_period_debits SET calls=calls+1,units=units+$3 WHERE account_id=$1 AND utc_day=$2",&[&account,&day,&i64::from(p.units_per_call)]).await?;
    tx.execute("UPDATE workflow_routine_turn_debits SET turns=turns+1 WHERE account_id=$1 AND context_id=$2",&[&account,&p.context_id]).await?;
    tx.execute("INSERT INTO workflow_routine_calls(account_id,id,policy_id,request_digest,units,phase,created_ms) VALUES($1,$2,$3,$4,$5,'unknown',floor(extract(epoch FROM clock_timestamp())*1000)::bigint)",&[&account,&request_id,&p.policy_id,&hash,&i64::from(p.units_per_call)]).await?;
    let mut response = response(&load(tx, account, request_id).await?)?;
    response.execute_once = true;
    Ok(response)
}
pub(super) async fn produced(
    tx: &Transaction<'_>,
    input: &IntegrationPrincipal,
    id: Uuid,
    hash: &[u8],
) -> Result<Call, AuthError> {
    let row = load(tx, input.account_id(), id).await?;
    if row.get::<_, String>(2) != "unknown" {
        if row.get::<_, Option<Vec<u8>>>(8).as_deref() != Some(hash) {
            return Err(AuthError::Conflict);
        }
        return response(&row);
    }
    tx.execute("UPDATE workflow_routine_calls SET phase='produced',produced_digest=$3 WHERE account_id=$1 AND id=$2",&[&input.account_id(),&id,&hash]).await?;
    response(&load(tx, input.account_id(), id).await?)
}

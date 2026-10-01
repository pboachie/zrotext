// SPDX-License-Identifier: AGPL-3.0-only
//! Unmounted source candidate for attributed usage review requests. A request
//! is not an issued monetary credit, negative meter event or quota refund.
use crate::auth::{
    self, AuthError, SessionPrincipal, TokenHasher,
    account::{self, OwnerMutationFence},
};
use tokio_postgres::Client;
use uuid::Uuid;

pub struct ReviewRequest<'a> {
    pub message_id: Uuid,
    pub request_id: Uuid,
    pub decision: &'a str,
    pub reason: &'a str,
    pub password: &'a str,
    pub factor: Option<&'a str>,
    pub origin: &'a str,
    pub csrf_cookie: &'a str,
    pub csrf_header: &'a str,
}
pub struct ReviewContext<'a> {
    pub hasher: &'a TokenHasher,
    pub cipher: Option<&'a auth::mfa::MfaCipher>,
    pub canonical_origin: &'a str,
}

pub async fn record_request(
    client: &mut Client,
    owner: &SessionPrincipal,
    context: &ReviewContext<'_>,
    request: &ReviewRequest<'_>,
) -> Result<bool, AuthError> {
    if !matches!(request.decision, "request_credit" | "retain_charge")
        || !matches!(
            request.reason,
            "uncertain_execution" | "meter_rejection" | "owner_cancelled_review"
        )
    {
        return Err(AuthError::InvalidInput);
    }
    owner.require_csrf(
        context.hasher,
        request.origin,
        context.canonical_origin,
        request.csrf_cookie,
        request.csrf_header,
    )?;
    let hash = account::verify_current_password(client, owner, request.password).await?;
    let tenant = owner.tenant.account_id();
    let tx = client.transaction().await?;
    // Canonical account->customer->outbox order precedes the final owner
    // password/MFA/session fence. No replay bypasses live owner authority.
    tx.query_opt("SELECT 1 FROM accounts WHERE id=$1 FOR UPDATE", &[&tenant])
        .await?
        .ok_or(AuthError::Unauthorized)?;
    tx.query_opt(
        "SELECT 1 FROM billing_customers WHERE account_id=$1 FOR SHARE",
        &[&tenant],
    )
    .await?
    .ok_or(AuthError::Unauthorized)?;
    tx.query_opt("SELECT 1 FROM billing_usage_outbox WHERE account_id=$1 AND message_id=$2 AND state='review' FOR UPDATE",&[&tenant,&request.message_id]).await?.ok_or(AuthError::Unauthorized)?;
    let existing=tx.query_opt("SELECT request_id,decision,reason FROM billing_usage_adjustment_requests WHERE account_id=$1 AND message_id=$2",&[&tenant,&request.message_id]).await?;
    if let Some(row) = &existing
        && (row.get::<_, Uuid>(0) != request.request_id
            || row.get::<_, String>(1) != request.decision
            || row.get::<_, String>(2) != request.reason)
    {
        return Err(AuthError::InvalidInput);
    }
    if matches!(
        account::fence_owner_mutation(
            &tx,
            context.cipher,
            context.hasher,
            owner,
            &hash,
            request.factor
        )
        .await?,
        OwnerMutationFence::FactorRejected
    ) {
        tx.commit().await?;
        return Err(AuthError::InvalidCredentials);
    }
    let inserted = if existing.is_none() {
        tx.execute("INSERT INTO billing_usage_adjustment_requests(account_id,message_id,request_id,decision,reason,requested_units,owner_user_id,owner_session_id) VALUES($1,$2,$3,$4,$5,CASE WHEN $4='request_credit' THEN -1 ELSE 0 END,$6,$7)",&[&tenant,&request.message_id,&request.request_id,&request.decision,&request.reason,&owner.user_id,&owner.session_id]).await?>0
    } else {
        false
    };
    tx.commit().await?;
    Ok(inserted)
}

#[cfg(test)]
mod tests;

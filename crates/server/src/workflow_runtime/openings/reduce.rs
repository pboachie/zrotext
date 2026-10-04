// SPDX-License-Identifier: AGPL-3.0-only
use super::{
    contracts::{AllocationMutation, OpeningKey, OpeningMutation},
    model::{Outcome, next_version},
    store,
};
use crate::{
    auth::SessionPrincipal,
    http_owner_conversations::{self as owner_context, ConversationError},
};
use tokio_postgres::{Client, Transaction};
use uuid::Uuid;

async fn opening(
    tx: &Transaction<'_>,
    account: Uuid,
    key: OpeningKey,
) -> Result<String, ConversationError> {
    let row=tx.query_opt("SELECT definition_version,state_version,phase FROM workflow_openings WHERE account_id=$1 AND id=$2 FOR UPDATE", &[&account,&key.opening_id]).await?.ok_or(ConversationError::NotFound)?;
    if row.get::<_, i64>(0) != key.definition_version || row.get::<_, i64>(1) != key.state_version {
        return Err(ConversationError::Conflict);
    }
    Ok(row.get(2))
}

/// Closing admission preserves confirmed occupancy. Explicit cancellation is
/// a separate subsequent reduction and releases it, even at MAX/full budget.
pub async fn close(
    client: &mut Client,
    owner: &SessionPrincipal,
    request: OpeningMutation,
) -> Result<Outcome, ConversationError> {
    change(client, owner, request, false).await
}
pub async fn cancel(
    client: &mut Client,
    owner: &SessionPrincipal,
    request: OpeningMutation,
) -> Result<Outcome, ConversationError> {
    change(client, owner, request, true).await
}
async fn change(
    client: &mut Client,
    owner: &SessionPrincipal,
    request: OpeningMutation,
    cancel: bool,
) -> Result<Outcome, ConversationError> {
    if !request.validate() {
        return Err(ConversationError::Invalid);
    }
    let account = owner.tenant.account_id();
    let operation = if cancel { 8 } else { 7 };
    let digest = store::digest(account, operation, &request)?;
    let tx = store::begin(client).await?;
    owner_context::lock_owner(&tx, owner).await?;
    if let Some(receipt) = store::replay(&tx, account, request.request_id, &digest).await? {
        owner_context::fresh_owner(&tx, owner).await?;
        tx.commit().await?;
        return Ok(Outcome {
            receipt,
            applied: false,
            recorded: true,
        });
    }
    let phase = opening(&tx, account, request.opening).await?;
    let target = if cancel { "cancelled" } else { "closed" };
    if phase == "cancelled" || phase == target {
        let receipt = store::status(&tx, account, request.opening, phase).await?;
        owner_context::fresh_owner(&tx, owner).await?;
        tx.commit().await?;
        return Ok(Outcome {
            receipt,
            applied: false,
            recorded: false,
        });
    }
    // At most open->closed->cancelled: fresh terminal UUIDs append no rows.
    tx.query("SELECT id FROM workflow_opening_offers WHERE account_id=$1 AND opening_id=$2 ORDER BY id FOR UPDATE", &[&account,&request.opening.opening_id]).await?;
    tx.query("SELECT id FROM workflow_opening_allocations WHERE account_id=$1 AND opening_id=$2 ORDER BY id FOR UPDATE", &[&account,&request.opening.opening_id]).await?;
    tx.execute("UPDATE workflow_opening_offers SET phase=$3,state_version=CASE WHEN state_version=9223372036854775807 THEN state_version ELSE state_version+1 END WHERE account_id=$1 AND opening_id=$2 AND (phase='active' OR ($3='cancelled' AND phase='closed'))", &[&account,&request.opening.opening_id,&target]).await?;
    tx.execute("UPDATE workflow_opening_allocations SET phase='cancelled',state_version=CASE WHEN state_version=9223372036854775807 THEN state_version ELSE state_version+1 END WHERE account_id=$1 AND opening_id=$2 AND (phase='pending' OR ($3 AND phase='confirmed'))", &[&account,&request.opening.opening_id,&cancel]).await?;
    let version =
        next_version(request.opening.state_version, true).ok_or(ConversationError::Conflict)?;
    tx.execute(
        "UPDATE workflow_openings SET phase=$3,state_version=$4 WHERE account_id=$1 AND id=$2",
        &[&account, &request.opening.opening_id, &target, &version],
    )
    .await?;
    let receipt = store::status(
        &tx,
        account,
        OpeningKey {
            state_version: version,
            ..request.opening
        },
        target.into(),
    )
    .await?;
    store::record(
        &tx,
        owner,
        store::Mutation {
            request: request.request_id,
            operation,
            subject_kind: 1,
            subject: request.opening.opening_id,
            digest: &digest,
            receipt: &receipt,
            charged: false,
        },
    )
    .await?;
    owner_context::fresh_owner(&tx, owner).await?;
    tx.commit().await?;
    Ok(Outcome {
        receipt,
        applied: true,
        recorded: true,
    })
}

/// No historical contact/source/reader lookup: a current account owner may
/// release an occupied unit after its complete authority binding was erased.
pub async fn release(
    client: &mut Client,
    owner: &SessionPrincipal,
    request: AllocationMutation,
) -> Result<Outcome, ConversationError> {
    if !request.validate() {
        return Err(ConversationError::Invalid);
    }
    let account = owner.tenant.account_id();
    let digest = store::digest(account, 6, &request)?;
    let tx = store::begin(client).await?;
    owner_context::lock_owner(&tx, owner).await?;
    if let Some(receipt) = store::replay(&tx, account, request.request_id, &digest).await? {
        owner_context::fresh_owner(&tx, owner).await?;
        tx.commit().await?;
        return Ok(Outcome {
            receipt,
            applied: false,
            recorded: true,
        });
    }
    let opening_phase = opening(&tx, account, request.opening).await?;
    let row=tx.query_opt("SELECT state_version,phase FROM workflow_opening_allocations WHERE account_id=$1 AND opening_id=$2 AND id=$3 FOR UPDATE", &[&account,&request.opening.opening_id,&request.allocation_id]).await?.ok_or(ConversationError::NotFound)?;
    let version: i64 = row.get(0);
    let phase: String = row.get(1);
    if version != request.allocation_version {
        return Err(ConversationError::Conflict);
    }
    let applied = matches!(phase.as_str(), "pending" | "confirmed");
    let allocation_version = if applied {
        next_version(version, true).ok_or(ConversationError::Conflict)?
    } else {
        version
    };
    let opening_version = if applied {
        next_version(request.opening.state_version, true).ok_or(ConversationError::Conflict)?
    } else {
        request.opening.state_version
    };
    if applied {
        tx.execute("UPDATE workflow_opening_allocations SET phase='released',state_version=$4 WHERE account_id=$1 AND opening_id=$2 AND id=$3", &[&account,&request.opening.opening_id,&request.allocation_id,&allocation_version]).await?;
        tx.execute(
            "UPDATE workflow_openings SET state_version=$3 WHERE account_id=$1 AND id=$2",
            &[&account, &request.opening.opening_id, &opening_version],
        )
        .await?;
    }
    let mut receipt = store::status(
        &tx,
        account,
        OpeningKey {
            state_version: opening_version,
            ..request.opening
        },
        opening_phase,
    )
    .await?;
    receipt.allocation_id = Some(request.allocation_id);
    receipt.allocation_version = Some(allocation_version);
    receipt.phase = if applied { "released".into() } else { phase };
    if applied {
        store::record(
            &tx,
            owner,
            store::Mutation {
                request: request.request_id,
                operation: 6,
                subject_kind: 3,
                subject: request.allocation_id,
                digest: &digest,
                receipt: &receipt,
                charged: false,
            },
        )
        .await?;
    }
    owner_context::fresh_owner(&tx, owner).await?;
    tx.commit().await?;
    Ok(Outcome {
        receipt,
        applied,
        recorded: applied,
    })
}

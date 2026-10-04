// SPDX-License-Identifier: AGPL-3.0-only
use super::{model, *};
use crate::{
    auth::SessionPrincipal,
    http_owner_conversations::{fresh_owner, lock_owner},
};
use tokio_postgres::{Client, Transaction};
use uuid::Uuid;

async fn begin<'a>(client: &'a mut Client, owner: &SessionPrincipal) -> Result<Transaction<'a>> {
    let tx = client.transaction().await?;
    tx.batch_execute("SET LOCAL lock_timeout='3s'; SET LOCAL statement_timeout='5s'")
        .await?;
    lock_owner(&tx, owner).await?;
    if !lifecycle::installed(&tx).await? {
        return Err(ConversationError::Unavailable);
    }
    Ok(tx)
}
async fn replay(
    tx: &Transaction<'_>,
    account: Uuid,
    request: Uuid,
    hash: &[u8; 32],
) -> Result<Option<Acknowledgment>> {
    let row = tx.query_opt("SELECT config_id,config_version,record_version,state,request_digest FROM provider_configuration_mutations WHERE account_id=$1 AND request_id=$2", &[&account,&request]).await?;
    row.map(|r| {
        if r.get::<_, Vec<u8>>(4).as_slice() != hash {
            return Err(ConversationError::Conflict);
        }
        Acknowledgment::row(&r)
    })
    .transpose()
}
async fn capacity(tx: &Transaction<'_>, account: Uuid, withdrawal: bool) -> Result<()> {
    let count: i64 = tx
        .query_one(
            "SELECT count(*) FROM provider_configuration_mutations WHERE account_id=$1",
            &[&account],
        )
        .await?
        .get(0);
    // Reserve one irreversible withdrawal identity per possible head. Metadata
    // never evicts another request, including at the ordinary capacity boundary.
    let limit = if withdrawal {
        model::MUTATIONS
    } else {
        model::MUTATIONS - model::HEADS
    };
    if count >= limit {
        return Err(ConversationError::Conflict);
    }
    Ok(())
}
async fn record(
    tx: &Transaction<'_>,
    owner: &SessionPrincipal,
    request: Uuid,
    operation: &str,
    hash: &[u8; 32],
    value: &Acknowledgment,
) -> Result<()> {
    tx.execute("INSERT INTO provider_configuration_mutations(account_id,request_id,config_id,config_version,operation,request_digest,record_version,state,created_by,created_session) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)", &[&owner.tenant.account_id(),&request,&value.config_id,&value.config_version,&operation,&&hash[..],&value.record_version,&value.state,&owner.user_id,&owner.session_id]).await?;
    Ok(())
}
pub async fn create(
    client: &mut Client,
    owner: &SessionPrincipal,
    input: Mutation,
) -> Result<Acknowledgment> {
    mutate(client, owner, input, true).await
}
pub async fn revise(
    client: &mut Client,
    owner: &SessionPrincipal,
    input: Mutation,
) -> Result<Acknowledgment> {
    mutate(client, owner, input, false).await
}
async fn mutate(
    client: &mut Client,
    owner: &SessionPrincipal,
    input: Mutation,
    first: bool,
) -> Result<Acknowledgment> {
    let request = model::identity(&input.request_id)?;
    let config = model::identity(&input.config_id)?;
    if (first && input.expected_record_version != 0)
        || (!first && input.expected_record_version < 1)
    {
        return Err(ConversationError::Invalid);
    }
    let bytes = input.declaration.bytes()?;
    let operation = if first { "create" } else { "revise" };
    let account = owner.tenant.account_id();
    let hash = model::request_digest(
        account,
        config,
        operation,
        input.expected_record_version,
        Some(&bytes),
    )?;
    let tx = begin(client, owner).await?;
    let result = if let Some(result) = replay(&tx, account, request, &hash).await? {
        result
    } else {
        capacity(&tx, account, false).await?;
        let result = if first {
            let count: i64 = tx
                .query_one(
                    "SELECT count(*) FROM provider_configuration_heads WHERE account_id=$1",
                    &[&account],
                )
                .await?
                .get(0);
            if count >= model::HEADS {
                return Err(ConversationError::Conflict);
            }
            if tx.query_opt("SELECT 1 FROM provider_configuration_heads WHERE account_id=$1 AND config_id=$2", &[&account,&config]).await?.is_some() {
                return Err(ConversationError::Conflict);
            }
            tx.execute("INSERT INTO provider_configuration_heads(account_id,config_id,config_version,record_version,state,created_by,created_session) VALUES($1,$2,1,1,'draft',$3,$4)", &[&account,&config,&owner.user_id,&owner.session_id]).await?;
            Acknowledgment {
                config_id: config,
                config_version: 1,
                record_version: 1,
                state: "draft".into(),
                acceptance: "unavailable",
            }
        } else {
            let row = tx.query_opt("SELECT config_id,config_version,record_version,state FROM provider_configuration_heads WHERE account_id=$1 AND config_id=$2 FOR UPDATE", &[&account,&config]).await?.ok_or(ConversationError::NotFound)?;
            let old = Acknowledgment::row(&row)?;
            if old.state != "draft"
                || old.record_version != input.expected_record_version
                || old.config_version >= model::VERSIONS
            {
                return Err(ConversationError::Conflict);
            }
            let record_version = old
                .record_version
                .checked_add(1)
                .ok_or(ConversationError::Conflict)?;
            let value = Acknowledgment {
                config_version: old.config_version + 1,
                record_version,
                ..old
            };
            tx.execute("UPDATE provider_configuration_heads SET config_version=$3,record_version=$4 WHERE account_id=$1 AND config_id=$2", &[&account,&config,&value.config_version,&value.record_version]).await?;
            value
        };
        let declaration_digest = model::digest(&bytes);
        tx.execute("INSERT INTO provider_configuration_versions(account_id,config_id,version,declaration,declaration_digest) VALUES($1,$2,$3,$4,$5)", &[&account,&config,&result.config_version,&bytes,&&declaration_digest[..]]).await?;
        record(&tx, owner, request, operation, &hash, &result).await?;
        result
    };
    fresh_owner(&tx, owner).await?;
    tx.commit().await?;
    Ok(result)
}
pub async fn withdraw(
    client: &mut Client,
    owner: &SessionPrincipal,
    input: Withdrawal,
) -> Result<Acknowledgment> {
    let request = model::identity(&input.request_id)?;
    let config = model::identity(&input.config_id)?;
    if input.expected_record_version < 1 {
        return Err(ConversationError::Invalid);
    }
    let account = owner.tenant.account_id();
    let hash = model::request_digest(
        account,
        config,
        "withdraw",
        input.expected_record_version,
        None,
    )?;
    let tx = begin(client, owner).await?;
    let result = if let Some(result) = replay(&tx, account, request, &hash).await? {
        result
    } else {
        capacity(&tx, account, true).await?;
        let row = tx.query_opt("SELECT config_id,config_version,record_version,state FROM provider_configuration_heads WHERE account_id=$1 AND config_id=$2 FOR UPDATE", &[&account,&config]).await?.ok_or(ConversationError::NotFound)?;
        let old = Acknowledgment::row(&row)?;
        if old.state != "draft" || old.record_version != input.expected_record_version {
            return Err(ConversationError::Conflict);
        }
        let result = Acknowledgment {
            record_version: old.record_version.saturating_add(1),
            state: "withdrawn".into(),
            ..old
        };
        tx.execute("UPDATE provider_configuration_heads SET state='withdrawn',record_version=$3 WHERE account_id=$1 AND config_id=$2", &[&account,&config,&result.record_version]).await?;
        tx.execute("UPDATE provider_configuration_versions SET declaration=NULL WHERE account_id=$1 AND config_id=$2 AND declaration IS NOT NULL", &[&account,&config]).await?;
        record(&tx, owner, request, "withdraw", &hash, &result).await?;
        result
    };
    fresh_owner(&tx, owner).await?;
    tx.commit().await?;
    Ok(result)
}
pub async fn read(client: &mut Client, owner: &SessionPrincipal, config: Uuid) -> Result<Details> {
    if config.is_nil() {
        return Err(ConversationError::Invalid);
    }
    let tx = begin(client, owner).await?;
    let row = tx.query_opt("SELECT h.config_id,h.config_version,h.record_version,h.state,v.declaration,v.declaration_digest FROM provider_configuration_heads h JOIN provider_configuration_versions v ON (v.account_id,v.config_id,v.version)=(h.account_id,h.config_id,h.config_version) WHERE h.account_id=$1 AND h.config_id=$2 FOR SHARE OF h,v", &[&owner.tenant.account_id(),&config]).await?.ok_or(ConversationError::NotFound)?;
    let metadata = Acknowledgment::row(&row)?;
    let declaration = match (metadata.state.as_str(), row.get::<_, Option<Vec<u8>>>(4)) {
        ("withdrawn", None) => None,
        ("draft", Some(bytes)) => {
            let parsed: Declaration =
                serde_json::from_slice(&bytes).map_err(|_| ConversationError::Unavailable)?;
            if parsed.bytes().map_err(|_| ConversationError::Unavailable)? != bytes
                || model::digest(&bytes).as_slice() != row.get::<_, Vec<u8>>(5)
            {
                return Err(ConversationError::Unavailable);
            }
            Some(parsed)
        }
        _ => return Err(ConversationError::Unavailable),
    };
    fresh_owner(&tx, owner).await?;
    tx.commit().await?;
    Ok(Details {
        metadata,
        declaration,
        unavailable_reasons: [
            "provider_identity_unverified",
            "sender_eligibility_unverified",
            "policy_unaccepted",
            "cost_bound_unavailable",
        ],
    })
}

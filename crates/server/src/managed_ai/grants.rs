// SPDX-License-Identifier: AGPL-3.0-only
use super::{Error, GrantRequest, ManagedGrants, OwnerCeremony, lifecycle};
use crate::{
    auth::{SessionPrincipal, account, mfa},
    http_owner_conversations::{activation, context, fresh_owner, lock_owner},
    sealed_manifest_store::outbound::{CurrentAuthority, lock_current},
};
use tokio_postgres::{Client, Transaction};
use uuid::Uuid;

async fn now(tx: &Transaction<'_>) -> Result<i64, Error> {
    Ok(activation::now(tx).await?)
}
async fn begin(client: &mut Client) -> Result<Transaction<'_>, Error> {
    let tx = client.transaction().await?;
    tx.batch_execute("SET LOCAL lock_timeout='3s'; SET LOCAL statement_timeout='5s'")
        .await?;
    if !lifecycle::installed(&tx).await? {
        return Err(Error::Unavailable);
    }
    Ok(tx)
}
async fn current(
    tx: &Transaction<'_>,
    account: Uuid,
    id: Uuid,
    expected: i64,
) -> Result<GrantRequest, Error> {
    let row = tx.query_opt("SELECT g.current_version,g.revoked_ms,v.binding::text,g.contact_id,g.purpose,v.policy_id,v.policy_version,v.policy_digest,v.reader_id,v.reader_generation FROM managed_reader_grants g JOIN managed_reader_grant_versions v ON (v.account_id,v.grant_id,v.version)=(g.account_id,g.id,g.current_version) WHERE g.account_id=$1 AND g.id=$2 FOR UPDATE OF g FOR SHARE OF v", &[&account,&id]).await?.ok_or(Error::NotFound)?;
    if row.get::<_, i64>(0) != expected || row.get::<_, Option<i64>>(1).is_some() {
        return Err(Error::Conflict);
    }
    let request: GrantRequest =
        serde_json::from_str(&row.get::<_, String>(2)).map_err(|_| Error::Unavailable)?;
    request.validate()?;
    if request.contact != row.get::<_, Uuid>(3)
        || request.purpose.slug() != row.get::<_, String>(4)
        || request.policy.id != row.get::<_, Uuid>(5)
        || request.policy.version != row.get::<_, i64>(6)
        || row.get::<_, Vec<u8>>(7) != request.policy.digest
        || request.policy.reader != row.get::<_, Uuid>(8)
        || request.policy.reader_generation != row.get::<_, i64>(9)
    {
        return Err(Error::Unavailable);
    }
    let normalized=tx.query("SELECT source_id,source_version,digest FROM managed_reader_selections WHERE account_id=$1 AND grant_id=$2 AND grant_version=$3 AND kind='workflow_context_v1' ORDER BY source_id,source_version,digest FOR SHARE",&[&account,&id,&expected]).await?;
    if normalized.len() != request.selections.len()
        || normalized.iter().zip(&request.selections).any(|(row, s)| {
            row.get::<_, Uuid>(0) != s.id
                || row.get::<_, i64>(1) != s.version
                || row.get::<_, Vec<u8>>(2) != s.digest
        })
    {
        return Err(Error::Unavailable);
    }
    Ok(request)
}

/// Locks real service policy/key rows; public caller metadata is never an issuer.
async fn policy(tx: &Transaction<'_>, account: Uuid, r: &GrantRequest) -> Result<(), Error> {
    let p = &r.policy;
    let row = tx.query_opt("SELECT p.expires_ms,p.max_calls,p.max_input_bytes,p.max_cost_microunits,k.expires_ms,k.revoked_ms,k.key_point,k.key_id FROM managed_reader_policies p JOIN managed_reader_keys k ON (k.account_id,k.id,k.generation)=(p.account_id,p.reader_id,p.reader_generation) WHERE p.account_id=$1 AND p.id=$2 AND p.version=$3 AND p.digest=$4 AND p.reader_id=$5 AND p.reader_generation=$6 FOR SHARE OF p,k", &[&account,&p.id,&p.version,&p.digest.as_slice(),&p.reader,&p.reader_generation]).await?.ok_or(Error::Unavailable)?;
    let point: Vec<u8> = row.get(6);
    if point.len() != 65
        || point.first() != Some(&4)
        || p256::PublicKey::from_sec1_bytes(&point).is_err()
        || row.get::<_, Vec<u8>>(7) != crate::sealed_manifest::key_id(3, &point)
        || row.get::<_, Option<i64>>(5).is_some()
        || r.expires_ms > row.get::<_, i64>(0).min(row.get(4))
        || r.max_calls > row.get::<_, i64>(1)
        || r.max_input_bytes > row.get::<_, i64>(2)
        || r.max_cost_microunits > row.get::<_, i64>(3)
    {
        return Err(Error::Forbidden);
    }
    Ok(())
}
async fn sources(
    tx: &Transaction<'_>,
    owner: &SessionPrincipal,
    authority: &mut CurrentAuthority<'_, '_>,
    r: &GrantRequest,
) -> Result<(), Error> {
    if r.selections.is_empty() {
        return Err(Error::Invalid);
    }
    for s in &r.selections {
        let (header, deadline) =
            context::managed_grant_source(tx, owner, authority, s.id, s.version, &s.digest).await?;
        let consent_deadline =
            context::decisions::fence::contact_scope(tx, r.contact, r.purpose.slug(), &header)
                .await?;
        if r.expires_ms > deadline.min(consent_deadline) {
            return Err(Error::Forbidden);
        }
    }
    let accepted = now(tx).await?;
    if r.expires_ms <= accepted || r.expires_ms.saturating_sub(accepted) > 86_400_000 {
        return Err(Error::Forbidden);
    }
    fresh_owner(tx, owner).await?;
    Ok(())
}
async fn event(
    tx: &Transaction<'_>,
    owner: &SessionPrincipal,
    id: Uuid,
    version: i64,
    operation: &str,
) -> Result<(), Error> {
    tx.execute("INSERT INTO managed_reader_events(account_id,id,grant_id,grant_version,operation,actor_user_id,actor_session_id,created_ms) VALUES($1,$2,$3,$4,$5,$6,$7,$8)", &[&owner.tenant.account_id(),&Uuid::new_v4(),&id,&version,&operation,&owner.user_id,&owner.session_id,&now(tx).await?]).await?;
    Ok(())
}
async fn insert_version(
    tx: &Transaction<'_>,
    owner: &SessionPrincipal,
    id: Uuid,
    version: i64,
    r: &GrantRequest,
    operation: &str,
) -> Result<(), Error> {
    let account = owner.tenant.account_id();
    let p = &r.policy;
    let binding = serde_json::to_string(r).map_err(|_| Error::Invalid)?;
    tx.execute("INSERT INTO managed_reader_grant_versions(account_id,grant_id,id,version,policy_id,policy_version,policy_digest,reader_id,reader_generation,binding,created_by_user,created_session,created_ms) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10::text::jsonb,$11,$12,$13)", &[&account,&id,&Uuid::new_v4(),&version,&p.id,&p.version,&p.digest.as_slice(),&p.reader,&p.reader_generation,&binding,&owner.user_id,&owner.session_id,&now(tx).await?]).await?;
    for s in &r.selections {
        tx.execute("INSERT INTO managed_reader_selections(account_id,id,grant_id,grant_version,kind,source_id,source_version,digest) VALUES($1,$2,$3,$4,'workflow_context_v1',$5,$6,$7)", &[&account,&Uuid::new_v4(),&id,&version,&s.id,&s.version,&s.digest.as_slice()]).await?;
    }
    event(tx, owner, id, version, operation).await
}
impl ManagedGrants {
    pub async fn create(
        &self,
        client: &mut Client,
        ceremony: &OwnerCeremony<'_>,
        r: &GrantRequest,
    ) -> Result<Uuid, Error> {
        self.issue(client, ceremony, None, r).await
    }
    /// Replacing policy/instructions or widening requires a new owner ceremony.
    /// A different contact or purpose requires a new grant ID.
    pub async fn replace(
        &self,
        client: &mut Client,
        ceremony: &OwnerCeremony<'_>,
        id: Uuid,
        expected: i64,
        r: &GrantRequest,
    ) -> Result<(), Error> {
        self.issue(client, ceremony, Some((id, expected)), r)
            .await
            .map(|_| ())
    }
    async fn issue(
        &self,
        client: &mut Client,
        ceremony: &OwnerCeremony<'_>,
        existing: Option<(Uuid, i64)>,
        r: &GrantRequest,
    ) -> Result<Uuid, Error> {
        let &OwnerCeremony {
            owner,
            hasher,
            cipher,
            password,
            factor,
        } = ceremony;
        if !self.candidate {
            return Err(Error::Unavailable);
        }
        r.validate()?;
        let verified = account::verify_current_password(client, owner, password).await?;
        let account = owner.tenant.account_id();
        let tx = begin(client).await?;
        let mut authority = lock_current(&tx, account)
            .await
            .map_err(|_| Error::Forbidden)?;
        lock_owner(&tx, owner).await?;
        let user = tx
            .query_one(
                "SELECT password_hash,mfa_enabled FROM users WHERE id=$1",
                &[&owner.user_id],
            )
            .await?;
        let stored: String = user.get(0);
        if stored != verified {
            return Err(Error::Authentication(
                crate::auth::AuthError::InvalidCredentials,
            ));
        }
        if !user.get::<_, bool>(1) {
            return Err(Error::Forbidden);
        }
        let (id, version, operation) = if let Some((id, expected)) = existing {
            if id.is_nil() || !(1..128).contains(&expected) {
                return Err(Error::Invalid);
            }
            let old = current(&tx, account, id, expected).await?;
            if old.contact != r.contact || old.purpose != r.purpose {
                return Err(Error::Invalid);
            }
            (id, expected + 1, "replace")
        } else {
            let count: i64 = tx
                .query_one(
                    "SELECT count(*) FROM managed_reader_grants WHERE account_id=$1",
                    &[&account],
                )
                .await?
                .get(0);
            if count >= 128 {
                return Err(Error::Conflict);
            }
            (Uuid::new_v4(), 1, "create")
        };
        policy(&tx, account, r).await?;
        let proof = mfa::consume_ceremony_factor(
            &tx,
            cipher,
            hasher,
            owner,
            factor,
            now(&tx).await? as u64,
        )
        .await?;
        let Some(proof) = proof else {
            drop(authority);
            tx.commit().await?;
            return Err(Error::Authentication(
                crate::auth::AuthError::InvalidCredentials,
            ));
        };
        // Archive validation advances its verification high-water mark. Defer
        // that mutation until a factor succeeds, so a rejected-factor commit
        // persists only ceremony failure accounting. Any later source refusal
        // rolls back the factor and all authority writes together.
        sources(&tx, owner, &mut authority, r).await?;
        if version == 1 {
            tx.execute("INSERT INTO managed_reader_grants(account_id,id,contact_id,purpose,current_version) VALUES($1,$2,$3,$4,1)", &[&account,&id,&r.contact,&r.purpose.slug()]).await?;
        } else {
            tx.execute(
                "UPDATE managed_reader_grants SET current_version=$3 WHERE account_id=$1 AND id=$2",
                &[&account, &id, &version],
            )
            .await?;
        }
        insert_version(&tx, owner, id, version, r, operation).await?;
        // Recheck clocks/current authority after the final row locks and writes.
        policy(&tx, account, r).await?;
        sources(&tx, owner, &mut authority, r).await?;
        if !proof.current_at(now(&tx).await? as u64) {
            return Err(Error::Forbidden);
        }
        fresh_owner(&tx, owner).await?;
        drop(authority);
        tx.commit().await?;
        Ok(id)
    }
    pub async fn narrow(
        &self,
        client: &mut Client,
        owner: &SessionPrincipal,
        id: Uuid,
        expected: i64,
        r: &GrantRequest,
    ) -> Result<i64, Error> {
        r.validate()?;
        if id.is_nil() || !(1..128).contains(&expected) {
            return Err(Error::Invalid);
        }
        let tx = begin(client).await?;
        lock_owner(&tx, owner).await?;
        let old = current(&tx, owner.tenant.account_id(), id, expected).await?;
        if !r.narrows(&old) {
            return Err(Error::Forbidden);
        }
        let version = expected + 1;
        tx.execute(
            "UPDATE managed_reader_grants SET current_version=$3 WHERE account_id=$1 AND id=$2",
            &[&owner.tenant.account_id(), &id, &version],
        )
        .await?;
        // No root, policy, key or source freshness requirement for reduction.
        insert_version(&tx, owner, id, version, r, "narrow").await?;
        fresh_owner(&tx, owner).await?;
        tx.commit().await?;
        Ok(version)
    }
    pub async fn revoke(
        &self,
        client: &mut Client,
        owner: &SessionPrincipal,
        id: Uuid,
    ) -> Result<(), Error> {
        if id.is_nil() {
            return Err(Error::Invalid);
        }
        let tx = begin(client).await?;
        lock_owner(&tx, owner).await?;
        let row = tx.query_opt("SELECT current_version,revoked_ms FROM managed_reader_grants WHERE account_id=$1 AND id=$2 FOR UPDATE", &[&owner.tenant.account_id(),&id]).await?.ok_or(Error::NotFound)?;
        if row.get::<_, Option<i64>>(1).is_none() {
            tx.execute("UPDATE managed_reader_grants SET revoked_ms=$3,revocation_generation=1 WHERE account_id=$1 AND id=$2", &[&owner.tenant.account_id(),&id,&now(&tx).await?]).await?;
            event(&tx, owner, id, row.get(0), "revoke").await?;
        }
        fresh_owner(&tx, owner).await?;
        tx.commit().await?;
        Ok(())
    }
}

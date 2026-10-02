// SPDX-License-Identifier: AGPL-3.0-only
use super::*;
use crate::http_owner_conversations::{fresh_owner, lock_owner};
use sha2::{Digest, Sha256};

fn cancellation_digest(account: Uuid, reservation: Uuid) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(b"ZROtext/exposure/pre-intent-cancel/v1\0");
    digest.update(account.as_bytes());
    digest.update(reservation.as_bytes());
    digest.finalize().into()
}

pub(super) async fn cancel(
    client: &mut Client,
    owner: &SessionPrincipal,
    reservation: Uuid,
) -> Result<bool, Error> {
    if reservation.is_nil() {
        return Err(Error::Unavailable);
    }
    let account = owner.tenant.account_id();
    let tx = client.transaction().await?;
    let deployment_id: Uuid = tx
        .query_opt(
            "SELECT deployment_id FROM exposure_reservations WHERE account_id=$1 AND id=$2",
            &[&account, &reservation],
        )
        .await?
        .ok_or(Error::Unavailable)?
        .get(0);
    // Same global serialization as admission, intent and settlement. Cleanup
    // then locks the account and owner, but never acquires root/action authority
    // afterwards. It cannot renew consent, policy, entitlement or execution.
    store::deployment(&tx, Some(deployment_id)).await?;
    lock_owner(&tx, owner).await?;
    let row = tx
        .query_opt(
            "SELECT maximum_units,state,lease_id,lease_until_ms,actual_units,result_digest
         FROM exposure_reservations WHERE account_id=$1 AND id=$2 FOR UPDATE",
            &[&account, &reservation],
        )
        .await?
        .ok_or(Error::Unavailable)?;
    let state: String = row.get(1);
    let digest = cancellation_digest(account, reservation);
    if row.get::<_, Option<Uuid>>(2).is_some() || row.get::<_, Option<i64>>(3).is_some() {
        return Err(Error::Conflict);
    }
    if state == "released" {
        if row.get::<_, Option<i64>>(4) != Some(0)
            || row.get::<_, Option<Vec<u8>>>(5).as_deref() != Some(&digest[..])
        {
            return Err(Error::Conflict);
        }
        fresh_owner(&tx, owner).await?;
        tx.commit().await?;
        return Ok(false);
    }
    if state != "reserved" {
        return Err(Error::Conflict);
    }
    let maximum: i64 = row.get(0);
    let scopes = store::bound_scopes(&tx, account, reservation).await?;
    for budget in scopes {
        if tx
            .execute(
                "UPDATE exposure_scope_budgets SET outstanding_units=outstanding_units-$5
             WHERE account_id=$1 AND scope_kind=$2 AND scope_id=$3 AND version=$4
             AND outstanding_units>=$5",
                &[
                    &account,
                    &budget.kind,
                    &budget.id,
                    &budget.version,
                    &maximum,
                ],
            )
            .await?
            != 1
        {
            return Err(Error::Conflict);
        }
    }
    if tx
        .execute(
            "UPDATE exposure_deployment_budgets SET outstanding_units=outstanding_units-$2
         WHERE id=$1 AND outstanding_units>=$2",
            &[&deployment_id, &maximum],
        )
        .await?
        != 1
    {
        return Err(Error::Conflict);
    }
    tx.execute(
        "UPDATE exposure_reservations SET state='released',actual_units=0,result_digest=$3
         WHERE account_id=$1 AND id=$2",
        &[&account, &reservation, &&digest[..]],
    )
    .await?;
    // Owner wall-clock expiry can advance during any counter or trigger wait.
    // Recheck after the final write so refusal rolls back every budget credit.
    fresh_owner(&tx, owner).await?;
    tx.commit().await?;
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cancellation_receipt_is_stable_and_bound_to_both_identities() {
        let account = Uuid::from_u128(1);
        let reservation = Uuid::from_u128(2);
        let receipt = cancellation_digest(account, reservation);
        assert_eq!(receipt, cancellation_digest(account, reservation));
        assert_ne!(receipt, cancellation_digest(reservation, account));
        assert_ne!(receipt, cancellation_digest(account, Uuid::from_u128(3)));
    }
}

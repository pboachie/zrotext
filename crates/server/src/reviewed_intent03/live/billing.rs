// SPDX-License-Identifier: AGPL-3.0-only
//! Narrow namespace bridge for unchanged legacy billing policy. Public is the
//! already validated installation; temporary relations must never precede it.
use super::*;
use zrotext_delivery_store::AcceptOutcome;

pub(super) struct Account03<'held, 'db> {
    tx: &'held Transaction<'db>,
    inner: sealed::AccountAdmission<'held, 'db>,
}
async fn enter(tx: &Transaction<'_>) -> Result<()> {
    ready(tx).await?;
    // Closed stock grants must not allow this runtime to manufacture public
    // relation/function shadows. TEMP is separate and remains explicitly last.
    if tx
        .query_one(
            "SELECT pg_catalog.has_schema_privilege(current_user,'public','CREATE')",
            &[],
        )
        .await?
        .try_get::<_, bool>(0)?
    {
        return Err(Error::Unavailable);
    }
    tx.batch_execute("SET LOCAL search_path TO pg_catalog,public,pg_temp")
        .await?;
    Ok(())
}
async fn restore<T>(
    tx: &Transaction<'_>,
    outcome: std::result::Result<T, StoreError>,
) -> Result<T> {
    let restored = tx
        .batch_execute("SET LOCAL search_path TO pg_catalog")
        .await;
    match outcome {
        Ok(value) => {
            restored?;
            Ok(value)
        }
        // Preserve the original policy/SQL refusal. An SQL error may already
        // have aborted this transaction; every caller returns/rolls it back,
        // never resumes work, retries or treats path restoration as authority.
        Err(error) => Err(store_error(error)),
    }
}
pub(super) async fn lock<'held, 'db>(
    tx: &'held Transaction<'db>,
    account: Uuid,
) -> Result<Account03<'held, 'db>> {
    enter(tx).await?;
    let inner = restore(tx, sealed::lock_account(tx, account, true).await).await?;
    Ok(Account03 { tx, inner })
}
impl Account03<'_, '_> {
    pub(super) async fn enqueue(&self, input: &Profile03QueueInput<'_>) -> Result<AcceptOutcome> {
        enter(self.tx).await?;
        restore(self.tx, self.inner.enqueue_profile03(input).await).await
    }
}

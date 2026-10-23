// SPDX-License-Identifier: AGPL-3.0-only
//! Candidate configuration is separate from the actual native/HMAC proof.
use crate::{StoreError, hosted_runtime_identity};
use tokio_postgres::GenericClient;
use uuid::Uuid;

/// Namespace/revision selected by a connection initializer. This is public
/// configuration, not a verified backend, transaction or content capability.
/// The HMAC key stays outside this crate. Every transaction independently
/// enters its actual native backend through the protected database operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HostedBackendCandidate {
    namespace: Uuid,
    revision: i64,
}
impl HostedBackendCandidate {
    pub fn new(namespace: Uuid, revision: i64) -> Result<Self, StoreError> {
        if namespace.is_nil() || revision <= 0 {
            return Err(StoreError::InvalidInput);
        }
        Ok(Self {
            namespace,
            revision,
        })
    }
}

/// Call immediately after BEGIN as the ordinary invoker, before account,
/// customer, root or device locks. The returned expiry is the immutable old
/// backend proof's bound, not a renewal or owner/message permission.
pub async fn enter_hosted_transaction<C: GenericClient + Sync>(
    db: &C,
    candidate: Option<&HostedBackendCandidate>,
) -> Result<Option<i64>, StoreError> {
    let ready = hosted_runtime_identity::optional(db)
        .await
        .map_err(|_| StoreError::RuntimeIdentityUnavailable)?;
    if !ready {
        // Only a genuinely absent legacy hosted installation may take this
        // manual path. An existing old/partial hosted graph needs the new
        // closed capability, even if a caller omitted its candidate.
        let legacy: bool = db.query_one(
            "SELECT pg_catalog.to_regclass('public.hosted_billing_namespaces') IS NOT NULL OR pg_catalog.to_regclass('public.hosted_runtime_sessions') IS NOT NULL OR pg_catalog.to_regprocedure('public.hosted_runtime_marker()') IS NOT NULL OR pg_catalog.to_regclass('hosted_billing_namespaces') IS NOT NULL OR pg_catalog.to_regclass('hosted_runtime_sessions') IS NOT NULL OR pg_catalog.to_regprocedure('hosted_runtime_marker()') IS NOT NULL",
            &[],
        ).await?.get(0);
        return if candidate.is_none() && !legacy {
            Ok(None)
        } else {
            Err(StoreError::RuntimeIdentityUnavailable)
        };
    }
    hosted_runtime_identity::require(db)
        .await
        .map_err(|_| StoreError::RuntimeIdentityUnavailable)?;
    // The actual stable configuration tuple and mandatory namespace writer
    // share this fence. Empty namespace selection is not a predicate lock:
    // this real held scope must precede that read, even for manual accounts.
    db.query_one("SELECT public.hosted_runtime_scope()", &[])
        .await?;
    // This read selects candidate configuration only and takes no content
    // lock. Enter rechecks its actual native identity, current namespace and
    // exact previously HMAC-bound session; these rows cannot authenticate it.
    let rows = db
        .query(
            "SELECT namespace_id,policy_revision FROM public.hosted_billing_namespaces",
            &[],
        )
        .await?;
    let expiry = match (rows.as_slice(), candidate) {
        ([], None) => None,
        ([row], Some(candidate))
            if row.try_get::<_, Uuid>("namespace_id")? == candidate.namespace
                && row.try_get::<_, i64>("policy_revision")? == candidate.revision =>
        {
            let expires: i64 = db
                .query_one(
                    "SELECT public.hosted_runtime_enter($1,$2)",
                    &[&candidate.namespace, &candidate.revision],
                )
                .await?
                .try_get(0)?;
            if expires <= 0 {
                return Err(StoreError::RuntimeIdentityUnavailable);
            }
            Some(expires)
        }
        _ => return Err(StoreError::RuntimeIdentityUnavailable),
    };
    // Only after the closed public capability plus actual hosted entry (or
    // genuinely namespace-empty manual selection) succeeded. Existing Store
    // and hosted-worker SQL uses unqualified names; temporary objects come
    // last. This setting authenticates no backend, owner or content scope.
    db.batch_execute("SET LOCAL search_path TO pg_catalog,public,pg_temp")
        .await?;
    Ok(expiry)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn candidate_configuration_never_accepts_nil_or_nonpositive_revision() {
        assert!(HostedBackendCandidate::new(Uuid::nil(), 1).is_err());
        for revision in [i64::MIN, -1, 0] {
            assert!(HostedBackendCandidate::new(Uuid::from_u128(1), revision).is_err());
        }
        assert!(HostedBackendCandidate::new(Uuid::from_u128(1), i64::MAX).is_ok());
    }
}

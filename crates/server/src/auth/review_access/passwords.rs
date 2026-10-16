// SPDX-License-Identifier: AGPL-3.0-only
//! Owned real verifier evidence. No SQL/session/MFA authority follows from it.
use super::{
    AccessError, Result,
    frames::{CookieKey, Operation, Preparation, Scope, valid_alias},
};
use argon2::PasswordHash;
use std::collections::BTreeMap;
use tokio_postgres::GenericClient;
use uuid::Uuid;
use zeroize::Zeroizing;

// Fixed syntactically valid synthetic PHC, not a configured broker verifier.
// Passing Some avoids the ordinary lazy dummy's cold extra Argon2 hash. Every
// review branch executes exactly one bounded verification under the same worker.
const DUMMY_PHC: &str = "$argon2id$v=19$m=65536,t=3,p=1$EREREREREREREREREREREQ$IiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiI";

pub struct Aliases(BTreeMap<String, Uuid>);
impl Aliases {
    pub fn new(entries: impl IntoIterator<Item = (String, Uuid)>) -> Result<Self> {
        let mut entries_out = BTreeMap::new();
        for (alias, principal) in entries {
            if !valid_alias(&alias)
                || principal.is_nil()
                || entries_out.len() >= 8
                || entries_out.insert(alias, principal).is_some()
            {
                return Err(AccessError::Rejected);
            }
        }
        if entries_out.is_empty() {
            return Err(AccessError::Rejected);
        }
        Ok(Self(entries_out))
    }
    pub(super) fn principal(&self, alias: &str) -> Option<Uuid> {
        self.0.get(alias).copied()
    }
}

/// Bound *before* entering the shared 64MiB worker. Malformed/excessive stored
/// PHCs never become an Argon2-controlled allocation or a cheap alias oracle.
pub fn bounded_phc(input: &str) -> bool {
    if input.len() > 1024 {
        return false;
    }
    let Ok(hash) = PasswordHash::new(input) else {
        return false;
    };
    hash.algorithm.as_str() == "argon2id"
        && hash.version == Some(19)
        && hash.params.iter().count() == 3
        && hash.params.get_decimal("m") == Some(65536)
        && hash.params.get_decimal("t") == Some(3)
        && hash.params.get_decimal("p") == Some(1)
        && hash.salt.as_ref().map(|s| s.len()) == Some(16)
        && hash.hash.as_ref().map(|h| h.len()) == Some(32)
}

// No public constructor/Debug/Serialize. Only an actual configured-alias row
// capture can create this owned identity; unknown aliases have None, never fake IDs.
pub(super) struct BrokerSnapshot {
    pub(super) scope: Scope,
    pub(super) principal: Uuid,
    pub(super) credential: Uuid,
    pub(super) revision: i64,
    pub(super) verifier: Zeroizing<String>,
    pub(super) observed_ms: i64,
}

pub(super) async fn capture(
    client: &impl GenericClient,
    scope: &Scope,
    aliases: &Aliases,
    alias: &str,
) -> Result<Option<BrokerSnapshot>> {
    let Some(principal) = aliases.principal(alias) else {
        return Ok(None);
    };
    capture_principal(client, scope, principal).await
}
pub(super) async fn capture_principal(
    client: &impl GenericClient,
    scope: &Scope,
    principal: Uuid,
) -> Result<Option<BrokerSnapshot>> {
    scope.validate()?;
    let row=client.query_opt("SELECT b.credential_id,b.credential_revision,b.password_verifier, \
        floor(extract(epoch FROM pg_catalog.clock_timestamp())*1000)::bigint FROM public.review_brokers b \
        JOIN public.review_realm_installation m ON m.realm_id=b.realm_id \
        WHERE b.id=$1 AND b.realm_id=$2 AND b.disabled_ms IS NULL AND m.origin=$3 \
        AND pg_catalog.sha256(pg_catalog.uuid_send(m.database_id))=$4 AND m.auth_key_digest=$5 \
        AND m.active_config_digest=$6 AND m.active_config_revision=$7",
        &[&principal,&scope.realm,&scope.origin,&&scope.database[..],&&scope.key[..],&&scope.config[..],&(scope.config_revision as i64)]).await?;
    Ok(row.map(|r| BrokerSnapshot {
        scope: scope.clone(),
        principal,
        credential: r.get(0),
        revision: r.get(1),
        verifier: Zeroizing::new(r.get(2)),
        observed_ms: r.get(3),
    }))
}

pub(super) struct PasswordEvidence {
    pub(super) snapshot: BrokerSnapshot,
    pub(super) request_digest: [u8; 32],
    pub(super) operation: Operation,
}

/// Database clients are deliberately absent: hashing cannot retain a writer,
/// pooled connection or transaction. Admission/guard claim must commit first.
pub(super) async fn check(
    snapshot: Option<BrokerSnapshot>,
    key: &CookieKey,
    scope: &Scope,
    preparation: &Preparation,
    password: &str,
) -> Result<PasswordEvidence> {
    if !matches!(
        preparation.operation,
        Operation::InitialBootstrap | Operation::BrokerForResume | Operation::RootComplete
    ) || password.is_empty()
        || password.len() > 1024
    {
        return Err(AccessError::Rejected);
    }
    let request_digest = preparation.commitment(key, scope);
    let operation = preparation.operation;
    let usable = snapshot.as_ref().is_some_and(|s| {
        s.scope == *scope
            && s.observed_ms > 0
            && s.observed_ms as u64 >= preparation.prepared
            && bounded_phc(&s.verifier)
    });
    let verifier = Some(
        snapshot
            .as_ref()
            .filter(|_| usable)
            .map_or_else(|| DUMMY_PHC.to_owned(), |s| s.verifier.to_string()),
    );
    // Even a password matching the dummy can never manufacture a configured
    // principal. The dummy does not initialize or generate another PHC here.
    let verified = super::super::password_work::verify(password, verifier)
        .await
        .is_ok();
    if !usable || !verified {
        return Err(AccessError::Rejected);
    }
    let snapshot = snapshot.ok_or(AccessError::Rejected)?;
    Ok(PasswordEvidence {
        snapshot,
        request_digest,
        operation,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn review_phc_policy_bounds_actual_work_before_verification() {
        assert!(bounded_phc(DUMMY_PHC));
        let actual = super::super::super::password_work::hash("synthetic-review-password")
            .await
            .unwrap();
        assert!(bounded_phc(&actual));
        for bad in [
            actual.replace("m=65536", "m=131072"),
            actual.replace("t=3", "t=4"),
            actual.replace("p=1", "p=2"),
            actual.replace("argon2id", "argon2i"),
            actual.replace("v=19", "v=16"),
            "!".to_owned(),
        ] {
            assert!(!bounded_phc(&bad));
        }
    }
    #[test]
    fn review_aliases_are_closed_and_do_not_normalize_untrusted_inputs() {
        let principal = Uuid::new_v4();
        for alias in [
            "",
            "Pilot",
            " pilot",
            "pilot ",
            "-pilot",
            "é",
            &"x".repeat(33),
        ] {
            assert!(Aliases::new([(alias.to_owned(), principal)]).is_err());
        }
        assert!(
            Aliases::new([
                ("pilot".to_owned(), principal),
                ("pilot".to_owned(), principal)
            ])
            .is_err()
        );
    }
}

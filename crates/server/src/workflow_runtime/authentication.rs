// SPDX-License-Identifier: AGPL-3.0-only
use super::{Operation, Permissions};
use crate::auth::{AuthError, TokenHasher};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use tokio_postgres::Client;
use uuid::Uuid;

/// Constructed only by workflow-credential authentication. It is a request
/// identity, not a reusable effect permit; stores must recheck under locks.
#[derive(Clone)]
pub struct IntegrationPrincipal {
    account: Uuid,
    grant: Uuid,
    credential_hash: [u8; 32],
    permissions: Permissions,
}
impl IntegrationPrincipal {
    pub fn account_id(&self) -> Uuid {
        self.account
    }
    pub fn grant_id(&self) -> Uuid {
        self.grant
    }
    pub(crate) fn credential_hash(&self) -> &[u8; 32] {
        &self.credential_hash
    }
    pub fn require(&self, operation: Operation) -> Result<(), AuthError> {
        if self.permissions.allows(operation) {
            Ok(())
        } else {
            Err(AuthError::Forbidden)
        }
    }
}

pub(super) fn credential_shape(token: &str) -> bool {
    let Some(encoded) = token.strip_prefix("ztw_") else {
        return false;
    };
    encoded.len() == 43
        && URL_SAFE_NO_PAD
            .decode(encoded)
            .is_ok_and(|bytes| bytes.len() == 32 && URL_SAFE_NO_PAD.encode(bytes) == encoded)
}

/// Workflow credentials have their own domain and prefix. Owner cookies,
/// ordinary API keys, agent keys and opaque caller authorization flags are
/// never alternatives. Unknown credentials produce no audit or queue writes.
pub async fn authenticate(
    client: &Client,
    hasher: &TokenHasher,
    token: &str,
) -> Result<IntegrationPrincipal, AuthError> {
    if !credential_shape(token) {
        return Err(AuthError::Unauthorized);
    }
    let credential_hash = hasher.workflow_credential_hash(token);
    let row = client.query_opt(
        "SELECT g.account_id,g.grant_id,g.permissions FROM workflow_integration_grants g \
         JOIN accounts a ON a.id=g.account_id \
         JOIN memberships m ON (m.account_id,m.user_id)=(g.account_id,g.created_by_user) \
         JOIN users u ON u.id=m.user_id \
         JOIN sessions s ON (s.account_id,s.user_id,s.id)=(g.account_id,g.created_by_user,g.created_session) \
         JOIN workflow_contexts c ON (c.account_id,c.id,c.revision)=(g.account_id,g.context_id,g.context_revision) \
         JOIN connector_registrations r ON (r.account_id,r.connector_id)=(g.account_id,g.connector_id) \
         JOIN connector_keys k ON (k.account_id,k.connector_id,k.key_id)=(g.account_id,g.connector_id,g.reader_key_id) \
         WHERE g.credential_hash=$1 AND g.revoked_ms IS NULL AND g.expires_ms>floor(extract(epoch FROM clock_timestamp())*1000)::bigint \
         AND a.disabled_at IS NULL AND m.role='owner' AND m.revoked_at IS NULL \
         AND u.email_verified_at IS NOT NULL AND u.mfa_enabled \
         AND s.revoked_at IS NULL AND s.expires_at>clock_timestamp() \
         AND c.purged_at IS NULL AND c.expires_at_ms>floor(extract(epoch FROM clock_timestamp())*1000)::bigint \
         AND r.state='active' AND r.key_id=g.reader_key_id AND r.manifest_generation=g.trust_generation \
         AND r.manifest_version=g.manifest_version AND r.manifest_digest=g.manifest_digest \
         AND r.expires_ms>floor(extract(epoch FROM clock_timestamp())*1000)::bigint \
         AND k.retired_ms IS NULL \
         AND k.valid_from_ms<=floor(extract(epoch FROM clock_timestamp())*1000)::bigint \
         AND k.valid_until_ms>floor(extract(epoch FROM clock_timestamp())*1000)::bigint",
        &[&credential_hash.as_slice()],
    ).await?.ok_or(AuthError::Unauthorized)?;
    let permissions = Permissions::from_stored(row.get(2)).map_err(|_| AuthError::Unauthorized)?;
    Ok(IntegrationPrincipal {
        account: row.get(0),
        grant: row.get(1),
        credential_hash,
        permissions,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    #[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; disposable workflow schema"]
    async fn unknown_workflow_credentials_create_no_access_or_action_records() {
        let (fixture, _, _) = crate::http_owner_conversations::activation::tests::pending().await;

        let hasher = TokenHasher::new(crate::test_keys::key(89)).unwrap();
        let token = format!("ztw_{}", URL_SAFE_NO_PAD.encode([8; 32]));
        assert!(matches!(
            authenticate(&fixture.db, &hasher, &token).await,
            Err(AuthError::Unauthorized)
        ));
        let counts = fixture
            .db
            .query_one(
                "SELECT (SELECT count(*) FROM workflow_integration_access), \
             (SELECT count(*) FROM workflow_integration_grants), \
             (SELECT count(*) FROM workflow_connector_context_envelopes)",
                &[],
            )
            .await
            .unwrap();
        for index in 0..3 {
            assert_eq!(counts.get::<_, i64>(index), 0);
        }
        fixture.cleanup().await;
    }

    #[test]
    fn workflow_credentials_cannot_downgrade_to_another_authentication_realm() {
        let encoded = URL_SAFE_NO_PAD.encode([8; 32]);
        assert!(credential_shape(&format!("ztw_{encoded}")));
        for prefix in ["ztk_", "zts_", "ztd_", ""] {
            assert!(!credential_shape(&format!("{prefix}{encoded}")));
        }
        for token in [
            format!("ztw_{encoded}="),
            format!("ztw_{encoded} "),
            format!("ztw_{}", URL_SAFE_NO_PAD.encode([8; 31])),
            "ztw_%%%".into(),
        ] {
            assert!(!credential_shape(&token));
        }
        let hasher = TokenHasher::new(crate::test_keys::key(89)).unwrap();
        let principal = IntegrationPrincipal {
            account: Uuid::new_v4(),
            grant: Uuid::new_v4(),
            credential_hash: hasher.workflow_credential_hash(&format!("ztw_{encoded}")),
            permissions: Permissions::new(&[Operation::Propose]).unwrap(),
        };
        assert!(principal.require(Operation::Propose).is_ok());
        assert!(principal.require(Operation::Send).is_err());
        assert!(principal.require(Operation::ContextContent).is_err());
        assert_eq!(principal.credential_hash().len(), 32);
    }
}

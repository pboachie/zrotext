// SPDX-License-Identifier: AGPL-3.0-only
use super::{
    IntegrationPrincipal,
    contracts::{Method, MethodInfo},
};
use crate::auth::AuthError;
use serde::Serialize;
use tokio_postgres::Client;
use uuid::Uuid;

#[derive(Serialize)]
pub struct ReadyMethod {
    #[serde(flatten)]
    pub info: MethodInfo,
    /// Permission bits are discovery hints, never a reusable effect permit.
    pub permission_granted: bool,
}
#[derive(Serialize)]
pub struct SelectedScope {
    pub context_id: Uuid,
    pub device_id: Uuid,
    pub line_id: Uuid,
}
#[derive(Serialize)]
pub struct Readiness {
    pub available: bool,
    pub methods: Vec<ReadyMethod>,
    pub scope: SelectedScope,
    pub send_semantics: &'static str,
}

pub async fn read(
    client: &mut Client,
    principal: &IntegrationPrincipal,
) -> Result<Readiness, AuthError> {
    let tx = client.transaction().await?;
    tx.batch_execute("SET LOCAL lock_timeout='3s'; SET LOCAL statement_timeout='5s'")
        .await?;
    let context: Uuid = tx.query_opt("SELECT context_id FROM workflow_integration_grants WHERE account_id=$1 AND grant_id=$2 AND credential_hash=$3", &[&principal.account_id(),&principal.grant_id(),&principal.credential_hash().as_slice()]).await?.ok_or(AuthError::Forbidden)?.get(0);
    let operation = Method::ALL
        .into_iter()
        .map(Method::operation)
        .find(|operation| principal.require(*operation).is_ok())
        .ok_or(AuthError::Forbidden)?;
    let mut proof = super::scope::lock_scope(&tx, principal, context, operation).await?;
    let scope = SelectedScope {
        context_id: proof.header.context,
        device_id: proof.header.device,
        line_id: proof.header.line,
    };
    proof.recheck().await?;
    drop(proof);
    tx.commit().await?;
    Ok(Readiness {
        available: true,
        methods: Method::ALL
            .into_iter()
            .map(|method| {
                let mut info = method.info();
                info.transport_mounted = true;
                ReadyMethod {
                    permission_granted: principal.require(method.operation()).is_ok(),
                    info,
                }
            })
            .collect(),
        scope,
        send_semantics: "owner_bound_prepared_only",
    })
}

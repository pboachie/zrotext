// SPDX-License-Identifier: AGPL-3.0-only
//! Authenticated inspection of the original pending line proposal; never issue a replacement key.
use super::*;
use base64::{Engine, engine::general_purpose::STANDARD};

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

pub async fn context(
    client: &mut Client,
    p: &SessionPrincipal,
    id: Uuid,
    origin: &str,
) -> Result<Option<serde_json::Value>> {
    if id.is_nil() {
        return Err(reject());
    }
    let tx = owner::begin(client).await?;
    let account = p.tenant.account_id();
    let (pin, fingerprint) = root(&tx, account).await?;
    owner::owner_locks(&tx, p, false).await?;
    first(&tx, account).await?;
    let row = tx.query_opt(
        "SELECT transcript,device_id,line_id,generation,issued_ms,expires_ms FROM sealed_line_key_challenges \
         WHERE account_id=$1 AND challenge_id=$2 AND user_id=$3 AND session_id=$4 \
           AND completed_ms IS NULL FOR UPDATE",
        &[&account,&id,&p.user_id,&p.session_id],
    ).await?;
    let Some(row) = row else {
        owner::live(&tx, p).await?;
        tx.commit().await?;
        return Ok(None);
    };
    let bytes: Vec<u8> = row.get(0);
    let statement = codec::decode(&bytes).map_err(|_| reject())?;
    let scope = statement.scope();
    if !identity(p, scope)
        || scope.challenge != *id.as_bytes()
        || scope.origin != origin
        || row.get::<_, Uuid>(1).as_bytes() != &scope.device
        || row.get::<_, Uuid>(2).as_bytes() != &scope.line
        || row.get::<_, i64>(3) != scope.next_generation as i64
        || row.get::<_, i64>(4) != scope.issued_ms as i64
        || row.get::<_, i64>(5) != scope.expires_ms as i64
        || statement.root_pin() != &pin
        || statement.root_fingerprint() != &fingerprint
        || next(&tx, account, Uuid::from_bytes(scope.line)).await? != scope.next_generation as i64
    {
        return Err(reject());
    }
    replacement_allowed(
        &tx,
        p,
        Uuid::from_bytes(scope.device),
        Uuid::from_bytes(scope.line),
    )
    .await?;
    distinct(&tx, account, statement.approval_point(), &pin).await?;
    fresh(&tx, p, &statement, None).await?;
    let utc = now(&tx, scope.issued_ms).await?;
    if utc >= scope.expires_ms {
        return Err(reject());
    }
    let expected = serde_json::json!({
        "scope": {
            "account":hex(&scope.account),"user":hex(&scope.user),"owner_session":hex(&scope.owner_session),
            "device":hex(&scope.device),"line":hex(&scope.line),"next_generation":scope.next_generation,
            "challenge":hex(&scope.challenge),"nonce":hex(&scope.nonce),"issued_ms":scope.issued_ms,
            "expires_ms":scope.expires_ms,"approval_fingerprint":hex(&scope.approval_fingerprint),
            "paired_signing_fingerprint":hex(&scope.paired_signing_fingerprint),
            "connection_epoch":scope.connection_epoch,"deployment_epoch":scope.deployment_epoch,
            "site_id":scope.site_id,"instance_id":scope.instance_id,"origin":scope.origin
        },"root_pin":hex(&pin)
    });
    let value = serde_json::json!({
        "v":1,"kind":1,"account_id":account,"user_id":p.user_id,"session_id":p.session_id,
        "origin":origin,"root_fingerprint_hex":hex(&fingerprint),"proposal_sha256_hex":hex(&hash(&bytes)),
        "proposal_b64":STANDARD.encode(&bytes),"expected_context":expected,
        "server_now_ms":utc.to_string(),"expires_ms":scope.expires_ms.to_string()
    });
    // Recheck all live deadlines after the last database wait and before publication.
    fresh(&tx, p, &statement, None).await?;
    tx.commit().await?;
    Ok(Some(value))
}

#[cfg(test)]
mod tests;

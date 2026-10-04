// SPDX-License-Identifier: AGPL-3.0-only
use super::*;

// Failure diagnostics contain only fixed labels and deadline differences.
pub(super) async fn deadline_diagnostic(
    f: &OriginalCase,
    original: Uuid,
    input: &IntegrationPrincipal,
    output: Option<&IntegrationPrincipal>,
    policy: &Policy,
    phase: &'static str,
    started: std::time::Instant,
) -> String {
    let output_grant = output.map(IntegrationPrincipal::grant_id);
    let row = f.case.f.db.query_one(
        "WITH moment AS MATERIALIZED (SELECT floor(extract(epoch FROM clock_timestamp())*1000)::bigint AS now_ms) SELECT now_ms,(SELECT expires_ms FROM original_reply_grants WHERE account_id=$1 AND grant_id=$2),(SELECT expires_ms FROM workflow_integration_grants WHERE account_id=$1 AND grant_id=$3),(SELECT expires_ms FROM workflow_integration_grants WHERE account_id=$1 AND grant_id=$4),(SELECT expires_at_ms FROM workflow_contexts WHERE account_id=$1 AND id=$5),(SELECT floor(extract(epoch FROM expires_at)*1000)::bigint FROM sessions WHERE account_id=$1 AND id=$6) FROM moment",
        &[&f.case.f.account,&original,&input.grant_id(),&output_grant,&policy.context_id,&f.case.owner.session_id],
    ).await;
    let elapsed = started.elapsed().as_millis();
    let Ok(row) = row else {
        return format!("phase={phase} elapsed_ms={elapsed} deadline_snapshot=unavailable");
    };
    let now: i64 = row.get(0);
    let mut result = format!("phase={phase} elapsed_ms={elapsed}");
    for (index, label) in [
        (1, "original"),
        (2, "input_grant"),
        (3, "output_grant"),
        (4, "input_context"),
        (5, "owner_session"),
    ] {
        let deadline: Option<i64> = row.get(index);
        let remaining = deadline.map(|value| value.saturating_sub(now)).unwrap_or(0);
        result.push_str(&format!(
            " {label}_present={} {label}_live={} {label}_remaining_ms={remaining}",
            deadline.is_some(),
            deadline.is_some_and(|value| value > now)
        ));
    }
    result.push_str(&format!(
        " policy_live={} policy_remaining_ms={}",
        policy.expires_ms > now,
        policy.expires_ms.saturating_sub(now)
    ));
    result
}
pub(super) fn refusal_class<T>(result: &Result<T, AuthError>) -> &'static str {
    match result {
        Ok(_) => "ok",
        Err(AuthError::Forbidden) => "forbidden",
        Err(AuthError::Database(_)) => "database",
        Err(_) => "other_refusal",
    }
}

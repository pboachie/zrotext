// SPDX-License-Identifier: AGPL-3.0-only
//! Dedicated review-workspace JNI adapter. No ordinary authority conversion.
use super::*;
use crate::review_root_custody::{ReviewAuthority, ReviewHandle, ReviewSigningService};
use serde::Deserialize;

static REVIEW_SERVICE: OnceLock<ReviewSigningService> = OnceLock::new();
fn review_service() -> &'static ReviewSigningService {
    REVIEW_SERVICE.get_or_init(ReviewSigningService::default)
}
pub(super) fn close_all() {
    review_service().close_all();
}

/// Internal bounded JNI snapshot constructed by the authenticated Kotlin context.
/// Parsing it is NOT authentication. Cookie/password/locator values are forbidden.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ContextInput {
    version: u8,
    realm: [u8; 16],
    database_commitment: [u8; 32],
    config_commitment: [u8; 32],
    config_revision: u64,
    origin: String,
    account_id: [u8; 16],
    owner_user_id: [u8; 16],
    review_owner_session_id: [u8; 16],
    broker_principal_id: [u8; 16],
    credential_id: [u8; 16],
    credential_revision: u64,
    broker_session_id: [u8; 16],
    authentication_event_id: [u8; 16],
    issued_ms: u64,
    absolute_expiry_ms: u64,
    idle_deadline_ms: u64,
    context_epoch: u64,
}
fn context(raw: &[u8]) -> Result<ReviewAuthority, ()> {
    let v: ContextInput = serde_json::from_slice(raw).map_err(|_| ())?;
    if v.version != 1 || v.origin.len() > 255 {
        return Err(());
    }
    Ok(ReviewAuthority {
        realm: v.realm,
        database_commitment: v.database_commitment,
        config_commitment: v.config_commitment,
        config_revision: v.config_revision,
        origin: v.origin,
        account_id: v.account_id,
        owner_user_id: v.owner_user_id,
        review_owner_session_id: v.review_owner_session_id,
        broker_principal_id: v.broker_principal_id,
        credential_id: v.credential_id,
        credential_revision: v.credential_revision,
        broker_session_id: v.broker_session_id,
        authentication_event_id: v.authentication_event_id,
        issued_ms: v.issued_ms,
        absolute_expiry_ms: v.absolute_expiry_ms,
        idle_deadline_ms: v.idle_deadline_ms,
        context_epoch: v.context_epoch,
    })
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_org_zrotext_gateway_AndroidReviewRootCustodyNativeBridge_nativeOpen(
    mut env: JNIEnv<'_>,
    _object: JObject<'_>,
    unsigned: JByteArray<'_>,
    backup: JByteArray<'_>,
    card: JByteArray<'_>,
    expected_account: JByteArray<'_>,
    site: JString<'_>,
    fingerprint: JByteArray<'_>,
    bundle: JByteArray<'_>,
    current_context: JByteArray<'_>,
    server_ms: jlong,
    anchored_elapsed: jlong,
    uncertainty: jlong,
    now_elapsed: jlong,
) -> jlong {
    boundary(&mut env, &[], 0, |env| {
        let expected = identity(env, &expected_account, &site, &fingerprint)?;
        let current = context(&bytes(env, &current_context, 4096)?)?;
        let handle = review_service()
            .open_custody(
                &bytes(env, &unsigned, 663)?,
                &bytes(env, &backup, 748)?,
                &bytes(env, &card, 645)?,
                &expected,
                &fixed(env, &bundle)?,
                current,
                TimeAnchor {
                    authenticated_server_ms: positive(server_ms)?,
                    authenticated_elapsed_ms: positive(anchored_elapsed)?,
                    uncertainty_ms: positive(uncertainty)?,
                },
                fresh_elapsed(env, now_elapsed)?,
            )
            .map_err(|_| ())?;
        Ok(handle.as_u64() as jlong)
    })
}
#[unsafe(no_mangle)]
pub extern "system" fn Java_org_zrotext_gateway_AndroidReviewRootCustodyNativeBridge_nativeReview(
    mut env: JNIEnv<'_>,
    _object: JObject<'_>,
    handle: jlong,
) -> jbyteArray {
    let parsed = positive(handle)
        .ok()
        .and_then(|v| ReviewHandle::from_u64(v).ok());
    let result = boundary(&mut env, &[], std::ptr::null_mut(), |env| {
        let h = parsed.ok_or(())?;
        let value = review_service().review(h).map_err(|_| ())?;
        Ok(env
            .byte_array_from_slice(&value)
            .map_err(|_| ())?
            .into_raw())
    });
    if result.is_null()
        && let Some(h) = parsed
    {
        review_service().close(h);
    }
    result
}
#[unsafe(no_mangle)]
pub extern "system" fn Java_org_zrotext_gateway_AndroidReviewRootCustodyNativeBridge_nativeSign(
    mut env: JNIEnv<'_>,
    _object: JObject<'_>,
    handle: jlong,
    token: JByteArray<'_>,
    current_context: JByteArray<'_>,
    now_elapsed: jlong,
) -> jobjectArray {
    let parsed = positive(handle)
        .ok()
        .and_then(|v| ReviewHandle::from_u64(v).ok());
    let output = boundary(&mut env, &[&token], std::ptr::null_mut(), |env| {
        let h = parsed.ok_or(())?;
        let current = context(&bytes(env, &current_context, 4096)?)?;
        fresh_elapsed(env, now_elapsed)?;
        let secret = Zeroizing::new(bytes(env, &token, 79)?);
        review_service()
            .sign_with_public_output(h, &secret, &current, env, elapsed, |env, s| {
                arrays(env, &[&s.enrollment, &s.custody]).map_err(|_| SigningError::Unavailable)
            })
            .map_err(|_| ())
    });
    if let Some(h) = parsed {
        review_service().close(h);
    }
    output
}
#[unsafe(no_mangle)]
pub extern "system" fn Java_org_zrotext_gateway_AndroidReviewRootCustodyNativeBridge_nativeClose(
    mut env: JNIEnv<'_>,
    _object: JObject<'_>,
    handle: jlong,
) {
    boundary(&mut env, &[], (), |_| {
        review_service().close(ReviewHandle::from_u64(positive(handle)?).map_err(|_| ())?);
        Ok(())
    });
}
#[unsafe(no_mangle)]
pub extern "system" fn Java_org_zrotext_gateway_AndroidReviewRootCustodyNativeBridge_nativeCloseAll(
    mut env: JNIEnv<'_>,
    _object: JObject<'_>,
) {
    boundary(&mut env, &[], (), |_| {
        close_all();
        Ok(())
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn closed_snapshot_refuses_ordinary_fields_duplicates_and_unknown_secrets() {
        assert!(context(br#"{"account_id":"ordinary","role":"owner"}"#).is_err());
        assert!(context(br#"{"version":1,"version":1}"#).is_err());
        assert!(context(br#"{"password":"forbidden"}"#).is_err());
    }
    #[test]
    fn complete_typed_snapshot_accepts_only_closed_metadata() {
        let value = serde_json::json!({
            "version":1, "realm":vec![1u8;16], "database_commitment":vec![2u8;32],
            "config_commitment":vec![3u8;32], "config_revision":1, "origin":"https://example.test",
            "account_id":vec![4u8;16], "owner_user_id":vec![5u8;16],
            "review_owner_session_id":vec![6u8;16], "broker_principal_id":vec![7u8;16],
            "credential_id":vec![8u8;16], "credential_revision":1,
            "broker_session_id":vec![9u8;16], "authentication_event_id":vec![10u8;16],
            "issued_ms":1000,"absolute_expiry_ms":20000,"idle_deadline_ms":19000,"context_epoch":1
        });
        let encoded = serde_json::to_vec(&value).unwrap();
        assert!(context(&encoded).is_ok());
        let mut unknown = value.clone();
        unknown["locator"] = serde_json::json!("forbidden");
        assert!(context(&serde_json::to_vec(&unknown).unwrap()).is_err());
        let mut wrong = value.clone();
        wrong["version"] = serde_json::json!(2);
        assert!(context(&serde_json::to_vec(&wrong).unwrap()).is_err());
        let mut duplicate = encoded;
        duplicate.pop();
        duplicate.extend_from_slice(br#","version":1}"#);
        assert!(context(&duplicate).is_err());
    }
}

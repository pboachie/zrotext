// SPDX-License-Identifier: AGPL-3.0-only
//! Narrow JNI entry points. No root scalar, arbitrary signer or secret logging.

use crate::{
    custody,
    signing::{Authority, OperationHandle, SigningError, SigningService, TimeAnchor},
    typed::{self, OperationKind, TypedOutput, TypedService},
};
use jni::{
    JNIEnv,
    objects::{JByteArray, JObject, JString},
    sys::{jboolean, jbyteArray, jint, jlong, jobjectArray},
};
use std::{
    panic::{AssertUnwindSafe, catch_unwind},
    sync::OnceLock,
};
use zeroize::Zeroizing;
use zrotext_root_material::root_backup::ExpectedIdentity;

static SERVICE: OnceLock<SigningService> = OnceLock::new();
static TYPED_SERVICE: OnceLock<TypedService> = OnceLock::new();

fn typed_service() -> &'static TypedService {
    TYPED_SERVICE.get_or_init(TypedService::default)
}

fn service() -> &'static SigningService {
    SERVICE.get_or_init(SigningService::default)
}

fn bytes(env: &JNIEnv<'_>, input: &JByteArray<'_>, maximum: usize) -> Result<Vec<u8>, ()> {
    let length = env.get_array_length(input).map_err(|_| ())?;
    if length <= 0 || length as usize > maximum {
        return Err(());
    }
    env.convert_byte_array(input).map_err(|_| ())
}
fn bounded_bytes(env: &JNIEnv<'_>, input: &JByteArray<'_>, maximum: usize) -> Result<Vec<u8>, ()> {
    let length = env.get_array_length(input).map_err(|_| ())?;
    if length < 0 || length as usize > maximum {
        return Err(());
    }
    env.convert_byte_array(input).map_err(|_| ())
}

fn fixed<const N: usize>(env: &JNIEnv<'_>, input: &JByteArray<'_>) -> Result<[u8; N], ()> {
    bytes(env, input, N)?.try_into().map_err(|_| ())
}

fn origin(env: &mut JNIEnv<'_>, input: &JString<'_>) -> Result<String, ()> {
    let length = env
        .call_method(input, "length", "()I", &[])
        .map_err(|_| ())?
        .i()
        .map_err(|_| ())?;
    if !(1..=512).contains(&length) {
        return Err(());
    }
    let value = env.get_string(input).map_err(|_| ())?;
    let value = value.to_str().map_err(|_| ())?;
    if !zrotext_root_material::sealed_root_enrollment::canonical_origin(value) {
        return Err(());
    }
    Ok(value.to_owned())
}

fn identity(
    env: &mut JNIEnv<'_>,
    account: &JByteArray<'_>,
    site: &JString<'_>,
    fingerprint: &JByteArray<'_>,
) -> Result<ExpectedIdentity, ()> {
    Ok(ExpectedIdentity {
        account_id: fixed(env, account)?,
        origin: origin(env, site)?,
        root_fingerprint: fixed(env, fingerprint)?,
    })
}

fn authority(
    env: &JNIEnv<'_>,
    account: &JByteArray<'_>,
    user: &JByteArray<'_>,
    session: &JByteArray<'_>,
) -> Result<Authority, ()> {
    Ok(Authority {
        account_id: fixed(env, account)?,
        user_id: fixed(env, user)?,
        session_id: fixed(env, session)?,
    })
}

fn positive(input: jlong) -> Result<u64, ()> {
    u64::try_from(input).map_err(|_| ())
}

fn elapsed(env: &mut JNIEnv<'_>) -> Result<u64, SigningError> {
    let result = env
        .call_static_method("android/os/SystemClock", "elapsedRealtime", "()J", &[])
        .and_then(|value| value.j())
        .map_err(|_| SigningError::TimeRejected)?;
    u64::try_from(result).map_err(|_| SigningError::TimeRejected)
}

fn fresh_elapsed(env: &mut JNIEnv<'_>, supplied: jlong) -> Result<u64, ()> {
    let actual = elapsed(env).map_err(|_| ())?;
    let age = actual.checked_sub(positive(supplied)?).ok_or(())?;
    if age > 5_000 {
        return Err(());
    }
    Ok(actual)
}

fn arrays(env: &mut JNIEnv<'_>, values: &[&[u8]]) -> Result<jobjectArray, ()> {
    let class = env.find_class("[B").map_err(|_| ())?;
    let result = env
        .new_object_array(values.len() as i32, class, JObject::null())
        .map_err(|_| ())?;
    for (index, value) in values.iter().enumerate() {
        let value = env.byte_array_from_slice(value).map_err(|_| ())?;
        env.set_object_array_element(&result, index as i32, &value)
            .map_err(|_| ())?;
        env.delete_local_ref(value).map_err(|_| ())?;
    }
    Ok(result.into_raw())
}

fn created_arrays(env: &mut JNIEnv<'_>, kit: &custody::CreatedKit) -> Result<jobjectArray, ()> {
    let class = env.find_class("[B").map_err(|_| ())?;
    let result = env
        .new_object_array(5, class, JObject::null())
        .map_err(|_| ())?;
    // Finish every fallible public allocation first. The secret is inserted
    // last, and a failed insertion clears its actual Java array immediately.
    for (index, value) in [
        (0, kit.encrypted_backup.as_slice()),
        (1, kit.public_card.as_slice()),
        (3, kit.identity.root_fingerprint.as_slice()),
        (4, kit.root_pin.as_slice()),
    ] {
        let value = env.byte_array_from_slice(value).map_err(|_| ())?;
        env.set_object_array_element(&result, index, &value)
            .map_err(|_| ())?;
        env.delete_local_ref(value).map_err(|_| ())?;
    }
    let token = env
        .byte_array_from_slice(&kit.recovery_token)
        .map_err(|_| ())?;
    if env.set_object_array_element(&result, 2, &token).is_err() {
        let _ = clear_token(env, &token);
        return Err(());
    }
    Ok(result.into_raw())
}

/// Overwrite the actual Java input array, including malformed/oversize tokens,
/// with a bounded scratch allocation. UI/IME copies remain a separate concern.
fn clear_token(env: &mut JNIEnv<'_>, token: &JByteArray<'_>) -> Result<(), ()> {
    // Clear a Java exception first so cleanup calls do not leave secret input.
    if env.exception_check().map_err(|_| ())? {
        env.exception_clear().map_err(|_| ())?;
    }
    let length = env.get_array_length(token).map_err(|_| ())?;
    let zeros = [0_i8; 1024];
    let mut offset = 0;
    while offset < length {
        let count = (length - offset).min(zeros.len() as i32);
        env.set_byte_array_region(token, offset, &zeros[..count as usize])
            .map_err(|_| ())?;
        offset += count;
    }
    Ok(())
}

/// All native entry points contain unwinding and expose one fixed error string.
/// Token cleanup occurs after the body on success, rejection, and panic.
fn boundary<T>(
    env: &mut JNIEnv<'_>,
    tokens: &[&JByteArray<'_>],
    failure: T,
    body: impl FnOnce(&mut JNIEnv<'_>) -> Result<T, ()>,
) -> T {
    let result = catch_unwind(AssertUnwindSafe(|| body(env)));
    let mut cleaned = Ok(());
    for token in tokens {
        if clear_token(env, token).is_err() {
            cleaned = Err(());
        }
    }
    match (result, cleaned) {
        (Ok(Ok(value)), Ok(())) => value,
        (result, _) => {
            if result.is_err() {
                service().close_all();
                typed_service().close_all();
            }
            if env.exception_check().unwrap_or(false) {
                let _ = env.exception_clear();
            }
            let _ = env.throw_new(
                "java/lang/IllegalStateException",
                "Owner custody operation rejected",
            );
            failure
        }
    }
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_org_zrotext_gateway_AndroidOwnerCustodyNativeBridge_nativeCreate(
    mut env: JNIEnv<'_>,
    _object: JObject<'_>,
    account: JByteArray<'_>,
    site: JString<'_>,
) -> jobjectArray {
    boundary(&mut env, &[], std::ptr::null_mut(), |env| {
        let kit = custody::create(fixed(env, &account)?, &origin(env, &site)?).map_err(|_| ())?;
        created_arrays(env, &kit)
    })
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_org_zrotext_gateway_AndroidOwnerCustodyNativeBridge_nativeRecoveryCheck(
    mut env: JNIEnv<'_>,
    _object: JObject<'_>,
    backup: JByteArray<'_>,
    card: JByteArray<'_>,
    token: JByteArray<'_>,
    account: JByteArray<'_>,
    site: JString<'_>,
    fingerprint: JByteArray<'_>,
) -> jboolean {
    boundary(&mut env, &[&token], 0, |env| {
        let expected = identity(env, &account, &site, &fingerprint)?;
        let token = Zeroizing::new(bytes(env, &token, 79)?);
        let root = custody::recover(
            &bytes(env, &backup, 748)?,
            &bytes(env, &card, 645)?,
            &token,
            &expected,
        )
        .map_err(|_| ())?;
        drop(root);
        Ok(1)
    })
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_org_zrotext_gateway_AndroidOwnerCustodyNativeBridge_nativeOpenCustody(
    mut env: JNIEnv<'_>,
    _object: JObject<'_>,
    challenge: JByteArray<'_>,
    backup: JByteArray<'_>,
    card: JByteArray<'_>,
    expected_account: JByteArray<'_>,
    expected_site: JString<'_>,
    expected_fingerprint: JByteArray<'_>,
    bundle_id: JByteArray<'_>,
    current_account: JByteArray<'_>,
    current_user: JByteArray<'_>,
    current_session: JByteArray<'_>,
    server_ms: jlong,
    authenticated_elapsed_ms: jlong,
    uncertainty_ms: jlong,
    now_elapsed_ms: jlong,
) -> jlong {
    boundary(&mut env, &[], 0, |env| {
        let expected = identity(
            env,
            &expected_account,
            &expected_site,
            &expected_fingerprint,
        )?;
        let authority = authority(env, &current_account, &current_user, &current_session)?;
        let anchor = TimeAnchor {
            authenticated_server_ms: positive(server_ms)?,
            authenticated_elapsed_ms: positive(authenticated_elapsed_ms)?,
            uncertainty_ms: positive(uncertainty_ms)?,
        };
        let actual_elapsed = fresh_elapsed(env, now_elapsed_ms)?;
        let handle = service()
            .open_custody(
                &bytes(env, &challenge, 663)?,
                &bytes(env, &backup, 748)?,
                &bytes(env, &card, 645)?,
                &expected,
                &fixed(env, &bundle_id)?,
                authority,
                anchor,
                actual_elapsed,
            )
            .map_err(|_| ())?;
        Ok(handle.as_u64() as jlong)
    })
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_org_zrotext_gateway_AndroidOwnerCustodyNativeBridge_nativeReviewCustody(
    mut env: JNIEnv<'_>,
    _object: JObject<'_>,
    handle: jlong,
) -> jbyteArray {
    boundary(&mut env, &[], std::ptr::null_mut(), |env| {
        let handle = OperationHandle::from_u64(positive(handle)?).map_err(|_| ())?;
        let unsigned = service().review(handle).map_err(|_| ())?;
        Ok(env
            .byte_array_from_slice(&unsigned)
            .map_err(|_| ())?
            .into_raw())
    })
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_org_zrotext_gateway_AndroidOwnerCustodyNativeBridge_nativeSignCustody(
    mut env: JNIEnv<'_>,
    _object: JObject<'_>,
    handle: jlong,
    token: JByteArray<'_>,
    current_account: JByteArray<'_>,
    current_user: JByteArray<'_>,
    current_session: JByteArray<'_>,
    now_elapsed_ms: jlong,
) -> jobjectArray {
    let parsed_handle = positive(handle)
        .ok()
        .and_then(|value| OperationHandle::from_u64(value).ok());
    let result = boundary(&mut env, &[&token], std::ptr::null_mut(), |env| {
        let handle = parsed_handle.ok_or(())?;
        let authority = authority(env, &current_account, &current_user, &current_session)?;
        fresh_elapsed(env, now_elapsed_ms)?;
        let token = Zeroizing::new(bytes(env, &token, 79)?);
        service()
            .sign_with_public_output(
                handle,
                &token,
                &authority,
                env,
                elapsed,
                |env, signatures| {
                    arrays(env, &[&signatures.enrollment, &signatures.custody])
                        .map_err(|_| SigningError::Unavailable)
                },
            )
            .map_err(|_| ())
    });
    // A malformed token/authority/JNI input must consume its approval as well.
    if let Some(handle) = parsed_handle {
        service().close(handle);
    }
    result
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_org_zrotext_gateway_AndroidOwnerCustodyNativeBridge_nativeClose(
    mut env: JNIEnv<'_>,
    _object: JObject<'_>,
    handle: jlong,
) {
    boundary(&mut env, &[], (), |_| {
        let handle = OperationHandle::from_u64(positive(handle)?).map_err(|_| ())?;
        service().close(handle);
        typed_service().close(handle);
        Ok(())
    });
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_org_zrotext_gateway_AndroidOwnerCustodyNativeBridge_nativeCloseAll(
    mut env: JNIEnv<'_>,
    _object: JObject<'_>,
) {
    boundary(&mut env, &[], (), |_| {
        service().close_all();
        typed_service().close_all();
        Ok(())
    });
}

/// Keep prepared output owned until every outer input cleanup has settled.
/// Cleanup failures refuse publication; panics are contained for the JNI caller.
fn finish_prepared<C, T>(
    context: &mut C,
    input_count: usize,
    body: impl FnOnce(&mut C) -> Result<T, ()>,
    mut clear_input: impl FnMut(&mut C, usize) -> Result<(), ()>,
    discard: impl FnOnce(&mut C, T) -> Result<(), ()>,
) -> (Result<T, ()>, bool) {
    let result = catch_unwind(AssertUnwindSafe(|| body(context)));
    let mut panicked = result.is_err();
    let mut cleaned = true;
    for index in 0..input_count {
        match catch_unwind(AssertUnwindSafe(|| clear_input(context, index))) {
            Ok(Ok(())) => {}
            Ok(Err(())) => cleaned = false,
            Err(_) => {
                cleaned = false;
                panicked = true;
            }
        }
    }
    let output = match result {
        Ok(Ok(value)) if cleaned => Ok(value),
        Ok(Ok(value)) => {
            let discarded = catch_unwind(AssertUnwindSafe(|| discard(context, value)));
            panicked |= discarded.is_err();
            Err(())
        }
        _ => Err(()),
    };
    (output, panicked)
}

struct NativeTypedOutput<'local> {
    array: jobjectArray,
    secret: Option<JByteArray<'local>>,
}
fn typed_arrays<'local>(
    env: &mut JNIEnv<'local>,
    artifact: TypedOutput,
) -> Result<NativeTypedOutput<'local>, SigningError> {
    match artifact {
        TypedOutput::Public(values) => {
            let borrowed: Vec<_> = values.iter().map(Vec::as_slice).collect();
            Ok(NativeTypedOutput {
                array: arrays(env, &borrowed).map_err(|_| SigningError::Unavailable)?,
                secret: None,
            })
        }
        TypedOutput::Archive(kit) => {
            let class = env
                .find_class("[B")
                .map_err(|_| SigningError::Unavailable)?;
            let result = env
                .new_object_array(5, class, JObject::null())
                .map_err(|_| SigningError::Unavailable)?;
            for (index, value) in [
                (0, kit.encrypted_backup.as_slice()),
                (1, kit.public_receipt.as_slice()),
                (3, kit.archive_id.as_slice()),
                (4, kit.archive_point.as_slice()),
            ] {
                let value = env
                    .byte_array_from_slice(value)
                    .map_err(|_| SigningError::Unavailable)?;
                env.set_object_array_element(&result, index, &value)
                    .map_err(|_| SigningError::Unavailable)?;
                env.delete_local_ref(value)
                    .map_err(|_| SigningError::Unavailable)?;
            }
            let secret = env
                .byte_array_from_slice(kit.recovery.as_slice())
                .map_err(|_| SigningError::Unavailable)?;
            if env.set_object_array_element(&result, 2, &secret).is_err() {
                let _ = clear_token(env, &secret);
                return Err(SigningError::Unavailable);
            }
            Ok(NativeTypedOutput {
                array: result.into_raw(),
                secret: Some(secret),
            })
        }
    }
}

fn discard_typed(env: &mut JNIEnv<'_>, output: NativeTypedOutput<'_>) -> Result<(), ()> {
    if let Some(secret) = output.secret {
        clear_token(env, &secret)?;
    }
    Ok(())
}

fn prepared_boundary<'local>(
    env: &mut JNIEnv<'local>,
    tokens: &[&JByteArray<'_>],
    body: impl FnOnce(&mut JNIEnv<'local>) -> Result<NativeTypedOutput<'local>, ()>,
) -> jobjectArray {
    let (result, panicked) = finish_prepared(
        env,
        tokens.len(),
        body,
        |env, index| clear_token(env, tokens[index]),
        discard_typed,
    );
    match result {
        Ok(output) => output.array,
        Err(()) => {
            if panicked {
                service().close_all();
                typed_service().close_all();
            }
            if env.exception_check().unwrap_or(false) {
                let _ = env.exception_clear();
            }
            let _ = env.throw_new(
                "java/lang/IllegalStateException",
                "Owner custody operation rejected",
            );
            std::ptr::null_mut()
        }
    }
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_org_zrotext_gateway_AndroidOwnerCustodyNativeBridge_nativeOpenTyped(
    mut env: JNIEnv<'_>,
    _object: JObject<'_>,
    kind: jint,
    proposal: JByteArray<'_>,
    expected_json: JByteArray<'_>,
    backup: JByteArray<'_>,
    card: JByteArray<'_>,
    expected_account: JByteArray<'_>,
    expected_site: JString<'_>,
    expected_fingerprint: JByteArray<'_>,
    current_account: JByteArray<'_>,
    current_user: JByteArray<'_>,
    current_session: JByteArray<'_>,
    server_ms: jlong,
    anchored_elapsed: jlong,
    uncertainty: jlong,
    now_elapsed: jlong,
) -> jlong {
    boundary(&mut env, &[], 0, |env| {
        let kind = OperationKind::try_from(kind).map_err(|_| ())?;
        let identity = identity(
            env,
            &expected_account,
            &expected_site,
            &expected_fingerprint,
        )?;
        let authority = authority(env, &current_account, &current_user, &current_session)?;
        let anchor = TimeAnchor {
            authenticated_server_ms: positive(server_ms)?,
            authenticated_elapsed_ms: positive(anchored_elapsed)?,
            uncertainty_ms: positive(uncertainty)?,
        };
        let now = fresh_elapsed(env, now_elapsed)?;
        let handle = typed_service()
            .open(
                kind,
                &bounded_bytes(env, &proposal, typed::MAX_PROPOSAL)?,
                &bytes(env, &expected_json, typed::MAX_EXPECTED)?,
                &bytes(env, &backup, 748)?,
                &bytes(env, &card, 645)?,
                &identity,
                authority,
                anchor,
                now,
            )
            .map_err(|_| ())?;
        Ok(handle.as_u64() as jlong)
    })
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_org_zrotext_gateway_AndroidOwnerCustodyNativeBridge_nativeReviewTyped(
    mut env: JNIEnv<'_>,
    _object: JObject<'_>,
    handle: jlong,
) -> jobjectArray {
    boundary(&mut env, &[], std::ptr::null_mut(), |env| {
        let handle = OperationHandle::from_u64(positive(handle)?).map_err(|_| ())?;
        let values = typed_service().review(handle).map_err(|_| ())?;
        arrays(env, &values.iter().map(Vec::as_slice).collect::<Vec<_>>())
    })
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_org_zrotext_gateway_AndroidOwnerCustodyNativeBridge_nativeSignTyped(
    mut env: JNIEnv<'_>,
    _object: JObject<'_>,
    handle: jlong,
    root_token: JByteArray<'_>,
    archive_backup: JByteArray<'_>,
    archive_recovery: JByteArray<'_>,
    current_account: JByteArray<'_>,
    current_user: JByteArray<'_>,
    current_session: JByteArray<'_>,
    now_elapsed: jlong,
) -> jobjectArray {
    let parsed = positive(handle)
        .ok()
        .and_then(|value| OperationHandle::from_u64(value).ok());
    let result = prepared_boundary(&mut env, &[&root_token, &archive_recovery], |env| {
        let handle = parsed.ok_or(())?;
        let authority = authority(env, &current_account, &current_user, &current_session)?;
        fresh_elapsed(env, now_elapsed)?;
        let token = Zeroizing::new(bytes(env, &root_token, 79)?);
        let archive = bounded_bytes(env, &archive_backup, 845)?;
        let recovery = Zeroizing::new(bounded_bytes(env, &archive_recovery, 32)?);
        typed_service()
            .execute_with_output(
                handle,
                &token,
                &archive,
                &recovery,
                &authority,
                env,
                elapsed,
                typed_arrays,
                |env, output| {
                    let _ = discard_typed(env, output);
                },
            )
            .map_err(|_| ())
    });
    if let Some(handle) = parsed {
        typed_service().close(handle);
    }
    result
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_org_zrotext_gateway_AndroidOwnerCustodyNativeBridge_nativeArchiveRecoveryCheck(
    mut env: JNIEnv<'_>,
    _object: JObject<'_>,
    backup: JByteArray<'_>,
    recovery: JByteArray<'_>,
    expected_account: JByteArray<'_>,
    expected_site: JString<'_>,
    root_fingerprint: JByteArray<'_>,
    archive_id: JByteArray<'_>,
    archive_point: JByteArray<'_>,
) -> jboolean {
    boundary(&mut env, &[&recovery], 0, |env| {
        let expected = identity(env, &expected_account, &expected_site, &root_fingerprint)?;
        let recovery = Zeroizing::new(bytes(env, &recovery, 32)?);
        typed::check_archive_recovery(
            &bytes(env, &backup, 845)?,
            &recovery,
            &expected,
            &fixed(env, &archive_id)?,
            &fixed(env, &archive_point)?,
        )
        .map_err(|_| ())?;
        Ok(1)
    })
}

#[cfg(test)]
mod tests;

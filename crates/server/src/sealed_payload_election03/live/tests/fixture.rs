// SPDX-License-Identifier: AGPL-3.0-only
use super::*;
pub(super) fn source(c: &crate::auth::SessionCredentials) -> RequestSource<'_> {
    RequestSource {
        session_cookie: &c.token,
        origin: ORIGIN,
        csrf_cookie: &c.csrf_token,
        csrf_header: &c.csrf_token,
    }
}
pub(super) fn sign(key: &SigningKey, label: &[u8], bytes: &[u8]) -> Vec<u8> {
    let s: Signature = key.sign(&crypto::framed(label, bytes).unwrap());
    s.normalize_s().to_bytes().to_vec()
}
pub(super) async fn prepared() -> (Case, Vec<u8>) {
    prepared_with_keys(false, false).await
}
pub(super) async fn prepared_actual_genesis() -> (Case, Vec<u8>) {
    prepared_with_keys(true, false).await
}
pub(super) async fn prepared_claimed_genesis() -> (Case, Vec<u8>) {
    prepared_with_keys(true, true).await
}
async fn prepared_with_keys(actual_genesis: bool, claimed: bool) -> (Case, Vec<u8>) {
    let mut c = if claimed {
        Case::new_claimed().await
    } else {
        Case::new().await
    };
    c.heartbeat().await;
    c.approve().await;
    let lease = c.lease();
    let ack = run::next_ack(&mut c.db.reader, lease, run::Purpose::Sealed, &[])
        .await
        .unwrap()
        .unwrap();
    assert!(
        run::confirm_sealed_install(&mut c.db.reader, lease, ack)
            .await
            .unwrap()
    );
    let now:i64=c.db.reader.query_one("SELECT pg_catalog.floor(extract(epoch FROM pg_catalog.clock_timestamp())*1000)::bigint",&[]).await.unwrap().get(0);
    let account = c.principal.tenant.account_id();
    let payload = SigningKey::generate_from_rng(&mut rand::rng());
    let archive = SigningKey::generate_from_rng(&mut rand::rng());
    let outbound = SigningKey::generate_from_rng(&mut rand::rng());
    let mut roles = Vec::new();
    let phone_role = if actual_genesis {
        (4, &c.phone_key, c.device, c.line, 2)
    } else {
        (5, &outbound, Uuid::nil(), c.line, 1)
    };
    for (role, key, device, line, scope) in [
        (1, &payload, c.device, c.line, 4u16),
        (2, &archive, Uuid::nil(), Uuid::nil(), 12),
        // Content outbound custody is distinct from the original SEALED
        // activation/election approval key retained by this real ceremony.
        phone_role,
        (6, &c.root_key, Uuid::nil(), Uuid::nil(), 0),
    ] {
        let point = key.verifying_key().to_sec1_point(false);
        let mut bytes = vec![role];
        bytes.extend_from_slice(&crate::sealed_manifest::key_id(role, point.as_bytes()));
        bytes.extend_from_slice(point.as_bytes());
        bytes.extend_from_slice(device.as_bytes());
        bytes.extend_from_slice(line.as_bytes());
        bytes.extend_from_slice(&scope.to_be_bytes());
        bytes.extend_from_slice(&((now - 1000) as u64).to_be_bytes());
        bytes.extend_from_slice(&((now + 3_600_000) as u64).to_be_bytes());
        bytes.push(1);
        roles.push(bytes);
    }
    roles.sort_by(|a, b| a[..33].cmp(&b[..33]));
    let manifest = |profile: u8, version: u64, previous: [u8; 32]| {
        let mut bytes = b"ZTMA".to_vec();
        bytes.push(profile);
        if profile == 3 {
            bytes.extend_from_slice(&[3, 2]);
        }
        bytes.extend_from_slice(account.as_bytes());
        bytes.extend_from_slice(&1u64.to_be_bytes());
        bytes.extend_from_slice(&version.to_be_bytes());
        bytes.extend_from_slice(&((now - 1000) as u64).to_be_bytes());
        bytes.extend_from_slice(&((now + 3_600_000) as u64).to_be_bytes());
        bytes.extend_from_slice(&previous);
        bytes.extend_from_slice(&c.pin[29..94]);
        bytes.push(roles.len() as u8);
        for role in &roles {
            bytes.extend_from_slice(role)
        }
        let sig = sign(
            &c.root_key,
            if profile == 2 {
                b"ZTSE/manifest/v2\0"
            } else {
                b"ZTSE/manifest/v3\0"
            },
            &bytes,
        );
        bytes.extend_from_slice(&sig);
        bytes
    };
    let prior = manifest(2, 1, [0; 32]);
    let successor = manifest(3, 2, crypto::sha(&prior[..prior.len() - 64]));
    let tx = c.db.reader.transaction().await.unwrap();
    let admission = crate::sealed_manifest_store::admit(&tx, lease, c.line, 1, &prior)
        .await
        .unwrap();
    drop(admission);
    tx.commit().await.unwrap();
    crate::payload_profile_elections::require(&c.db.reader)
        .await
        .unwrap();
    (c, successor)
}

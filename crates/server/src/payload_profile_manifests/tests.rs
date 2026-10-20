// SPDX-License-Identifier: AGPL-3.0-only
use super::*;
use crate::payload_profile_writer::tests::Fixture;
use postgres_protocol::escape::escape_identifier;
use sha2::{Digest, Sha256};
use tokio_postgres::error::SqlState;
use uuid::Uuid;

// Public synthetic structural candidates only. These trailing signature bytes
// are not root authorization; the production adapter verifies original crypto.
fn point(seed: u8) -> [u8; 65] {
    p256::ecdsa::SigningKey::from_slice(&[seed; 32])
        .unwrap()
        .verifying_key()
        .to_sec1_point(false)
        .as_bytes()
        .try_into()
        .unwrap()
}
fn role(
    role: u8,
    seed: u8,
    device: Uuid,
    line: Uuid,
    scope: u16,
    from: u64,
    until: u64,
) -> Vec<u8> {
    let point = point(seed);
    let mut out = vec![role];
    out.extend(crate::sealed_manifest::key_id(role, &point));
    out.extend(point);
    out.extend(device.as_bytes());
    out.extend(line.as_bytes());
    out.extend(scope.to_be_bytes());
    out.extend(from.to_be_bytes());
    out.extend(until.to_be_bytes());
    out.push(1);
    out
}
fn manifest(
    account: Uuid,
    version: u64,
    issued: u64,
    expires: u64,
    prior: &[u8],
    roles: &[Vec<u8>],
) -> Vec<u8> {
    let mut out = b"ZTMA\x03\x03\x03".to_vec();
    out.extend(account.as_bytes());
    for n in [1, version, issued, expires] {
        out.extend(n.to_be_bytes());
    }
    out.extend(Sha256::digest(prior));
    out.extend(point(23));
    out.push(roles.len().try_into().unwrap());
    for key in roles {
        out.extend(key);
    }
    out.extend([1; 64]);
    out
}

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL with CREATEDB/CREATEROLE on a disposable PostgreSQL cluster"]
async fn expired_same_key_renewal_and_explicit_replacement_preserve_original_records() {
    let fixture = fixture().await;
    let account = Uuid::new_v4();
    let device = Uuid::new_v4();
    let line = Uuid::new_v4();
    let zero = Uuid::nil();
    let mut keys = vec![
        role(1, 17, device, line, 4, 1000, 5000),
        role(2, 19, zero, zero, 12, 1000, 5000),
        role(4, 21, device, line, 2, 1000, 5000),
        role(6, 23, zero, zero, 0, 1000, 5000),
    ];
    let mut prior = manifest(account, 2, 1000, 5000, &[0; 32], &keys);
    for (step, mode, signer, issued, expires) in [
        (0, "enroll", 25, 9000, 20000),
        (1, "renew", 25, 21000, 30000),
        (2, "replace", 27, 31000, 40000),
    ] {
        for key in &mut keys {
            if step == 2 && key[0] == 5 && key[148] == 1 {
                key[148] = 2;
            } else if key[148] == 1 {
                key[140..148].copy_from_slice(&u64::to_be_bytes(expires));
            }
        }
        if step != 1 {
            keys.push(role(5, signer, zero, line, 1, issued, expires));
        }
        keys.sort_by(|a, b| a[..33].cmp(&b[..33]));
        let successor = manifest(
            account,
            3 + step,
            issued,
            expires,
            &prior[..prior.len() - 64],
            &keys,
        );
        let point = point(signer);
        let id = crate::sealed_manifest::key_id(5, &point);
        let row = fixture
            .owner
            .query_one(
                "SELECT public.payload_profile_manifest_keys($1,$2,$3,$4,$5,$6)",
                &[
                    &prior,
                    &successor,
                    &line,
                    &&point[..],
                    &&id[..],
                    &(issued as i64),
                ],
            )
            .await
            .unwrap();
        assert_eq!(row.get::<_, String>(0), mode);
        for at in [153 + 98 + 15, 153 + 130 + 1, 153 + 132 + 7, 153 + 148] {
            let mut changed = successor.clone();
            changed[at] ^= 1;
            let error = fixture
                .owner
                .query_one(
                    "SELECT public.payload_profile_manifest_keys($1,$2,$3,$4,$5,$6)",
                    &[
                        &prior,
                        &changed,
                        &line,
                        &&point[..],
                        &&id[..],
                        &(issued as i64),
                    ],
                )
                .await
                .unwrap_err();
            assert_eq!(error.code(), Some(&SqlState::CHECK_VIOLATION));
        }
        prior = successor;
    }
    fixture.finish().await;
}

async fn fixture() -> Fixture {
    let fixture = Fixture::new().await;
    fixture.owner.batch_execute(&format!("GRANT EXECUTE ON FUNCTION public.payload_profile_v2_capture(uuid,uuid,bytea,bytea,bytea,bytea,bytea,bytea),public.payload_profile_v2_ready(),public.payload_profile_election_reserve(uuid,uuid,uuid,uuid,uuid,bytea,bytea,bigint),public.payload_profile_election_device_proof(uuid,uuid,bytea),public.payload_profile_election_accept(uuid,uuid,uuid,bytea,bigint),public.payload_profile_election_ready(),public.payload_profile_selection_reserve(uuid,uuid,uuid,uuid,bytea,bigint),public.payload_profile_selection_device_proof(uuid,uuid,bytea,bytea),public.payload_profile_selection_approve(uuid,uuid,uuid,bytea,bigint),public.payload_profile_selection_install(uuid,uuid,bytea,bytea),public.payload_profile_selection_ready(),public.payload_profile_manifest_install(uuid,uuid,uuid,uuid,bytea,bytea,bytea,bigint),public.payload_profile_manifest_retention(uuid,uuid,bigint,bytea,bytea,bigint,bytea),public.payload_profile_manifest_ready() TO {}",escape_identifier(&fixture.runtime_role))).await.unwrap();
    require(&fixture.db).await.unwrap();
    assert!(require(&fixture.owner).await.is_err());
    fixture
}

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL with CREATEDB/CREATEROLE on a disposable PostgreSQL cluster"]
async fn manifest_successors_refuse_partial_disabled_rewritten_policy_and_helper_changes() {
    let mut fixture = fixture().await;
    for mutation in [
        "ALTER TABLE public.payload_profile_manifest_successors DISABLE TRIGGER payload_profile_manifest_before_change",
        "ALTER TABLE public.payload_profile_manifest_successors DISABLE TRIGGER payload_profile_manifest_after_insert",
        "ALTER TABLE public.payload_profile_manifest_successors DROP CONSTRAINT payload_profile_manifest_successors_check",
        "ALTER TABLE public.payload_profile_manifest_successors ADD COLUMN unreviewed boolean",
        "ALTER TABLE public.payload_profile_manifest_successors ENABLE ROW LEVEL SECURITY",
        "CREATE POLICY unreviewed ON public.payload_profile_manifest_successors USING(true)",
        "CREATE RULE unreviewed AS ON UPDATE TO public.payload_profile_manifest_successors DO INSTEAD NOTHING",
        "DROP TABLE public.payload_profile_manifest_successors CASCADE",
        "CREATE OR REPLACE FUNCTION public.payload_profile_manifest_ancestry(account uuid,election uuid,version bigint,digest bytea,manifest bytea,accepted_ms bigint) RETURNS boolean LANGUAGE sql STABLE STRICT SECURITY DEFINER SET search_path TO pg_catalog AS 'SELECT true'",
        "CREATE OR REPLACE FUNCTION public.payload_profile_manifest_ready() RETURNS boolean LANGUAGE sql STABLE SET search_path TO pg_catalog AS 'SELECT true'",
        "CREATE OR REPLACE FUNCTION public.payload_profile_manifest_retention(account uuid,election uuid,version bigint,digest bytea,manifest bytea,accepted_ms bigint,ancestry_sha256 bytea) RETURNS boolean LANGUAGE sql STABLE STRICT SECURITY DEFINER SET search_path TO pg_catalog AS 'SELECT true'",
        "CREATE OR REPLACE FUNCTION public.payload_profile_manifest_rows_guard() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path TO pg_catalog SET lock_timeout TO '3s' AS 'BEGIN RETURN NEW; END'",
        "GRANT EXECUTE ON FUNCTION public.payload_profile_manifest_scope(uuid,uuid,uuid,bytea,bytea) TO PUBLIC",
    ] {
        let tx = fixture.owner.transaction().await.unwrap();
        tx.batch_execute(mutation).await.unwrap();
        assert!(optional(&tx).await.is_err(), "{mutation}");
        tx.rollback().await.unwrap();
        require(&fixture.db).await.unwrap();
    }
    fixture.finish().await;
}

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL with CREATEDB/CREATEROLE on a disposable PostgreSQL cluster"]
async fn runtime_retention_projection_refuses_unretained_checkpoint_and_missing_capability() {
    let fixture = fixture().await;
    let account = Uuid::new_v4();
    let election = Uuid::new_v4();
    let digest = vec![1_u8; 32];
    let manifest = vec![2_u8; 366];
    let row = fixture
        .db
        .query_one(
            "SELECT public.payload_profile_manifest_retention($1,$2,$3,$4,$5,$6,$7)",
            &[
                &account, &election, &1_i64, &digest, &manifest, &1_i64, &digest,
            ],
        )
        .await
        .unwrap();
    assert!(!row.get::<_, bool>(0));
    let role = escape_identifier(&fixture.runtime_role);
    fixture.owner.batch_execute(&format!("REVOKE EXECUTE ON FUNCTION public.payload_profile_manifest_retention(uuid,uuid,bigint,bytea,bytea,bigint,bytea) FROM {role}")).await.unwrap();
    assert!(require(&fixture.db).await.is_err());
    fixture.finish().await;
}

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL with CREATEDB/CREATEROLE on a disposable PostgreSQL cluster"]
async fn manifest_successors_deny_row_column_internal_epoch_and_scope_authority() {
    let fixture = fixture().await;
    let role = escape_identifier(&fixture.runtime_role);
    for statement in [
        "DELETE FROM public.payload_profile_manifest_successors",
        "UPDATE public.payload_profile_manifest_successors SET accepted_ms=accepted_ms",
        "UPDATE public.payload_profile_account_anchors SET selection_epoch=selection_epoch+1",
        "SELECT public.payload_profile_selection_owner('00000000-0000-0000-0000-000000000001','00000000-0000-0000-0000-000000000002','00000000-0000-0000-0000-000000000003')",
    ] {
        let error = fixture.db.batch_execute(statement).await.unwrap_err();
        assert_eq!(error.code(), Some(&SqlState::INSUFFICIENT_PRIVILEGE));
    }
    for (grant, revoke) in [
        (
            format!(
                "GRANT UPDATE(accepted_ms) ON public.payload_profile_manifest_successors TO {role}"
            ),
            format!(
                "REVOKE ALL(accepted_ms) ON public.payload_profile_manifest_successors FROM {role}"
            ),
        ),
        (
            format!("GRANT INSERT ON public.payload_profile_manifest_successors TO {role}"),
            format!("REVOKE INSERT ON public.payload_profile_manifest_successors FROM {role}"),
        ),
        (
            format!(
                "GRANT EXECUTE ON FUNCTION public.payload_profile_epoch_valid(uuid,bigint) TO {role}"
            ),
            format!(
                "REVOKE EXECUTE ON FUNCTION public.payload_profile_epoch_valid(uuid,bigint) FROM {role}"
            ),
        ),
        (
            format!(
                "GRANT EXECUTE ON FUNCTION public.payload_profile_manifest_scope(uuid,uuid,uuid,bytea,bytea) TO {role}"
            ),
            format!(
                "REVOKE EXECUTE ON FUNCTION public.payload_profile_manifest_scope(uuid,uuid,uuid,bytea,bytea) FROM {role}"
            ),
        ),
    ] {
        fixture.owner.batch_execute(&grant).await.unwrap();
        assert!(require(&fixture.db).await.is_err(), "{grant}");
        fixture.owner.batch_execute(&revoke).await.unwrap();
        require(&fixture.db).await.unwrap();
    }
    fixture.finish().await;
}

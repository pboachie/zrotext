// SPDX-License-Identifier: AGPL-3.0-only
use super::*;
use crate::test_database::Fixture;
use postgres_protocol::escape::escape_identifier;
use sha2::{Digest, Sha256};
use tokio_postgres::error::SqlState;
use uuid::Uuid;

#[path = "../conversation_profile03_storage/test_fixture.rs"]
mod current_fixture;

async fn fixture() -> Fixture {
    let fixture = current_fixture::new().await;
    require(&fixture.runtime).await.unwrap();
    assert!(require(&fixture.owner).await.is_err());
    fixture
}

fn statement() -> Vec<u8> {
    let mut bytes = b"ZTCA\x03\x03\x03\0".to_vec();
    for _ in 0..9 {
        bytes.extend(Uuid::new_v4().as_bytes());
    }
    for n in [2_u64, 1, 3, 1, 1000, 2000, 1000, 3000] {
        bytes.extend(n.to_be_bytes());
    }
    for n in 1..=13 {
        bytes.extend([n; 32]);
    }
    bytes.push(25);
    bytes.extend(b"conversation-content03-v1");
    bytes.extend(Sha256::digest(b"With your approval, ZROtext sends and receives SMS for this selected phone line and conversation, and transfers encrypted message content to your paired browser and the explicitly listed customer-controlled readers. Stop closes new sending, capture and transfer; retained encrypted content is deleted separately."));
    bytes.extend([3, b'+', b'1', b'2', 0]);
    bytes
}

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL with CREATEDB/CREATEROLE on a disposable PostgreSQL cluster"]
async fn interval_parser_rejects_changed_header_identity_window_disclosure_peer_and_trailing_bytes()
{
    let fixture = fixture().await;
    let original = statement();
    assert_eq!(original.len(), 695);
    let row = fixture
        .owner
        .query_one(
            "SELECT (public.conversation_profile03_interval_parse($1)).peer",
            &[&original],
        )
        .await
        .unwrap();
    assert_eq!(row.get::<_, String>(0), "+12");
    for at in [0, 4, 5, 6, 7, 167, 183, 207, 632, 633, 658, 690, 691, 694] {
        let mut changed = original.clone();
        changed[at] ^= 1;
        assert!(
            fixture
                .owner
                .query_one(
                    "SELECT public.conversation_profile03_interval_parse($1)",
                    &[&changed]
                )
                .await
                .is_err(),
            "offset {at}"
        );
    }
    for range in [8..24, 216..248, 600..632] {
        let mut changed = original.clone();
        changed[range].fill(0);
        let error = fixture
            .owner
            .query_one(
                "SELECT public.conversation_profile03_interval_parse($1)",
                &[&changed],
            )
            .await
            .unwrap_err();
        assert_eq!(error.code(), Some(&SqlState::CHECK_VIOLATION));
    }
    let mut changed = original.clone();
    changed.push(0);
    assert!(
        fixture
            .owner
            .query_one(
                "SELECT public.conversation_profile03_interval_parse($1)",
                &[&changed]
            )
            .await
            .is_err()
    );
    fixture.finish().await;
}

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL with CREATEDB/CREATEROLE on a disposable PostgreSQL cluster"]
async fn interval_schema_refuses_partial_disabled_rewritten_policy_declaration_and_unknown_columns()
{
    let mut fixture = fixture().await;
    for mutation in [
        "ALTER TABLE public.conversation_profile03_intervals DISABLE TRIGGER conversation_profile03_interval_before_change",
        "ALTER TABLE public.conversation_profile03_intervals DISABLE TRIGGER conversation_profile03_interval_after_change",
        "ALTER TABLE public.conversation_profile03_intervals ADD COLUMN unreviewed boolean",
        "ALTER TABLE public.conversation_profile03_intervals ENABLE ROW LEVEL SECURITY",
        "CREATE POLICY unreviewed ON public.conversation_profile03_intervals USING(true)",
        "CREATE RULE unreviewed AS ON UPDATE TO public.conversation_profile03_intervals DO INSTEAD NOTHING",
        "DROP TABLE public.conversation_profile03_intervals CASCADE",
        "CREATE OR REPLACE FUNCTION public.conversation_profile03_interval_ready() RETURNS boolean LANGUAGE sql STABLE SET search_path TO pg_catalog AS 'SELECT true'",
        "CREATE OR REPLACE FUNCTION public.conversation_profile03_interval_complete() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path TO pg_catalog SET lock_timeout TO '3s' AS 'BEGIN RETURN NULL; END'",
        "GRANT EXECUTE ON FUNCTION public.conversation_profile03_interval_scope(uuid,uuid,uuid,bytea,boolean) TO PUBLIC",
    ] {
        let tx = fixture.owner.transaction().await.unwrap();
        tx.batch_execute(mutation).await.unwrap();
        assert!(optional(&tx).await.is_err(), "{mutation}");
        tx.rollback().await.unwrap();
        require(&fixture.runtime).await.unwrap();
    }
    fixture.finish().await;
}

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL with CREATEDB/CREATEROLE on a disposable PostgreSQL cluster"]
async fn interval_runtime_cannot_edit_originals_epoch_or_internal_scope_and_actor_helpers() {
    let fixture = fixture().await;
    for sql in [
        "DELETE FROM public.conversation_profile03_intervals",
        "UPDATE public.conversation_profile03_intervals SET installed_ms=installed_ms",
        "UPDATE public.payload_profile_account_anchors SET selection_epoch=selection_epoch+1",
        "SELECT public.conversation_profile03_interval_parse(''::bytea)",
        "SELECT public.conversation_profile03_interval_scope(NULL,NULL,NULL,NULL,true)",
        "SELECT public.conversation_profile03_interval_device_actor(NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL)",
    ] {
        let error = fixture.runtime.batch_execute(sql).await.unwrap_err();
        assert_eq!(error.code(), Some(&SqlState::INSUFFICIENT_PRIVILEGE));
    }
    let role = escape_identifier(&fixture.runtime_role);
    for (grant, revoke) in [
        (
            format!("GRANT UPDATE(phase) ON public.conversation_profile03_intervals TO {role}"),
            format!("REVOKE ALL(phase) ON public.conversation_profile03_intervals FROM {role}"),
        ),
        (
            format!("GRANT INSERT ON public.conversation_profile03_intervals TO {role}"),
            format!("REVOKE INSERT ON public.conversation_profile03_intervals FROM {role}"),
        ),
        (
            format!(
                "GRANT EXECUTE ON FUNCTION public.conversation_profile03_interval_lock(uuid,uuid) TO {role}"
            ),
            format!(
                "REVOKE EXECUTE ON FUNCTION public.conversation_profile03_interval_lock(uuid,uuid) FROM {role}"
            ),
        ),
    ] {
        fixture.owner.batch_execute(&grant).await.unwrap();
        assert!(require(&fixture.runtime).await.is_err(), "{grant}");
        fixture.owner.batch_execute(&revoke).await.unwrap();
        require(&fixture.runtime).await.unwrap();
    }
    fixture.finish().await;
}

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL with CREATEDB/CREATEROLE on a disposable PostgreSQL cluster"]
async fn interval_key_scope_keeps_integration_readers_account_scoped_and_content_roles_line_bound()
{
    let fixture = fixture().await;
    let device = Uuid::new_v4();
    let line = Uuid::new_v4();
    let point = p256::ecdsa::SigningKey::from_slice(&[17; 32])
        .unwrap()
        .verifying_key()
        .to_sec1_point(false);
    for role in 1_i32..=5 {
        let mut key_id = Sha256::new();
        key_id.update(b"ZTSE/key/v1");
        key_id.update(if role <= 3 { [0, 0, 16] } else { [0, 1, 1] });
        key_id.update(point.as_bytes());
        let key_id = key_id.finalize().to_vec();
        // Only this internal structural key helper is exercised here. The fixture
        // does not turn these unsigned test bytes into root or content authority.
        let mut manifest = vec![0; 153];
        manifest[..7].copy_from_slice(b"ZTMA\x03\x03\x03");
        manifest[152] = 1;
        manifest.push(role as u8);
        manifest.extend(&key_id);
        manifest.extend(point.as_bytes());
        manifest.extend(if matches!(role, 1 | 4) {
            *device.as_bytes()
        } else {
            [0; 16]
        });
        manifest.extend(if matches!(role, 2 | 3) {
            [0; 16]
        } else {
            *line.as_bytes()
        });
        let scope: u16 = match role {
            1 => 4,
            2 | 3 => 12,
            4 => 2,
            5 => 1,
            _ => unreachable!(),
        };
        manifest.extend(scope.to_be_bytes());
        manifest.extend(1_u64.to_be_bytes());
        manifest.extend(100_u64.to_be_bytes());
        manifest.push(1);
        manifest.extend([0; 64]);
        let query = "SELECT public.conversation_profile03_key_until($1,$2,$3,$4,$5,10)";
        assert_eq!(
            fixture
                .owner
                .query_one(query, &[&manifest, &role, &key_id, &device, &line])
                .await
                .unwrap()
                .get::<_, i64>(0),
            100
        );
        let mut changed_line = manifest.clone();
        changed_line[153 + 114..153 + 130].copy_from_slice(if matches!(role, 2 | 3) {
            line.as_bytes()
        } else {
            &[0; 16]
        });
        let error = fixture
            .owner
            .query_one(query, &[&changed_line, &role, &key_id, &device, &line])
            .await
            .unwrap_err();
        assert_eq!(error.code(), Some(&SqlState::CHECK_VIOLATION));
        if role == 3 {
            for directions in [4_u16, 8] {
                let mut changed_scope = manifest.clone();
                changed_scope[153 + 130..153 + 132].copy_from_slice(&directions.to_be_bytes());
                let error = fixture
                    .owner
                    .query_one(query, &[&changed_scope, &role, &key_id, &device, &line])
                    .await
                    .unwrap_err();
                assert_eq!(error.code(), Some(&SqlState::CHECK_VIOLATION));
            }
        }
    }
    fixture.finish().await;
}

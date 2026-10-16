// SPDX-License-Identifier: AGPL-3.0-only
use super::*;
use p256::{
    ecdsa::{Signature, SigningKey, signature::Signer},
    elliptic_curve::Generate,
};
use postgres_protocol::escape::{escape_identifier, escape_literal};
use sha2::{Digest, Sha256};
use tokio_postgres::{Config, NoTls, error::SqlState};

const ORIGIN: &str = "https://registration.example";
type Driver = tokio::task::JoinHandle<std::result::Result<(), tokio_postgres::Error>>;
async fn connect(config: &Config) -> (Client, Driver) {
    let (client, connection) = config.connect(NoTls).await.unwrap();
    (client, tokio::spawn(connection))
}
async fn close(client: Client, driver: Driver) {
    drop(client);
    tokio::time::timeout(std::time::Duration::from_secs(5), driver)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
}

// Administrative access creates only disposable LOGIN roles/database. All
// migrations and data writes use their ordinary owner; reads use a different
// ordinary role with narrow SELECT and the column privilege required by SHARE.
struct Fixture {
    admin: Client,
    admin_driver: Driver,
    owner: Client,
    owner_driver: Driver,
    reader: Client,
    reader_driver: Driver,
    database: String,
    owner_role: String,
    read_role: String,
}
impl Fixture {
    async fn new() -> Self {
        let raw = std::env::var("ZT_AUTH_TEST_DATABASE_URL").expect("disposable test cluster");
        let mut config: Config = raw.parse().unwrap();
        let (admin, admin_driver) = connect(&config).await;
        let suffix = Uuid::new_v4().simple().to_string();
        let database = format!("registration_{suffix}");
        let owner_role = format!("registration_owner_{suffix}");
        let read_role = format!("registration_read_{suffix}");
        let password = Uuid::new_v4().simple().to_string();
        let verifier = postgres_protocol::password::scram_sha_256(password.as_bytes());
        for role in [&owner_role, &read_role] {
            admin.batch_execute(&format!("CREATE ROLE {} LOGIN PASSWORD {} NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS", escape_identifier(role), escape_literal(&verifier))).await.unwrap();
        }
        admin
            .batch_execute(&format!(
                "CREATE DATABASE {} OWNER {}",
                escape_identifier(&database),
                escape_identifier(&owner_role)
            ))
            .await
            .unwrap();
        config
            .dbname(&database)
            .user(&owner_role)
            .password(&password);
        let (mut owner, owner_driver) = connect(&config).await;
        let directory = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../deploy/compose/migrations");
        zrotext_migrator::apply(&mut owner, &directory, false)
            .await
            .unwrap();
        owner.batch_execute(&format!("GRANT USAGE ON SCHEMA public TO {r}; GRANT SELECT ON public.accounts,public.payload_profile_account_anchors,public.sealed_manifest_authorities,public.sealed_line_key_receipts,public.device_keys,public.line_owner_approval_keys TO {r}; GRANT UPDATE(id) ON public.accounts TO {r}; GRANT UPDATE(account_id) ON public.payload_profile_account_anchors,public.sealed_manifest_authorities,public.sealed_line_key_receipts,public.device_keys,public.line_owner_approval_keys TO {r}", r=escape_identifier(&read_role))).await.unwrap();
        config.user(&read_role);
        let (reader, reader_driver) = connect(&config).await;
        assert!(!reader.query_one("SELECT rolsuper OR rolcreatedb OR rolcreaterole OR rolreplication OR rolbypassrls FROM pg_catalog.pg_roles WHERE rolname=current_user", &[]).await.unwrap().get::<_,bool>(0));
        assert!(!reader.query_one("SELECT EXISTS(SELECT 1 FROM pg_catalog.pg_class WHERE relnamespace='public'::regnamespace AND relowner=current_user::regrole)", &[]).await.unwrap().get::<_,bool>(0));
        Self {
            admin,
            admin_driver,
            owner,
            owner_driver,
            reader,
            reader_driver,
            database,
            owner_role,
            read_role,
        }
    }
    async fn finish(self) {
        close(self.reader, self.reader_driver).await;
        close(self.owner, self.owner_driver).await;
        self.admin
            .batch_execute(&format!(
                "DROP DATABASE {}",
                escape_identifier(&self.database)
            ))
            .await
            .unwrap();
        for role in [&self.read_role, &self.owner_role] {
            self.admin
                .batch_execute(&format!("DROP ROLE {}", escape_identifier(role)))
                .await
                .unwrap();
        }
        close(self.admin, self.admin_driver).await;
    }
}
struct Seed {
    locator: Locator,
    identity: OriginalIdentity,
    transcript: Vec<u8>,
    root_signature: [u8; 64],
    approval_signature: [u8; 64],
    approval_point: [u8; 65],
    approval_fingerprint: [u8; 32],
    paired_fingerprint: [u8; 32],
    paired_point: Vec<u8>,
    root_fingerprint: [u8; 32],
    issued: i64,
    expires: i64,
    completed: i64,
}
impl Seed {
    async fn new(owner: &Client) -> Self {
        Self::with_offset(owner, -600_000).await
    }
    async fn with_offset(owner: &Client, offset: i64) -> Self {
        let account = Uuid::new_v4();
        let registration = Uuid::new_v4();
        let identity = OriginalIdentity {
            account,
            registration,
            user: Uuid::new_v4(),
            owner_session: Uuid::new_v4(),
            device: Uuid::new_v4(),
            line: Uuid::new_v4(),
            generation: 1,
        };
        let root = SigningKey::generate_from_rng(&mut rand::rng());
        let approval = SigningKey::generate_from_rng(&mut rand::rng());
        let paired = SigningKey::generate_from_rng(&mut rand::rng());
        let approval_point: [u8; 65] = approval
            .verifying_key()
            .to_sec1_point(false)
            .as_bytes()
            .try_into()
            .unwrap();
        let paired_point = paired
            .verifying_key()
            .to_sec1_point(false)
            .as_bytes()
            .to_vec();
        let approval_fingerprint: [u8; 32] = Sha256::digest(approval_point).into();
        let paired_fingerprint: [u8; 32] = Sha256::digest(&paired_point).into();
        let mut pin = b"ZTRP\x02".to_vec();
        pin.extend_from_slice(account.as_bytes());
        pin.extend_from_slice(&1u64.to_be_bytes());
        pin.extend_from_slice(root.verifying_key().to_sec1_point(false).as_bytes());
        let pin: [u8; 94] = pin.try_into().unwrap();
        let root_fingerprint =
            sealed_root_enrollment::root_fingerprint(&pin, account.as_bytes()).unwrap();
        let now: i64 = owner
            .query_one(
                "SELECT floor(extract(epoch FROM clock_timestamp())*1000)::bigint",
                &[],
            )
            .await
            .unwrap()
            .get(0);
        let issued = now + offset;
        let expires = issued + 300_000;
        let completed = issued + 1;
        let statement = registration::Statement::new(
            registration::Scope {
                account: *account.as_bytes(),
                user: *identity.user.as_bytes(),
                owner_session: *identity.owner_session.as_bytes(),
                device: *identity.device.as_bytes(),
                line: *identity.line.as_bytes(),
                next_generation: 1,
                challenge: *registration.as_bytes(),
                nonce: [5; 32],
                issued_ms: issued as u64,
                expires_ms: expires as u64,
                approval_fingerprint,
                paired_signing_fingerprint: paired_fingerprint,
                connection_epoch: 1,
                deployment_epoch: 1,
                site_id: "synthetic-site".into(),
                instance_id: "synthetic-instance".into(),
                origin: ORIGIN.into(),
            },
            pin,
            root_fingerprint,
            approval_point,
        )
        .unwrap();
        let transcript = registration::encode(&statement).unwrap();
        let signature: Signature = root.sign(&transcript);
        let root_signature: [u8; 64] = signature.normalize_s().to_bytes().into();
        let signature: Signature = approval.sign(&transcript);
        let approval_signature: [u8; 64] = signature.normalize_s().to_bytes().into();
        owner
            .execute("INSERT INTO public.accounts(id) VALUES($1)", &[&account])
            .await
            .unwrap();
        owner
            .execute(
                "INSERT INTO public.devices(id,account_id,display_name) VALUES($1,$2,'synthetic')",
                &[&identity.device, &account],
            )
            .await
            .unwrap();
        owner.execute("INSERT INTO public.device_keys(device_id,account_id,signing_key_sec1,fingerprint) VALUES($1,$2,$3,$4)", &[&identity.device,&account,&paired_point,&&paired_fingerprint[..]]).await.unwrap();
        owner.execute("INSERT INTO public.line_owner_approval_keys(account_id,signing_key_sec1,fingerprint) VALUES($1,$2,$3)", &[&account,&&approval_point[..],&&approval_fingerprint[..]]).await.unwrap();
        owner.execute("INSERT INTO public.sealed_manifest_authorities(account_id,root_pin,root_fingerprint,generation,anchor_digest) VALUES($1,$2,$3,1,$4)", &[&account,&&pin[..],&&root_fingerprint[..],&&[0u8;32][..]]).await.unwrap();
        owner.execute("INSERT INTO public.sealed_line_key_receipts(account_id,registration_id,user_id,session_id,device_id,line_id,generation,transcript,root_signature,approval_signature,approval_point,approval_fingerprint,paired_fingerprint,issued_ms,expires_ms,completed_ms) VALUES($1,$2,$3,$4,$5,$6,1,$7,$8,$9,$10,$11,$12,$13,$14,$15)", &[&account,&registration,&identity.user,&identity.owner_session,&identity.device,&identity.line,&transcript,&&root_signature[..],&&approval_signature[..],&&approval_point[..],&&approval_fingerprint[..],&&paired_fingerprint[..],&issued,&expires,&completed]).await.unwrap();
        Self {
            locator: Locator {
                account,
                registration,
            },
            identity,
            transcript,
            root_signature,
            approval_signature,
            approval_point,
            approval_fingerprint,
            paired_fingerprint,
            paired_point,
            root_fingerprint,
            issued,
            expires,
            completed,
        }
    }
    fn canonical(&self) -> Vec<u8> {
        RegistrationEvidence03 {
            transcript: &self.transcript,
            root_signature: &self.root_signature,
            approval_signature: &self.approval_signature,
            approval_point: &self.approval_point,
            approval_fingerprint: &self.approval_fingerprint,
            paired_fingerprint: &self.paired_fingerprint,
            issued_ms: self.issued as u64,
            expires_ms: self.expires as u64,
            completed_ms: self.completed as u64,
        }
        .canonical()
        .unwrap()
    }
}

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL with disposable cluster administrator"]
async fn future_completion_missing_original_root_and_revoked_root_refuse() {
    let mut f = Fixture::new().await;
    let future = Seed::with_offset(&f.owner, 600_000).await;
    assert!(matches!(
        read(&mut f.reader, future.locator, ORIGIN).await,
        Err(ReadError::Refused)
    ));
    let revoked = Seed::new(&f.owner).await;
    f.owner.execute("UPDATE public.sealed_manifest_authorities SET revoked_at=clock_timestamp() WHERE account_id=$1", &[&revoked.locator.account]).await.unwrap();
    assert!(matches!(
        read(&mut f.reader, revoked.locator, ORIGIN).await,
        Err(ReadError::Refused)
    ));
    let absent = Seed::new(&f.owner).await;
    f.owner
        .execute(
            "DELETE FROM public.sealed_manifest_authorities WHERE account_id=$1",
            &[&absent.locator.account],
        )
        .await
        .unwrap();
    assert!(matches!(
        read(&mut f.reader, absent.locator, ORIGIN).await,
        Err(ReadError::Refused)
    ));
    f.finish().await;
}

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL with disposable cluster administrator"]
async fn original_signed_history_survives_expiry_without_granting_current_authority() {
    let mut f = Fixture::new().await;
    let s = Seed::new(&f.owner).await;
    let before: String = f.owner.query_one("SELECT row_to_json(r)::text FROM public.sealed_line_key_receipts r WHERE account_id=$1", &[&s.locator.account]).await.unwrap().get(0);
    let proof = read(&mut f.reader, s.locator, ORIGIN).await.unwrap();
    assert!(proof.identity() == s.identity);
    assert_eq!(proof.root_fingerprint(), &s.root_fingerprint);
    assert_eq!(
        proof.paired_signing_key_id(),
        &crate::sealed_manifest::key_id(4, &s.paired_point)
    );
    assert_eq!(proof.canonical_evidence(), s.canonical());
    assert_eq!(
        proof.evidence_digest(),
        &<[u8; 32]>::from(Sha256::digest(s.canonical()))
    );
    let after: String = f.owner.query_one("SELECT row_to_json(r)::text FROM public.sealed_line_key_receipts r WHERE account_id=$1", &[&s.locator.account]).await.unwrap().get(0);
    assert_eq!(before, after);
    f.owner
        .execute(
            "UPDATE public.device_keys SET revoked_at=clock_timestamp() WHERE account_id=$1",
            &[&s.locator.account],
        )
        .await
        .unwrap();
    f.owner.execute("UPDATE public.line_owner_approval_keys SET revoked_at=clock_timestamp() WHERE account_id=$1", &[&s.locator.account]).await.unwrap();
    assert!(read(&mut f.reader, s.locator, ORIGIN).await.is_ok());
    assert!(matches!(
        read(&mut f.reader, s.locator, "https://other.example").await,
        Err(ReadError::Refused)
    ));
    f.finish().await;
}

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL with disposable cluster administrator"]
async fn persisted_receipt_corruption_and_wrong_original_keys_are_refused() {
    let mut f = Fixture::new().await;
    let s = Seed::new(&f.owner).await;
    // Only this disposable owner corrupts historical rows to exercise the
    // reader's independent checks. Production immutability remains enabled.
    f.owner
        .batch_execute("ALTER TABLE public.sealed_line_key_receipts DISABLE TRIGGER USER")
        .await
        .unwrap();
    for mutation in [
        "root_signature=decode(repeat('00',64),'hex')",
        "approval_signature=decode(repeat('00',64),'hex')",
        "transcript=decode('00','hex')",
        "user_id=gen_random_uuid()",
        "session_id=gen_random_uuid()",
        "device_id=gen_random_uuid()",
        "line_id=gen_random_uuid()",
        "generation=2",
        "issued_ms=issued_ms+1",
        "expires_ms=expires_ms-1",
        "paired_fingerprint=decode(repeat('01',32),'hex')",
        "approval_point=decode(repeat('04',65),'hex')",
    ] {
        f.owner
            .batch_execute(&format!(
                "UPDATE public.sealed_line_key_receipts SET {mutation}"
            ))
            .await
            .unwrap();
        assert!(
            matches!(
                read(&mut f.reader, s.locator, ORIGIN).await,
                Err(ReadError::Refused)
            ),
            "{mutation}"
        );
        f.owner.execute("UPDATE public.sealed_line_key_receipts SET user_id=$1,session_id=$2,device_id=$3,line_id=$4,generation=1,transcript=$5,root_signature=$6,approval_signature=$7,approval_point=$8,paired_fingerprint=$9,issued_ms=$10,expires_ms=$11", &[&s.identity.user,&s.identity.owner_session,&s.identity.device,&s.identity.line,&s.transcript,&&s.root_signature[..],&&s.approval_signature[..],&&s.approval_point[..],&&s.paired_fingerprint[..],&s.issued,&s.expires]).await.unwrap();
    }
    f.owner
        .batch_execute("ALTER TABLE public.sealed_line_key_receipts ENABLE TRIGGER USER")
        .await
        .unwrap();
    f.owner
        .batch_execute("ALTER TABLE public.device_keys DISABLE TRIGGER USER")
        .await
        .unwrap();
    f.owner
        .execute(
            "UPDATE public.device_keys SET signing_key_sec1=$1",
            &[&&s.approval_point[..]],
        )
        .await
        .unwrap();
    assert!(matches!(
        read(&mut f.reader, s.locator, ORIGIN).await,
        Err(ReadError::Refused)
    ));
    f.owner
        .execute(
            "UPDATE public.device_keys SET signing_key_sec1=$1",
            &[&s.paired_point],
        )
        .await
        .unwrap();
    f.owner
        .batch_execute("ALTER TABLE public.device_keys ENABLE TRIGGER USER")
        .await
        .unwrap();
    assert!(read(&mut f.reader, s.locator, ORIGIN).await.is_ok());
    f.finish().await;
}

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL with disposable cluster administrator"]
async fn conflicting_fences_refuse_while_another_account_progresses() {
    let mut f = Fixture::new().await;
    let s = Seed::new(&f.owner).await;
    let other = Seed::new(&f.owner).await;
    let key = adapter_contract::account_fence_key(s.locator.account.as_bytes()).unwrap();
    let tx = f.owner.transaction().await.unwrap();
    tx.query_one("SELECT pg_advisory_xact_lock($1)", &[&key])
        .await
        .unwrap();
    assert!(matches!(
        read(&mut f.reader, s.locator, ORIGIN).await,
        Err(ReadError::Busy)
    ));
    assert!(read(&mut f.reader, other.locator, ORIGIN).await.is_ok());
    tx.rollback().await.unwrap();
    for query in [
        "SELECT account_id FROM public.sealed_manifest_authorities WHERE account_id=$1 FOR UPDATE",
        "SELECT account_id FROM public.payload_profile_account_anchors WHERE account_id=$1 FOR UPDATE",
        "SELECT id FROM public.accounts WHERE id=$1 FOR UPDATE",
        "SELECT account_id FROM public.sealed_line_key_receipts WHERE account_id=$1 FOR UPDATE",
        "SELECT account_id FROM public.device_keys WHERE account_id=$1 FOR UPDATE",
        "SELECT account_id FROM public.line_owner_approval_keys WHERE account_id=$1 FOR UPDATE",
    ] {
        let tx = f.owner.transaction().await.unwrap();
        tx.query_one(query, &[&s.locator.account]).await.unwrap();
        assert!(
            matches!(read(&mut f.reader,s.locator,ORIGIN).await,Err(ReadError::Database(ref e)) if e.code()==Some(&SqlState::LOCK_NOT_AVAILABLE)),
            "{query}"
        );
        assert!(read(&mut f.reader, other.locator, ORIGIN).await.is_ok());
        tx.rollback().await.unwrap();
    }
    assert!(read(&mut f.reader, s.locator, ORIGIN).await.is_ok());
    f.finish().await;
}

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL with disposable cluster administrator"]
async fn missing_or_disabled_account_history_and_temporary_shadows_never_supply_evidence() {
    let mut f = Fixture::new().await;
    let s = Seed::new(&f.owner).await;
    f.reader.batch_execute("CREATE TEMP TABLE sealed_line_key_receipts(fake boolean); CREATE TEMP TABLE sealed_manifest_authorities(fake boolean); CREATE TEMP TABLE payload_profile_account_anchors(fake boolean); SET search_path=pg_temp,pg_catalog").await.unwrap();
    assert!(read(&mut f.reader, s.locator, ORIGIN).await.is_ok());
    assert!(matches!(
        read(
            &mut f.reader,
            Locator {
                registration: Uuid::new_v4(),
                ..s.locator
            },
            ORIGIN
        )
        .await,
        Err(ReadError::Refused)
    ));
    f.owner
        .execute(
            "UPDATE public.accounts SET disabled_at=clock_timestamp() WHERE id=$1",
            &[&s.locator.account],
        )
        .await
        .unwrap();
    assert!(matches!(
        read(&mut f.reader, s.locator, ORIGIN).await,
        Err(ReadError::Refused)
    ));
    f.owner
        .execute(
            "UPDATE public.accounts SET disabled_at=NULL WHERE id=$1",
            &[&s.locator.account],
        )
        .await
        .unwrap();
    f.owner
        .batch_execute("ALTER TABLE public.payload_profile_account_anchors DISABLE TRIGGER USER")
        .await
        .unwrap();
    f.owner
        .execute(
            "DELETE FROM public.payload_profile_account_anchors WHERE account_id=$1",
            &[&s.locator.account],
        )
        .await
        .unwrap();
    f.owner
        .batch_execute("ALTER TABLE public.payload_profile_account_anchors ENABLE TRIGGER USER")
        .await
        .unwrap();
    assert!(matches!(
        read(&mut f.reader, s.locator, ORIGIN).await,
        Err(ReadError::Refused)
    ));
    f.finish().await;
}

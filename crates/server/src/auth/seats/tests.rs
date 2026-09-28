// SPDX-License-Identifier: AGPL-3.0-only
use super::*;
use crate::auth::{self, Role, login, register, verify_email};
use std::sync::Arc;
use tokio_postgres::NoTls;

/// The auth-side schema every seat test needs, applied in order.
const AUTH_MIGRATIONS: [&str; 9] = [
    include_str!("../../../../../deploy/compose/migrations/002_auth.sql"),
    include_str!("../../../../../deploy/compose/migrations/005_verification_outbox.sql"),
    include_str!("../../../../../deploy/compose/migrations/012_auth_abuse_limits.sql"),
    include_str!("../../../../../deploy/compose/migrations/013_owner_mfa.sql"),
    include_str!("../../../../../deploy/compose/migrations/014_owner_mfa_failure_budget.sql"),
    include_str!("../../../../../deploy/compose/migrations/016_auth_abuse_atomic.sql"),
    include_str!("../../../../../deploy/compose/migrations/025_account_recovery.sql"),
    include_str!("../../../../../deploy/compose/migrations/048_observer_memberships.sql"),
    include_str!("../../../../../deploy/compose/migrations/053_observer_seat_invitations.sql"),
];

/// Extra migrations for the observer device-status read, which shares the
/// enrollment status query and its tables.
const DEVICE_MIGRATIONS: [&str; 5] = [
    include_str!("../../../../../deploy/compose/migrations/001_foundation.sql"),
    include_str!("../../../../../deploy/compose/migrations/003_delivery.sql"),
    include_str!("../../../../../deploy/compose/migrations/004_enrollment.sql"),
    include_str!("../../../../../deploy/compose/migrations/041_device_preconditions.sql"),
    include_str!("../../../../../deploy/compose/migrations/047_device_network_service.sql"),
];

struct Fixture {
    db: Client,
    setup: Client,
    schema: String,
    url: String,
    hasher: Arc<TokenHasher>,
    owner: SessionPrincipal,
    owner_credentials: auth::SessionCredentials,
    password: String,
}

impl Fixture {
    async fn new(with_devices: bool) -> Self {
        let base =
            std::env::var("ZT_AUTH_TEST_DATABASE_URL").expect("disposable database required");
        let (setup, connection) = tokio_postgres::connect(&base, NoTls).await.unwrap();
        tokio::spawn(async move { connection.await.unwrap() });
        let schema = format!("observer_seats_{}", Uuid::new_v4().simple());
        setup
            .batch_execute(&format!("CREATE SCHEMA {schema}"))
            .await
            .unwrap();
        let separator = if base.contains('?') { '&' } else { '?' };
        let url = format!("{base}{separator}options=-csearch_path%3D{schema}");
        let (mut db, connection) = tokio_postgres::connect(&url, NoTls).await.unwrap();
        tokio::spawn(async move { connection.await.unwrap() });
        // 002 creates accounts and users, which the enrollment-side device
        // migrations reference; everything else follows it.
        db.batch_execute(AUTH_MIGRATIONS[0]).await.unwrap();
        if with_devices {
            for migration in DEVICE_MIGRATIONS {
                db.batch_execute(migration).await.unwrap();
            }
        }
        for migration in &AUTH_MIGRATIONS[1..] {
            db.batch_execute(migration).await.unwrap();
        }
        let hasher = Arc::new(TokenHasher::new(crate::test_keys::key(42)).unwrap());
        let password = format!("synthetic-{}", Uuid::new_v4());
        let signup = register(&mut db, &hasher, "owner@example.test", &password)
            .await
            .unwrap();
        assert!(
            verify_email(&mut db, &hasher, &signup.verification_token)
                .await
                .unwrap()
        );
        let owner_credentials = login(&db, &hasher, "owner@example.test", &password)
            .await
            .unwrap();
        let owner = auth::authenticate_session(&db, &hasher, &owner_credentials.token)
            .await
            .unwrap();
        assert_eq!(owner.role, Role::Owner);
        Self {
            db,
            setup,
            schema,
            url,
            hasher,
            owner,
            owner_credentials,
            password,
        }
    }

    /// A second, independent owner with its own account for tenant isolation.
    async fn other_owner(&mut self, email: &str) -> SessionPrincipal {
        let password = format!("synthetic-{}", Uuid::new_v4());
        let signup = register(&mut self.db, &self.hasher, email, &password)
            .await
            .unwrap();
        assert!(
            verify_email(&mut self.db, &self.hasher, &signup.verification_token)
                .await
                .unwrap()
        );
        let credentials = login(&self.db, &self.hasher, email, &password)
            .await
            .unwrap();
        auth::authenticate_session(&self.db, &self.hasher, &credentials.token)
            .await
            .unwrap()
    }

    async fn finish(self) {
        self.setup
            .batch_execute(&format!("DROP SCHEMA {} CASCADE", self.schema))
            .await
            .unwrap();
    }
}

/// Accept an invitation and verify the address with the chosen password,
/// returning the live observer session credentials.
async fn accept_and_verify(
    db: &mut Client,
    hasher: &TokenHasher,
    token: &str,
    password: &str,
    email: &str,
) -> auth::SessionCredentials {
    accept_invitation(db, hasher, token, password)
        .await
        .unwrap();
    let mail = crate::auth::claim_verification_mail(db, hasher)
        .await
        .unwrap()
        .expect("acceptance queues a verification code");
    assert_eq!(mail.email, email);
    assert!(
        crate::auth::verify_email_with_password(db, hasher, &mail.token, password)
            .await
            .unwrap()
    );
    login(db, hasher, email, password).await.unwrap()
}

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL; disposable observer seat schema"]
async fn invitation_acceptance_verification_and_sign_in_flow() {
    let mut f = Fixture::new(false).await;
    let issued = create_invitation(&mut f.db, &f.hasher, &f.owner, "observer@example.test")
        .await
        .unwrap();
    assert!(issued.token.starts_with("zti_"));
    assert_eq!(issued.email, "observer@example.test");
    // Only the HMAC of the token is stored, never the token itself.
    let stored: Vec<u8> =
        f.db.query_one(
            "SELECT token_hash FROM seat_invitations WHERE id=$1",
            &[&issued.id],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(
        stored,
        f.hasher.digest(b"seat-invitation-v1", &issued.token)
    );

    let page = list_seats(&f.db, &f.owner).await.unwrap();
    assert!(page.seats.is_empty());
    assert_eq!(page.invitations.len(), 1);
    assert_eq!(page.invitations[0].id, issued.id);
    assert!(page.invitations[0].accepted_at_ms.is_none());

    let credentials = accept_and_verify(
        &mut f.db,
        &f.hasher,
        &issued.token,
        &f.password,
        "observer@example.test",
    )
    .await;
    let observer = auth::authenticate_session(&f.db, &f.hasher, &credentials.token)
        .await
        .unwrap();
    assert_eq!(observer.role, Role::Observer);
    assert_eq!(observer.tenant.account_id(), f.owner.tenant.account_id());

    // The owner sees the seat as active and the invitation as accepted.
    let page = list_seats(&f.db, &f.owner).await.unwrap();
    assert_eq!(page.seats.len(), 1);
    assert_eq!(page.seats[0].email, "observer@example.test");
    assert!(page.seats[0].email_verified);
    assert!(page.seats[0].revoked_at_ms.is_none());
    assert!(page.invitations[0].accepted_at_ms.is_some());
    assert_eq!(
        page.invitations[0].accepted_user_id,
        Some(page.seats[0].user_id)
    );
    f.finish().await;
}

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL; disposable observer seat schema"]
async fn invitations_are_single_use_cancellable_and_expiry_bound() {
    let mut f = Fixture::new(false).await;
    let issued = create_invitation(&mut f.db, &f.hasher, &f.owner, "first@example.test")
        .await
        .unwrap();
    // Replay after acceptance: the second accept runs the same password work
    // and fails with the same error as an unknown token.
    accept_invitation(&mut f.db, &f.hasher, &issued.token, &f.password)
        .await
        .unwrap();
    assert!(matches!(
        accept_invitation(&mut f.db, &f.hasher, &issued.token, &f.password).await,
        Err(AuthError::InvalidCredentials)
    ));

    // Cancellation kills a live invitation permanently.
    let canceled = create_invitation(&mut f.db, &f.hasher, &f.owner, "second@example.test")
        .await
        .unwrap();
    assert!(
        cancel_invitation(&mut f.db, &f.owner, canceled.id)
            .await
            .unwrap()
    );
    assert!(
        !cancel_invitation(&mut f.db, &f.owner, canceled.id)
            .await
            .unwrap()
    );
    assert!(matches!(
        accept_invitation(&mut f.db, &f.hasher, &canceled.token, &f.password).await,
        Err(AuthError::InvalidCredentials)
    ));

    // Expiry is evaluated by the server clock at acceptance time.
    let expired = create_invitation(&mut f.db, &f.hasher, &f.owner, "third@example.test")
        .await
        .unwrap();
    f.db.execute(
        "UPDATE seat_invitations SET expires_at=now()-interval '1 second' WHERE id=$1",
        &[&expired.id],
    )
    .await
    .unwrap();
    assert!(matches!(
        accept_invitation(&mut f.db, &f.hasher, &expired.token, &f.password).await,
        Err(AuthError::InvalidCredentials)
    ));
    assert!(
        !invitation_token_is_live(&f.db, &f.hasher, &expired.token)
            .await
            .unwrap()
    );

    // Malformed tokens never reach the database probe.
    for malformed in ["", "zti_", "ztv_short", "zti_not-base64!"] {
        assert!(matches!(
            accept_invitation(&mut f.db, &f.hasher, malformed, &f.password).await,
            Err(AuthError::InvalidInput)
        ));
    }
    assert!(
        !invitation_token_is_live(&f.db, &f.hasher, "zti_not-base64!")
            .await
            .unwrap()
    );
    f.finish().await;
}

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL; disposable observer seat schema"]
async fn conflicting_existing_user_is_rejected_untouched() {
    let mut f = Fixture::new(false).await;
    // An existing owner address can never be claimed by an invitation.
    assert!(matches!(
        create_invitation(&mut f.db, &f.hasher, &f.owner, "owner@example.test").await,
        Err(AuthError::Conflict)
    ));

    // A user that appears after issuance blocks acceptance without being
    // modified: its password, membership, and the invitation all stay intact.
    let issued = create_invitation(&mut f.db, &f.hasher, &f.owner, "observer@example.test")
        .await
        .unwrap();
    let other_password = format!("synthetic-{}", Uuid::new_v4());
    let signup = register(
        &mut f.db,
        &f.hasher,
        "observer@example.test",
        &other_password,
    )
    .await
    .unwrap();
    assert!(matches!(
        accept_invitation(&mut f.db, &f.hasher, &issued.token, &f.password).await,
        Err(AuthError::Conflict)
    ));
    let row = f
        .db
        .query_one(
            "SELECT u.email_verified_at,m.role,m.revoked_at FROM users u JOIN memberships m ON m.user_id=u.id WHERE u.id=$1",
            &[&signup.user_id],
        )
        .await
        .unwrap();
    assert!(row.get::<_, Option<std::time::SystemTime>>(0).is_none());
    assert_eq!(row.get::<_, String>(1), "owner");
    assert!(row.get::<_, Option<std::time::SystemTime>>(2).is_none());
    // The invitation was not consumed by the refusal.
    let accepted: Option<std::time::SystemTime> =
        f.db.query_one(
            "SELECT accepted_at FROM seat_invitations WHERE id=$1",
            &[&issued.id],
        )
        .await
        .unwrap()
        .get(0);
    assert!(accepted.is_none());
    // The pre-existing account is intact: its owner verifies and signs in
    // with its own password, entirely unaffected by the invitation.
    assert!(
        verify_email(&mut f.db, &f.hasher, &signup.verification_token)
            .await
            .unwrap()
    );
    assert!(
        login(&f.db, &f.hasher, "observer@example.test", &other_password)
            .await
            .is_ok()
    );
    f.finish().await;
}

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL; disposable observer seat schema"]
async fn seat_removal_revokes_every_credential_and_never_resurrects() {
    let mut f = Fixture::new(false).await;
    let issued = create_invitation(&mut f.db, &f.hasher, &f.owner, "observer@example.test")
        .await
        .unwrap();
    let credentials = accept_and_verify(
        &mut f.db,
        &f.hasher,
        &issued.token,
        &f.password,
        "observer@example.test",
    )
    .await;
    let observer = auth::authenticate_session(&f.db, &f.hasher, &credentials.token)
        .await
        .unwrap();
    let observer_id = observer.user_id;
    // A stray reset code the seat could have used is dead after removal.
    let reset = crate::auth::random_token("ztr_");
    let reset_hash = f.hasher.digest(b"password-reset-v1", &reset);
    f.db
        .execute(
            "INSERT INTO password_resets(id,account_id,user_id,token_hash,expires_at) VALUES($1,$2,$3,$4,now()+interval '1 hour')",
            &[
                &Uuid::new_v4(),
                &f.owner.tenant.account_id(),
                &observer_id,
                &&reset_hash[..],
            ],
        )
        .await
        .unwrap();

    // The owner cannot be removed, and an unknown seat id is not found.
    assert!(
        !remove_observer(&mut f.db, &f.owner, f.owner.user_id)
            .await
            .unwrap()
    );
    assert!(
        !remove_observer(&mut f.db, &f.owner, Uuid::new_v4())
            .await
            .unwrap()
    );
    assert!(
        remove_observer(&mut f.db, &f.owner, observer_id)
            .await
            .unwrap()
    );

    // Every credential of the seat is dead: session, login, reset code.
    assert!(matches!(
        auth::authenticate_session(&f.db, &f.hasher, &credentials.token).await,
        Err(AuthError::Unauthorized)
    ));
    assert!(matches!(
        login(&f.db, &f.hasher, "observer@example.test", &f.password).await,
        Err(AuthError::InvalidCredentials)
    ));
    assert!(
        !crate::auth::account::reset_token_is_live(&f.db, &f.hasher, &reset)
            .await
            .unwrap()
    );
    assert_eq!(
        f.db.query_one(
            "SELECT count(*) FROM sessions WHERE user_id=$1 AND revoked_at IS NULL",
            &[&observer_id]
        )
        .await
        .unwrap()
        .get::<_, i64>(0),
        0
    );
    assert_eq!(
        f.db.query_one(
            "SELECT count(*) FROM password_resets WHERE user_id=$1 AND used_at IS NULL",
            &[&observer_id]
        )
        .await
        .unwrap()
        .get::<_, i64>(0),
        0
    );
    // Second removal is a no-op and the owner is unaffected.
    assert!(
        !remove_observer(&mut f.db, &f.owner, observer_id)
            .await
            .unwrap()
    );
    assert!(
        auth::authenticate_session(&f.db, &f.hasher, &f.owner_credentials.token)
            .await
            .is_ok()
    );

    // No request path restores the seat: the revoked tombstone stays.
    assert!(
        f.db.execute(
            "UPDATE memberships SET revoked_at=NULL WHERE user_id=$1",
            &[&observer_id]
        )
        .await
        .is_err()
    );
    // Re-accepting the consumed invitation cannot recreate the seat either.
    assert!(matches!(
        accept_invitation(&mut f.db, &f.hasher, &issued.token, &f.password).await,
        Err(AuthError::InvalidCredentials)
    ));
    // The owner still lists the tombstone as removed, not active.
    let page = list_seats(&f.db, &f.owner).await.unwrap();
    assert_eq!(page.seats.len(), 1);
    assert!(page.seats[0].revoked_at_ms.is_some());
    f.finish().await;
}

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL; disposable observer seat schema"]
async fn concurrent_accepts_and_cancel_race_have_one_winner() {
    let mut f = Fixture::new(false).await;
    let issued = create_invitation(&mut f.db, &f.hasher, &f.owner, "observer@example.test")
        .await
        .unwrap();
    let token_a = issued.token.clone();
    let token_b = issued.token.clone();
    let hasher = f.hasher.clone();
    let password = f.password.clone();
    let url = f.url.clone();
    let first = tokio::spawn(async move {
        let (mut client, connection) = tokio_postgres::connect(&url, NoTls).await.unwrap();
        tokio::spawn(async move { connection.await.unwrap() });
        accept_invitation(&mut client, &hasher, &token_a, &password).await
    });
    let second = {
        let url = f.url.clone();
        let hasher = f.hasher.clone();
        let password = f.password.clone();
        tokio::spawn(async move {
            let (mut client, connection) = tokio_postgres::connect(&url, NoTls).await.unwrap();
            tokio::spawn(async move { connection.await.unwrap() });
            accept_invitation(&mut client, &hasher, &token_b, &password).await
        })
    };
    let outcomes = [first.await.unwrap(), second.await.unwrap()];
    assert_eq!(
        outcomes.iter().filter(|result| result.is_ok()).count(),
        1,
        "exactly one concurrent acceptance wins"
    );
    assert_eq!(
        outcomes
            .iter()
            .filter(|result| matches!(result, Err(AuthError::InvalidCredentials)))
            .count(),
        1
    );

    // A cancel racing an acceptance can only lose once the row is claimed.
    let racing = create_invitation(&mut f.db, &f.hasher, &f.owner, "racer@example.test")
        .await
        .unwrap();
    let cancel_url = f.url.clone();
    let cancel_owner = f.owner.clone();
    let cancel_id = racing.id;
    let cancel = tokio::spawn(async move {
        let (mut client, connection) = tokio_postgres::connect(&cancel_url, NoTls).await.unwrap();
        tokio::spawn(async move { connection.await.unwrap() });
        cancel_invitation(&mut client, &cancel_owner, cancel_id).await
    });
    let acceptance = accept_invitation(&mut f.db, &f.hasher, &racing.token, &f.password).await;
    let canceled = cancel.await.unwrap().unwrap();
    match (acceptance.is_ok(), canceled) {
        // The acceptance won the row lock; the cancel then found it consumed.
        (true, false) => {}
        // The cancel won; the acceptance then failed the liveness recheck.
        (false, true) => assert!(matches!(acceptance, Err(AuthError::InvalidCredentials))),
        outcome => panic!("unexpected race outcome: {outcome:?}"),
    }
    f.finish().await;
}

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL; disposable observer seat schema"]
async fn seat_management_is_tenant_scoped() {
    let mut f = Fixture::new(false).await;
    let other = f.other_owner("other-owner@example.test").await;
    let issued = create_invitation(&mut f.db, &f.hasher, &f.owner, "observer@example.test")
        .await
        .unwrap();
    // Another account's owner sees none of this account's seats or
    // invitations and can neither cancel nor remove them.
    let stranger_page = list_seats(&f.db, &other).await.unwrap();
    assert!(stranger_page.seats.is_empty());
    assert!(stranger_page.invitations.is_empty());
    assert!(
        !cancel_invitation(&mut f.db, &other, issued.id)
            .await
            .unwrap()
    );
    let credentials = accept_and_verify(
        &mut f.db,
        &f.hasher,
        &issued.token,
        &f.password,
        "observer@example.test",
    )
    .await;
    let observer = auth::authenticate_session(&f.db, &f.hasher, &credentials.token)
        .await
        .unwrap();
    assert!(
        !remove_observer(&mut f.db, &other, observer.user_id)
            .await
            .unwrap()
    );
    // The observer itself cannot manage seats, not even its own.
    assert!(matches!(
        create_invitation(&mut f.db, &f.hasher, &observer, "another@example.test").await,
        Err(AuthError::Unauthorized)
    ));
    assert!(matches!(
        list_seats(&f.db, &observer).await,
        Err(AuthError::Unauthorized)
    ));
    assert!(matches!(
        remove_observer(&mut f.db, &observer, observer.user_id).await,
        Err(AuthError::Unauthorized)
    ));
    // An address can hold only one open invitation server-wide: once this
    // account invites it, another account's invitation is refused.
    let shared = create_invitation(&mut f.db, &f.hasher, &f.owner, "shared@example.test")
        .await
        .unwrap();
    assert!(matches!(
        create_invitation(&mut f.db, &f.hasher, &other, "shared@example.test").await,
        Err(AuthError::Conflict)
    ));
    assert!(
        cancel_invitation(&mut f.db, &f.owner, shared.id)
            .await
            .unwrap()
    );
    // After cancellation the address is free for the other account.
    assert!(
        create_invitation(&mut f.db, &f.hasher, &other, "shared@example.test")
            .await
            .is_ok()
    );
    f.finish().await;
}

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL; disposable observer seat schema"]
async fn seat_and_invitation_budgets_are_bounded() {
    let mut f = Fixture::new(false).await;
    for index in 0..MAX_OPEN_INVITATIONS {
        create_invitation(
            &mut f.db,
            &f.hasher,
            &f.owner,
            &format!("observer-{index}@example.test"),
        )
        .await
        .unwrap();
    }
    assert!(matches!(
        create_invitation(&mut f.db, &f.hasher, &f.owner, "overflow@example.test").await,
        Err(AuthError::Conflict)
    ));
    let page = list_seats(&f.db, &f.owner).await.unwrap();
    assert_eq!(page.invitations.len() as i64, MAX_OPEN_INVITATIONS);
    // Canceling one opens exactly one slot again.
    let victim = page.invitations.last().unwrap().id;
    assert!(
        cancel_invitation(&mut f.db, &f.owner, victim)
            .await
            .unwrap()
    );
    let overflow = create_invitation(&mut f.db, &f.hasher, &f.owner, "overflow@example.test")
        .await
        .unwrap();
    // An expired invitation no longer counts against the open cap.
    f.db.execute(
        "UPDATE seat_invitations SET expires_at=now()-interval '1 second' WHERE id=$1",
        &[&overflow.id],
    )
    .await
    .unwrap();
    let stale = create_invitation(&mut f.db, &f.hasher, &f.owner, "stale@example.test")
        .await
        .unwrap();

    // The live-observer seat cap also bounds invitation creation.
    for index in 0..MAX_ACTIVE_OBSERVERS {
        let user_id = Uuid::new_v4();
        f.db
            .execute(
                "INSERT INTO users(id,email,password_hash,email_verified_at) SELECT $1,$2,password_hash,now() FROM users WHERE id=$3",
                &[&user_id, &format!("bulk-{index}@example.test"), &f.owner.user_id],
            )
            .await
            .unwrap();
        f.db.execute(
            "INSERT INTO memberships(account_id,user_id,role) VALUES($1,$2,'observer')",
            &[&f.owner.tenant.account_id(), &user_id],
        )
        .await
        .unwrap();
    }
    assert!(matches!(
        create_invitation(&mut f.db, &f.hasher, &f.owner, "seat-overflow@example.test").await,
        Err(AuthError::Conflict)
    ));
    // Removing one seat frees the seat cap again.
    let page = list_seats(&f.db, &f.owner).await.unwrap();
    let victim = page.seats.last().unwrap().user_id;
    assert!(remove_observer(&mut f.db, &f.owner, victim).await.unwrap());
    // Freeing an invitation slot as well lets the creation through: both the
    // live-seat and open-invitation caps must be below their bounds.
    assert!(
        cancel_invitation(&mut f.db, &f.owner, stale.id)
            .await
            .unwrap()
    );
    assert!(
        create_invitation(&mut f.db, &f.hasher, &f.owner, "seat-overflow@example.test")
            .await
            .is_ok()
    );
    f.finish().await;
}

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL; disposable observer seat schema"]
async fn expired_unverified_observers_are_pending_user_pruning() {
    let mut f = Fixture::new(false).await;
    let issued = create_invitation(&mut f.db, &f.hasher, &f.owner, "observer@example.test")
        .await
        .unwrap();
    let acceptance = accept_invitation(&mut f.db, &f.hasher, &issued.token, &f.password)
        .await
        .unwrap();
    // A fresh unverified observer is never pruned.
    assert_eq!(prune_expired_pending_observers(&mut f.db).await.unwrap(), 0);
    f.db.execute(
        "UPDATE users SET created_at=now()-interval '2 days' WHERE id=$1",
        &[&acceptance.user_id],
    )
    .await
    .unwrap();
    assert_eq!(prune_expired_pending_observers(&mut f.db).await.unwrap(), 1);
    // The user, membership, and invitation link are gone; the invitation row
    // keeps only its audit columns and the address is free again.
    assert_eq!(
        f.db.query_one("SELECT count(*) FROM users", &[])
            .await
            .unwrap()
            .get::<_, i64>(0),
        1
    );
    assert_eq!(
        f.db.query_one("SELECT count(*) FROM memberships", &[])
            .await
            .unwrap()
            .get::<_, i64>(0),
        1
    );
    let row =
        f.db.query_one(
            "SELECT accepted_at,accepted_user_id FROM seat_invitations WHERE id=$1",
            &[&issued.id],
        )
        .await
        .unwrap();
    assert!(row.get::<_, Option<std::time::SystemTime>>(0).is_some());
    assert!(row.get::<_, Option<Uuid>>(1).is_none());
    assert!(
        create_invitation(&mut f.db, &f.hasher, &f.owner, "observer@example.test")
            .await
            .is_ok()
    );
    f.finish().await;
}

/// The complete owner and invitee browser flow over the real HTTP routes:
/// invite, list, accept, verify, sign in, read device status, and remove.
#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL; disposable observer seat schema"]
async fn observer_seat_browser_flow_over_http() {
    use axum::{
        body::{Body, to_bytes},
        http::{Request, StatusCode, header},
    };
    use tower::ServiceExt;

    let mut f = Fixture::new(true).await;
    let state = crate::http_auth::AuthHttpState::new(
        f.url.clone(),
        f.hasher.clone(),
        "https://example.test".into(),
        Arc::new(crate::http_auth::DisabledVerificationDispatcher),
    )
    .unwrap();
    let app = axum::Router::new()
        .nest("/auth", crate::http_auth::router(state))
        .nest(
            "/observer",
            crate::http_observer::router(crate::http_observer::ObserverState {
                database_url: f.url.clone(),
                auth_hasher: f.hasher.clone(),
            }),
        );
    let owner_cookie = format!(
        "__Host-zrotext_session={}; __Host-zrotext_csrf={}",
        f.owner_credentials.token, f.owner_credentials.csrf_token
    );

    let request = |method: &str, path: &str, cookie: &str, csrf: Option<&str>, body: String| {
        let mut builder = Request::builder()
            .method(method)
            .uri(path)
            .header("origin", "https://example.test")
            .header("cookie", cookie);
        if !body.is_empty() {
            builder = builder.header("content-type", "application/json");
        }
        if let Some(csrf) = csrf {
            builder = builder.header("x-zrotext-csrf", csrf);
        }
        builder.body(Body::from(body)).unwrap()
    };

    // The owner invites an observer and receives the token exactly once.
    let response = app
        .clone()
        .oneshot(request(
            "POST",
            "/auth/seats/invitations",
            &owner_cookie,
            Some(&f.owner_credentials.csrf_token),
            serde_json::json!({"email":"observer@example.test"}).to_string(),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);
    let body = to_bytes(response.into_body(), 65_536).await.unwrap();
    let issued: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let invitation_token = issued["token"].as_str().unwrap().to_owned();
    let invitation_id: Uuid = issued["id"].as_str().unwrap().parse().unwrap();
    assert!(invitation_token.starts_with("zti_"));

    // The owner lists the outstanding invitation.
    let response = app
        .clone()
        .oneshot(request(
            "GET",
            "/auth/seats",
            &owner_cookie,
            Some(&f.owner_credentials.csrf_token),
            String::new(),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), 65_536).await.unwrap();
    let seats: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(seats["invitations"].as_array().unwrap().len(), 1);
    assert_eq!(seats["invitations"][0]["status"], "open");

    // The invitee accepts with a fresh password; no cookies are needed.
    let observer_password = format!("synthetic-{}", Uuid::new_v4());
    let response = app
        .clone()
        .oneshot(request(
            "POST",
            "/auth/seats/accept",
            "",
            None,
            serde_json::json!({"token":invitation_token,"password":observer_password}).to_string(),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
    // A replay of the same token is rejected.
    let response = app
        .clone()
        .oneshot(request(
            "POST",
            "/auth/seats/accept",
            "",
            None,
            serde_json::json!({"token":invitation_token,"password":observer_password}).to_string(),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);

    // The invitee verifies independently with the queued code and password.
    let mail = crate::auth::claim_verification_mail(&mut f.db, &f.hasher)
        .await
        .unwrap()
        .expect("acceptance queued a verification code");
    let response = app
        .clone()
        .oneshot(request(
            "POST",
            "/auth/verify-email",
            "",
            None,
            serde_json::json!({"token":mail.token,"password":observer_password}).to_string(),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NO_CONTENT);

    // The verified invitee signs in and receives session cookies.
    let response = app
        .clone()
        .oneshot(request(
            "POST",
            "/auth/login",
            "",
            None,
            serde_json::json!({"email":"observer@example.test","password":observer_password})
                .to_string(),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
    let mut observer_session = String::new();
    let mut observer_csrf = String::new();
    for value in response.headers().get_all(header::SET_COOKIE) {
        let cookie = value.to_str().unwrap();
        if cookie.starts_with("__Host-zrotext_session=") {
            observer_session = cookie.split(';').next().unwrap().to_owned();
        } else if cookie.starts_with("__Host-zrotext_csrf=") {
            observer_csrf = cookie.split(';').next().unwrap().to_owned();
        }
    }
    let observer_cookie = format!("{observer_session}; {observer_csrf}");
    let observer_csrf_value = observer_csrf
        .split_once('=')
        .expect("csrf cookie")
        .1
        .to_owned();

    // The observer reads its own session metadata and the device status.
    let response = app
        .clone()
        .oneshot(request(
            "GET",
            "/auth/session",
            &observer_cookie,
            None,
            String::new(),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), 65_536).await.unwrap();
    let session: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(session["role"], "observer");
    let response = app
        .clone()
        .oneshot(request(
            "GET",
            "/observer/devices",
            &observer_cookie,
            Some(&observer_csrf_value),
            String::new(),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), 65_536).await.unwrap();
    let devices: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert!(devices["devices"].as_array().unwrap().is_empty());

    // Seat management stays owner-only, including for a signed-in observer.
    for (method, path) in [
        ("GET", "/auth/seats"),
        ("POST", "/auth/seats/invitations"),
        (
            "DELETE",
            format!("/auth/seats/invitations/{invitation_id}").as_str(),
        ),
    ] {
        let response = app
            .clone()
            .oneshot(request(
                method,
                path,
                &observer_cookie,
                Some(&observer_csrf_value),
                serde_json::json!({"email":"intruder@example.test"}).to_string(),
            ))
            .await
            .unwrap();
        assert_eq!(
            response.status(),
            StatusCode::UNAUTHORIZED,
            "{method} {path}"
        );
    }

    // The owner sees the active seat and removes it.
    let response = app
        .clone()
        .oneshot(request(
            "GET",
            "/auth/seats",
            &owner_cookie,
            Some(&f.owner_credentials.csrf_token),
            String::new(),
        ))
        .await
        .unwrap();
    let body = to_bytes(response.into_body(), 65_536).await.unwrap();
    let seats: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(seats["seats"].as_array().unwrap().len(), 1);
    assert_eq!(seats["seats"][0]["status"], "active");
    let observer_user_id: Uuid = seats["seats"][0]["user_id"]
        .as_str()
        .unwrap()
        .parse()
        .unwrap();
    let response = app
        .clone()
        .oneshot(request(
            "DELETE",
            &format!("/auth/seats/{observer_user_id}"),
            &owner_cookie,
            Some(&f.owner_credentials.csrf_token),
            String::new(),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NO_CONTENT);

    // The removed seat is dead: no sign-in, and the old session is revoked.
    let response = app
        .clone()
        .oneshot(request(
            "POST",
            "/auth/login",
            "",
            None,
            serde_json::json!({"email":"observer@example.test","password":observer_password})
                .to_string(),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    let response = app
        .clone()
        .oneshot(request(
            "GET",
            "/observer/devices",
            &observer_cookie,
            Some(&observer_csrf_value),
            String::new(),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

    // The owner still manages the account after the removal.
    let response = app
        .clone()
        .oneshot(request(
            "GET",
            "/auth/seats",
            &owner_cookie,
            Some(&f.owner_credentials.csrf_token),
            String::new(),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), 65_536).await.unwrap();
    let seats: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(seats["seats"][0]["status"], "removed");
    f.finish().await;
}

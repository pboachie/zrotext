// SPDX-License-Identifier: AGPL-3.0-only
//! Test-local acquisition of a genuine MFA-enrolled owner through the
//! maintained auth APIs. This is only the first step of opening-pair
//! preparation. Root, phone, interval, archive, socket and SDK producers are
//! not available here, so [`prepare_pair`] stays unavailable and its refusal is
//! never a successful pair.
use crate::auth::{
    self, AuthError, Role, TokenHasher,
    mfa::{self, MfaCipher},
};
use crate::sealed_manifest_store::tests::Fixture;
use totp_rs::{Builder, Secret};
use uuid::Uuid;

/// Private holder of the owner identity and final credentials. It is neither
/// `Debug`, `Display`, `Clone` nor serializable, and its fields cannot be read
/// outside this module except through the request-header accessors.
pub(super) struct GenuineOwner {
    account_id: Uuid,
    user_id: Uuid,
    session_id: Uuid,
    cookie: String,
    csrf: String,
}

impl GenuineOwner {
    pub(super) fn account_id(&self) -> Uuid {
        self.account_id
    }
    pub(super) fn user_id(&self) -> Uuid {
        self.user_id
    }
    pub(super) fn session_id(&self) -> Uuid {
        self.session_id
    }
    pub(super) fn cookie_header(&self) -> &str {
        &self.cookie
    }
    pub(super) fn csrf_header(&self) -> &str {
        &self.csrf
    }
}

/// Outcome of further preparation. The only reachable value is `Unavailable`.
pub(super) enum Preparation {
    Unavailable(Absent),
}

/// Producers that must be separately owned before a genuine pair can exist.
#[derive(Debug, Eq, PartialEq)]
pub(super) enum Absent {
    RootRecoveryAndArchive,
    EnrolledSocketAndAck,
    SdkCustodyAndExpected,
}

impl Preparation {
    pub(super) fn first_missing(&self) -> &Absent {
        match self {
            Self::Unavailable(absent) => absent,
        }
    }
    pub(super) fn is_genuine_pair(&self) -> bool {
        match self {
            Self::Unavailable(_) => false,
        }
    }
}

/// Refuses explicitly: no real producer exists in this module.
pub(super) fn prepare_pair(_owner: &GenuineOwner) -> Preparation {
    Preparation::Unavailable(Absent::RootRecoveryAndArchive)
}

/// Runs the real auth APIs end to end on the borrowed fixture connection.
pub(super) async fn acquire(f: &mut Fixture) -> GenuineOwner {
    let hasher = TokenHasher::new(crate::test_keys::key(84)).unwrap();
    let cipher = MfaCipher::new(crate::test_keys::key(85)).unwrap();
    let email = format!("{}@example.test", Uuid::new_v4().simple());
    let password = Uuid::new_v4().to_string();
    let wrong = Uuid::new_v4().to_string();
    let db = &mut f.db;
    // The borrowed fixture's train stops before this numbered auth migration,
    // which MFA enrollment confirmation requires. Apply the real file to the
    // same isolated schema rather than a substitute column.
    db.batch_execute(include_str!(
        "../../../../../../../deploy/compose/migrations/055_trusted_browser_epoch.sql"
    ))
    .await
    .unwrap();

    let signup = auth::register(db, &hasher, &email, &password)
        .await
        .unwrap();
    // An unverified address cannot sign in, and a wrong password cannot verify.
    assert!(matches!(
        auth::login(db, &hasher, &email, &password).await,
        Err(AuthError::EmailNotVerified)
    ));
    assert!(
        !auth::verify_email_with_password(db, &hasher, &signup.verification_token, &wrong)
            .await
            .unwrap()
    );
    assert!(
        auth::verify_email_with_password(db, &hasher, &signup.verification_token, &password)
            .await
            .unwrap()
    );

    let first = auth::login(db, &hasher, &email, &password).await.unwrap();
    let principal = auth::authenticate_session(db, &hasher, &first.token)
        .await
        .unwrap();
    assert_eq!(principal.session_id, first.id);
    assert_eq!(principal.tenant.account_id(), signup.account_id);
    assert_eq!(principal.user_id, signup.user_id);
    assert_eq!(principal.role, Role::Owner);

    let enrollment = mfa::begin_enrollment(db, &cipher, &principal, &password)
        .await
        .unwrap();
    let totp = Builder::new()
        .with_secret(Secret::try_from_base32(&enrollment.secret_base32).unwrap())
        .build()
        .unwrap();
    let recovery = mfa::confirm_enrollment(
        db,
        &cipher,
        &hasher,
        &principal,
        &totp.generate_current().to_string(),
    )
    .await
    .unwrap();
    assert!(!recovery.codes.is_empty());

    // A password alone no longer yields a session; it yields the challenge.
    let Err(AuthError::MfaRequired {
        account_id,
        user_id,
    }) = auth::login(db, &hasher, &email, &password).await
    else {
        panic!("password login must require the second factor");
    };
    assert_eq!((account_id, user_id), (signup.account_id, signup.user_id));
    let code = recovery.codes[0].clone();
    let challenge = mfa::begin_login_challenge(db, &hasher, account_id, user_id, &password)
        .await
        .unwrap();
    let credentials = mfa::complete_login(db, None, &hasher, &challenge, &code)
        .await
        .unwrap();
    // The recovery code is one-use: a new challenge cannot spend it again.
    let again = mfa::begin_login_challenge(db, &hasher, account_id, user_id, &password)
        .await
        .unwrap();
    assert!(matches!(
        mfa::complete_login(db, None, &hasher, &again, &code).await,
        Err(AuthError::InvalidCredentials)
    ));

    let finalized = auth::authenticate_session(db, &hasher, &credentials.token)
        .await
        .unwrap();
    assert_ne!(credentials.id, first.id);
    assert_ne!(credentials.token, first.token);
    assert_eq!(finalized.session_id, credentials.id);
    assert_eq!(finalized.tenant.account_id(), signup.account_id);
    assert_eq!(finalized.user_id, signup.user_id);
    assert_eq!(finalized.role, Role::Owner);
    GenuineOwner {
        account_id: finalized.tenant.account_id(),
        user_id: finalized.user_id,
        session_id: finalized.session_id,
        cookie: format!(
            "__Host-zrotext_session={}; __Host-zrotext_csrf={}",
            credentials.token, credentials.csrf_token
        ),
        csrf: credentials.csrf_token,
    }
}

#[test]
fn holder_is_not_debug_display_or_clone() {
    use std::{fmt, hint, marker::PhantomData};
    trait Fallback {
        const DEBUG: bool = false;
        const DISPLAY: bool = false;
        const CLONE: bool = false;
    }
    impl<T> Fallback for T {}
    struct Probe<T>(PhantomData<T>);
    #[allow(dead_code)]
    impl<T: fmt::Debug> Probe<T> {
        const DEBUG: bool = true;
    }
    #[allow(dead_code)]
    impl<T: fmt::Display> Probe<T> {
        const DISPLAY: bool = true;
    }
    #[allow(dead_code)]
    impl<T: Clone> Probe<T> {
        const CLONE: bool = true;
    }
    assert!(!hint::black_box(Probe::<GenuineOwner>::DEBUG));
    assert!(!hint::black_box(Probe::<GenuineOwner>::DISPLAY));
    assert!(!hint::black_box(Probe::<GenuineOwner>::CLONE));
    // Control: the probe does detect a type that has these traits.
    for has in [
        Probe::<String>::DEBUG,
        Probe::<String>::DISPLAY,
        Probe::<String>::CLONE,
    ] {
        assert!(hint::black_box(has));
    }
}

#[test]
fn further_preparation_is_unavailable_and_never_a_genuine_pair() {
    let owner = GenuineOwner {
        account_id: Uuid::nil(),
        user_id: Uuid::nil(),
        session_id: Uuid::nil(),
        cookie: String::new(),
        csrf: String::new(),
    };
    let outcome = prepare_pair(&owner);
    assert!(!outcome.is_genuine_pair());
    assert_eq!(outcome.first_missing(), &Absent::RootRecoveryAndArchive);
    // Every producer that is still missing is nameable; none is satisfied here.
    for absent in [
        Absent::RootRecoveryAndArchive,
        Absent::EnrolledSocketAndAck,
        Absent::SdkCustodyAndExpected,
    ] {
        assert!(!Preparation::Unavailable(absent).is_genuine_pair());
    }
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; isolated schema, real auth and MFA APIs"]
async fn real_auth_apis_yield_a_distinct_authenticated_mfa_owner() {
    let mut f = Fixture::without_authority().await;
    let owner = acquire(&mut f).await;
    assert_ne!(owner.account_id(), f.account);
    let row = f
        .db
        .query_one(
            "SELECT m.role,u.mfa_enabled,u.email_verified_at IS NOT NULL,s.revoked_at IS NULL FROM sessions s JOIN users u ON u.id=s.user_id JOIN memberships m ON (m.account_id,m.user_id)=(s.account_id,s.user_id) WHERE s.id=$1 AND s.account_id=$2 AND s.user_id=$3",
            &[&owner.session_id(), &owner.account_id(), &owner.user_id()],
        )
        .await
        .unwrap();
    assert_eq!(row.get::<_, String>(0), "owner");
    assert!(row.get::<_, bool>(1) && row.get::<_, bool>(2) && row.get::<_, bool>(3));
    assert!(owner.cookie_header().contains(owner.csrf_header()));
    assert!(!prepare_pair(&owner).is_genuine_pair());
    f.cleanup().await;
}

// SPDX-License-Identifier: AGPL-3.0-only
//! Durable, at-least-once email verification delivery. PostgreSQL stores no
//! raw verification code. The operational pepper reconstructs a code only for
//! a currently claimed, unexpired challenge.

use super::{
    AuthError, TokenHasher, VERIFICATION_HOURS, normalize_email, password_work,
    verification_token_for_id,
};
use tokio_postgres::Client;
use uuid::Uuid;

pub struct VerificationMail {
    pub verification_id: Uuid,
    pub lease_id: Uuid,
    pub attempt_count: i32,
    pub email: String,
    /// Secret: never place in logs, URLs, response bodies, or metrics.
    pub token: String,
}

/// Password proof prevents third parties from repeatedly mailing an address.
/// A generic HTTP response must be used for all `false` results. This database
/// throttle permits at most three resends per 24-hour window, 60 seconds apart.
/// Resends never extend the pending window that began at sign-up; after it
/// elapses the owner must sign up again, which replaces the expired record.
pub async fn request_verification_resend(
    client: &mut Client,
    hasher: &TokenHasher,
    email: &str,
    password: &str,
) -> Result<bool, AuthError> {
    let Ok(email) = normalize_email(email) else {
        return Ok(false);
    };
    let row = client
        .query_opt(
            "SELECT u.id,u.password_hash FROM users u JOIN memberships m ON m.user_id=u.id JOIN accounts a ON a.id=m.account_id WHERE u.email=$1 AND u.email_verified_at IS NULL AND u.created_at>now()-($2::integer * interval '1 hour') AND a.disabled_at IS NULL",
            &[&email, &VERIFICATION_HOURS],
        )
        .await?;
    let user_id = row.as_ref().map(|row| row.get::<_, Uuid>(0));
    let stored = row.as_ref().map(|row| row.get::<_, String>(1));
    match password_work::verify(password, stored.clone()).await {
        Ok(()) => {}
        Err(AuthError::InvalidCredentials) => return Ok(false),
        Err(error) => return Err(error),
    }
    let Some(user_id) = user_id else {
        return Ok(false);
    };
    let tx = client.transaction().await?;
    let permitted = tx
        .query_opt(
            "UPDATE users SET verification_resend_count=CASE WHEN verification_resend_window_at IS NULL OR verification_resend_window_at <= now()-interval '24 hours' THEN 1 ELSE verification_resend_count+1 END, verification_resend_window_at=CASE WHEN verification_resend_window_at IS NULL OR verification_resend_window_at <= now()-interval '24 hours' THEN now() ELSE verification_resend_window_at END, verification_resend_last_at=now() WHERE id=$1 AND password_hash=$2 AND email_verified_at IS NULL AND created_at>now()-($3::integer * interval '1 hour') AND (verification_resend_last_at IS NULL OR verification_resend_last_at <= now()-interval '60 seconds') AND (verification_resend_window_at IS NULL OR verification_resend_window_at <= now()-interval '24 hours' OR verification_resend_count<3) RETURNING id",
            &[&user_id, &stored, &VERIFICATION_HOURS],
        )
        .await?
        .is_some();
    if !permitted {
        tx.rollback().await?;
        return Ok(false);
    }
    // Resend the same code while valid. This also revives a dead-letter job
    // after the user explicitly requests it. Older pre-outbox challenges are
    // replaced because their random code cannot be reconstructed.
    let current = tx
        .query_opt(
            "SELECT v.id FROM email_verifications v JOIN verification_mail_outbox o ON o.verification_id=v.id WHERE v.user_id=$1 AND v.used_at IS NULL AND v.expires_at>now() ORDER BY v.created_at DESC LIMIT 1",
            &[&user_id],
        )
        .await?;
    if let Some(row) = current {
        let id: Uuid = row.get(0);
        tx.execute(
            "UPDATE verification_mail_outbox SET next_attempt_at=now(),attempt_count=0,lease_id=NULL,leased_until=NULL,delivered_at=NULL,canceled_at=NULL,dead_at=NULL WHERE verification_id=$1",
            &[&id],
        )
        .await?;
    } else {
        tx.execute(
            "UPDATE email_verifications SET used_at=now() WHERE user_id=$1 AND used_at IS NULL",
            &[&user_id],
        )
        .await?;
        let id = Uuid::new_v4();
        let token = verification_token_for_id(hasher, id);
        let token_hash = hasher.digest(b"email-verification-v1", &token);
        let account_id: Uuid = tx
            .query_one(
                "SELECT account_id FROM memberships WHERE user_id=$1",
                &[&user_id],
            )
            .await?
            .get(0);
        // A replacement code expires with the pending window, not after it.
        tx.execute(
            "INSERT INTO email_verifications(id,account_id,user_id,token_hash,expires_at) SELECT $1,$2,u.id,$4,u.created_at+($5::integer * interval '1 hour') FROM users u WHERE u.id=$3",
            &[&id, &account_id, &user_id, &&token_hash[..], &VERIFICATION_HOURS],
        )
        .await?;
        tx.execute(
            "INSERT INTO verification_mail_outbox(verification_id) VALUES($1)",
            &[&id],
        )
        .await?;
    }
    tx.commit().await?;
    Ok(true)
}

/// Claims at most one due mail with a five-minute lease. Multiple API sites
/// can poll concurrently; `SKIP LOCKED` and the lease UUID fence stale acks.
pub async fn claim_verification_mail(
    client: &mut Client,
    hasher: &TokenHasher,
) -> Result<Option<VerificationMail>, AuthError> {
    let tx = client.transaction().await?;
    let row = tx
        .query_opt(
            "SELECT o.verification_id,u.email,v.token_hash,o.attempt_count FROM verification_mail_outbox o JOIN email_verifications v ON v.id=o.verification_id JOIN users u ON u.id=v.user_id JOIN accounts a ON a.id=v.account_id WHERE o.delivered_at IS NULL AND o.canceled_at IS NULL AND o.dead_at IS NULL AND o.attempt_count<6 AND o.next_attempt_at<=now() AND (o.leased_until IS NULL OR o.leased_until<=now()) AND v.used_at IS NULL AND v.expires_at>now() AND u.email_verified_at IS NULL AND u.created_at>now()-($1::integer * interval '1 hour') AND a.disabled_at IS NULL ORDER BY o.next_attempt_at,o.verification_id LIMIT 1 FOR UPDATE OF o SKIP LOCKED",
            &[&VERIFICATION_HOURS],
        )
        .await?;
    let Some(row) = row else {
        tx.commit().await?;
        return Ok(None);
    };
    let verification_id: Uuid = row.get(0);
    let email: String = row.get(1);
    let stored_hash: Vec<u8> = row.get(2);
    let attempt_count: i32 = row.get::<_, i32>(3) + 1;
    let token = verification_token_for_id(hasher, verification_id);
    if stored_hash != hasher.digest(b"email-verification-v1", &token) {
        // Never mail a code that the verification route cannot accept.
        tx.execute(
            "UPDATE verification_mail_outbox SET dead_at=now() WHERE verification_id=$1",
            &[&verification_id],
        )
        .await?;
        tx.commit().await?;
        eprintln!("verification mail dead-lettered (category=integrity)");
        return Ok(None);
    }
    let lease_id = Uuid::new_v4();
    tx.execute(
        "UPDATE verification_mail_outbox SET lease_id=$2,leased_until=now()+interval '5 minutes',attempt_count=attempt_count+1 WHERE verification_id=$1",
        &[&verification_id, &lease_id],
    )
    .await?;
    tx.commit().await?;
    Ok(Some(VerificationMail {
        verification_id,
        lease_id,
        attempt_count,
        email,
        token,
    }))
}

/// An acknowledgement can only affect its own live claim. A failed SMTP
/// result may be ambiguous; retrying can deliver duplicate emails, never a
/// second account or a second usable code for the same challenge.
pub async fn ack_verification_mail(
    client: &Client,
    mail: &VerificationMail,
    delivered: bool,
) -> Result<bool, AuthError> {
    let changed = if delivered {
        client
            .execute(
                "UPDATE verification_mail_outbox SET delivered_at=now(),lease_id=NULL,leased_until=NULL WHERE verification_id=$1 AND lease_id=$2 AND canceled_at IS NULL AND delivered_at IS NULL",
                &[&mail.verification_id, &mail.lease_id],
            )
            .await?
    } else {
        client
            .execute(
                "UPDATE verification_mail_outbox SET lease_id=NULL,leased_until=NULL,next_attempt_at=now()+(power(2,least(attempt_count,5))::integer * interval '1 minute'),dead_at=CASE WHEN attempt_count>=6 THEN now() ELSE dead_at END WHERE verification_id=$1 AND lease_id=$2 AND canceled_at IS NULL AND delivered_at IS NULL",
                &[&mail.verification_id, &mail.lease_id],
            )
            .await?
    };
    Ok(changed == 1)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::{register, verify_email};
    use tokio_postgres::NoTls;

    #[tokio::test]
    #[ignore = "requires ZT_AUTH_TEST_DATABASE_URL; run the documented PostgreSQL test command"]
    async fn postgres_claim_ack_resend_and_expiry_are_fenced() {
        let base_url = std::env::var("ZT_AUTH_TEST_DATABASE_URL")
            .expect("set ZT_AUTH_TEST_DATABASE_URL for PostgreSQL-backed tests");
        let (setup, connection) = tokio_postgres::connect(&base_url, NoTls).await.unwrap();
        tokio::spawn(async move { connection.await.unwrap() });
        let schema = format!("outbox_test_{}", Uuid::new_v4().simple());
        setup
            .batch_execute(&format!("CREATE SCHEMA {schema}"))
            .await
            .unwrap();
        let url = format!("{base_url}?options=-csearch_path%3D{schema}");
        let (mut a, connection) = tokio_postgres::connect(&url, NoTls).await.unwrap();
        tokio::spawn(async move { connection.await.unwrap() });
        let (mut b, connection) = tokio_postgres::connect(&url, NoTls).await.unwrap();
        tokio::spawn(async move { connection.await.unwrap() });
        a.batch_execute(include_str!(
            "../../../../deploy/compose/migrations/002_auth.sql"
        ))
        .await
        .unwrap();
        a.batch_execute(include_str!(
            "../../../../deploy/compose/migrations/005_verification_outbox.sql"
        ))
        .await
        .unwrap();
        let hasher = TokenHasher::new(crate::test_keys::key(29)).unwrap();
        let signup = register(
            &mut a,
            &hasher,
            "owner@example.test",
            &crate::test_keys::password(1),
        )
        .await
        .unwrap();
        let first = claim_verification_mail(&mut a, &hasher)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(first.token, signup.verification_token);
        assert_eq!(first.email, "owner@example.test");
        assert!(
            claim_verification_mail(&mut b, &hasher)
                .await
                .unwrap()
                .is_none()
        );
        assert!(ack_verification_mail(&a, &first, false).await.unwrap());
        assert!(
            claim_verification_mail(&mut b, &hasher)
                .await
                .unwrap()
                .is_none()
        );
        a.execute(
            "UPDATE verification_mail_outbox SET next_attempt_at=now()-interval '1 second' WHERE verification_id=$1",
            &[&first.verification_id],
        )
        .await
        .unwrap();
        let retry = claim_verification_mail(&mut b, &hasher)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(retry.token, first.token);
        assert_ne!(retry.lease_id, first.lease_id);
        assert!(!ack_verification_mail(&a, &first, true).await.unwrap());
        assert!(ack_verification_mail(&b, &retry, true).await.unwrap());
        assert!(!ack_verification_mail(&b, &retry, true).await.unwrap());
        assert!(
            claim_verification_mail(&mut a, &hasher)
                .await
                .unwrap()
                .is_none()
        );
        // Label 3 is a fixture password this account never registered with.
        assert!(
            !request_verification_resend(
                &mut a,
                &hasher,
                "owner@example.test",
                &crate::test_keys::password(3)
            )
            .await
            .unwrap()
        );
        assert!(
            request_verification_resend(
                &mut a,
                &hasher,
                "owner@example.test",
                &crate::test_keys::password(1)
            )
            .await
            .unwrap()
        );
        assert!(
            !request_verification_resend(
                &mut a,
                &hasher,
                "owner@example.test",
                &crate::test_keys::password(1)
            )
            .await
            .unwrap()
        );
        let resent = claim_verification_mail(&mut b, &hasher)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(resent.token, first.token);
        assert!(verify_email(&mut a, &hasher, &resent.token).await.unwrap());
        assert!(!ack_verification_mail(&b, &resent, true).await.unwrap());
        assert!(
            claim_verification_mail(&mut a, &hasher)
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            !request_verification_resend(
                &mut a,
                &hasher,
                "owner@example.test",
                &crate::test_keys::password(1)
            )
            .await
            .unwrap()
        );
        setup
            .batch_execute(&format!("DROP SCHEMA {schema} CASCADE"))
            .await
            .unwrap();
    }

    #[tokio::test]
    #[ignore = "requires ZT_AUTH_TEST_DATABASE_URL; run the documented PostgreSQL test command"]
    async fn postgres_resend_limit_and_expired_code_rotation() {
        let base_url = std::env::var("ZT_AUTH_TEST_DATABASE_URL")
            .expect("set ZT_AUTH_TEST_DATABASE_URL for PostgreSQL-backed tests");
        let (setup, connection) = tokio_postgres::connect(&base_url, NoTls).await.unwrap();
        tokio::spawn(async move { connection.await.unwrap() });
        let schema = format!("outbox_limit_test_{}", Uuid::new_v4().simple());
        setup
            .batch_execute(&format!("CREATE SCHEMA {schema}"))
            .await
            .unwrap();
        let url = format!("{base_url}?options=-csearch_path%3D{schema}");
        let (mut client, connection) = tokio_postgres::connect(&url, NoTls).await.unwrap();
        tokio::spawn(async move { connection.await.unwrap() });
        client
            .batch_execute(include_str!(
                "../../../../deploy/compose/migrations/002_auth.sql"
            ))
            .await
            .unwrap();
        client
            .batch_execute(include_str!(
                "../../../../deploy/compose/migrations/005_verification_outbox.sql"
            ))
            .await
            .unwrap();
        let hasher = TokenHasher::new(crate::test_keys::key(31)).unwrap();
        let signup = register(
            &mut client,
            &hasher,
            "limit@example.test",
            &crate::test_keys::password(1),
        )
        .await
        .unwrap();
        client
            .execute(
                "UPDATE email_verifications SET expires_at=now()-interval '1 second' WHERE user_id=$1",
                &[&signup.user_id],
            )
            .await
            .unwrap();
        assert!(
            request_verification_resend(
                &mut client,
                &hasher,
                "limit@example.test",
                &crate::test_keys::password(1)
            )
            .await
            .unwrap()
        );
        let rotated = claim_verification_mail(&mut client, &hasher)
            .await
            .unwrap()
            .unwrap();
        assert_ne!(rotated.token, signup.verification_token);
        assert!(
            !verify_email(&mut client, &hasher, &signup.verification_token)
                .await
                .unwrap()
        );
        let mut claimed = rotated;
        for attempt in 0..6 {
            assert_eq!(claimed.attempt_count, attempt + 1);
            assert!(
                ack_verification_mail(&client, &claimed, false)
                    .await
                    .unwrap()
            );
            client
                .execute(
                    "UPDATE verification_mail_outbox SET next_attempt_at=now()-interval '1 second' WHERE verification_id=$1",
                    &[&claimed.verification_id],
                )
                .await
                .unwrap();
            if attempt < 5 {
                claimed = claim_verification_mail(&mut client, &hasher)
                    .await
                    .unwrap()
                    .unwrap();
            }
        }
        assert!(
            claim_verification_mail(&mut client, &hasher)
                .await
                .unwrap()
                .is_none()
        );
        for _ in 0..2 {
            client
                .execute(
                    "UPDATE users SET verification_resend_last_at=now()-interval '61 seconds' WHERE id=$1",
                    &[&signup.user_id],
                )
                .await
                .unwrap();
            assert!(
                request_verification_resend(
                    &mut client,
                    &hasher,
                    "limit@example.test",
                    &crate::test_keys::password(1)
                )
                .await
                .unwrap()
            );
        }
        assert!(
            claim_verification_mail(&mut client, &hasher)
                .await
                .unwrap()
                .is_some()
        );
        client
            .execute(
                "UPDATE users SET verification_resend_last_at=now()-interval '61 seconds' WHERE id=$1",
                &[&signup.user_id],
            )
            .await
            .unwrap();
        assert!(
            !request_verification_resend(
                &mut client,
                &hasher,
                "limit@example.test",
                &crate::test_keys::password(1)
            )
            .await
            .unwrap()
        );
        setup
            .batch_execute(&format!("DROP SCHEMA {schema} CASCADE"))
            .await
            .unwrap();
    }
}

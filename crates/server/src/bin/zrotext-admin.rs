// SPDX-License-Identifier: AGPL-3.0-only
//! Local operator bootstrap and password recovery. No HTTP route or
//! verification email is involved.

use std::{
    env,
    error::Error,
    io::{IsTerminal, Read},
};
use zeroize::Zeroizing;
use zrotext_server::{auth, http_auth::RegistrationPolicy, runtime_db};

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let arguments = env::args().skip(1).collect::<Vec<_>>();
    match arguments.as_slice() {
        [command, flag, email] if command == "create-owner" && flag == "--email" => {
            create_owner(email).await
        }
        [command, flag, email] if command == "issue-invite" && flag == "--email" => {
            issue_invite(email)
        }
        [command, flag, email] if command == "reset-password" && flag == "--email" => {
            reset_password(email).await
        }
        _ => Err(
            "usage: zrotext-admin create-owner|issue-invite|reset-password --email <address>"
                .into(),
        ),
    }
}

async fn create_owner(email: &str) -> Result<(), Box<dyn Error>> {
    match env::var("REGISTRATION_MODE") {
        Ok(mode) if mode != "closed" => {
            return Err("owner bootstrap requires REGISTRATION_MODE=closed".into());
        }
        Err(env::VarError::NotUnicode(_)) => {
            return Err("REGISTRATION_MODE must be valid UTF-8".into());
        }
        _ => {}
    }
    let password = read_password_from_stdin()?;
    let mut database = connect_database().await?;
    if !auth::bootstrap_owner(&mut database, email, &password).await? {
        return Err("owner bootstrap unavailable: database already contains an account".into());
    }
    println!("verified first owner created; close any temporary registration access");
    Ok(())
}

/// Recovery for instances without SMTP. Applies the same revocations as an
/// emailed reset: every session, owner API key, pending MFA login challenge
/// and outstanding reset code. MFA enrollment is preserved.
async fn reset_password(email: &str) -> Result<(), Box<dyn Error>> {
    let password = read_password_from_stdin()?;
    let mut database = connect_database().await?;
    if !auth::account::operator_reset_password(&mut database, email, &password).await? {
        return Err("no verified owner of an active account has that address".into());
    }
    println!(
        "password reset; all sessions and API keys issued by this owner were revoked; MFA enrollment is unchanged"
    );
    Ok(())
}

fn read_password_from_stdin() -> Result<Zeroizing<String>, Box<dyn Error>> {
    if std::io::stdin().is_terminal() {
        return Err(
            "pipe the password on stdin from a non-echoing prompt; never pass it as an argument"
                .into(),
        );
    }
    let mut password = Zeroizing::new(String::new());
    std::io::stdin()
        .lock()
        .take(1026)
        .read_to_string(&mut password)?;
    if password.ends_with("\r\n") {
        let length = password.len();
        password.truncate(length - 2);
    } else if password.ends_with('\n') {
        password.pop();
    }
    if password.bytes().any(|byte| byte == b'\r' || byte == b'\n')
        || !(12..=1024).contains(&password.len())
    {
        return Err("password on stdin must be one line of 12 to 1024 bytes".into());
    }
    Ok(password)
}

async fn connect_database() -> Result<runtime_db::PooledClient, Box<dyn Error>> {
    let database_url = env::var("DATABASE_URL")
        .map_err(|_| "DATABASE_URL must be set in the operator environment")?;
    Ok(runtime_db::connect(&database_url).await?)
}

fn optional_env(name: &'static str) -> Result<Option<String>, Box<dyn Error>> {
    match env::var(name) {
        Ok(value) if value.is_empty() => Ok(None),
        Ok(value) => Ok(Some(value)),
        Err(env::VarError::NotPresent) => Ok(None),
        Err(env::VarError::NotUnicode(_)) => Err(format!("{name} must be valid UTF-8").into()),
    }
}

fn issue_invite(email: &str) -> Result<(), Box<dyn Error>> {
    let mode = optional_env("REGISTRATION_MODE")?;
    let emails = optional_env("REGISTRATION_ALLOWED_EMAILS")?;
    let domains = optional_env("REGISTRATION_ALLOWED_DOMAINS")?;
    let key = optional_env("REGISTRATION_ENROLLMENT_KEY_B64")?.map(Zeroizing::new);
    let policy = RegistrationPolicy::parse(
        mode.as_deref(),
        emails.as_deref(),
        domains.as_deref(),
        key.as_ref().map(|key| key.as_str()),
    )?;
    let invite = policy.issue_invite(email)?;
    println!("{invite}");
    Ok(())
}

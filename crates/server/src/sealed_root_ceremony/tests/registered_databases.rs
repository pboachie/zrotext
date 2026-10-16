// SPDX-License-Identifier: AGPL-3.0-only
//! Test-only database selection. A schema cannot isolate concurrent index builds
//! from another schema's old snapshots in the same database.
use tokio_postgres::Config;
use zeroize::Zeroizing;

const STANDARD: [&str; 5] = [
    "ZT_AUTH_TEST_DATABASE_URL",
    "ZT_DELIVERY_TEST_DATABASE_URL",
    "ZT_INBOUND_TEST_DATABASE_URL",
    "ZT_FAILOVER_TEST_DATABASE_URL",
    "ZT_POSTGRES_TLS_TEST_DATABASE_URL",
];

fn explicit_name(config: &Config, control: bool) -> Result<&str, &'static str> {
    let name = config
        .get_dbname()
        .ok_or("explicit test database required")?;
    // Deliberately narrow fixture profile, never lowercasing/normalizing input.
    // Actual connected current_database() is also compared on every connection.
    if name.is_empty()
        || name.len() > 63
        || !name.as_bytes()[0].is_ascii_lowercase()
        || !name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
        || matches!(name, "template0" | "template1")
        || control && name == "postgres"
    {
        return Err("unsupported explicit test database name");
    }
    Ok(name)
}

fn parse(value: &str) -> Result<Config, &'static str> {
    value
        .parse()
        .map_err(|_| "invalid test database configuration")
}

fn select(
    empty: &str,
    mfa: &str,
    standard: &[&str],
    recovery_login: bool,
) -> Result<Config, &'static str> {
    let empty = parse(empty)?;
    let mfa = parse(mfa)?;
    let empty_name = explicit_name(&empty, true)?;
    let mfa_name = explicit_name(&mfa, true)?;
    if empty_name == mfa_name {
        return Err("registered controls require distinct databases");
    }
    for value in standard {
        let config = parse(value)?;
        let name = explicit_name(&config, false)?;
        // Conservatively reject equal names even across hosts/ports. Hostname
        // aliases and user/URL spelling cannot establish database isolation.
        if name == empty_name || name == mfa_name {
            return Err("registered control overlaps a standard test database");
        }
    }
    Ok(if recovery_login { mfa } else { empty })
}

pub(super) fn configuration(recovery_login: bool) -> Result<Config, String> {
    // Never fall back to a shared URL or PostgreSQL's user-derived dbname.
    let empty = Zeroizing::new(
        std::env::var("ZT_REGISTERED_OWNER_EMPTY_DATABASE_URL")
            .map_err(|_| "requires explicit registered empty-control database")?,
    );
    let mfa = Zeroizing::new(
        std::env::var("ZT_REGISTERED_OWNER_MFA_DATABASE_URL")
            .map_err(|_| "requires explicit registered MFA-control database")?,
    );
    let mut standard = Vec::new();
    for name in STANDARD {
        match std::env::var(name) {
            Ok(value) => standard.push(Zeroizing::new(value)),
            Err(std::env::VarError::NotPresent) => {}
            Err(_) => return Err("invalid standard test database configuration".into()),
        }
    }
    let refs = standard
        .iter()
        .map(|value| value.as_str())
        .collect::<Vec<_>>();
    select(&empty, &mfa, &refs, recovery_login).map_err(str::to_owned)
}

#[cfg(test)]
mod tests {
    use super::*;

    const EMPTY: &str = "postgresql://ordinary@localhost/zt_registered_empty";
    const MFA: &str = "postgresql://ordinary@localhost/zt_registered_mfa";

    #[test]
    fn explicit_pair_selects_only_its_owned_database_without_changing_role() {
        let standard = ["postgresql://postgres@localhost/postgres"; 4];
        for recovery in [false, true] {
            let config = select(EMPTY, MFA, &standard, recovery).unwrap();
            assert_eq!(config.get_user(), Some("ordinary"));
            assert_eq!(
                config.get_dbname(),
                Some(if recovery {
                    "zt_registered_mfa"
                } else {
                    "zt_registered_empty"
                })
            );
        }
    }

    #[test]
    fn missing_default_reserved_and_unsupported_names_refuse_without_normalization() {
        for value in [
            "",
            "postgresql://ordinary@localhost",
            "host=localhost user=ordinary",
            "host=localhost dbname=''",
            "postgresql://ordinary@localhost/postgres",
            "postgresql://ordinary@localhost/template0",
            "postgresql://ordinary@localhost/template1",
            "postgresql://ordinary@localhost/Quoted",
            "postgresql://ordinary@localhost/space%20name",
            "postgresql://ordinary@localhost/%24user",
        ] {
            assert!(select(value, MFA, &[], false).is_err());
            assert!(select(EMPTY, value, &[], true).is_err());
        }
        let overlong = format!("host=localhost dbname={}", "a".repeat(64));
        assert!(select(&overlong, MFA, &[], false).is_err());
    }

    #[test]
    fn both_controls_are_validated_even_when_only_one_is_selected() {
        assert!(select(EMPTY, "", &[], false).is_err());
        assert!(select("", MFA, &[], true).is_err());
        assert!(select(EMPTY, EMPTY, &[], false).is_err());
    }

    #[test]
    fn hostname_port_user_and_url_aliases_cannot_hide_a_database_collision() {
        for colliding in [
            "postgresql://different@alias.example.test/zt_registered_empty",
            "postgresql://ordinary@localhost:6543/zt_registered_empty",
            "host=localhost user=ordinary dbname=zt_registered_empty",
            "postgresql://ordinary@localhost/zt_registered_%65mpty",
        ] {
            assert!(select(EMPTY, colliding, &[], false).is_err());
            assert!(select(EMPTY, MFA, &[colliding], false).is_err());
            assert!(select(EMPTY, MFA, &[colliding], true).is_err());
        }
        for slot in 0..STANDARD.len() {
            let mut standard = ["postgresql://ordinary@localhost/postgres"; STANDARD.len()];
            standard[slot] = MFA;
            assert!(select(EMPTY, MFA, &standard, false).is_err());
        }
    }

    #[test]
    fn configured_standard_urls_must_have_explicit_unambiguous_database_names() {
        for standard in [
            "",
            "host=localhost user=ordinary",
            "invalid",
            "host=localhost dbname=Template",
        ] {
            assert!(select(EMPTY, MFA, &[standard], false).is_err());
        }
    }

    #[test]
    fn errors_do_not_echo_untrusted_connection_configuration() {
        let input = "host=alias.example.test unexpected=untrusted-fixture-input";
        let error = select(input, MFA, &[], false).err().unwrap();
        assert_eq!(error, "invalid test database configuration");
        assert!(!error.contains("untrusted-fixture-input"));
        assert!(!error.contains("alias.example.test"));
    }
}

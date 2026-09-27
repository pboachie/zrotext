// SPDX-License-Identifier: AGPL-3.0-only
//! Environment policy for the independent-quorum failover decision module.
//!
//! Mirrors the `AlphaPolicy::parse` convention: a pure function over the
//! environment values, called by the server binary with `env::var` results, so
//! the default-disabled behavior stays unit-testable. The module is disabled
//! unless `FAILOVER_QUORUM_ENABLED=true` and a well-formed three-member
//! configuration is supplied.

/// Number of independent failure domains the design requires before an
/// automatic failover decision can be trusted
/// (`MULTI-LOCATION.md`, "Automatic failover needs an independent decision").
pub const REQUIRED_MEMBERS: usize = 3;

/// Parsed `FAILOVER_QUORUM_ENABLED` / `FAILOVER_QUORUM_MEMBERS` configuration.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QuorumPolicy {
    members: Vec<String>,
}

impl QuorumPolicy {
    /// Parse the failover-quorum configuration. `enabled` is the raw
    /// `FAILOVER_QUORUM_ENABLED` value and `members` the raw
    /// `FAILOVER_QUORUM_MEMBERS` value; `None` means unset. Disabled is the
    /// default: absent or `false` returns a disabled policy that requires no
    /// member configuration. Invalid values fail closed with an error instead
    /// of guessing.
    pub fn parse(enabled: Option<&str>, members: Option<&str>) -> Result<Self, String> {
        match enabled {
            None | Some("false") => Ok(Self::disabled()),
            Some("true") => parse_members(members),
            Some(_) => Err("FAILOVER_QUORUM_ENABLED must be true or false".to_owned()),
        }
    }

    /// The disabled default: no decision is ever taken and no further
    /// configuration is read.
    pub fn disabled() -> Self {
        Self {
            members: Vec::new(),
        }
    }

    /// Whether any failover-quorum behavior is active in this process.
    pub fn enabled(&self) -> bool {
        !self.members.is_empty()
    }

    /// The configured quorum member identifiers, empty when disabled.
    pub fn members(&self) -> &[String] {
        &self.members
    }
}

fn parse_members(members: Option<&str>) -> Result<QuorumPolicy, String> {
    let raw =
        members.ok_or("FAILOVER_QUORUM_MEMBERS is required when FAILOVER_QUORUM_ENABLED=true")?;
    let parsed: Vec<String> = raw.split(',').map(str::trim).map(str::to_owned).collect();
    if parsed.len() != REQUIRED_MEMBERS {
        return Err(format!(
            "FAILOVER_QUORUM_MEMBERS must list exactly {REQUIRED_MEMBERS} members"
        ));
    }
    if parsed.iter().any(String::is_empty) {
        return Err("FAILOVER_QUORUM_MEMBERS must not contain empty member identifiers".to_owned());
    }
    for (index, member) in parsed.iter().enumerate() {
        if parsed[..index].contains(member) {
            return Err("FAILOVER_QUORUM_MEMBERS must list distinct members".to_owned());
        }
    }
    Ok(QuorumPolicy { members: parsed })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn policy_is_disabled_by_default_and_ignores_member_configuration() {
        let policy = QuorumPolicy::parse(None, None).unwrap();
        assert!(!policy.enabled());
        assert!(policy.members().is_empty());
        // Even a garbage member list is not read while the flag is off.
        let policy = QuorumPolicy::parse(None, Some("only-one,,duplicate,,x")).unwrap();
        assert!(!policy.enabled());
        let policy = QuorumPolicy::parse(Some("false"), None).unwrap();
        assert!(!policy.enabled());
    }

    #[test]
    fn enabled_policy_requires_exactly_three_distinct_members() {
        let policy =
            QuorumPolicy::parse(Some("true"), Some("workload-a, workload-b, witness")).unwrap();
        assert!(policy.enabled());
        assert_eq!(policy.members(), ["workload-a", "workload-b", "witness"]);
        assert!(
            QuorumPolicy::parse(Some("true"), None).is_err(),
            "missing members must fail closed"
        );
        assert!(
            QuorumPolicy::parse(Some("true"), Some("workload-a,workload-b")).is_err(),
            "two members cannot form an independent quorum"
        );
        assert!(
            QuorumPolicy::parse(Some("true"), Some("a,b,c,d")).is_err(),
            "a fourth member changes the failure domain assumptions"
        );
        assert!(
            QuorumPolicy::parse(Some("true"), Some("a,b,")).is_err(),
            "empty identifiers are rejected"
        );
        assert!(
            QuorumPolicy::parse(Some("true"), Some("a,b,a")).is_err(),
            "duplicate members are rejected"
        );
    }

    #[test]
    fn invalid_flag_value_fails_closed() {
        assert!(QuorumPolicy::parse(Some("1"), None).is_err());
        assert!(QuorumPolicy::parse(Some("yes"), None).is_err());
        assert!(QuorumPolicy::parse(Some("TRUE"), None).is_err());
    }
}

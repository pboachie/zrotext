// SPDX-License-Identifier: AGPL-3.0-only
//! Explicitly scoped synthetic-content test traffic. Never use for customer messages.

use std::collections::HashSet;
use uuid::Uuid;

#[derive(Clone, Debug)]
pub struct AlphaPolicy {
    enabled: bool,
    allowed_accounts: HashSet<Uuid>,
    allowed_recipients: HashSet<String>,
}

impl AlphaPolicy {
    pub fn parse(
        enabled: Option<&str>,
        account_ids: Option<&str>,
        recipients: Option<&str>,
    ) -> Result<Self, &'static str> {
        let enabled = match enabled {
            None | Some("false") => false,
            Some("true") => true,
            _ => return Err("SYNTHETIC_ALPHA_ENABLED must be true or false"),
        };
        if !enabled {
            return Ok(Self {
                enabled: false,
                allowed_accounts: HashSet::new(),
                allowed_recipients: HashSet::new(),
            });
        }
        let account_ids = account_ids.ok_or("synthetic alpha account allowlist is required")?;
        let recipients = recipients.ok_or("synthetic alpha recipient allowlist is required")?;
        let allowed_accounts = account_ids
            .split(',')
            .map(|value| {
                let id = Uuid::parse_str(value).map_err(|_| "invalid synthetic alpha account")?;
                (id.to_string() == value)
                    .then_some(id)
                    .ok_or("invalid synthetic alpha account")
            })
            .collect::<Result<HashSet<_>, _>>()?;
        let allowed_recipients = recipients
            .split(',')
            .map(|value| {
                let valid = value.starts_with('+')
                    && (3..=16).contains(&value.len())
                    && value.as_bytes()[1] != b'0'
                    && value.as_bytes()[1..].iter().all(u8::is_ascii_digit);
                valid
                    .then(|| value.to_owned())
                    .ok_or("invalid synthetic alpha recipient")
            })
            .collect::<Result<HashSet<_>, _>>()?;
        if allowed_accounts.is_empty() || allowed_recipients.is_empty() {
            return Err("synthetic alpha allowlists must not be empty");
        }
        Ok(Self {
            enabled,
            allowed_accounts,
            allowed_recipients,
        })
    }

    pub fn enabled(&self) -> bool {
        self.enabled
    }

    pub fn allows(&self, account_id: Uuid, recipient_e164: &str) -> bool {
        self.enabled
            && self.allowed_accounts.contains(&account_id)
            && self.allowed_recipients.contains(recipient_e164)
    }

    pub fn allows_account(&self, account_id: Uuid) -> bool {
        self.enabled && self.allowed_accounts.contains(&account_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn disabled_policy_is_closed() {
        let account = Uuid::new_v4();
        let policy = AlphaPolicy::parse(None, None, None).unwrap();
        assert!(!policy.allows(account, "+15555550101"));
        assert!(!policy.allows_account(account));
    }

    #[test]
    fn enabled_policy_requires_exact_allowlists() {
        let account = Uuid::new_v4();
        let policy = AlphaPolicy::parse(
            Some("true"),
            Some(&account.to_string()),
            Some("+15555550101"),
        )
        .unwrap();
        assert!(policy.allows(account, "+15555550101"));
        assert!(!policy.allows(account, "+15555550102"));
        assert!(!policy.allows(Uuid::new_v4(), "+15555550101"));
        assert!(AlphaPolicy::parse(Some("true"), None, Some("+15555550101")).is_err());
        assert!(
            AlphaPolicy::parse(Some("true"), Some(&account.to_string()), Some("+0123")).is_err()
        );
        assert!(AlphaPolicy::parse(Some("TRUE"), None, None).is_err());
    }
}

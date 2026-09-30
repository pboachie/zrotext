// SPDX-License-Identifier: AGPL-3.0-only
//! Founder gating for the one-device outbound MMS spike (#438). The server,
//! not the phone, decides whether a spike attempt may run: a grant frame is
//! issued only when the founder has enabled the feature, named the one
//! gateway device, and allowlisted the controlled recipient, and only while
//! that recipient has not stopped (suppression or owner hold). Disabled by
//! default; a missing or malformed setting keeps the whole feature off.

use std::collections::HashSet;
use uuid::Uuid;

/// How far ahead the grant frame's expiry may sit. The phone's validator
/// accepts at most 35 seconds, so the server issues 30 to leave room for
/// clock skew and stream delay.
pub(crate) const MMS_SPIKE_GRANT_TTL_MS: i64 = 30_000;

#[derive(Clone, Debug)]
pub struct MmsSpikePolicy {
    enabled: bool,
    device: Uuid,
    recipients: HashSet<String>,
}

impl MmsSpikePolicy {
    pub fn parse(
        enabled: Option<&str>,
        device_id: Option<&str>,
        recipients: Option<&str>,
    ) -> Result<Self, &'static str> {
        let enabled = match enabled {
            None | Some("false") => false,
            Some("true") => true,
            _ => return Err("MMS_SPIKE_GRANT_ENABLED must be true or false"),
        };
        if !enabled {
            return Ok(Self::disabled());
        }
        let device = device_id.ok_or("MMS spike device is required when enabled")?;
        let device = Uuid::parse_str(device)
            .ok()
            .filter(|id| id.to_string() == device)
            .ok_or("invalid MMS spike device id")?;
        let recipients = recipients.ok_or("MMS spike recipient allowlist is required")?;
        let recipients = recipients
            .split(',')
            .map(|value| value.trim())
            .filter(|value| !value.is_empty())
            .map(|value| {
                valid_recipient(value)
                    .then(|| value.to_owned())
                    .ok_or("invalid MMS spike recipient")
            })
            .collect::<Result<HashSet<_>, _>>()?;
        if recipients.is_empty() {
            return Err("MMS spike recipient allowlist must not be empty");
        }
        Ok(Self {
            enabled,
            device,
            recipients,
        })
    }

    pub fn disabled() -> Self {
        Self {
            enabled: false,
            device: Uuid::nil(),
            recipients: HashSet::new(),
        }
    }

    pub fn enabled(&self) -> bool {
        self.enabled
    }

    /// The one device the founder named, if the feature is on.
    pub fn gated_device(&self) -> Option<Uuid> {
        self.enabled.then_some(self.device)
    }

    /// The allowlisted recipients in a stable order (configuration order is
    /// lost by the set; sorted so grant issuance is deterministic).
    pub fn recipients(&self) -> Vec<&str> {
        let mut values: Vec<&str> = self.recipients.iter().map(String::as_str).collect();
        values.sort_unstable();
        values
    }

    pub fn allows_recipient(&self, recipient_e164: &str) -> bool {
        self.enabled && self.recipients.contains(recipient_e164)
    }
}

/// Same E.164 shape the phone's build allowlist and `MmsSpikePolicy.E164`
/// accept: `+` followed by 2..=15 digits, first digit 1-9.
fn valid_recipient(value: &str) -> bool {
    value.starts_with('+')
        && (3..=16).contains(&value.len())
        && value.as_bytes()[1] != b'0'
        && value.as_bytes()[1..].iter().all(u8::is_ascii_digit)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn device() -> String {
        "01234567-89ab-cdef-0123-456789abcdef".to_string()
    }

    #[test]
    fn missing_or_false_settings_keep_the_spike_off() {
        assert!(!MmsSpikePolicy::parse(None, None, None).unwrap().enabled());
        assert!(
            !MmsSpikePolicy::parse(Some("false"), Some(&device()), Some("+15551234567"))
                .unwrap()
                .enabled()
        );
        assert!(
            MmsSpikePolicy::parse(Some("false"), None, None)
                .unwrap()
                .gated_device()
                .is_none()
        );
    }

    #[test]
    fn enabled_requires_a_well_formed_device_and_allowlist() {
        let policy = MmsSpikePolicy::parse(
            Some("true"),
            Some(&device()),
            Some("+15551234567,+15557654321"),
        )
        .unwrap();
        assert_eq!(policy.gated_device(), Some(device().parse().unwrap()));
        assert_eq!(policy.recipients(), vec!["+15551234567", "+15557654321"]);
        assert!(policy.allows_recipient("+15551234567"));
        assert!(!policy.allows_recipient("+15550000000"));

        assert!(MmsSpikePolicy::parse(Some("true"), None, None).is_err());
        assert!(MmsSpikePolicy::parse(Some("true"), Some(&device()), None).is_err());
        assert!(MmsSpikePolicy::parse(Some("true"), Some(&device()), Some("")).is_err());
        assert!(
            MmsSpikePolicy::parse(Some("true"), Some(&device()), Some("+1555123456X")).is_err()
        );
        // A leading zero, a missing plus, and an over-long entry all refuse.
        assert!(
            MmsSpikePolicy::parse(Some("true"), Some(&device()), Some("+05551234567")).is_err()
        );
        assert!(MmsSpikePolicy::parse(Some("true"), Some(&device()), Some("15551234567")).is_err());
        assert!(
            MmsSpikePolicy::parse(Some("true"), Some(&device()), Some("+155512345678901234"))
                .is_err()
        );
        // A malformed device id (non-canonical form) refuses.
        assert!(
            MmsSpikePolicy::parse(Some("true"), Some("not-a-uuid"), Some("+15551234567")).is_err()
        );
        assert!(MmsSpikePolicy::parse(Some("yes"), None, None).is_err());
        // An empty or wrongly-cased flag refuses startup rather than
        // silently enabling or disabling the spike (audit mutation M02).
        for value in ["", "TRUE", "True", "on", "0", "1"] {
            assert!(
                MmsSpikePolicy::parse(Some(value), None, None).is_err(),
                "flag {value:?} must refuse startup"
            );
        }
    }
}

// SPDX-License-Identifier: AGPL-3.0-only
//! Immutable window identities bound by the existing exact-action approval.
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct WindowPolicy {
    pub timezone: Option<String>,
    pub first_local_date: String,
    pub opens_minute: u16,
    pub closes_minute: u16,
    pub repeat_every_days: Option<u16>,
    pub max_occurrences: u16,
    pub pacing_seconds: u32,
}

impl WindowPolicy {
    pub fn valid_shape(&self) -> bool {
        self.first_local_date.len() == 10
            && self.first_local_date.bytes().enumerate().all(|(i, b)| {
                if i == 4 || i == 7 {
                    b == b'-'
                } else {
                    b.is_ascii_digit()
                }
            })
            && self
                .timezone
                .as_ref()
                .is_none_or(|z| !z.is_empty() && z.len() <= 128 && z.is_ascii())
            && self.opens_minute < 1440
            && self.closes_minute < 1440
            && self.opens_minute != self.closes_minute
            && (1..=100).contains(&self.max_occurrences)
            && (60..=86400).contains(&self.pacing_seconds)
            && match self.repeat_every_days {
                Some(days) => (1..=365).contains(&days),
                None => self.max_occurrences == 1,
            }
    }

    /// The exact workflow action's window_id must equal this identity. It
    /// includes every recurrence/window/pacing field, even an unknown zone.
    /// Constructing an identity is not approval or permission to send.
    pub fn identity(&self) -> Result<String, time::WindowError> {
        if !self.valid_shape() {
            return Err(time::WindowError::Invalid);
        }
        let value = serde_json::to_value(self).map_err(|_| time::WindowError::Invalid)?;
        let fields = value
            .as_object()
            .ok_or(time::WindowError::Invalid)?
            .iter()
            .collect::<std::collections::BTreeMap<_, _>>();
        let bytes = serde_json::to_vec(&fields).map_err(|_| time::WindowError::Invalid)?;
        let digest = Sha256::digest([b"ZT/window-policy/v1\0".as_slice(), &bytes].concat());
        Ok(format!(
            "window-v1-{}",
            digest
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>()
        ))
    }

    /// Resolve the selected occurrence in local calendar days, not 24-hour
    /// UTC increments. This calculates timing only; every occurrence still
    /// needs its own exact approved action and live transaction authority.
    pub async fn resolve_occurrence<C: tokio_postgres::GenericClient + Sync>(
        &self,
        db: &C,
        ordinal: u16,
    ) -> Result<time::Resolution, time::WindowError> {
        if !self.valid_shape() || ordinal >= self.max_occurrences {
            return Err(time::WindowError::Invalid);
        }
        let days = i32::from(self.repeat_every_days.unwrap_or(0)) * i32::from(ordinal);
        let date: String = db
            .query_one(
                "SELECT to_char($1::text::date + $2::integer, 'YYYY-MM-DD')",
                &[&self.first_local_date, &days],
            )
            .await
            .map_err(time::WindowError::calendar)?
            .get(0);
        time::resolve(
            db,
            time::LocalWindow {
                date: &date,
                timezone: self.timezone.as_deref(),
                opens_minute: self.opens_minute,
                closes_minute: self.closes_minute,
            },
        )
        .await
    }
}
use super::time;

#[cfg(test)]
mod tests {
    use super::*;
    fn policy() -> WindowPolicy {
        WindowPolicy {
            timezone: Some("UTC".into()),
            first_local_date: "2027-01-01".into(),
            opens_minute: 540,
            closes_minute: 1020,
            repeat_every_days: Some(1),
            max_occurrences: 3,
            pacing_seconds: 60,
        }
    }
    #[test]
    fn every_window_field_invalidates_its_approved_identity() {
        let original = policy();
        let identity = original.identity().unwrap();
        assert_eq!(
            identity,
            "window-v1-5dc7bb93a52584b76a0e59f8439c04cd51e525f72cbfee4c1fb407b8cda8c8ae"
        );
        let mut edits = Vec::new();
        let mut p = original.clone();
        p.timezone = None;
        edits.push(p);
        let mut p = original.clone();
        p.first_local_date = "2027-01-02".into();
        edits.push(p);
        let mut p = original.clone();
        p.opens_minute += 1;
        edits.push(p);
        let mut p = original.clone();
        p.closes_minute -= 1;
        edits.push(p);
        let mut p = original.clone();
        p.repeat_every_days = Some(2);
        edits.push(p);
        let mut p = original.clone();
        p.max_occurrences += 1;
        edits.push(p);
        let mut p = original.clone();
        p.pacing_seconds += 1;
        edits.push(p);
        for changed in edits {
            assert_ne!(changed.identity().unwrap(), identity);
        }
        let parsed: WindowPolicy =
            serde_json::from_value(serde_json::to_value(&original).unwrap()).unwrap();
        assert_eq!(parsed.identity().unwrap(), identity);
    }
    #[test]
    fn recurrence_and_pacing_are_bounded_and_single_occurrence_is_explicit() {
        let mut p = policy();
        p.max_occurrences = 101;
        assert!(p.identity().is_err());
        let mut p = policy();
        p.repeat_every_days = Some(0);
        assert!(p.identity().is_err());
        let mut p = policy();
        p.repeat_every_days = None;
        assert!(p.identity().is_err());
        p.max_occurrences = 1;
        assert!(p.identity().is_ok());
        p.pacing_seconds = 0;
        assert!(p.identity().is_err());
        let mut p = policy();
        p.closes_minute = 1440;
        assert!(p.identity().is_err());
        let mut value = serde_json::to_value(policy()).unwrap();
        value["caller_authorized"] = true.into();
        assert!(serde_json::from_value::<WindowPolicy>(value).is_err());
    }
}

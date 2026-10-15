// SPDX-License-Identifier: AGPL-3.0-only
//! ADR 0004 step 4 (wiring): the default-off `line_readiness` device-stream
//! frame. A phone reports one readiness observation per line; the hub records
//! the latest accepted observation per line and answers `line_readiness_ack`.
//! An observation is input to the later routing decision, never authority:
//! acceptance stores what the phone reported and nothing more. No SIM slot,
//! subscription identifier, ICCID, IMSI or phone number appears in any
//! field, preimage, digest or stored row.
use super::*;
use sha2::{Digest, Sha256};

/// The readiness kinds, mirroring the schema enum and the phone-side
/// preimage codes. `ready` claims a fresh observation; a missing observation
/// can only ever report offline.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub(super) enum LineReadinessKind {
    Inactive,
    BindingNotActive,
    ContinuityPending,
    CardChanged,
    OfflinePastThreshold,
    Ready,
}

impl LineReadinessKind {
    /// The byte the phone hashes into the readiness preimage. Keeping the
    /// codes here makes a schema renumber a compile-visible change.
    fn preimage_code(self) -> u8 {
        match self {
            Self::Inactive => 1,
            Self::BindingNotActive => 2,
            Self::ContinuityPending => 3,
            Self::CardChanged => 4,
            Self::OfflinePastThreshold => 5,
            Self::Ready => 6,
        }
    }

    fn storage(self) -> &'static str {
        match self {
            Self::Inactive => "inactive",
            Self::BindingNotActive => "binding_not_active",
            Self::ContinuityPending => "continuity_pending",
            Self::CardChanged => "card_changed",
            Self::OfflinePastThreshold => "offline_past_threshold",
            Self::Ready => "ready",
        }
    }
}

/// The domain separator of the phone's local canonical readiness preimage
/// (`ZT/line/readiness/v1`), NUL-terminated exactly as the Android store
/// writes it.
const PREIMAGE_DOMAIN: &[u8] = b"ZT/line/readiness/v1\0";

/// The exact frame content the digest binds, after structural validation.
/// Like the phone-side model, the line identity is redacted from any debug
/// rendering: an opaque identifier, not a fact to log.
pub(super) struct Observation {
    line_id: Uuid,
    binding_generation: i64,
    kind: LineReadinessKind,
    since_observation_ms: Option<i64>,
    observed_at_ms: i64,
    digest: [u8; 32],
}

impl std::fmt::Debug for Observation {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Observation")
            .field("line", &"redacted")
            .field("binding_generation", &self.binding_generation)
            .field("kind", &self.kind)
            .field("fresh", &self.since_observation_ms.is_some())
            .finish_non_exhaustive()
    }
}

#[derive(Debug)]
pub(super) enum LineReadinessError {
    /// The frame contradicts itself or its digest: malformed evidence, not a
    /// routing fact.
    InvalidInput,
    Database(tokio_postgres::Error),
}

impl From<tokio_postgres::Error> for LineReadinessError {
    fn from(value: tokio_postgres::Error) -> Self {
        Self::Database(value)
    }
}

impl Observation {
    /// Validates the fail-closed rules the schema states and re-derives the
    /// digest from the frame fields inside the authenticated session. The
    /// hub never trusts the digest alone: the recomputation proves the
    /// fields are exactly what the phone hashed.
    pub(super) fn parse(
        line_id: Uuid,
        binding_generation: i64,
        kind: LineReadinessKind,
        since_observation_ms: Option<i64>,
        observed_at_ms: i64,
        digest: &str,
    ) -> Result<Self, LineReadinessError> {
        if line_id.is_nil()
            || binding_generation < 1
            || observed_at_ms <= 0
            || since_observation_ms.is_some_and(|age| age < 0)
        {
            return Err(LineReadinessError::InvalidInput);
        }
        // A missing observation fails closed: only offline may carry a null
        // age, and a ready claim must name the age of its evidence.
        if since_observation_ms.is_none() && kind != LineReadinessKind::OfflinePastThreshold {
            return Err(LineReadinessError::InvalidInput);
        }
        if kind == LineReadinessKind::Ready && since_observation_ms.is_none() {
            return Err(LineReadinessError::InvalidInput);
        }
        if digest.len() != 43
            || !digest
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
        {
            return Err(LineReadinessError::InvalidInput);
        }
        let decoded = URL_SAFE_NO_PAD
            .decode(digest.as_bytes())
            .ok()
            .filter(|raw| URL_SAFE_NO_PAD.encode(raw) == digest)
            .and_then(|raw| <[u8; 32]>::try_from(raw).ok())
            .ok_or(LineReadinessError::InvalidInput)?;
        let mut preimage = Vec::with_capacity(PREIMAGE_DOMAIN.len() + 16 + 2 + 8 + 8);
        preimage.extend_from_slice(PREIMAGE_DOMAIN);
        preimage.extend_from_slice(line_id.as_bytes());
        preimage.push(kind.preimage_code());
        preimage.push(if since_observation_ms.is_none() { 0 } else { 1 });
        if let Some(age) = since_observation_ms {
            preimage.extend_from_slice(&age.to_be_bytes());
        }
        preimage.extend_from_slice(&observed_at_ms.to_be_bytes());
        if Sha256::digest(&preimage).as_slice() != decoded {
            return Err(LineReadinessError::InvalidInput);
        }
        Ok(Self {
            line_id,
            binding_generation,
            kind,
            since_observation_ms,
            observed_at_ms,
            digest: decoded,
        })
    }

    fn storage_digest(&self) -> String {
        URL_SAFE_NO_PAD.encode(self.digest)
    }
}

/// Records the observation as the line's latest, keyed by line identity and
/// bounded to one row per line. An older phone clock never rolls a newer
/// observation back; such a frame is answered `accepted=false` because it
/// changed nothing. The answer is also `false` when the line or its named
/// binding generation is not this account's current identity for this
/// device.
pub(super) async fn ingest(
    client: &mut Client,
    session: InboundSession<'_>,
    observation: &Observation,
) -> Result<bool, LineReadinessError> {
    let tx = client.transaction().await?;
    if tx
        .query_opt(
            "SELECT id FROM accounts WHERE id=$1 AND disabled_at IS NULL FOR SHARE",
            &[&session.account_id],
        )
        .await?
        .is_none()
    {
        return Ok(false);
    }
    // The line must exist in this account and name its current binding
    // generation, and this device must be the line's bound phone for that
    // generation — otherwise the phone's roster is stale and the
    // observation describes an identity the hub no longer serves.
    let current = tx
        .query_opt(
            "SELECT current_binding_generation FROM phone_lines \
             WHERE account_id=$1 AND id=$2 FOR SHARE",
            &[&session.account_id, &observation.line_id],
        )
        .await?;
    let Some(current) = current else {
        return Ok(false);
    };
    let current_generation: i64 = current.get(0);
    if current_generation != observation.binding_generation {
        return Ok(false);
    }
    let bound = tx
        .query_opt(
            "SELECT 1 FROM device_line_bindings WHERE account_id=$1 AND line_id=$2 \
             AND device_id=$3 AND generation=$4 FOR SHARE",
            &[
                &session.account_id,
                &observation.line_id,
                &session.device_id,
                &observation.binding_generation,
            ],
        )
        .await?
        .is_some();
    if !bound {
        return Ok(false);
    }
    let recorded = tx
        .execute(
            "INSERT INTO line_readiness_observations \
             (account_id, line_id, device_id, binding_generation, kind, \
              since_observation_ms, observed_at_ms, digest, hub_received_at) \
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8, now()) \
             ON CONFLICT (account_id, line_id) DO UPDATE SET \
             device_id = EXCLUDED.device_id, \
             binding_generation = EXCLUDED.binding_generation, \
             kind = EXCLUDED.kind, \
             since_observation_ms = EXCLUDED.since_observation_ms, \
             observed_at_ms = EXCLUDED.observed_at_ms, \
             digest = EXCLUDED.digest, \
             hub_received_at = now() \
             WHERE line_readiness_observations.observed_at_ms <= EXCLUDED.observed_at_ms",
            &[
                &session.account_id,
                &observation.line_id,
                &session.device_id,
                &observation.binding_generation,
                &observation.kind.storage(),
                &observation.since_observation_ms,
                &observation.observed_at_ms,
                &observation.storage_digest(),
            ],
        )
        .await?;
    tx.commit().await?;
    Ok(recorded == 1)
}

/// A lock or statement timeout during ingest is contention with erasure or
/// another writer of the same row, not a failed observation; the handler
/// keeps the session and lets the next observation cycle retry. Every other
/// database failure is a retriable stream condition, not a policy refusal.
pub(super) fn is_contention(error: &tokio_postgres::Error) -> bool {
    // 55P03 lock_timeout and 57014 statement_timeout.
    matches!(
        error.code().map(|code| code.code()),
        Some("55P03" | "57014")
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn observation_for(
        kind: LineReadinessKind,
        since: Option<i64>,
        observed_at_ms: i64,
    ) -> (Uuid, String) {
        let line_id = Uuid::from_u128(0x0000_0000_0000_4000_8000_0000_0000_0021);
        let mut preimage = Vec::new();
        preimage.extend_from_slice(PREIMAGE_DOMAIN);
        preimage.extend_from_slice(line_id.as_bytes());
        preimage.push(kind.preimage_code());
        preimage.push(if since.is_none() { 0 } else { 1 });
        if let Some(age) = since {
            preimage.extend_from_slice(&age.to_be_bytes());
        }
        preimage.extend_from_slice(&observed_at_ms.to_be_bytes());
        (line_id, URL_SAFE_NO_PAD.encode(Sha256::digest(&preimage)))
    }

    #[test]
    fn parse_accepts_a_ready_observation_whose_digest_binds_the_fields() {
        let (line_id, digest) =
            observation_for(LineReadinessKind::Ready, Some(1200), 1_700_000_000_000);
        let observation = Observation::parse(
            line_id,
            1,
            LineReadinessKind::Ready,
            Some(1200),
            1_700_000_000_000,
            &digest,
        )
        .unwrap();
        assert_eq!(observation.kind, LineReadinessKind::Ready);
        assert_eq!(observation.since_observation_ms, Some(1200));
    }

    #[test]
    fn parse_accepts_offline_with_a_null_age_and_rejects_ready_without_one() {
        let (line_id, digest) = observation_for(
            LineReadinessKind::OfflinePastThreshold,
            None,
            1_700_000_000_000,
        );
        Observation::parse(
            line_id,
            1,
            LineReadinessKind::OfflinePastThreshold,
            None,
            1_700_000_000_000,
            &digest,
        )
        .unwrap();
        let (line_id, digest) =
            observation_for(LineReadinessKind::Ready, Some(1), 1_700_000_000_000);
        let error = Observation::parse(
            line_id,
            1,
            LineReadinessKind::Ready,
            None,
            1_700_000_000_000,
            &digest,
        )
        .unwrap_err();
        assert!(matches!(error, LineReadinessError::InvalidInput));
    }

    #[test]
    fn parse_rejects_a_digest_that_does_not_bind_the_reported_fields() {
        let (line_id, digest) =
            observation_for(LineReadinessKind::Ready, Some(1200), 1_700_000_000_000);
        // Same shape, different reported age: the recomputation must refuse.
        let error = Observation::parse(
            line_id,
            1,
            LineReadinessKind::Ready,
            Some(1300),
            1_700_000_000_000,
            &digest,
        )
        .unwrap_err();
        assert!(matches!(error, LineReadinessError::InvalidInput));
    }

    #[test]
    fn parse_rejects_malformed_structure_and_digest_shapes() {
        let (line_id, digest) =
            observation_for(LineReadinessKind::Ready, Some(1200), 1_700_000_000_000);
        // A nil line, a zero generation, a non-positive observation time and
        // a negative age are each malformed.
        let structures = [
            (Uuid::nil(), 1, Some(1200), 1_700_000_000_000),
            (line_id, 0, Some(1200), 1_700_000_000_000),
            (line_id, 1, Some(1200), 0),
            (line_id, 1, Some(-1), 1_700_000_000_000),
        ];
        for (line, generation, since, observed) in structures {
            assert!(matches!(
                Observation::parse(
                    line,
                    generation,
                    LineReadinessKind::Ready,
                    since,
                    observed,
                    &digest
                )
                .unwrap_err(),
                LineReadinessError::InvalidInput
            ));
        }
        // A digest that is not 43 unpadded base64url characters, and one
        // whose decoded bytes do not round-trip, are malformed evidence.
        for bad in ["", "AAAA", &"A".repeat(44), "AAAA$AAAA$AAAA$AAAA$AAAA$AAA"] {
            assert!(matches!(
                Observation::parse(
                    line_id,
                    1,
                    LineReadinessKind::Ready,
                    Some(1200),
                    1_700_000_000_000,
                    bad
                )
                .unwrap_err(),
                LineReadinessError::InvalidInput
            ));
        }
    }

    #[test]
    fn preimage_codes_match_the_phone_side_numbering() {
        assert_eq!(LineReadinessKind::Inactive.preimage_code(), 1);
        assert_eq!(LineReadinessKind::BindingNotActive.preimage_code(), 2);
        assert_eq!(LineReadinessKind::ContinuityPending.preimage_code(), 3);
        assert_eq!(LineReadinessKind::CardChanged.preimage_code(), 4);
        assert_eq!(LineReadinessKind::OfflinePastThreshold.preimage_code(), 5);
        assert_eq!(LineReadinessKind::Ready.preimage_code(), 6);
        assert_eq!(PREIMAGE_DOMAIN, b"ZT/line/readiness/v1\0");
    }
}

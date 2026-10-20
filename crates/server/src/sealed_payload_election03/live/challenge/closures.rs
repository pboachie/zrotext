// SPDX-License-Identifier: AGPL-3.0-only
//! Structural projection of immutable SQL closures, never proof by timeout.
use super::*;
use std::collections::HashSet;

pub(super) struct Closed {
    pub opening: Uuid,
    pub challenge: Uuid,
    pub binding: Uuid,
    pub core: [u8; 500],
    pub closed_ms: u64,
    pub target: Uuid,
}

pub(super) fn project(
    current: &[u8; 500],
    opening: Uuid,
    challenge: Uuid,
    binding: Uuid,
    rows: &[Closed],
) -> Result<Vec<serde_json::Value>> {
    if rows.len() > 16 {
        return Err(Error::Unsupported);
    }
    let old_binding = Uuid::from_slice(&current[72..88]).map_err(|_| Error::Unsupported)?;
    let mut ids = HashSet::new();
    for id in [old_binding, opening, challenge, binding] {
        if id.is_nil() || !ids.insert(id) {
            return Err(Error::Unsupported);
        }
    }
    let number =
        |core: &[u8; 500], at| crypto::number(&core[at..at + 8]).map_err(|_| Error::Unsupported);
    let current_generation = number(current, 96)?;
    let old_generation = number(current, 88)?;
    let mut previous = old_generation;
    let mut out = Vec::with_capacity(rows.len());
    for (i, row) in rows.iter().enumerate() {
        for id in [row.opening, row.challenge, row.binding] {
            if id.is_nil() || !ids.insert(id) {
                return Err(Error::Unsupported);
            }
        }
        let c = &row.core;
        let generation = number(c, 96)?;
        let issued = number(c, 384)?;
        let expires = number(c, 392)?;
        let (next, target) = rows
            .get(i + 1)
            .map_or((current, challenge), |next| (&next.core, next.challenge));
        // Sessions, nonce and successor digest may change between explicit
        // openings. The original02 binding/root/manifest/reader/origin may not.
        if &c[..8] != b"ZTPE\x03\x01\x02\x03"
            || c[496..] != [0; 4]
            || c[..56] != current[..56]
            || c[72..96] != current[72..96]
            || c[104..216] != current[104..216]
            || c[256..352] != current[256..352]
            || c[400..432] != current[400..432]
            || c[56..72] != *row.challenge.as_bytes()
            || generation <= previous
            || generation >= current_generation
            || issued == 0
            || issued >= expires
            || expires - issued > 300_000
            || row.target != target
            || row.closed_ms != number(next, 384)?
            || expires > row.closed_ms
            || [104, 136, 184, 224, 256, 288, 320, 352, 400, 432, 464]
                .into_iter()
                .any(|at| c[at..at + 32] == [0; 32])
        {
            return Err(Error::Unsupported);
        }
        previous = generation;
        out.push(serde_json::json!({"opening_id":row.opening,"challenge_id":row.challenge,
            "new_binding_id":row.binding,"core":B.encode(c),"closed_unaccepted_ms":row.closed_ms.to_string(),
            "superseded_by_challenge_id":row.target}));
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn core(challenge: Uuid, generation: u64, issued: u64, expires: u64) -> [u8; 500] {
        let mut c = [1; 500];
        c[..8].copy_from_slice(b"ZTPE\x03\x01\x02\x03");
        c[56..72].copy_from_slice(challenge.as_bytes());
        c[72..88].copy_from_slice(Uuid::from_u128(1).as_bytes());
        for (at, n) in [(88, 1u64), (96, generation), (384, issued), (392, expires)] {
            c[at..at + 8].copy_from_slice(&n.to_be_bytes());
        }
        c[496..].fill(0);
        c
    }
    fn run(rows: &[Closed]) -> Result<Vec<serde_json::Value>> {
        project(
            &core(Uuid::from_u128(20), 4, 5000, 6000),
            Uuid::from_u128(21),
            Uuid::from_u128(20),
            Uuid::from_u128(22),
            rows,
        )
    }
    fn rows() -> Vec<Closed> {
        vec![
            Closed {
                opening: Uuid::from_u128(2),
                challenge: Uuid::from_u128(3),
                binding: Uuid::from_u128(4),
                core: core(Uuid::from_u128(3), 2, 1000, 2000),
                closed_ms: 3000,
                target: Uuid::from_u128(6),
            },
            Closed {
                opening: Uuid::from_u128(5),
                challenge: Uuid::from_u128(6),
                binding: Uuid::from_u128(7),
                core: core(Uuid::from_u128(6), 3, 3000, 4000),
                closed_ms: 5000,
                target: Uuid::from_u128(20),
            },
        ]
    }
    #[test]
    fn full_chain_can_project_unseen_intermediate_without_inventing_local_rows() {
        assert_eq!(run(&rows()).unwrap().len(), 2);
        assert!(run(&[]).unwrap().is_empty());
    }
    #[test]
    fn chain_requires_exact_links_closure_time_original_scope_and_unique_identities() {
        for mode in 0..8 {
            let mut r = rows();
            match mode {
                0 => r[0].closed_ms -= 1,
                1 => r[0].closed_ms += 1,
                2 => r[0].target = Uuid::from_u128(20),
                3 => r[1].opening = r[0].binding,
                4 => r[0].core[256] ^= 1,
                5 => r[0].core[400] ^= 1,
                6 => r[0].core[392..400].copy_from_slice(&3001u64.to_be_bytes()),
                _ => r.reverse(),
            }
            assert!(run(&r).is_err());
        }
    }
}

//! Authenticated bounded discovery metadata, never consumption authority.
use crate::{
    original_current::{OriginalCurrentClient, VerifiedOriginalCurrent, sample, uuid},
    original_http::{HttpError, Request},
};
use serde::Deserialize;
use serde_json::value::RawValue;

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct OriginalReplyCursor {
    pub accepted_at_ms: u64,
    pub event: [u8; 16],
}
pub struct OriginalReplyEventMetadata {
    pub event: [u8; 16],
    pub accepted_at_ms: u64,
    pub observed_at_ms: u64,
    pub historical_manifest_version: u64,
    pub activation_manifest_version: u64,
    pub disposition: String,
    pub active_request_ids: Vec<[u8; 16]>,
}
pub struct OriginalReplyPage {
    pub events: Vec<OriginalReplyEventMetadata>,
    pub next: Option<OriginalReplyCursor>,
    pub authority: VerifiedOriginalCurrent,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WireCursor {
    accepted_at_ms: u64,
    event_id: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WireEvent {
    event_id: String,
    accepted_at_ms: u64,
    observed_at_ms: u64,
    historical_manifest_version: u64,
    activation_manifest_version: u64,
    disposition: String,
    active_request_ids: Vec<String>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WirePage {
    events: Vec<WireEvent>,
    next: Box<RawValue>,
    proof: Box<RawValue>,
}
fn need(v: bool) -> Result<(), HttpError> {
    if v {
        Ok(())
    } else {
        Err(HttpError::Unavailable)
    }
}
fn positive(n: u64) -> bool {
    (1..=9007199254740991).contains(&n)
}
fn id(s: &str) -> Result<[u8; 16], HttpError> {
    need(s.len() == 36)?;
    let mut out = [0; 16];
    let mut at = 0;
    let bytes = s.as_bytes();
    for (i, byte) in bytes.iter().enumerate() {
        if [8, 13, 18, 23].contains(&i) {
            need(*byte == b'-')?;
            continue;
        }
        let n = match *byte {
            b'0'..=b'9' => *byte - b'0',
            b'a'..=b'f' => *byte - b'a' + 10,
            _ => return Err(HttpError::Unavailable),
        };
        out[at / 2] = (out[at / 2] << 4) | n;
        at += 1;
    }
    need(out != [0; 16])?;
    Ok(out)
}
impl OriginalCurrentClient {
    /// One request. A closed, correlated page is returned only after current
    /// authority and accepted-history comparison are durably verified.
    pub fn page(
        &self,
        grant: &str,
        cursor: Option<OriginalReplyCursor>,
        limit: u8,
        clock: impl Fn() -> u64,
    ) -> Result<OriginalReplyPage, HttpError> {
        let bad = HttpError::Unavailable;
        need((1..=32).contains(&limit))?;
        if let Some(c) = cursor {
            need(positive(c.accepted_at_ms) && c.event != [0; 16])?
        }
        let mut state = self.state.try_lock().map_err(|_| bad)?;
        need(!state.failed)?;
        let now = sample(&mut state, &clock)?;
        let saved = self.checkpoint.snapshot(&self.scope, now).map_err(|_| {
            state.failed = true;
            bad
        })?;
        if saved.revision != state.revision {
            state.failed = true;
            return Err(bad);
        }
        let latest = saved.history.last().ok_or(bad)?;
        let wire = self.transport.exchange(
            grant,
            latest.version,
            Request::Page {
                limit,
                cursor: cursor.map(|c| (c.accepted_at_ms, uuid(&c.event))),
            },
        )?;
        let r: WirePage = serde_json::from_str(wire.json.get()).map_err(|_| bad)?;
        need(r.events.len() <= usize::from(limit))?;
        let mut after = cursor.unwrap_or(OriginalReplyCursor {
            accepted_at_ms: 0,
            event: [0; 16],
        });
        let mut events = Vec::new();
        let mut ids = std::collections::HashSet::new();
        for row in r.events {
            let event = id(&row.event_id)?;
            need(ids.insert(event))?;
            need(
                [
                    row.accepted_at_ms,
                    row.observed_at_ms,
                    row.historical_manifest_version,
                    row.activation_manifest_version,
                ]
                .iter()
                .all(|n| positive(*n)),
            )?;
            let current = OriginalReplyCursor {
                accepted_at_ms: row.accepted_at_ms,
                event,
            };
            need(current > after)?;
            after = current;
            need(
                matches!(
                    row.disposition.as_str(),
                    "unassociated" | "owner_review" | "request_available"
                ) && row.active_request_ids.len() <= 8,
            )?;
            let mut requests = std::collections::HashSet::new();
            let mut active_request_ids = Vec::new();
            for text in row.active_request_ids {
                let value = id(&text)?;
                need(requests.insert(value))?;
                active_request_ids.push(value)
            }
            events.push(OriginalReplyEventMetadata {
                event,
                accepted_at_ms: row.accepted_at_ms,
                observed_at_ms: row.observed_at_ms,
                historical_manifest_version: row.historical_manifest_version,
                activation_manifest_version: row.activation_manifest_version,
                disposition: row.disposition,
                active_request_ids,
            });
        }
        let next =
            match serde_json::from_str::<Option<WireCursor>>(r.next.get()).map_err(|_| bad)? {
                Some(c) => {
                    need(positive(c.accepted_at_ms))?;
                    let next = OriginalReplyCursor {
                        accepted_at_ms: c.accepted_at_ms,
                        event: id(&c.event_id)?,
                    };
                    need(events.len() == usize::from(limit) && next == after)?;
                    Some(next)
                }
                None => {
                    need(events.len() < usize::from(limit))?;
                    None
                }
            };
        let authority = self.accept_proof(r.proof.get(), &saved, latest, &clock, &mut state)?;
        Ok(OriginalReplyPage {
            events,
            next,
            authority,
        })
    }
}

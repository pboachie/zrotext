// SPDX-License-Identifier: AGPL-3.0-only
//! Explicit public issuer copies. Default takeout remains a separate snapshot;
//! the selected state-only branch never loads contacts or opens a private vault.

use super::{
    Error,
    model::*,
    store::{self, State as IssuerState},
};
use crate::auth::{self, SessionPrincipal};
use serde::Serialize;
use tokio_postgres::{Client, Transaction};
use uuid::Uuid;

#[derive(Clone, Serialize)]
pub(crate) struct PublicState {
    root_pin_b64: Fixed<94>,
    root_fingerprint_b64: Fixed<32>,
    trust_generation: Number,
    last_mutation_ms: Number,
    current: Current,
    signed_statement: Option<Packed<314, 817>>,
}
fn state(value: &IssuerState, now: i64) -> PublicState {
    PublicState {
        root_pin_b64: Fixed(value.pin),
        root_fingerprint_b64: Fixed(value.fingerprint),
        trust_generation: Number(1),
        last_mutation_ms: Number(value.last_ms),
        current: value.current(now),
        signed_statement: value.signed.clone().map(Packed),
    }
}
#[derive(Serialize)]
pub(crate) struct StateView {
    kind: &'static str,
    state: Option<PublicState>,
}
#[derive(Default, Serialize)]
pub(crate) struct Page {
    state: Option<PublicState>,
    pending: Vec<PendingView>,
    receipts: Vec<ReceiptView>,
    pending_next_cursor: Option<String>,
    receipt_next_cursor: Option<String>,
}
#[derive(Clone, Copy, PartialEq, Eq)]
struct Cursor {
    generation: i64,
    authorization: Uuid,
}
fn cursor(raw: &str) -> Result<Cursor, Error> {
    if raw.len() > 56 || !raw.is_ascii() {
        return Err(Error::Invalid);
    }
    let (generation, id) = raw.split_once(':').ok_or(Error::Invalid)?;
    if generation.is_empty()
        || generation.len() > 19
        || !generation.bytes().all(|b| b.is_ascii_digit())
    {
        return Err(Error::Invalid);
    }
    let generation: i64 = generation.parse().map_err(|_| Error::Invalid)?;
    let authorization = Uuid::parse_str(id).map_err(|_| Error::Invalid)?;
    if generation <= 0
        || generation.to_string() != raw.split_once(':').ok_or(Error::Invalid)?.0
        || authorization.is_nil()
        || id.len() != 36
        || authorization.to_string() != id
    {
        return Err(Error::Invalid);
    }
    Ok(Cursor {
        generation,
        authorization,
    })
}
fn text(generation: i64, authorization: Uuid) -> String {
    format!("{generation}:{authorization}")
}
async fn read(
    client: &mut Client,
    owner: &SessionPrincipal,
    only: bool,
    pending: Option<&str>,
    receipts: Option<&str>,
) -> Result<(Option<PublicState>, Page), Error> {
    let pending = pending.map(cursor).transpose()?;
    let receipts = receipts.map(cursor).transpose()?;
    let tx = crate::sealed_root_ceremony::begin(client).await?;
    let result = async {
        auth::require_current_owner(&tx, owner).await?;
        let aggregate = store::load(&tx, owner.tenant.account_id(), false).await?;
        let mut page = Page::default();
        let mut public = None;
        let mut previous = 0;
        if let Some(a) = aggregate {
            let now = store::clock(&tx, a.state.last_ms).await?;
            previous = now;
            public = Some(state(&a.state, now));
            if !only {
                if pending.is_some_and(|c| {
                    !a.pending
                        .iter()
                        .any(|p| p.generation == c.generation && p.authorization == c.authorization)
                }) || receipts.is_some_and(|c| {
                    !a.receipts.iter().any(|r| {
                        r.generation == c.generation
                            && r.authorization == c.authorization
                            && r.visible(now)
                    })
                }) {
                    return Err(Error::NotFound);
                }
                let mut p = a
                    .pending
                    .iter()
                    .filter(|p| {
                        pending.is_none_or(|c| {
                            (p.generation, p.authorization) > (c.generation, c.authorization)
                        })
                    })
                    .collect::<Vec<_>>();
                p.sort_by_key(|p| (p.generation, p.authorization));
                page.pending = p
                    .into_iter()
                    .map(|p| match p.view(&a.state, now) {
                        ResultView::Pending(v) => Ok(*v),
                        _ => Err(Error::Unavailable),
                    })
                    .collect::<Result<Vec<_>, _>>()?;
                let mut r = a
                    .receipts
                    .iter()
                    .filter(|r| {
                        r.visible(now)
                            && receipts.is_none_or(|c| {
                                (r.generation, r.authorization) > (c.generation, c.authorization)
                            })
                    })
                    .collect::<Vec<_>>();
                r.sort_by_key(|r| (r.generation, r.authorization));
                if r.len() > 20 {
                    page.receipt_next_cursor = Some(text(r[19].generation, r[19].authorization));
                }
                page.receipts = r
                    .into_iter()
                    .take(20)
                    .map(|r| match r.view(&a.state, now) {
                        ResultView::Receipt(v) => Ok(*v),
                        _ => Err(Error::Unavailable),
                    })
                    .collect::<Result<Vec<_>, _>>()?;
                for item in &page.pending {
                    encode(item)?;
                }
                page.state = Some(state(&a.state, now));
            }
        } else if pending.is_some() || receipts.is_some() {
            return Err(Error::NotFound);
        }
        if only {
            let bytes = encode(&StateView {
                kind: "contact_reader_state",
                state: public.clone(),
            })?;
            if bytes.len() > 4096 {
                return Err(Error::Unavailable);
            }
        }
        auth::require_current_owner(&tx, owner).await?;
        store::clock(&tx, previous).await?;
        Ok((public, page))
    }
    .await;
    match result {
        Ok(value) => {
            tx.commit().await?;
            Ok(value)
        }
        Err(error) => {
            tx.rollback().await?;
            Err(error)
        }
    }
}
pub(crate) async fn state_only(
    client: &mut Client,
    owner: &SessionPrincipal,
) -> Result<Vec<u8>, Error> {
    let (state, _) = read(client, owner, true, None, None).await?;
    let bytes = encode(&StateView {
        kind: "contact_reader_state",
        state,
    })?;
    if bytes.len() > 4096 {
        return Err(Error::Unavailable);
    }
    Ok(bytes)
}
pub(crate) async fn page(
    client: &mut Client,
    owner: &SessionPrincipal,
    pending: Option<&str>,
    receipts: Option<&str>,
) -> Result<Page, Error> {
    Ok(read(client, owner, false, pending, receipts).await?.1)
}
/// Only the actual maintained full-account erasure transaction calls this hook.
/// Earlier enrolled-root history blockers remain in force.
pub(crate) async fn erase(
    tx: &Transaction<'_>,
    account: Uuid,
) -> Result<Vec<(&'static str, u64)>, Error> {
    if !super::lifecycle::installed(tx).await? {
        return Ok(Vec::new());
    }
    let mut counts = Vec::new();
    for table in [
        "contact_reader_pending",
        "contact_reader_receipts",
        "contact_reader_state",
    ] {
        let count = tx
            .execute(
                &format!("DELETE FROM {table} WHERE account_id=$1"),
                &[&account],
            )
            .await?;
        counts.push((table, count));
    }
    Ok(counts)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn cursor_keeps_exact_identity_and_refuses_aliases() {
        let id = Uuid::from_u128(7);
        let raw = text(9, id);
        let c = cursor(&raw).unwrap();
        assert_eq!(c.authorization, id);
        assert_eq!(c.generation, 9);
        for raw in [
            format!("09:{id}"),
            format!("0:{id}"),
            format!("+9:{id}"),
            format!("9:{id}:x"),
            format!("9:{id}\n"),
            format!("9:{}", Uuid::nil()),
            format!("9223372036854775808:{id}"),
        ] {
            assert!(cursor(&raw).is_err());
        }
    }
    #[test]
    fn absent_selected_state_is_closed_null_never_an_allocator_default() {
        assert_eq!(
            encode(&StateView {
                kind: "contact_reader_state",
                state: None
            })
            .unwrap(),
            br#"{"kind":"contact_reader_state","state":null}"#
        );
    }
}

// SPDX-License-Identifier: AGPL-3.0-only
//! Account-scoped contacts: bounded manual and CSV intake with normalized
//! E.164 routing identities, per-purpose consent records, and owner export
//! and erasure coverage.
//!
//! Storage keeps only the routing number, consent metadata and timestamps
//! in the clear. Display names and free-text notes are sealed with the
//! contacts key-encryption key (see [`vault`]) and opened only for the
//! owning account's owner session or its takeout. Creating or importing a
//! contact never creates consent, never clears a suppression or an
//! off-channel hold, and never revives cancelled work; deleting a contact
//! removes its ciphertext and consent history and leaves those other
//! planes untouched. One account can hold one contact per normalized
//! number: equivalent spellings collapse onto the same routing identity,
//! and a create or import that collides reports a duplicate instead of
//! writing a second row. Concurrent updates serialize on the contact row;
//! a PATCH overwrites exactly the fields it carries.

pub mod consents;
mod csv;
pub mod vault;

use crate::{api_json::ApiJson, auth::TokenHasher, http_auth::require_owner_read};
use axum::{
    Json, Router,
    body::Bytes,
    extract::{DefaultBodyLimit, Path, Query, State},
    http::{HeaderMap, StatusCode, header},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use serde::{Deserialize, Serialize};
use std::{collections::HashSet, sync::Arc, time::SystemTime};
use tokio_postgres::Row;
use uuid::Uuid;
use vault::{ContactField, ContactFieldVault};

use consents::{ConsentRecordView, ConsentStateView};

/// One listing page of contacts.
const PAGE_SIZE: usize = 50;
/// Bounded request bodies: JSON mutations stay tiny, the CSV import has its
/// own parser-level limit with a small transport allowance on top.
const JSON_BODY_LIMIT: usize = 16 * 1_024;
const IMPORT_BODY_LIMIT: usize = csv::MAX_BODY_BYTES + 1_024;
/// Field bounds enforced before sealing.
const NAME_MAX_BYTES: usize = 256;
const NOTES_MAX_BYTES: usize = vault::FIELD_PLAINTEXT_MAX;
const RECIPIENT_MAX_BYTES: usize = 32;

#[derive(Clone)]
pub struct OwnerContactsState {
    pub database_url: String,
    pub auth_hasher: Arc<TokenHasher>,
    pub canonical_origin: String,
    /// Seals and opens names and notes. `None` deployments may still keep
    /// contacts, but no field that needs encryption is accepted or served.
    pub vault: Option<Arc<ContactFieldVault>>,
}

pub fn router(state: OwnerContactsState) -> Router {
    Router::new()
        .route(
            "/v1/owner/contacts",
            get(list_contacts).post(create_contact),
        )
        .route(
            "/v1/owner/contacts/import",
            post(import_contacts).layer(DefaultBodyLimit::max(IMPORT_BODY_LIMIT)),
        )
        .route(
            "/v1/owner/contacts/{contact_id}",
            get(contact_detail)
                .put(update_contact)
                .delete(delete_contact),
        )
        .route(
            "/v1/owner/contacts/{contact_id}/consents",
            post(consents::record_consent),
        )
        .layer(DefaultBodyLimit::max(JSON_BODY_LIMIT))
        .layer(middleware::from_fn(no_store))
        .with_state(Arc::new(state))
}

async fn no_store(request: axum::extract::Request, next: Next) -> Response {
    let mut response = next.run(request).await;
    response.headers_mut().insert(
        header::CACHE_CONTROL,
        header::HeaderValue::from_static("no-store"),
    );
    response
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ListQuery {
    /// A contact UUID keeps phone numbers out of request URLs and logs.
    before: Option<Uuid>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CreateBody {
    recipient_e164: String,
    display_name: Option<String>,
    notes: Option<String>,
}

/// One optional field of a PATCH-style body: absent keys leave the stored
/// value unchanged, an explicit null clears it, and a string replaces it.
#[derive(Debug, Default)]
enum PatchField<T> {
    #[default]
    Unchanged,
    Set(Option<T>),
}

impl<'de, T: Deserialize<'de>> Deserialize<'de> for PatchField<T> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        // Only reached for present keys; `#[serde(default)]` supplies
        // `Unchanged` for absent ones.
        Ok(match Option::<T>::deserialize(deserializer)? {
            Some(value) => PatchField::Set(Some(value)),
            None => PatchField::Set(None),
        })
    }
}

impl<T> PatchField<T> {
    fn as_set_text(&self) -> Option<&Option<T>> {
        match self {
            Self::Unchanged => None,
            Self::Set(value) => Some(value),
        }
    }
}

#[derive(Deserialize, Default)]
#[serde(deny_unknown_fields)]
struct UpdateBody {
    #[serde(default)]
    display_name: PatchField<String>,
    #[serde(default)]
    notes: PatchField<String>,
}

#[derive(Serialize)]
struct ContactView {
    contact_id: Uuid,
    recipient_e164: String,
    display_name: Option<String>,
    notes: Option<String>,
    created_at_ms: i64,
    updated_at_ms: i64,
}

#[derive(Serialize)]
struct ContactDetailView {
    #[serde(flatten)]
    contact: ContactView,
    consents: Vec<ConsentStateView>,
    consent_history: Vec<ConsentRecordView>,
}

#[derive(Serialize)]
struct ErrorBody {
    code: &'static str,
}

fn error(status: StatusCode, code: &'static str) -> Response {
    (status, Json(ErrorBody { code })).into_response()
}

fn unavailable() -> Response {
    error(StatusCode::SERVICE_UNAVAILABLE, "unavailable")
}

/// Collapses equivalent spellings onto one routing identity: separators are
/// dropped, and the result must be a bare E.164 number (`+` then 3..=16
/// digits without a leading zero). Anything else is rejected.
pub(crate) fn normalize_e164(value: &str) -> Option<String> {
    if value.len() > RECIPIENT_MAX_BYTES {
        return None;
    }
    let mut normalized = String::with_capacity(value.len());
    for character in value.chars() {
        match character {
            ' ' | '-' | '(' | ')' | '.' => continue,
            '0'..='9' => normalized.push(character),
            '+' if normalized.is_empty() => normalized.push(character),
            _ => return None,
        }
    }
    let bytes = normalized.as_bytes();
    ((3..=16).contains(&bytes.len())
        && bytes[0] == b'+'
        && (b'1'..=b'9').contains(&bytes[1])
        && bytes[2..].iter().all(u8::is_ascii_digit))
    .then_some(normalized)
}

fn bounded_text(value: &Option<String>, max: usize) -> bool {
    match value {
        Some(text) => (1..=max).contains(&text.len()),
        None => true,
    }
}

fn valid_create(body: &CreateBody) -> bool {
    bounded_text(&body.display_name, NAME_MAX_BYTES) && bounded_text(&body.notes, NOTES_MAX_BYTES)
}

fn valid_update(body: &UpdateBody) -> bool {
    body.display_name
        .as_set_text()
        .is_none_or(|value| bounded_text(value, NAME_MAX_BYTES))
        && body
            .notes
            .as_set_text()
            .is_none_or(|value| bounded_text(value, NOTES_MAX_BYTES))
}

/// Why an encrypted field could not be sealed or opened; mapped to a
/// bounded error response at the handler.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum FieldError {
    /// The deployment has no contacts key configured.
    Unconfigured,
    /// Sealing or opening failed: key or ciphertext trouble.
    Unreadable,
    /// A paging cursor named a contact this account does not have.
    MissingContactCursor,
}

impl FieldError {
    pub(crate) fn response(self) -> Response {
        match self {
            Self::Unconfigured => error(
                StatusCode::SERVICE_UNAVAILABLE,
                "contacts_vault_unconfigured",
            ),
            Self::Unreadable => error(StatusCode::SERVICE_UNAVAILABLE, "contacts_unreadable"),
            Self::MissingContactCursor => error(StatusCode::NOT_FOUND, "not_found"),
        }
    }
}

/// Seals one optional field; `None` stays SQL NULL.
fn seal_field(
    state: &OwnerContactsState,
    account_id: Uuid,
    contact_id: Uuid,
    field: ContactField,
    value: &Option<String>,
) -> Result<Option<Vec<u8>>, FieldError> {
    let Some(text) = value else {
        return Ok(None);
    };
    let Some(vault) = &state.vault else {
        return Err(FieldError::Unconfigured);
    };
    vault
        .seal(account_id, contact_id, field, text.as_bytes())
        .map(Some)
        .map_err(|_| FieldError::Unreadable)
}

/// Applies one PATCH field: absent keeps the stored ciphertext untouched,
/// null clears it, a string seals a replacement.
fn merge_field(
    state: &OwnerContactsState,
    account_id: Uuid,
    contact_id: Uuid,
    field: ContactField,
    patch: &PatchField<String>,
    stored: Option<Vec<u8>>,
) -> Result<Option<Vec<u8>>, FieldError> {
    let Some(value) = patch.as_set_text() else {
        return Ok(stored);
    };
    seal_field(state, account_id, contact_id, field, value)
}

/// Opens one optional stored field. Ciphertext without a configured vault,
/// or a ciphertext that fails its binding, refuses the whole read.
fn open_field(
    state: &OwnerContactsState,
    account_id: Uuid,
    contact_id: Uuid,
    field: ContactField,
    packed: Option<&[u8]>,
) -> Result<Option<String>, FieldError> {
    let Some(packed) = packed else {
        return Ok(None);
    };
    let Some(vault) = &state.vault else {
        return Err(FieldError::Unconfigured);
    };
    vault
        .open(account_id, contact_id, field, packed)
        .map(|plaintext| Some(String::from_utf8_lossy(&plaintext).into_owned()))
        .map_err(|_| FieldError::Unreadable)
}

struct ContactRow {
    contact_id: Uuid,
    recipient_e164: String,
    display_name_ciphertext: Option<Vec<u8>>,
    notes_ciphertext: Option<Vec<u8>>,
    created_at_ms: i64,
    updated_at_ms: i64,
}

fn contact_row(row: &Row) -> ContactRow {
    ContactRow {
        contact_id: row.get(0),
        recipient_e164: row.get(1),
        display_name_ciphertext: row.get(2),
        notes_ciphertext: row.get(3),
        created_at_ms: row.get(4),
        updated_at_ms: row.get(5),
    }
}

const CONTACT_COLUMNS: &str = "id,recipient_e164,display_name_ciphertext,notes_ciphertext, \
     (extract(epoch FROM created_at)*1000)::bigint, \
     (extract(epoch FROM updated_at)*1000)::bigint";

fn contact_view(
    state: &OwnerContactsState,
    account_id: Uuid,
    row: &ContactRow,
) -> Result<ContactView, FieldError> {
    Ok(ContactView {
        contact_id: row.contact_id,
        recipient_e164: row.recipient_e164.clone(),
        display_name: open_field(
            state,
            account_id,
            row.contact_id,
            ContactField::DisplayName,
            row.display_name_ciphertext.as_deref(),
        )?,
        notes: open_field(
            state,
            account_id,
            row.contact_id,
            ContactField::Notes,
            row.notes_ciphertext.as_deref(),
        )?,
        created_at_ms: row.created_at_ms,
        updated_at_ms: row.updated_at_ms,
    })
}

fn now_ms() -> Option<i64> {
    i64::try_from(
        SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .ok()?
            .as_millis(),
    )
    .ok()
}

async fn list_contacts(
    State(state): State<Arc<OwnerContactsState>>,
    Query(query): Query<ListQuery>,
    headers: HeaderMap,
) -> Response {
    if let Err(error) = crate::http_auth::require_owner_read_headers(&headers) {
        return error.into_response();
    }
    let Ok(client) = crate::runtime_db::connect(&state.database_url).await else {
        return unavailable();
    };
    let principal = match require_owner_read(&client, &state.auth_hasher, &headers).await {
        Ok(principal) => principal,
        Err(error) => return error.into_response(),
    };
    let account_id = principal.tenant.account_id();
    let before_point: Option<(SystemTime, Uuid)> = if let Some(before) = query.before {
        match client
            .query_opt(
                "SELECT created_at FROM contacts WHERE account_id=$1 AND id=$2",
                &[&account_id, &before],
            )
            .await
        {
            Ok(Some(row)) => Some((row.get(0), before)),
            Ok(None) => return StatusCode::NOT_FOUND.into_response(),
            Err(_) => return unavailable(),
        }
    } else {
        None
    };
    let before_at = before_point.as_ref().map(|point| point.0);
    let before_id = before_point.as_ref().map(|point| point.1);
    let rows = match client
        .query(
            &format!(
                "SELECT {CONTACT_COLUMNS} FROM contacts \
                 WHERE account_id=$1 \
                 AND ($2::timestamptz IS NULL OR (created_at,id)<($2,$3::uuid)) \
                 ORDER BY created_at DESC,id DESC LIMIT $4"
            ),
            &[
                &account_id,
                &before_at,
                &before_id,
                &((PAGE_SIZE + 1) as i64),
            ],
        )
        .await
    {
        Ok(rows) => rows,
        Err(_) => return unavailable(),
    };
    let has_more = rows.len() > PAGE_SIZE;
    let page: Vec<&Row> = rows.iter().take(PAGE_SIZE).collect();
    let next_cursor = if has_more {
        page.last().map(|row| row.get::<_, Uuid>(0))
    } else {
        None
    };
    let mut contacts = Vec::with_capacity(page.len());
    for row in page {
        let parsed = contact_row(row);
        match contact_view(&state, account_id, &parsed) {
            Ok(view) => contacts.push(view),
            Err(field_error) => return field_error.response(),
        }
    }
    #[derive(Serialize)]
    struct ListResponse {
        contacts: Vec<ContactView>,
        next_cursor: Option<Uuid>,
    }
    Json(ListResponse {
        contacts,
        next_cursor,
    })
    .into_response()
}

async fn create_contact(
    State(state): State<Arc<OwnerContactsState>>,
    crate::http_auth::preauth::OwnerMutation(owner, _slot): crate::http_auth::preauth::OwnerMutation,
    ApiJson(body): ApiJson<CreateBody>,
) -> Response {
    let Some(recipient) = normalize_e164(&body.recipient_e164) else {
        return error(StatusCode::BAD_REQUEST, "invalid_request");
    };
    if !valid_create(&body) {
        return error(StatusCode::BAD_REQUEST, "invalid_request");
    }
    let Ok(mut client) = crate::runtime_db::connect(&state.database_url).await else {
        return unavailable();
    };
    let account_id = owner.tenant.account_id();
    let Ok(tx) = client.transaction().await else {
        return unavailable();
    };
    let locked = tx
        .query_opt(
            "SELECT id FROM accounts WHERE id=$1 AND disabled_at IS NULL FOR NO KEY UPDATE",
            &[&account_id],
        )
        .await;
    match locked {
        Ok(Some(_)) => {}
        Ok(None) => return error(StatusCode::UNAUTHORIZED, "unauthorized"),
        Err(_) => return unavailable(),
    }
    let contact_id = Uuid::new_v4();
    let display_name = match seal_field(
        &state,
        account_id,
        contact_id,
        ContactField::DisplayName,
        &body.display_name,
    ) {
        Ok(sealed) => sealed,
        Err(field_error) => return field_error.response(),
    };
    let notes = match seal_field(
        &state,
        account_id,
        contact_id,
        ContactField::Notes,
        &body.notes,
    ) {
        Ok(sealed) => sealed,
        Err(field_error) => return field_error.response(),
    };
    let inserted = tx
        .query_opt(
            &format!(
                "INSERT INTO contacts(id,account_id,recipient_e164,display_name_ciphertext,notes_ciphertext) \
                 VALUES($1,$2,$3,$4,$5) ON CONFLICT (account_id,recipient_e164) DO NOTHING \
                 RETURNING {CONTACT_COLUMNS}"
            ),
            &[&contact_id, &account_id, &recipient, &display_name, &notes],
        )
        .await;
    let row = match inserted {
        Ok(Some(row)) => row,
        Ok(None) => {
            // Equivalent-number duplicate: report the existing contact for
            // review instead of writing a second row.
            let existing = tx
                .query_opt(
                    "SELECT id FROM contacts WHERE account_id=$1 AND recipient_e164=$2",
                    &[&account_id, &recipient],
                )
                .await;
            return match existing {
                Ok(Some(row)) => {
                    #[derive(Serialize)]
                    struct DuplicateView {
                        code: &'static str,
                        existing_contact_id: Uuid,
                        recipient_e164: String,
                    }
                    (
                        StatusCode::CONFLICT,
                        Json(DuplicateView {
                            code: "duplicate",
                            existing_contact_id: row.get(0),
                            recipient_e164: recipient,
                        }),
                    )
                        .into_response()
                }
                Ok(None) => unavailable(),
                Err(_) => unavailable(),
            };
        }
        Err(_) => return unavailable(),
    };
    let parsed = contact_row(&row);
    if tx.commit().await.is_err() {
        return unavailable();
    }
    let view = match contact_view(&state, account_id, &parsed) {
        Ok(view) => view,
        Err(field_error) => return field_error.response(),
    };
    (StatusCode::CREATED, Json(view)).into_response()
}

async fn contact_detail(
    State(state): State<Arc<OwnerContactsState>>,
    Path(contact_id): Path<Uuid>,
    headers: HeaderMap,
) -> Response {
    if let Err(error) = crate::http_auth::require_owner_read_headers(&headers) {
        return error.into_response();
    }
    let Ok(client) = crate::runtime_db::connect(&state.database_url).await else {
        return unavailable();
    };
    let principal = match require_owner_read(&client, &state.auth_hasher, &headers).await {
        Ok(principal) => principal,
        Err(error) => return error.into_response(),
    };
    let account_id = principal.tenant.account_id();
    let row = match client
        .query_opt(
            &format!("SELECT {CONTACT_COLUMNS} FROM contacts WHERE account_id=$1 AND id=$2"),
            &[&account_id, &contact_id],
        )
        .await
    {
        Ok(Some(row)) => row,
        Ok(None) => return error(StatusCode::NOT_FOUND, "not_found"),
        Err(_) => return unavailable(),
    };
    let parsed = contact_row(&row);
    let contact = match contact_view(&state, account_id, &parsed) {
        Ok(view) => view,
        Err(field_error) => return field_error.response(),
    };
    let history = match consents::consent_history(&client, account_id, contact_id).await {
        Ok(history) => history,
        Err(_) => return unavailable(),
    };
    let Some(now) = now_ms() else {
        return unavailable();
    };
    let states = consents::consent_states(&history, now);
    Json(ContactDetailView {
        contact,
        consents: states,
        consent_history: history,
    })
    .into_response()
}

async fn update_contact(
    State(state): State<Arc<OwnerContactsState>>,
    Path(contact_id): Path<Uuid>,
    crate::http_auth::preauth::OwnerMutation(owner, _slot): crate::http_auth::preauth::OwnerMutation,
    ApiJson(body): ApiJson<UpdateBody>,
) -> Response {
    if !valid_update(&body) {
        return error(StatusCode::BAD_REQUEST, "invalid_request");
    }
    let Ok(mut client) = crate::runtime_db::connect(&state.database_url).await else {
        return unavailable();
    };
    let account_id = owner.tenant.account_id();
    let Ok(tx) = client.transaction().await else {
        return unavailable();
    };
    // Concurrent updates serialize on the row; each request overwrites
    // exactly the fields it carries.
    let existing = tx
        .query_opt(
            &format!(
                "SELECT {CONTACT_COLUMNS} FROM contacts \
                 WHERE account_id=$1 AND id=$2 FOR UPDATE"
            ),
            &[&account_id, &contact_id],
        )
        .await;
    let existing = match existing {
        Ok(Some(row)) => contact_row(&row),
        Ok(None) => return error(StatusCode::NOT_FOUND, "not_found"),
        Err(_) => return unavailable(),
    };
    let display_name = match merge_field(
        &state,
        account_id,
        contact_id,
        ContactField::DisplayName,
        &body.display_name,
        existing.display_name_ciphertext.clone(),
    ) {
        Ok(sealed) => sealed,
        Err(field_error) => return field_error.response(),
    };
    let notes = match merge_field(
        &state,
        account_id,
        contact_id,
        ContactField::Notes,
        &body.notes,
        existing.notes_ciphertext.clone(),
    ) {
        Ok(sealed) => sealed,
        Err(field_error) => return field_error.response(),
    };
    let updated = tx
        .query_opt(
            &format!(
                "UPDATE contacts SET display_name_ciphertext=$3,notes_ciphertext=$4, \
                 updated_at=clock_timestamp() \
                 WHERE account_id=$1 AND id=$2 RETURNING {CONTACT_COLUMNS}"
            ),
            &[&account_id, &contact_id, &display_name, &notes],
        )
        .await;
    let row = match updated {
        Ok(Some(row)) => row,
        Ok(None) | Err(_) => return unavailable(),
    };
    let parsed = contact_row(&row);
    if tx.commit().await.is_err() {
        return unavailable();
    }
    match contact_view(&state, account_id, &parsed) {
        Ok(view) => Json(view).into_response(),
        Err(field_error) => field_error.response(),
    }
}

async fn delete_contact(
    State(state): State<Arc<OwnerContactsState>>,
    Path(contact_id): Path<Uuid>,
    crate::http_auth::preauth::OwnerMutation(owner, _slot): crate::http_auth::preauth::OwnerMutation,
) -> Response {
    let Ok(client) = crate::runtime_db::connect(&state.database_url).await else {
        return unavailable();
    };
    let account_id = owner.tenant.account_id();
    // Deleting a contact cascades its consent history. Suppressions, holds
    // and opt-out records are separate planes and stay exactly as they are.
    let deleted = client
        .query_opt(
            "DELETE FROM contacts WHERE account_id=$1 AND id=$2 RETURNING id",
            &[&account_id, &contact_id],
        )
        .await;
    match deleted {
        Ok(Some(_)) => StatusCode::NO_CONTENT.into_response(),
        Ok(None) => error(StatusCode::NOT_FOUND, "not_found"),
        Err(_) => unavailable(),
    }
}

#[derive(Serialize)]
struct ImportRowReport {
    /// Zero-based index into the CSV data rows.
    index: usize,
    recipient: String,
    outcome: &'static str,
    reason: Option<&'static str>,
}

#[derive(Serialize)]
struct ImportReport {
    created: usize,
    duplicates: usize,
    invalid: usize,
    rows: Vec<ImportRowReport>,
}

async fn import_contacts(
    State(state): State<Arc<OwnerContactsState>>,
    crate::http_auth::preauth::OwnerMutation(owner, _slot): crate::http_auth::preauth::OwnerMutation,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let content_type = headers
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .unwrap_or("");
    if !content_type
        .split(';')
        .any(|part| part.trim().eq_ignore_ascii_case("text/csv"))
    {
        return error(StatusCode::UNSUPPORTED_MEDIA_TYPE, "unsupported_media_type");
    }
    let parsed_rows = match csv::parse_contacts_csv(&body) {
        Ok(rows) => rows,
        Err(csv::CsvError::BodyTooLarge) => {
            return error(StatusCode::PAYLOAD_TOO_LARGE, "payload_too_large");
        }
        Err(_) => return error(StatusCode::BAD_REQUEST, "invalid_request"),
    };
    if parsed_rows.is_empty() {
        return error(StatusCode::BAD_REQUEST, "invalid_request");
    }
    let Ok(mut client) = crate::runtime_db::connect(&state.database_url).await else {
        return unavailable();
    };
    let account_id = owner.tenant.account_id();
    let Ok(tx) = client.transaction().await else {
        return unavailable();
    };
    let locked = tx
        .query_opt(
            "SELECT id FROM accounts WHERE id=$1 AND disabled_at IS NULL FOR NO KEY UPDATE",
            &[&account_id],
        )
        .await;
    match locked {
        Ok(Some(_)) => {}
        Ok(None) => return error(StatusCode::UNAUTHORIZED, "unauthorized"),
        Err(_) => return unavailable(),
    }
    struct ValidRow {
        recipient: String,
        display_name: Option<String>,
        notes: Option<String>,
    }
    let mut valid: Vec<ValidRow> = Vec::new();
    let mut reports: Vec<ImportRowReport> = Vec::with_capacity(parsed_rows.len());
    let mut seen: HashSet<String> = HashSet::new();
    for (index, row) in parsed_rows.iter().enumerate() {
        let Some(recipient) = normalize_e164(&row.recipient) else {
            reports.push(ImportRowReport {
                index,
                recipient: row.recipient.clone(),
                outcome: "invalid",
                reason: Some("invalid_recipient"),
            });
            continue;
        };
        if !bounded_text(&row.name, NAME_MAX_BYTES) || !bounded_text(&row.notes, NOTES_MAX_BYTES) {
            reports.push(ImportRowReport {
                index,
                recipient,
                outcome: "invalid",
                reason: Some("field_too_large"),
            });
            continue;
        }
        if !seen.insert(recipient.clone()) {
            reports.push(ImportRowReport {
                index,
                recipient,
                outcome: "duplicate",
                reason: Some("duplicate_in_import"),
            });
            continue;
        }
        reports.push(ImportRowReport {
            index,
            recipient: recipient.clone(),
            outcome: "created",
            reason: None,
        });
        valid.push(ValidRow {
            recipient,
            display_name: row.name.clone(),
            notes: row.notes.clone(),
        });
    }
    let needs_vault = valid
        .iter()
        .any(|row| row.display_name.is_some() || row.notes.is_some());
    if needs_vault && state.vault.is_none() {
        return error(
            StatusCode::SERVICE_UNAVAILABLE,
            "contacts_vault_unconfigured",
        );
    }
    // One transaction covers every valid row: a crash or restart commits
    // nothing, and a replay reports the earlier rows as duplicates.
    for row in &valid {
        let contact_id = Uuid::new_v4();
        let display_name = match seal_field(
            &state,
            account_id,
            contact_id,
            ContactField::DisplayName,
            &row.display_name,
        ) {
            Ok(sealed) => sealed,
            Err(field_error) => return field_error.response(),
        };
        let notes = match seal_field(
            &state,
            account_id,
            contact_id,
            ContactField::Notes,
            &row.notes,
        ) {
            Ok(sealed) => sealed,
            Err(field_error) => return field_error.response(),
        };
        let inserted = tx
            .query_opt(
                "INSERT INTO contacts(id,account_id,recipient_e164,display_name_ciphertext,notes_ciphertext) \
                 VALUES($1,$2,$3,$4,$5) ON CONFLICT (account_id,recipient_e164) DO NOTHING RETURNING id",
                &[&contact_id, &account_id, &row.recipient, &display_name, &notes],
            )
            .await;
        match inserted {
            Ok(Some(_)) => {}
            Ok(None) => {
                if let Some(report) = reports
                    .iter_mut()
                    .find(|report| report.recipient == row.recipient && report.outcome == "created")
                {
                    report.outcome = "duplicate";
                    report.reason = Some("duplicate_existing");
                }
            }
            Err(_) => return unavailable(),
        }
    }
    if tx.commit().await.is_err() {
        return unavailable();
    }
    let created = reports
        .iter()
        .filter(|report| report.outcome == "created")
        .count();
    let duplicates = reports
        .iter()
        .filter(|report| report.outcome == "duplicate")
        .count();
    let invalid = reports
        .iter()
        .filter(|report| report.outcome == "invalid")
        .count();
    Json(ImportReport {
        created,
        duplicates,
        invalid,
        rows: reports,
    })
    .into_response()
}

#[cfg(test)]
mod tests;

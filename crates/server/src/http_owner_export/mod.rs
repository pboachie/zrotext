// SPDX-License-Identifier: AGPL-3.0-only
//! Owner data export: one takeout page with the account profile,
//! devices, messages and per-message events. Unlike the pilot timeline
//! this carries the recipient and transport payload, so responses are
//! always no-store and never cached. Full history pages through the
//! same `before` cursor semantics as the timeline.

use crate::{auth::TokenHasher, http_auth::require_owner_read, http_owner_contacts::FieldError};
use axum::{
    Json, Router,
    extract::{Query, Request, State},
    http::{HeaderMap, StatusCode, header},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::get,
};
use base64::{Engine, engine::general_purpose::STANDARD};
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, sync::Arc, time::SystemTime};
#[cfg(test)]
use tokio_postgres::NoTls;
use tokio_postgres::Row;
use uuid::Uuid;

// One takeout page stays bounded; full-history exports walk the same
// before/next_cursor pagination as the pilot timeline.
const EXPORT_MESSAGE_LIMIT: usize = 500;
const EXPORT_CONTACT_LIMIT: usize = 500;

#[derive(Clone)]
pub struct OwnerExportState {
    pub database_url: String,
    pub auth_hasher: Arc<TokenHasher>,
    pub canonical_origin: String,
    /// Opens the encrypted contact fields for the takeout. Encrypted fields
    /// written under a since-removed key make the export fail closed rather
    /// than shipping ciphertext that cannot be read later.
    pub contacts_vault: Option<Arc<crate::http_owner_contacts::vault::ContactFieldVault>>,
}

pub fn router(state: OwnerExportState) -> Router {
    Router::new()
        .route("/v1/owner/export", get(export_account))
        .layer(middleware::from_fn(no_store))
        .with_state(Arc::new(state))
}

async fn no_store(request: Request, next: Next) -> Response {
    let mut response = next.run(request).await;
    response.headers_mut().insert(
        header::CACHE_CONTROL,
        header::HeaderValue::from_static("no-store"),
    );
    response
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ExportQuery {
    invoice_periods_after: Option<Uuid>,
    invoice_usage_after: Option<Uuid>,
    invoice_audit_after: Option<i64>,
    before: Option<Uuid>,
    sealed_before: Option<Uuid>,
    interval_before: Option<Uuid>,
    confirmation_before: Option<Uuid>,
    contacts_before: Option<Uuid>,
    workflow_grants_before: Option<Uuid>,
    workflow_envelopes_before: Option<Uuid>,
    workflow_access_before: Option<Uuid>,
    workflow_contexts_before: Option<Uuid>,
    workflow_versions_before: Option<Uuid>,
    workflow_exceptions_before: Option<Uuid>,
    workflow_audit_before: Option<Uuid>,
    agent_before: Option<Uuid>,
    workflow_actions_before: Option<String>,
    workflow_action_versions_before: Option<String>,
    workflow_action_mutations_before: Option<String>,
    workflow_correlations_before: Option<String>,
    workflow_message_links_before: Option<String>,
    workflow_routines_before: Option<String>,
    workflow_context_fences_before: Option<String>,
    schedule_policies_before: Option<String>,
    schedule_series_before: Option<Uuid>,
    schedule_occurrences_before: Option<Uuid>,
    schedule_audit_before: Option<Uuid>,
}

#[derive(Serialize)]
struct AccountView {
    account_id: Uuid,
    email: String,
    email_verified: bool,
    created_at_ms: i64,
}

#[derive(Serialize)]
struct DeviceView {
    device_id: Uuid,
    display_name: String,
    created_at_ms: i64,
    revoked_at_ms: Option<i64>,
}

#[derive(Serialize)]
struct MessageEventView {
    evidence_code: String,
    resulting_state: String,
    received_at_ms: i64,
    segment_index: Option<i32>,
    segment_count: Option<i32>,
}

// Content columns are nullable since migration 026: the retention worker
// scrubs the recipient and payload of old terminal messages while the
// message identity, state and events remain exportable.
#[derive(Serialize)]
struct MessageView {
    message_id: Uuid,
    device_id: Uuid,
    recipient_e164: Option<String>,
    transport_mode: String,
    transport_payload: Option<String>,
    payload_encoding: Option<PayloadEncoding>,
    content_scrubbed: bool,
    state: String,
    created_at_ms: i64,
    updated_at_ms: i64,
    expires_at_ms: i64,
    events: Vec<MessageEventView>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
enum PayloadEncoding {
    Utf8,
    Base64,
}

// Only the synthetic alpha transport carries text. A sealed envelope is a
// binary structure whose bytes may happen to decode as UTF-8, so it is
// always base64 to keep the representation independent of its content.
fn encode_payload(transport_mode: &str, payload: Vec<u8>) -> (String, PayloadEncoding) {
    if transport_mode == "synthetic_alpha" {
        match String::from_utf8(payload) {
            Ok(text) => return (text, PayloadEncoding::Utf8),
            Err(error) => return (STANDARD.encode(error.into_bytes()), PayloadEncoding::Base64),
        }
    }
    (STANDARD.encode(payload), PayloadEncoding::Base64)
}

fn message_view(row: &Row) -> Result<MessageView, tokio_postgres::Error> {
    let transport_mode: String = row.try_get(3)?;
    let recipient_e164: Option<String> = row.try_get(2)?;
    let payload: Option<Vec<u8>> = row.try_get(4)?;
    let content_scrubbed = recipient_e164.is_none() && payload.is_none();
    let (transport_payload, payload_encoding) = match payload {
        Some(bytes) => {
            let (text, encoding) = encode_payload(&transport_mode, bytes);
            (Some(text), Some(encoding))
        }
        None => (None, None),
    };
    Ok(MessageView {
        message_id: row.try_get(0)?,
        device_id: row.try_get(1)?,
        recipient_e164,
        transport_mode,
        transport_payload,
        payload_encoding,
        content_scrubbed,
        state: row.try_get(5)?,
        created_at_ms: row.try_get(6)?,
        updated_at_ms: row.try_get(7)?,
        expires_at_ms: row.try_get(8)?,
        events: Vec::new(),
    })
}

#[derive(Serialize)]
struct ExportView {
    workflow_schedule: crate::encrypted_schedule::lifecycle::ScheduleExport,
    workflow_integrations: crate::workflow_runtime::lifecycle::Export,
    invoice_billing: crate::billing::invoice::lifecycle::InvoiceExport,
    workflow_context: crate::http_owner_conversations::context::lifecycle::WorkflowExport,
    confirmation_inventory: crate::http_owner_conversations::confirmation_records::ProofInventory,
    agent_grants: crate::auth::agent_grants::GrantPage,
    workflow_decisions: crate::http_owner_conversations::context::decisions::lifecycle::Export,
    conversation_inventory: crate::http_owner_conversations::lifecycle::ConversationInventory,
    generated_at_ms: i64,
    account: AccountView,
    devices: Vec<DeviceView>,
    contacts: Vec<ContactExportView>,
    contacts_truncated: bool,
    contacts_next_cursor: Option<Uuid>,
    messages: Vec<MessageView>,
    messages_truncated: bool,
    next_cursor: Option<Uuid>,
}

/// One contact with its decrypted fields and full consent history. The
/// takeout is owner-authenticated and no-store, so the plaintext travels
/// only to the account's owner the same way message bodies do.
#[derive(Serialize)]
struct ContactExportView {
    contact_id: Uuid,
    recipient_e164: String,
    display_name: Option<String>,
    notes: Option<String>,
    created_at_ms: i64,
    updated_at_ms: i64,
    consents: Vec<crate::http_owner_contacts::consents::ConsentStateView>,
    consent_history: Vec<crate::http_owner_contacts::consents::ConsentRecordView>,
}

async fn export_account(
    State(state): State<Arc<OwnerExportState>>,
    Query(query): Query<ExportQuery>,
    headers: HeaderMap,
) -> Response {
    if let Err(error) = crate::http_auth::require_owner_read_headers(&headers) {
        return error.into_response();
    }
    let Ok(mut client) = crate::runtime_db::connect(&state.database_url).await else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    let principal = match require_owner_read(&client, &state.auth_hasher, &headers).await {
        Ok(principal) => principal,
        Err(error) => return error.into_response(),
    };
    let account_id = principal.tenant.account_id();
    let agent_grants =
        match crate::auth::agent_grants::list(&client, &principal, query.agent_before).await {
            Ok(Some(page)) => page,
            Ok(None) => return StatusCode::NOT_FOUND.into_response(),
            Err(_) => return StatusCode::SERVICE_UNAVAILABLE.into_response(),
        };
    let before_point: Option<(SystemTime, Uuid)> = if let Some(before) = query.before {
        match client
            .query_opt(
                "SELECT created_at FROM messages WHERE account_id=$1 AND id=$2",
                &[&account_id, &before],
            )
            .await
        {
            Ok(Some(row)) => Some((row.get(0), before)),
            Ok(None) => return StatusCode::NOT_FOUND.into_response(),
            Err(_) => return StatusCode::SERVICE_UNAVAILABLE.into_response(),
        }
    } else {
        None
    };
    let before_at = before_point.map(|point| point.0);
    let before_id = before_point.map(|point| point.1);
    let account = match client
        .query_opt(
            "SELECT a.id,u.email,(u.email_verified_at IS NOT NULL), \
             (extract(epoch FROM a.created_at)*1000)::bigint \
             FROM accounts a JOIN memberships m ON m.account_id=a.id \
             JOIN users u ON u.id=m.user_id WHERE a.id=$1 AND m.role='owner'",
            &[&account_id],
        )
        .await
    {
        Ok(Some(row)) => AccountView {
            account_id: row.get(0),
            email: row.get(1),
            email_verified: row.get(2),
            created_at_ms: row.get(3),
        },
        Ok(None) => return StatusCode::NOT_FOUND.into_response(),
        Err(_) => return StatusCode::SERVICE_UNAVAILABLE.into_response(),
    };
    let device_rows = match client
        .query(
            "SELECT id,display_name,(extract(epoch FROM created_at)*1000)::bigint, \
             (extract(epoch FROM revoked_at)*1000)::bigint \
             FROM devices WHERE account_id=$1 ORDER BY created_at,id",
            &[&account_id],
        )
        .await
    {
        Ok(rows) => rows
            .into_iter()
            .map(|row| DeviceView {
                device_id: row.get(0),
                display_name: row.get(1),
                created_at_ms: row.get(2),
                revoked_at_ms: row.get(3),
            })
            .collect::<Vec<_>>(),
        Err(_) => return StatusCode::SERVICE_UNAVAILABLE.into_response(),
    };
    let contacts = match export_contacts(&client, &state, account_id, query.contacts_before).await {
        Ok(contacts) => contacts,
        Err(field_error) => return field_error.response(),
    };
    let message_rows = match client
        .query(
            "SELECT id,device_id,recipient_e164,transport_mode, \
             transport_payload,state, \
             (extract(epoch FROM created_at)*1000)::bigint, \
             (extract(epoch FROM updated_at)*1000)::bigint, \
             (extract(epoch FROM expires_at)*1000)::bigint \
             FROM messages WHERE account_id=$1 AND \
             ($2::timestamptz IS NULL OR (created_at,id)<($2,$3::uuid)) \
             ORDER BY created_at DESC,id DESC LIMIT $4",
            &[
                &account_id,
                &before_at,
                &before_id,
                &(EXPORT_MESSAGE_LIMIT as i64 + 1),
            ],
        )
        .await
    {
        Ok(rows) => rows,
        Err(_) => return StatusCode::SERVICE_UNAVAILABLE.into_response(),
    };
    let messages_truncated = message_rows.len() > EXPORT_MESSAGE_LIMIT;
    let mut messages = match message_rows
        .iter()
        .take(EXPORT_MESSAGE_LIMIT)
        .map(message_view)
        .collect::<Result<Vec<_>, _>>()
    {
        Ok(messages) => messages,
        Err(_) => return StatusCode::SERVICE_UNAVAILABLE.into_response(),
    };
    let ids: Vec<Uuid> = messages.iter().map(|message| message.message_id).collect();
    if !ids.is_empty() {
        let events = match client
            .query(
                "SELECT selected.id,e.evidence_code,e.resulting_state, \
                 (extract(epoch FROM e.received_at)*1000)::bigint, \
                 e.segment_index,e.segment_count \
                 FROM unnest($2::uuid[]) AS selected(id) \
                 JOIN message_events e \
                 ON e.account_id=$1 AND e.message_id=selected.id \
                 ORDER BY e.received_at,e.id",
                &[&account_id, &ids],
            )
            .await
        {
            Ok(rows) => rows,
            Err(_) => return StatusCode::SERVICE_UNAVAILABLE.into_response(),
        };
        let positions: HashMap<Uuid, usize> = ids
            .iter()
            .enumerate()
            .map(|(index, id)| (*id, index))
            .collect();
        for row in events {
            let id: Uuid = row.get(0);
            let Some(&index) = positions.get(&id) else {
                continue;
            };
            messages[index].events.push(MessageEventView {
                evidence_code: row.get(1),
                resulting_state: row.get(2),
                received_at_ms: row.get(3),
                segment_index: row.get(4),
                segment_count: row.get(5),
            });
        }
    }
    let next_cursor = if messages_truncated {
        messages.last().map(|message| message.message_id)
    } else {
        None
    };
    let conversation_inventory = match crate::http_owner_conversations::lifecycle::inventory(
        &mut client,
        &principal,
        query.sealed_before,
        query.interval_before,
    )
    .await
    {
        Ok(view) => view,
        Err(error) => return error.into_response(),
    };
    let ContactsPage::Ready {
        contacts,
        truncated: contacts_truncated,
        next_cursor: contacts_next_cursor,
    } = contacts;
    let workflow_context = match crate::http_owner_conversations::context::lifecycle::export(
        &mut client,
        &principal,
        [
            query.workflow_contexts_before,
            query.workflow_versions_before,
            query.workflow_exceptions_before,
            query.workflow_audit_before,
        ],
    )
    .await
    {
        Ok(view) => view,
        Err(error) => return error.into_response(),
    };
    let workflow_decisions =
        match crate::http_owner_conversations::context::decisions::lifecycle::export(
            &mut client,
            &principal,
            [
                query.workflow_actions_before.as_deref(),
                query.workflow_action_versions_before.as_deref(),
                query.workflow_action_mutations_before.as_deref(),
                query.workflow_correlations_before.as_deref(),
                query.workflow_message_links_before.as_deref(),
                query.workflow_routines_before.as_deref(),
                query.workflow_context_fences_before.as_deref(),
            ],
        )
        .await
        {
            Ok(view) => view,
            Err(error) => return error.into_response(),
        };
    let workflow_schedule = match crate::encrypted_schedule::lifecycle::export(
        &mut client,
        &principal,
        crate::encrypted_schedule::lifecycle::Cursors {
            policies: query.schedule_policies_before,
            series: query.schedule_series_before,
            occurrences: query.schedule_occurrences_before,
            audit: query.schedule_audit_before,
        },
    )
    .await
    {
        Ok(view) => view,
        Err(error) => return error.into_response(),
    };
    let workflow_integrations = match crate::workflow_runtime::lifecycle::export(
        &mut client,
        &principal,
        [
            query.workflow_grants_before,
            query.workflow_envelopes_before,
            query.workflow_access_before,
        ],
    )
    .await
    {
        Ok(view) => view,
        Err(error) => return error.into_response(),
    };
    Json(ExportView {
        workflow_integrations,
        workflow_decisions,
        workflow_schedule,
        invoice_billing: match crate::billing::invoice::lifecycle::export(
            &mut client,
            &principal,
            query.invoice_periods_after,
            query.invoice_usage_after,
            query.invoice_audit_after,
        )
        .await
        {
            Ok(view) => view,
            Err(error) => return error.into_response(),
        },
        workflow_context,
        confirmation_inventory:
            match crate::http_owner_conversations::confirmation_records::inventory(
                &mut client,
                &principal,
                query.confirmation_before,
            )
            .await
            {
                Ok(view) => view,
                Err(error) => return error.into_response(),
            },
        agent_grants,
        conversation_inventory,
        generated_at_ms: SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|duration| duration.as_millis() as i64)
            .unwrap_or_default(),
        account,
        devices: device_rows,
        contacts,
        contacts_truncated,
        contacts_next_cursor,
        messages,
        messages_truncated,
        next_cursor,
    })
    .into_response()
}

/// One bounded page of the account's contacts with decrypted fields and
/// consent history, newest first, paged by the same `before` cursor
/// semantics as messages. A stored ciphertext the configured vault cannot
/// open fails the whole export instead of exporting unreadable fields.
enum ContactsPage {
    Ready {
        contacts: Vec<ContactExportView>,
        truncated: bool,
        next_cursor: Option<Uuid>,
    },
}

async fn export_contacts(
    client: &tokio_postgres::Client,
    state: &OwnerExportState,
    account_id: Uuid,
    before: Option<Uuid>,
) -> Result<ContactsPage, crate::http_owner_contacts::FieldError> {
    let before_point: Option<(SystemTime, Uuid)> = if let Some(before) = before {
        match client
            .query_opt(
                "SELECT created_at FROM contacts WHERE account_id=$1 AND id=$2",
                &[&account_id, &before],
            )
            .await
        {
            Ok(Some(row)) => Some((row.get(0), before)),
            Ok(None) => return Err(FieldError::MissingContactCursor),
            Err(_) => return Err(FieldError::Unreadable),
        }
    } else {
        None
    };
    let before_at = before_point.as_ref().map(|point| point.0);
    let before_id = before_point.as_ref().map(|point| point.1);
    let rows = match client
        .query(
            "SELECT id,recipient_e164,display_name_ciphertext,notes_ciphertext, \
             (extract(epoch FROM created_at)*1000)::bigint, \
             (extract(epoch FROM updated_at)*1000)::bigint \
             FROM contacts WHERE account_id=$1 \
             AND ($2::timestamptz IS NULL OR (created_at,id)<($2,$3::uuid)) \
             ORDER BY created_at DESC,id DESC LIMIT $4",
            &[
                &account_id,
                &before_at,
                &before_id,
                &((EXPORT_CONTACT_LIMIT + 1) as i64),
            ],
        )
        .await
    {
        Ok(rows) => rows,
        Err(_) => return Err(FieldError::Unreadable),
    };
    let truncated = rows.len() > EXPORT_CONTACT_LIMIT;
    let page: Vec<&Row> = rows.iter().take(EXPORT_CONTACT_LIMIT).collect();
    let next_cursor = if truncated {
        page.last().map(|row| row.get::<_, Uuid>(0))
    } else {
        None
    };
    let now_ms = SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_millis() as i64)
        .unwrap_or_default();
    let mut contacts = Vec::with_capacity(page.len());
    for row in page {
        let contact_id: Uuid = row.get(0);
        let display_name = match open_contact_field(
            &state.contacts_vault,
            account_id,
            contact_id,
            crate::http_owner_contacts::vault::ContactField::DisplayName,
            row.get::<_, Option<Vec<u8>>>(2).as_deref(),
        ) {
            Ok(value) => value,
            Err(field_error) => return Err(field_error),
        };
        let notes = match open_contact_field(
            &state.contacts_vault,
            account_id,
            contact_id,
            crate::http_owner_contacts::vault::ContactField::Notes,
            row.get::<_, Option<Vec<u8>>>(3).as_deref(),
        ) {
            Ok(value) => value,
            Err(field_error) => return Err(field_error),
        };
        let history = match crate::http_owner_contacts::consents::consent_history(
            client, account_id, contact_id,
        )
        .await
        {
            Ok(history) => history,
            Err(_) => return Err(FieldError::Unreadable),
        };
        let consents = crate::http_owner_contacts::consents::consent_states(&history, now_ms);
        contacts.push(ContactExportView {
            contact_id,
            recipient_e164: row.get(1),
            display_name,
            notes,
            created_at_ms: row.get(4),
            updated_at_ms: row.get(5),
            consents,
            consent_history: history,
        });
    }
    Ok(ContactsPage::Ready {
        contacts,
        truncated,
        next_cursor,
    })
}

/// Opens one optional contact field for the takeout. Ciphertext without a
/// configured vault refuses the export rather than shipping an unreadable
/// blob; a ciphertext that fails its binding fails the same way.
fn open_contact_field(
    vault: &Option<Arc<crate::http_owner_contacts::vault::ContactFieldVault>>,
    account_id: Uuid,
    contact_id: Uuid,
    field: crate::http_owner_contacts::vault::ContactField,
    packed: Option<&[u8]>,
) -> Result<Option<String>, crate::http_owner_contacts::FieldError> {
    let Some(packed) = packed else {
        return Ok(None);
    };
    let Some(vault) = vault else {
        return Err(crate::http_owner_contacts::FieldError::Unconfigured);
    };
    vault
        .open(account_id, contact_id, field, packed)
        .map(|plaintext| Some(String::from_utf8_lossy(&plaintext).into_owned()))
        .map_err(|_| crate::http_owner_contacts::FieldError::Unreadable)
}

#[cfg(test)]
mod tests;

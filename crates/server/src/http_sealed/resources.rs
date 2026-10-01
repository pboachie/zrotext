// SPDX-License-Identifier: AGPL-3.0-only
//! Sealed v1 slice-2 read-only resource groups (#538): devices, webhooks and
//! usage metering projected onto the API-key plane. Mounted on the same
//! default-off `SEALED_ADMISSION_ENABLED` router as the message route; these
//! handlers never mutate trust state, never return secrets, SIM identifiers,
//! phone numbers, key material or content, and every response carries
//! `Cache-Control: no-store` from the shared router middleware.

use super::{SealedHttpError, SealedResourceAuth};
use crate::auth::{ApiPrincipal, Scope};
use axum::{
    Json, Router,
    extract::{Path, Query, State},
    routing::get,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use uuid::Uuid;

const DEVICES_PAGE_SIZE: usize = 25;
const DELIVERIES_PAGE_DEFAULT: i64 = 20;
const DELIVERIES_PAGE_MAX: i64 = 20;

pub fn routes() -> Router<Arc<super::SealedHttpState>> {
    Router::new()
        .route("/devices", get(list_devices))
        .route("/devices/{device_id}", get(get_device))
        .route("/webhooks", get(list_webhooks))
        .route("/webhooks/{endpoint_id}/deliveries", get(list_deliveries))
        .route("/usage", get(get_usage))
}

#[derive(Deserialize)]
pub(crate) struct DevicePageQuery {
    before: Option<Uuid>,
}

#[derive(Serialize)]
struct LineBindingView {
    line_id: Uuid,
    binding_generation: i64,
    state: String,
}

#[derive(Serialize)]
struct DeviceView {
    device_id: Uuid,
    display_name: String,
    revoked: bool,
    active_socket_lease: bool,
    lines: Vec<LineBindingView>,
}

#[derive(Serialize)]
struct DevicePage {
    devices: Vec<DeviceView>,
    next_cursor: Option<Uuid>,
}

/// The device projection of the sealed plane: identity, revocation, the
/// authoritative socket-lease observation and the sealed-purpose line
/// bindings only — no SIM identifier, phone number, queue depth or report.
/// Cursor pagination mirrors the owner enrollment route: (created_at, id)
/// descending, `next_cursor` null after the last page.
async fn device_rows(
    state: &Arc<super::SealedHttpState>,
    auth: &SealedResourceAuth,
    before: Option<Uuid>,
    only: Option<Uuid>,
) -> Result<DevicePage, SealedHttpError> {
    auth.principal.require_read_for(Scope::DevicesRead)?;
    let client = super::connect(&state.database_url).await?;
    let account = auth.principal.tenant.account_id();
    let rows = client
        .query(
            "WITH page AS (                SELECT d.id,d.account_id,d.display_name,                  (d.revoked_at IS NOT NULL OR k.revoked_at IS NOT NULL) AS revoked,                  COALESCE(d.revoked_at IS NULL AND k.revoked_at IS NULL AND a.disabled_at IS NULL                    AND ds.lease_until>now() AND ds.connection_epoch>0                    AND ds.deployment_epoch=p.epoch AND s.enabled=TRUE AND s.draining=FALSE                    AND NOT pg_is_in_recovery(),FALSE) AS active_socket_lease,d.created_at                FROM devices d JOIN device_keys k ON (k.account_id,k.device_id)=(d.account_id,d.id)                JOIN accounts a ON a.id=d.account_id                LEFT JOIN device_sessions ds ON (ds.account_id,ds.device_id)=(d.account_id,d.id)                LEFT JOIN sites s ON s.site_id=ds.site_id                LEFT JOIN deployment_authority p ON p.singleton=TRUE                WHERE d.account_id=$1 AND ($2::uuid IS NULL OR d.id=$2)                  AND ($3::uuid IS NULL OR (d.created_at,d.id) <                  (SELECT c.created_at,c.id FROM devices c JOIN device_keys ck                    ON (ck.account_id,ck.device_id)=(c.account_id,c.id)                    WHERE c.account_id=$1 AND c.id=$3))                ORDER BY d.created_at DESC,d.id DESC LIMIT $4)                SELECT page.id,page.display_name,page.revoked,page.active_socket_lease,page.created_at,                  b.line_id,b.generation,b.state                FROM page LEFT JOIN device_line_bindings b                  ON (b.account_id,b.device_id)=(page.account_id,page.id) AND b.purpose='sealed'                ORDER BY page.created_at DESC,page.id DESC,b.line_id",
            &[&account, &only, &before, &((DEVICES_PAGE_SIZE + 1) as i64)],
        )
        .await
        .map_err(|_| SealedHttpError::Unavailable)?;
    Ok(assemble_device_page(rows))
}

fn assemble_device_page(rows: Vec<tokio_postgres::Row>) -> DevicePage {
    let mut devices: Vec<DeviceView> = Vec::new();
    for row in &rows {
        let id: Uuid = row.get(0);
        if devices.last().is_none_or(|last| last.device_id != id) {
            devices.push(DeviceView {
                device_id: id,
                display_name: row.get(1),
                revoked: row.get(2),
                active_socket_lease: row.get(3),
                lines: Vec::new(),
            });
        }
        if let Some(last) = devices.last_mut()
            && last.device_id == id
            && let (Ok(Some(line)), Ok(Some(generation)), Ok(Some(state))) = (
                row.try_get::<_, Option<Uuid>>(5),
                row.try_get::<_, Option<i64>>(6),
                row.try_get::<_, Option<String>>(7),
            )
        {
            last.lines.push(LineBindingView {
                line_id: line,
                binding_generation: generation,
                state,
            });
        }
    }
    let has_more = devices.len() > DEVICES_PAGE_SIZE;
    devices.truncate(DEVICES_PAGE_SIZE);
    DevicePage {
        next_cursor: if has_more {
            devices.last().map(|last| last.device_id)
        } else {
            None
        },
        devices,
    }
}

async fn list_devices(
    State(state): State<Arc<super::SealedHttpState>>,
    auth: SealedResourceAuth,
    Query(query): Query<DevicePageQuery>,
) -> Result<Json<DevicePage>, SealedHttpError> {
    Ok(Json(device_rows(&state, &auth, query.before, None).await?))
}

async fn get_device(
    State(state): State<Arc<super::SealedHttpState>>,
    auth: SealedResourceAuth,
    Path(device_id): Path<Uuid>,
) -> Result<Json<DeviceView>, SealedHttpError> {
    let page = device_rows(&state, &auth, None, Some(device_id)).await?;
    // An unknown device and another account's device are both a bare 404.
    page.devices
        .into_iter()
        .next()
        .map(Json)
        .ok_or(SealedHttpError::NotFound)
}

#[derive(Serialize)]
struct EndpointView {
    endpoint_id: Uuid,
    callback_url: String,
    enabled: bool,
    paused_at_ms: Option<i64>,
    failure_started_at_ms: Option<i64>,
    created_at_ms: i64,
}

#[derive(Serialize)]
struct EndpointPage {
    endpoints: Vec<EndpointView>,
}

async fn list_webhooks(
    State(state): State<Arc<super::SealedHttpState>>,
    auth: SealedResourceAuth,
) -> Result<Json<EndpointPage>, SealedHttpError> {
    auth.principal.require_read_for(Scope::WebhooksRead)?;
    let client = super::connect(&state.database_url).await?;
    let rows = client
        .query(
            "SELECT id,callback_url,enabled, \
             (extract(epoch FROM paused_at)*1000)::bigint, \
             (extract(epoch FROM failure_started_at)*1000)::bigint, \
             (extract(epoch FROM created_at)*1000)::bigint \
             FROM webhook_endpoints WHERE account_id=$1 ORDER BY created_at,id",
            &[&auth.principal.tenant.account_id()],
        )
        .await
        .map_err(|_| SealedHttpError::Unavailable)?;
    Ok(Json(EndpointPage {
        endpoints: rows
            .into_iter()
            .map(|row| EndpointView {
                endpoint_id: row.get(0),
                callback_url: row.get(1),
                enabled: row.get(2),
                paused_at_ms: row.get(3),
                failure_started_at_ms: row.get(4),
                created_at_ms: row.get(5),
            })
            .collect(),
    }))
}

#[derive(Deserialize)]
struct DeliveriesQuery {
    limit: Option<i64>,
    before: Option<Uuid>,
}

#[derive(Serialize)]
struct DeliveryView {
    delivery_id: Uuid,
    event_id: Uuid,
    status: String,
    generation: i16,
    terminal_reason: Option<String>,
    attempt_count: i16,
    next_attempt_at_ms: Option<i64>,
    created_at_ms: i64,
    updated_at_ms: i64,
}

#[derive(Serialize)]
struct DeliveriesPage {
    deliveries: Vec<DeliveryView>,
    next_before: Option<Uuid>,
}

async fn list_deliveries(
    State(state): State<Arc<super::SealedHttpState>>,
    auth: SealedResourceAuth,
    Path(endpoint_id): Path<Uuid>,
    Query(query): Query<DeliveriesQuery>,
) -> Result<Json<DeliveriesPage>, SealedHttpError> {
    auth.principal.require_read_for(Scope::WebhooksRead)?;
    let limit = query.limit.unwrap_or(DELIVERIES_PAGE_DEFAULT);
    if !(1..=DELIVERIES_PAGE_MAX).contains(&limit) {
        return Err(SealedHttpError::BadRequest);
    }
    let client = super::connect(&state.database_url).await?;
    let account = auth.principal.tenant.account_id();
    // Ownership first: a foreign or unknown endpoint is a bare 404 that
    // reveals nothing.
    let owned = client
        .query_opt(
            "SELECT 1 FROM webhook_endpoints WHERE account_id=$1 AND id=$2",
            &[&account, &endpoint_id],
        )
        .await
        .map_err(|_| SealedHttpError::Unavailable)?;
    if owned.is_none() {
        return Err(SealedHttpError::NotFound);
    }
    let rows = client
        .query(
            "SELECT id,event_id,status,generation,terminal_reason,attempt_count, \
             (extract(epoch FROM next_attempt_at)*1000)::bigint, \
             (extract(epoch FROM created_at)*1000)::bigint, \
             (extract(epoch FROM updated_at)*1000)::bigint \
             FROM webhook_deliveries WHERE account_id=$1 AND endpoint_id=$2 \
             AND ($3::uuid IS NULL OR (created_at,id) < \
               (SELECT c.created_at,c.id FROM webhook_deliveries c \
                 WHERE c.account_id=$1 AND c.endpoint_id=$2 AND c.id=$3)) \
             ORDER BY created_at DESC,id DESC LIMIT $4",
            &[&account, &endpoint_id, &query.before, &(limit + 1)],
        )
        .await
        .map_err(|_| SealedHttpError::Unavailable)?;
    let has_more = rows.len() as i64 > limit;
    let deliveries: Vec<DeliveryView> = rows
        .into_iter()
        .take(limit as usize)
        .map(|row| DeliveryView {
            delivery_id: row.get(0),
            event_id: row.get(1),
            status: row.get(2),
            generation: row.get(3),
            terminal_reason: row.get(4),
            attempt_count: row.get(5),
            next_attempt_at_ms: row.get(6),
            created_at_ms: row.get(7),
            updated_at_ms: row.get(8),
        })
        .collect();
    let next_before = if has_more {
        deliveries.last().map(|last| last.delivery_id)
    } else {
        None
    };
    Ok(Json(DeliveriesPage {
        deliveries,
        next_before,
    }))
}

#[derive(Serialize)]
struct UsageView {
    metric: &'static str,
    period_start: String,
    period_end: String,
    limit_units: i64,
    reserved_units: i64,
    refunded_units: i64,
    used_units: i64,
}

async fn get_usage(
    State(state): State<Arc<super::SealedHttpState>>,
    auth: SealedResourceAuth,
) -> Result<Json<UsageView>, SealedHttpError> {
    auth.principal.require_read_for(Scope::BillingRead)?;
    let client = super::connect(&state.database_url).await?;
    let row = client
        .query_opt(
            "SELECT period_start::text,period_end::text,limit_units,reserved_units,refunded_units \
             FROM usage_periods WHERE account_id=$1 AND metric='outbound_message' \
             AND period_start<=current_date AND period_end>current_date",
            &[&auth.principal.tenant.account_id()],
        )
        .await
        .map_err(|_| SealedHttpError::Unavailable)?
        .ok_or(SealedHttpError::NotFound)?;
    let reserved: i64 = row.get(3);
    let refunded: i64 = row.get(4);
    Ok(Json(UsageView {
        metric: "outbound_message",
        period_start: row.get(0),
        period_end: row.get(1),
        limit_units: row.get(2),
        reserved_units: reserved,
        refunded_units: refunded,
        used_units: reserved - refunded,
    }))
}

trait ReadScope {
    fn require_read_for(&self, scope: Scope) -> Result<(), SealedHttpError>;
}

impl ReadScope for ApiPrincipal {
    fn require_read_for(&self, scope: Scope) -> Result<(), SealedHttpError> {
        self.require(scope, None)
            .map_err(|_| SealedHttpError::Forbidden)
    }
}

#[cfg(test)]
mod tests;

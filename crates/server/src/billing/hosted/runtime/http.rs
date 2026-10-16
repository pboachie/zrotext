// SPDX-License-Identifier: AGPL-3.0-only
use super::{
    Error, Runtime, mode_name,
    provider::{self, id},
    repository as db,
};
use crate::{
    auth::SessionPrincipal,
    http_auth::{
        self,
        preauth::{OwnerAuthState, OwnerMutation},
    },
};
use axum::{
    Json, Router,
    body::Bytes,
    extract::{DefaultBodyLimit, Request, State},
    http::{HeaderMap, StatusCode, header},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use reqwest::Method;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};
use uuid::Uuid;

impl OwnerAuthState for Runtime {
    fn database_url(&self) -> &str {
        &self.auth.database_url
    }
    fn session_hasher(&self) -> &crate::auth::TokenHasher {
        &self.auth.hasher
    }
    fn canonical_origin(&self) -> &str {
        &self.auth.canonical_origin
    }
}
impl IntoResponse for Error {
    fn into_response(self) -> Response {
        let (status, code) = match self {
            Error::Session => (StatusCode::UNAUTHORIZED, "session_required"),
            Error::Forbidden => (StatusCode::FORBIDDEN, "forbidden"),
            Error::RateLimited => (StatusCode::TOO_MANY_REQUESTS, "rate_limited"),
            Error::Conflict => (StatusCode::CONFLICT, "billing_conflict"),
            Error::Pending => (StatusCode::CONFLICT, "billing_pending"),
            _ => (StatusCode::SERVICE_UNAVAILABLE, "billing_unavailable"),
        };
        (status, Json(json!({"code":code}))).into_response()
    }
}
pub(super) fn router(r: Arc<Runtime>) -> Router {
    Router::new()
        .route("/plan", get(plan))
        .route("/status", get(status))
        .route("/checkout", post(checkout))
        .route("/portal", post(portal))
        .route("/stripe-events", post(webhook))
        .layer(DefaultBodyLimit::max(64 * 1024))
        .layer(middleware::from_fn(no_store))
        .with_state(r)
}
async fn no_store(request: Request, next: Next) -> Response {
    let mut response = next.run(request).await;
    for (name, value) in [
        (header::CACHE_CONTROL, "no-store"),
        (header::REFERRER_POLICY, "no-referrer"),
        (header::X_CONTENT_TYPE_OPTIONS, "nosniff"),
    ] {
        response.headers_mut().insert(name, value.parse().unwrap());
    }
    response
}
fn empty(body: &Bytes) -> Result<(), Error> {
    if body.is_empty()
        || serde_json::from_slice::<Value>(body)
            .is_ok_and(|v| v.as_object().is_some_and(|o| o.is_empty()))
    {
        Ok(())
    } else {
        Err(Error::Conflict)
    }
}
async fn owner_now(r: &Runtime, p: &SessionPrincipal) -> Result<(), Error> {
    let mut conn = db::connect(r).await?;
    let tx = conn.transaction().await?;
    db::owner(&tx, r, p).await?;
    db::final_owner(&tx, p).await?;
    tx.commit().await?;
    Ok(())
}
async fn plan(State(r): State<Arc<Runtime>>) -> Result<Json<provider::Catalog>, Error> {
    let mut conn = db::connect(&r).await?;
    let marker = db::marker(&mut conn).await?;
    r.gate.check_marker(&marker).map_err(|_| Error::Identity)?;
    drop(conn);
    Ok(Json(r.provider.catalog().await?))
}

async fn status(State(r): State<Arc<Runtime>>, headers: HeaderMap) -> Result<Json<Value>, Error> {
    http_auth::require_owner_read_headers(&headers)?;
    let p = {
        let conn = db::connect(&r).await?;
        http_auth::require_owner_read(&conn, &r.auth.hasher, &headers).await?
    };
    observe_checkout(&r, &p).await?;
    let mut conn = db::connect(&r).await?;
    let tx = conn.transaction().await?;
    db::owner(&tx, &r, &p).await?;
    let account = p.tenant.account_id();
    let customer = db::customer(&tx, &r, account, false).await?;
    let projection=tx.query_opt("SELECT phase,valid_until,first_failure_at,outbound_limit,device_limit,payment_hold,review_required,dirty_generation,processed_generation FROM hosted_billing_projections WHERE namespace_id=$1 AND account_id=$2 FOR SHARE",&[&db::ns(&r),&account]).await?;
    let now = db::now(&tx).await?;
    let global_review: bool = tx
        .query_one(
            "SELECT review_required FROM hosted_billing_namespaces WHERE namespace_id=$1",
            &[&db::ns(&r)],
        )
        .await?
        .get(0);
    let mut outcome = customer.as_ref().map_or(
        json!({"state":"none","url":null,"expires_at_ms":null}),
        |c| {
            checkout_view(
                c,
                projection
                    .as_ref()
                    .is_some_and(|p| p.get::<_, String>(0) == "terminal"),
            )
        },
    );
    let entitlement=projection.as_ref().map_or(json!({"phase":if customer.as_ref().is_some_and(|c|c.processed==c.queued&&matches!(c.checkout_state.as_str(),"complete"|"expired")){"terminal"}else{"pending"},"valid_until_ms":now*1000,"first_failure_at_ms":null,"outbound_limit":0,"device_cap":0,"payment_hold":customer.as_ref().is_some_and(|c|c.hold),"review_required":customer.as_ref().is_some_and(|c|c.review)}),|row|{
        let mut phase=row.get::<_,String>(0);let valid=row.get::<_,i64>(1);
        if matches!(phase.as_str(),"active"|"grace")&&(valid<=now||row.get::<_,i64>(7)!=row.get::<_,i64>(8)){phase="pending".into();}
        json!({"phase":phase,"valid_until_ms":valid*1000,"first_failure_at_ms":row.get::<_,Option<i64>>(2).map(|v|v*1000),"outbound_limit":row.get::<_,i64>(3),"device_cap":row.get::<_,i64>(4),"payment_hold":row.get::<_,bool>(5),"review_required":row.get::<_,bool>(6)})
    });
    let mut entitlement = entitlement;
    if global_review {
        entitlement["phase"] = json!("restricted");
        entitlement["review_required"] = json!(true);
        entitlement["outbound_limit"] = json!(0);
        entitlement["device_cap"] = json!(0);
    }
    if global_review || customer.as_ref().is_some_and(|c| c.hold || c.review) {
        outcome["state"] = json!("pending");
        outcome["url"] = Value::Null;
    }
    let value = json!({"schema_version":1,"mode":mode_name(r.options.namespace.mode()),"account_id":account,"session_id":p.session_id,"observed_at_ms":now*1000,"customer_bound":customer.as_ref().is_some_and(|c|c.id.is_some()),"checkout":outcome,"entitlement":entitlement,"reconciliation_pending":global_review||customer.as_ref().is_some_and(|c|c.queued!=c.processed)||projection.as_ref().is_some_and(|row|row.get::<_,i64>(7)!=row.get::<_,i64>(8))});
    db::final_owner(&tx, &p).await?;
    tx.commit().await?;
    Ok(Json(value))
}
fn checkout_view(c: &db::Customer, terminal: bool) -> Value {
    let terminal = terminal || (c.complete && c.nonterminal == 0);
    let state = match c.checkout_state.as_str() {
        "none" => "none",
        "open" => "resumable",
        "complete" | "expired" if c.queued == c.processed && terminal => "replaceable",
        "complete" | "expired" => "reconciliation_required",
        _ => "pending",
    };
    json!({"state":state,"url":if state=="resumable"{c.checkout_url.clone()}else{None},"expires_at_ms":c.checkout_expires.map(|n|n*1000)})
}
async fn ensure_customer(r: &Runtime, p: &SessionPrincipal) -> Result<String, Error> {
    let account = p.tenant.account_id();
    let (operation, started, now) = {
        let mut conn = db::connect(r).await?;
        let tx = conn.transaction().await?;
        db::owner(&tx, r, p).await?;
        let c = db::customer(&tx, r, account, true)
            .await?
            .ok_or(Error::Database)?;
        if let Some(id) = c.id {
            db::final_owner(&tx, p).await?;
            tx.commit().await?;
            return Ok(id);
        }
        let now = db::now(&tx).await?;
        db::final_owner(&tx, p).await?;
        tx.commit().await?;
        (c.operation, c.started, now)
    };
    // Stripe retains idempotency keys for at least 24h. An unknown operation
    // outside our smaller window is reviewable, never replayed as a new charge.
    if now < started || now - started > 23 * 60 * 60 {
        return Err(Error::Pending);
    }
    owner_now(r, p).await?;
    let value = r
        .provider
        .request(
            &r.options.session_key,
            Method::POST,
            "/v1/customers",
            &[
                ("metadata[zrotext_namespace]", db::ns(r).to_string()),
                ("metadata[zrotext_account]", account.to_string()),
            ],
            Some(&format!("hosted-customer-{}-{operation}", db::ns(r))),
        )
        .await?;
    let customer = value["id"]
        .as_str()
        .filter(|v| id(v, "cus_"))
        .ok_or(Error::Identity)?;
    if value["object"] != "customer"
        || value["livemode"] != provider::live(&r.options)
        || value["metadata"]["zrotext_namespace"] != db::ns(r).to_string()
        || value["metadata"]["zrotext_account"] != account.to_string()
    {
        return Err(Error::Identity);
    }
    let mut conn = db::connect(r).await?;
    let tx = conn.transaction().await?;
    db::owner(&tx, r, p).await?;
    let c = db::customer(&tx, r, account, false)
        .await?
        .ok_or(Error::Identity)?;
    if c.operation != operation || c.id.as_ref().is_some_and(|c| c != customer) {
        return Err(Error::Conflict);
    }
    tx.execute("UPDATE hosted_billing_customers SET customer_id=$3,next_attempt_at=0 WHERE namespace_id=$1 AND account_id=$2 AND customer_id IS NULL",&[&db::ns(r),&account,&customer]).await?;
    db::final_owner(&tx, p).await?;
    tx.commit().await?;
    Ok(customer.into())
}
async fn checkout(
    State(r): State<Arc<Runtime>>,
    OwnerMutation(p, _slot): OwnerMutation,
    body: Bytes,
) -> Result<Json<Value>, Error> {
    empty(&body)?;
    let customer = ensure_customer(&r, &p).await?;
    observe_checkout(&r, &p).await?;
    let _catalog = r.provider.catalog_current(&r.options).await?;
    let subscriptions = r.provider.subscriptions(&r.options, &customer).await?;
    if !subscriptions.complete || !subscriptions.current.is_empty() {
        return Err(Error::Conflict);
    }
    let account = p.tenant.account_id();
    let operation = {
        let mut conn = db::connect(&r).await?;
        let tx = conn.transaction().await?;
        db::owner(&tx, &r, &p).await?;
        let c = db::customer(&tx, &r, account, false)
            .await?
            .ok_or(Error::Identity)?;
        let now = db::now(&tx).await?;
        db::require_no_global_review(&tx, &r).await?;
        if c.hold || c.review {
            return Err(Error::Conflict);
        }
        if c.checkout_state == "open" {
            let url = c.checkout_url.ok_or(Error::Pending)?;
            db::final_owner(&tx, &p).await?;
            tx.commit().await?;
            return Ok(Json(json!({"url":url})));
        }
        let operation = if c.checkout_state == "pending" {
            if c.checkout_started
                .is_none_or(|at| now < at || now - at > 23 * 60 * 60)
            {
                return Err(Error::Pending);
            }
            c.checkout.ok_or(Error::Identity)?
        } else {
            if matches!(c.checkout_state.as_str(), "complete" | "expired") {
                let terminal=tx.query_opt("SELECT 1 FROM hosted_billing_projections WHERE namespace_id=$1 AND account_id=$2 AND phase='terminal' AND dirty_generation=processed_generation",&[&db::ns(&r),&account]).await?.is_some();
                if c.queued != c.processed || !(terminal || (c.complete && c.nonterminal == 0)) {
                    return Err(Error::Pending);
                }
            }
            let operation = Uuid::new_v4();
            tx.execute("UPDATE hosted_billing_customers SET checkout_operation=$3,checkout_started_at=$4,checkout_id=NULL,checkout_url=NULL,checkout_expires_at=NULL,checkout_state='pending' WHERE namespace_id=$1 AND account_id=$2",&[&db::ns(&r),&account,&operation,&now]).await?;
            operation
        };
        db::final_owner(&tx, &p).await?;
        tx.commit().await?;
        operation
    };
    owner_now(&r, &p).await?;
    let origin = &r.auth.canonical_origin;
    let value = r
        .provider
        .request(
            &r.options.session_key,
            Method::POST,
            "/v1/checkout/sessions",
            &[
                ("mode", "subscription".into()),
                ("customer", customer.clone()),
                ("client_reference_id", account.to_string()),
                ("line_items[0][price]", r.options.plan.price().into()),
                ("line_items[0][quantity]", "1".into()),
                (
                    "automatic_tax[enabled]",
                    r.options.automatic_tax.to_string(),
                ),
                ("billing_address_collection", "required".into()),
                ("customer_update[address]", "auto".into()),
                ("allow_promotion_codes", "false".into()),
                ("metadata[zrotext_namespace]", db::ns(&r).to_string()),
                ("metadata[zrotext_account]", account.to_string()),
                (
                    "success_url",
                    format!("{origin}/owner/hosted?checkout=return"),
                ),
                (
                    "cancel_url",
                    format!("{origin}/owner/hosted?checkout=cancel"),
                ),
            ],
            Some(&format!("hosted-checkout-{}-{operation}", db::ns(&r))),
        )
        .await?;
    let session = value["id"]
        .as_str()
        .filter(|v| id(v, "cs_"))
        .ok_or(Error::Identity)?;
    if value["object"] != "checkout.session"
        || value["livemode"] != provider::live(&r.options)
        || value["customer"] != customer
    {
        return Err(Error::Identity);
    }
    let mut conn = db::connect(&r).await?;
    let tx = conn.transaction().await?;
    db::owner(&tx, &r, &p).await?;
    tx.execute("UPDATE hosted_billing_customers SET checkout_id=$4 WHERE namespace_id=$1 AND account_id=$2 AND checkout_operation=$3 AND checkout_state='pending' AND (checkout_id IS NULL OR checkout_id=$4)",&[&db::ns(&r),&account,&operation,&session]).await?;
    db::final_owner(&tx, &p).await?;
    tx.commit().await?;
    observe_checkout(&r, &p).await?;
    let mut conn = db::connect(&r).await?;
    let tx = conn.transaction().await?;
    db::owner(&tx, &r, &p).await?;
    let c = db::customer(&tx, &r, account, false)
        .await?
        .ok_or(Error::Pending)?;
    if c.checkout_state != "open" {
        return Err(Error::Pending);
    }
    let url = c.checkout_url.ok_or(Error::Pending)?;
    db::final_owner(&tx, &p).await?;
    tx.commit().await?;
    Ok(Json(json!({"url":url})))
}
async fn observe_checkout(r: &Runtime, p: &SessionPrincipal) -> Result<(), Error> {
    let account = p.tenant.account_id();
    let snapshot = {
        let mut conn = db::connect(r).await?;
        let tx = conn.transaction().await?;
        db::owner(&tx, r, p).await?;
        let c = db::customer(&tx, r, account, false).await?;
        db::final_owner(&tx, p).await?;
        tx.commit().await?;
        c
    };
    let Some(c) = snapshot else { return Ok(()) };
    let Some(session) = c.checkout_id else {
        return Ok(());
    };
    let customer = c.id.ok_or(Error::Identity)?;
    if !id(&session, "cs_") {
        return Err(Error::Identity);
    }
    let v = r
        .provider
        .request(
            &r.options.session_key,
            Method::GET,
            &format!("/v1/checkout/sessions/{session}"),
            &[("expand[]", "line_items".into())],
            None,
        )
        .await?;
    let status = v["status"]
        .as_str()
        .filter(|s| matches!(*s, "open" | "complete" | "expired"))
        .ok_or(Error::Provider)?;
    let expires = v["expires_at"]
        .as_i64()
        .filter(|n| *n >= 0 && *n < 253_402_300_799)
        .ok_or(Error::Provider)?;
    let items = v["line_items"]["data"].as_array().ok_or(Error::Provider)?;
    if v["object"] != "checkout.session"
        || v["id"] != session
        || v["livemode"] != provider::live(&r.options)
        || v["mode"] != "subscription"
        || v["customer"] != customer
        || v["client_reference_id"] != account.to_string()
        || v["metadata"]["zrotext_namespace"] != db::ns(r).to_string()
        || v["metadata"]["zrotext_account"] != account.to_string()
        || v["line_items"]["has_more"] != false
        || items.len() != 1
        || items[0]["quantity"] != 1
        || items[0]["price"]["id"] != r.options.plan.price()
        || items[0]["price"]["livemode"] != provider::live(&r.options)
    {
        return Err(Error::Identity);
    }
    let url = if status == "open" {
        Some(trusted_url(
            v["url"].as_str().ok_or(Error::Provider)?,
            "checkout.stripe.com",
        )?)
    } else {
        None
    };
    let mut conn = db::connect(r).await?;
    let tx = conn.transaction().await?;
    db::owner(&tx, r, p).await?;
    let current = db::customer(&tx, r, account, false)
        .await?
        .ok_or(Error::Identity)?;
    if current.checkout_id.as_deref() != Some(&session) {
        return Err(Error::Pending);
    }
    if status == "open" && expires <= db::now(&tx).await? {
        return Err(Error::Pending);
    }
    tx.execute("UPDATE hosted_billing_customers SET checkout_state=$4,checkout_url=$5,checkout_expires_at=$6 WHERE namespace_id=$1 AND account_id=$2 AND checkout_id=$3",&[&db::ns(r),&account,&session,&status,&url,&expires]).await?;
    if status != current.checkout_state && matches!(status, "complete" | "expired") {
        db::queue(&tx, r, account).await?;
    }
    db::final_owner(&tx, p).await?;
    tx.commit().await?;
    Ok(())
}
fn trusted_url(value: &str, host: &str) -> Result<String, Error> {
    let u = reqwest::Url::parse(value).map_err(|_| Error::Provider)?;
    if value.len() > 4096
        || value
            .bytes()
            .any(|b| b.is_ascii_control() || b.is_ascii_whitespace())
        || u.scheme() != "https"
        || u.host_str() != Some(host)
        || !u.username().is_empty()
        || u.password().is_some()
        || u.port().is_some()
    {
        return Err(Error::Provider);
    }
    Ok(value.into())
}
async fn portal(
    State(r): State<Arc<Runtime>>,
    OwnerMutation(p, _slot): OwnerMutation,
    body: Bytes,
) -> Result<Json<Value>, Error> {
    empty(&body)?;
    r.provider.current_portal(&r.options).await?;
    let customer = {
        let mut conn = db::connect(&r).await?;
        let tx = conn.transaction().await?;
        db::owner(&tx, &r, &p).await?;
        let c = db::customer(&tx, &r, p.tenant.account_id(), false)
            .await?
            .and_then(|c| c.id)
            .ok_or(Error::Pending)?;
        db::final_owner(&tx, &p).await?;
        tx.commit().await?;
        c
    };
    owner_now(&r, &p).await?;
    let value = r
        .provider
        .request(
            &r.options.session_key,
            Method::POST,
            "/v1/billing_portal/sessions",
            &[
                ("customer", customer.clone()),
                ("configuration", r.options.portal_configuration.clone()),
                (
                    "return_url",
                    format!("{}/owner/hosted", r.auth.canonical_origin),
                ),
            ],
            None,
        )
        .await?;
    let url = trusted_url(
        value["url"].as_str().ok_or(Error::Provider)?,
        "billing.stripe.com",
    )?;
    if value["object"] != "billing_portal.session"
        || value["livemode"] != provider::live(&r.options)
        || value["customer"] != customer
        || value["configuration"] != r.options.portal_configuration
    {
        return Err(Error::Identity);
    }
    owner_now(&r, &p).await?;
    Ok(Json(json!({"url":url})))
}

async fn webhook(
    State(r): State<Arc<Runtime>>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<StatusCode, Error> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| Error::Configuration)?
        .as_secs() as i64;
    let signature = headers
        .get("stripe-signature")
        .and_then(|s| s.to_str().ok())
        .ok_or(Error::Conflict)?;
    crate::billing::verify_raw_payload(&body, signature, &r.options.webhook_secret, now)
        .map_err(|_| Error::Conflict)?;
    let event: Value = serde_json::from_slice(&body).map_err(|_| Error::Conflict)?;
    let eid = event["id"]
        .as_str()
        .filter(|s| id(s, "evt_"))
        .ok_or(Error::Conflict)?;
    if event["object"] != "event"
        || event["livemode"] != provider::live(&r.options)
        || !event["context"].is_null()
        || !event["account"].is_null()
        || event["api_version"] != crate::billing::risk::STRIPE_API_VERSION
    {
        return Err(Error::Identity);
    }
    // Canonical event retrieval with the already identity-verified read key
    // proves the account for non-Connect events, which omit `account`.
    let digest = Sha256::digest(&body).to_vec();
    {
        let mut conn = db::connect(&r).await?;
        let marker = db::marker(&mut conn).await?;
        r.gate.check_marker(&marker).map_err(|_| Error::Identity)?;
        if let Some(row)=conn.query_opt("SELECT body_digest FROM hosted_billing_events WHERE namespace_id=$1 AND event_id=$2",&[&db::ns(&r),&eid]).await?{return if row.get::<_,Vec<u8>>(0)==digest{Ok(StatusCode::NO_CONTENT)}else{Err(Error::Conflict)}}
    }
    let canonical = r
        .provider
        .get(&r.options.read_key, &format!("/v1/events/{eid}"))
        .await?;
    for key in [
        "id",
        "object",
        "livemode",
        "type",
        "created",
        "account",
        "context",
        "api_version",
        "data",
    ] {
        if event[key] != canonical[key] {
            return Err(Error::Identity);
        }
    }
    let kind = event["type"]
        .as_str()
        .filter(|s| !s.is_empty() && s.len() <= 100)
        .ok_or(Error::Conflict)?;
    let object = &event["data"]["object"];
    let object_id = object["id"]
        .as_str()
        .filter(|s| super::super::namespace::valid_external_id(s))
        .unwrap_or("");
    let occurred = event["created"]
        .as_i64()
        .filter(|n| *n >= 0 && *n < 253_402_300_799)
        .ok_or(Error::Conflict)?;
    let risk = kind.starts_with("refund.")
        || kind.starts_with("charge.dispute.")
        || kind.starts_with("charge.refund");
    let resolution = if risk {
        Some(provider::resolve_risk(&r, kind, object).await?)
    } else {
        None
    };
    let customer = resolution
        .as_ref()
        .and_then(|x| x.customer.clone())
        .or_else(|| {
            object["customer"]
                .as_str()
                .filter(|s| id(s, "cus_"))
                .map(String::from)
        });
    let invoice = if kind == "invoice.payment_failed"
        && object["object"] == "invoice"
        && object["livemode"] == provider::live(&r.options)
        && id(object_id, "in_")
    {
        Some(object_id.to_owned())
    } else {
        resolution.as_ref().and_then(|x| x.invoice.clone())
    };
    let supported = matches!(
        kind,
        "customer.subscription.created"
            | "customer.subscription.updated"
            | "customer.subscription.deleted"
            | "invoice.payment_failed"
            | "invoice.paid"
            | "checkout.session.completed"
            | "checkout.session.expired"
    ) || risk;
    let mut conn = db::connect(&r).await?;
    let tx = conn.transaction().await?;
    // Lock namespace before discovering/binding any owner. Events never create
    // customer bindings, including exact-ID collisions in a different mode.
    let n = tx
        .query_one(
            "SELECT namespace_id,policy_revision,enabled FROM hosted_billing_namespaces FOR SHARE",
            &[],
        )
        .await?;
    if n.get::<_, Uuid>(0) != db::ns(&r)
        || n.get::<_, i64>(1) != r.options.policy_revision as i64
        || !n.get::<_, bool>(2)
    {
        return Err(Error::Identity);
    }
    tx.query_one(
        "SELECT pg_advisory_xact_lock(hashtextextended($1,0))",
        &[&format!("{}:{eid}", db::ns(&r))],
    )
    .await?;
    if let Some(row) = tx
        .query_opt(
            "SELECT body_digest FROM hosted_billing_events WHERE namespace_id=$1 AND event_id=$2",
            &[&db::ns(&r), &eid],
        )
        .await?
    {
        return if row.get::<_, Vec<u8>>(0) == digest {
            Ok(StatusCode::NO_CONTENT)
        } else {
            Err(Error::Conflict)
        };
    }
    let account = if let Some(customer) = &customer {
        tx.query_opt("SELECT account_id FROM hosted_billing_customers WHERE namespace_id=$1 AND customer_id=$2",&[&db::ns(&r),customer]).await?.map(|row|row.get::<_,Uuid>(0))
    } else {
        None
    };
    let mut hold = false;
    let mut review = risk;
    if let Some(account) = account {
        db::lock(&tx, &r, account).await?;
        let _ = db::customer(&tx, &r, account, false).await?;
        if let Some(resolution) = &resolution
            && resolution.attributed
            && let Some(subscription) = &resolution.subscription
        {
            hold=tx.query_opt("SELECT 1 FROM hosted_billing_projections WHERE namespace_id=$1 AND account_id=$2 AND subscription_id=$3 UNION ALL SELECT 1 FROM hosted_billing_history WHERE namespace_id=$1 AND account_id=$2 AND subscription_id=$3 LIMIT 1",&[&db::ns(&r),&account,subscription]).await?.is_some();
            review = !hold;
        }
        if hold || review {
            tx.execute("UPDATE hosted_billing_customers SET payment_hold=payment_hold OR $3,review_required=review_required OR $4 WHERE namespace_id=$1 AND account_id=$2",&[&db::ns(&r),&account,&hold,&review]).await?;
            tx.execute("UPDATE hosted_billing_projections SET payment_hold=payment_hold OR $3,review_required=review_required OR $4 WHERE namespace_id=$1 AND account_id=$2",&[&db::ns(&r),&account,&hold,&review]).await?;
        }
        if supported {
            db::queue(&tx, &r, account).await?;
        }
    }
    // An unsupported risk pointer cannot silently disappear merely because
    // attribution failed. Record a namespace review latch before acknowledging.
    if risk && account.is_none() {
        tx.execute(
            "UPDATE hosted_billing_namespaces SET review_required=true WHERE namespace_id=$1",
            &[&db::ns(&r)],
        )
        .await?;
    }
    let state = if hold {
        "held"
    } else if review {
        "review"
    } else if account.is_none() {
        "unbound"
    } else if supported {
        "queued"
    } else {
        "processed"
    };
    tx.execute("INSERT INTO hosted_billing_events(namespace_id,event_id,body_digest,event_type,object_id,customer_id,account_id,occurred_at,received_at,invoice_id,state) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11) ON CONFLICT DO NOTHING",&[&db::ns(&r),&eid,&digest,&kind,&object_id,&customer,&account,&occurred,&db::now(&tx).await?,&invoice,&state]).await?;
    // A concurrent replay must have exactly the original bytes. Never ACK a
    // changed delivery after losing the unique-index insertion race.
    let stored: Vec<u8> = tx
        .query_one(
            "SELECT body_digest FROM hosted_billing_events WHERE namespace_id=$1 AND event_id=$2",
            &[&db::ns(&r), &eid],
        )
        .await?
        .get(0);
    if stored != digest {
        return Err(Error::Conflict);
    }
    tx.commit().await?;
    r.notify.notify_one();
    Ok(StatusCode::NO_CONTENT)
}

#[cfg(test)]
mod url_tests {
    use super::*;
    #[test]
    fn checkout_fragment_is_opaque_and_preserved_byte_for_byte() {
        let value = "https://checkout.stripe.com/c/pay/cs_fixture#fidkdWxOYHwnPyd1blppbHNgWjA0YHc2THZfZ2pzTGM9N2lL";
        assert_eq!(trusted_url(value, "checkout.stripe.com").unwrap(), value);
    }
    #[test]
    fn returned_urls_refuse_raw_controls_and_authority_changes() {
        for value in [
            "https://checkout.stripe.com/c/pay/cs_\nfixture",
            "https://checkout.stripe.com/c/pay/cs_fixture#with space",
            "http://checkout.stripe.com/c/pay/cs_fixture",
            "https://checkout.stripe.com.foreign.example/c/pay/cs_fixture",
            "https://user@checkout.stripe.com/c/pay/cs_fixture",
            "https://checkout.stripe.com:444/c/pay/cs_fixture",
        ] {
            assert_eq!(
                trusted_url(value, "checkout.stripe.com"),
                Err(Error::Provider)
            );
        }
    }
}

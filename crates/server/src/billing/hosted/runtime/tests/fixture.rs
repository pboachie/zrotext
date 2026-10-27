// SPDX-License-Identifier: AGPL-3.0-only
use super::*;
use crate::{
    auth,
    http_auth::{AuthHttpState, DisabledVerificationDispatcher},
};
use axum::{
    Json, Router,
    body::{Body, to_bytes},
    extract::{Request, State},
    http::{Method, StatusCode},
    response::IntoResponse,
};
use serde_json::{Value, json};
use std::{collections::HashMap, sync::Mutex, time::SystemTime};

pub struct Fake {
    pub inner: Mutex<ProviderState>,
    pub pause: Mutex<Option<Arc<ReadPause>>>,
}
pub struct ReadPause {
    pub started: Notify,
    pub release: Notify,
}
pub struct ProviderState {
    pub live: bool,
    pub account: String,
    pub active: bool,
    pub subscriptions: Value,
    pub invoice: Value,
    pub events: HashMap<String, Value>,
    pub checkout: Option<Value>,
    pub operations: Vec<String>,
    pub requests: Vec<(String, String)>,
    pub outage: bool,
    pub lose_checkout: bool,
}
impl Fake {
    pub fn new(mode: Mode) -> Self {
        Self {
            pause: Mutex::new(None),
            inner: Mutex::new(ProviderState {
                live: mode == Mode::Live,
                account: "acct_fixture".into(),
                active: true,
                subscriptions: json!({"object":"list","has_more":false,"data":[]}),
                invoice: Value::Null,
                events: HashMap::new(),
                checkout: None,
                operations: Vec::new(),
                requests: Vec::new(),
                outage: false,
                lose_checkout: false,
            }),
        }
    }
    pub fn subscription(&self, now: i64, status: &str) {
        let mut s = self.inner.lock().unwrap();
        let live = s.live;
        s.subscriptions = json!({"object":"list","has_more":false,"data":[{"object":"subscription","id":"sub_fixture","livemode":live,"customer":"cus_fixture","status":status,"latest_invoice":"in_fixture","items":{"object":"list","has_more":false,"data":[{"id":"si_fixture","quantity":1,"price":{"id":"price_fixture","livemode":live},"current_period_start":now-600,"current_period_end":now+86400}]}}]});
        s.invoice = json!({"object":"invoice","id":"in_fixture","livemode":live,"customer":"cus_fixture","status":if status=="active"{"paid"}else{"open"},"parent":{"subscription_details":{"subscription":"sub_fixture"}},"period_start":now-90000,"period_end":now-600,"lines":{"object":"list","has_more":false,"data":[{"object":"line_item","id":"il_fixture","invoice":"in_fixture","livemode":live,"quantity":1,"parent":{"type":"subscription_item_details","subscription_item_details":{"subscription":"sub_fixture","subscription_item":"si_fixture","proration":false}},"pricing":{"type":"price_details","price_details":{"price":"price_fixture"}},"period":{"start":now-600,"end":now+86400}}]}});
    }
}
async fn respond(State(fake): State<Arc<Fake>>, request: Request) -> axum::response::Response {
    let path = request.uri().path().to_owned();
    let pause = if path == "/v1/subscriptions" {
        fake.pause.lock().unwrap().take()
    } else {
        None
    };
    if let Some(pause) = pause {
        pause.started.notify_one();
        pause.release.notified().await;
    }
    let method = request.method().clone();
    let key = request
        .headers()
        .get("idempotency-key")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_owned();
    let bytes = to_bytes(request.into_body(), 65536).await.unwrap();
    let url = reqwest::Url::parse(&format!(
        "https://fixture.example/?{}",
        String::from_utf8_lossy(&bytes)
    ))
    .unwrap();
    let fields: HashMap<String, String> = url
        .query_pairs()
        .map(|(k, v)| (k.into_owned(), v.into_owned()))
        .collect();
    let mut s = fake.inner.lock().unwrap();
    s.requests.push((method.to_string(), path.clone()));
    if s.outage {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    }
    let value = match path.as_str() {
        "/v1/account" => json!({"object":"account","id":s.account}),
        "/v1/balance" => json!({"object":"balance","livemode":s.live}),
        "/v1/prices/price_fixture" => {
            json!({"object":"price","id":"price_fixture","livemode":s.live,"active":s.active,"type":"recurring","billing_scheme":"per_unit","unit_amount":1200,"currency":"usd","tax_behavior":"exclusive","recurring":{"usage_type":"licensed","interval":"month","interval_count":1}})
        }
        "/v1/billing_portal/configurations/bpc_fixture" => {
            json!({"object":"billing_portal.configuration","id":"bpc_fixture","livemode":s.live,"active":true,"features":{"subscription_update":{"enabled":false}}})
        }
        "/v1/webhook_endpoints/we_fixture" => {
            json!({"object":"webhook_endpoint","id":"we_fixture","livemode":s.live,"status":"enabled","api_version":crate::billing::risk::STRIPE_API_VERSION,"url":"https://test.example/v1/billing/stripe-events","enabled_events":["*"]})
        }
        "/v1/subscriptions" => s.subscriptions.clone(),
        "/v1/invoices/in_fixture" => s.invoice.clone(),
        "/v1/customers" => {
            json!({"object":"customer","id":"cus_fixture","livemode":s.live,"metadata":{"zrotext_namespace":fields["metadata[zrotext_namespace]"],"zrotext_account":fields["metadata[zrotext_account]"]}})
        }
        "/v1/checkout/sessions" if method == Method::POST => {
            let repeat = s.operations.iter().any(|old| old == &key);
            s.operations.push(key);
            if s.checkout.is_none() || !repeat {
                let count = s
                    .operations
                    .iter()
                    .collect::<std::collections::HashSet<_>>()
                    .len();
                let session = if count == 1 {
                    "cs_fixture".to_owned()
                } else {
                    format!("cs_fixture{count}")
                };
                let now = SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs();
                s.checkout = Some(
                    json!({"id":session,"object":"checkout.session","livemode":s.live,"status":"open","mode":"subscription","customer":"cus_fixture","client_reference_id":fields["client_reference_id"],"metadata":{"zrotext_namespace":fields["metadata[zrotext_namespace]"],"zrotext_account":fields["metadata[zrotext_account]"]},"expires_at":now+3600,"url":format!("https://checkout.stripe.com/c/pay/{session}#fidkdWxOYHwnPyd1blppbHNgWjA0YHc2THZfZ2pzTGM9N2lL"),"line_items":{"has_more":false,"data":[{"quantity":1,"price":{"id":"price_fixture","livemode":s.live}}]}}),
                );
            }
            if s.lose_checkout {
                s.lose_checkout = false;
                return StatusCode::SERVICE_UNAVAILABLE.into_response();
            }
            s.checkout.clone().unwrap()
        }
        "/v1/checkout/sessions/cs_fixture" => s.checkout.clone().unwrap(),
        _ if path.starts_with("/v1/checkout/sessions/")
            && s.checkout
                .as_ref()
                .is_some_and(|c| c["id"] == path.trim_start_matches("/v1/checkout/sessions/")) =>
        {
            s.checkout.clone().unwrap()
        }
        "/v1/billing_portal/sessions" => {
            json!({"object":"billing_portal.session","livemode":s.live,"customer":fields["customer"],"configuration":fields["configuration"],"url":"https://billing.stripe.com/p/session/fixture"})
        }
        _ if path.starts_with("/v1/events/") => s
            .events
            .get(path.trim_start_matches("/v1/events/"))
            .cloned()
            .unwrap_or(Value::Null),
        _ if path.starts_with("/v1/invoices/")
            && s.invoice["id"] == path.trim_start_matches("/v1/invoices/") =>
        {
            s.invoice.clone()
        }
        _ => return StatusCode::NOT_FOUND.into_response(),
    };
    Json(value).into_response()
}
pub struct Fixture {
    pub database: crate::test_database::Fixture,
    pub app_url: String,
    pub auth: AuthHttpState,
    pub owner: auth::SessionPrincipal,
    pub login: auth::SessionCredentials,
    pub fake: Arc<Fake>,
    pub base: String,
    pub server: tokio::task::JoinHandle<()>,
    pub namespace: Uuid,
}
impl Fixture {
    pub async fn new(mode: Mode) -> Self {
        // Hosted startup intentionally reads public and requires the current
        // native transaction identity. A prefix107 search_path fixture cannot
        // exercise that contract or the stock ordinary-runtime ACLs.
        let mut database = crate::test_database::Fixture::new("ZT_AUTH_TEST_DATABASE_URL").await;
        database.verify().await;
        let hasher = Arc::new(auth::TokenHasher::new(crate::test_keys::key(1)).unwrap());
        let password = crate::test_keys::password(2);
        let signup = auth::register(
            &mut database.owner,
            &hasher,
            "hosted@example.test",
            &password,
        )
        .await
        .unwrap();
        auth::verify_email(&mut database.owner, &hasher, &signup.verification_token)
            .await
            .unwrap();
        let login = auth::login(&database.owner, &hasher, "hosted@example.test", &password)
            .await
            .unwrap();
        let owner = auth::authenticate_session(&database.owner, &hasher, &login.token)
            .await
            .unwrap();
        let namespace = Uuid::from_bytes([1; 16]);
        database.owner.execute("INSERT INTO public.hosted_billing_namespaces(namespace_id,mode,provider_account,policy_revision,enabled,old_binary_fenced) VALUES($1,$2,'acct_fixture',1,true,true)",&[&namespace,&mode_name(mode)]).await.unwrap();
        database
            .owner
            .execute(
                "INSERT INTO public.hosted_runtime_secrets VALUES($1,$2)",
                &[&namespace, &&[7u8; 32][..]],
            )
            .await
            .unwrap();
        let app_url = database.runtime_url.clone();
        let auth = AuthHttpState::new(
            app_url.clone(),
            hasher,
            "https://test.example".into(),
            Arc::new(DisabledVerificationDispatcher),
        )
        .unwrap();
        let fake = Arc::new(Fake::new(mode));
        let listener = tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let app = Router::new().fallback(respond).with_state(fake.clone());
        let server = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        Self {
            database,
            app_url,
            auth,
            owner,
            login,
            fake,
            base,
            server,
            namespace,
        }
    }
    pub async fn runtime(&self, mode: Mode) -> Arc<Runtime> {
        Runtime::start_with(
            self.auth.clone(),
            options(mode),
            Arc::new(AtomicBool::new(false)),
            Arc::new(Notify::new()),
            provider::Provider::fake(self.base.clone()),
        )
        .await
        .unwrap()
    }
    pub fn request(&self, path: &str, method: &str) -> axum::http::Request<Body> {
        axum::http::Request::builder()
            .method(method)
            .uri(path)
            .header("origin", "https://test.example")
            .header(
                "cookie",
                format!(
                    "__Host-zrotext_session={}; __Host-zrotext_csrf={}",
                    self.login.token, self.login.csrf_token
                ),
            )
            .header("x-zrotext-csrf", &self.login.csrf_token)
            .body(Body::empty())
            .unwrap()
    }
    pub async fn due(&self) {
        self.database
            .owner
            .execute(
                "UPDATE hosted_billing_customers SET next_attempt_at=0,lease_until=0",
                &[],
            )
            .await
            .unwrap();
    }
    pub async fn now(&self) -> i64 {
        self.database
            .owner
            .query_one(
                "SELECT floor(extract(epoch FROM clock_timestamp()))::bigint",
                &[],
            )
            .await
            .unwrap()
            .get(0)
    }
    pub async fn cleanup(self) {
        self.server.abort();
        let _ = self.server.await;
        self.database.finish().await;
    }
}

// SPDX-License-Identifier: AGPL-3.0-only
//! Default-disabled startup composition. No credential, consent or trust provisioning.
use super::{OwnerConversationsState, browser_assets::BrowserAssets, confirmed_http, owner_host};
use crate::device_socket::{self, DeviceSocketState};
use axum::Router;
use std::path::Path;

pub struct Startup {
    assets: BrowserAssets,
    wss_origin: String,
}

impl Startup {
    /// Disabled startup performs no filesystem access and ignores stale optional configuration.
    /// Enabling requires a packaged SDK and an explicitly selected WSS endpoint; neither grants
    /// a browser root pin, a phone decision, content admission or dispatch authorization.
    pub fn load(
        enabled: bool,
        sdk_directory: Option<&Path>,
        wss_origin: Option<&str>,
    ) -> Result<Option<Self>, &'static str> {
        if !enabled {
            return Ok(None);
        }
        let origin = wss_origin.ok_or("Conversation WSS origin required")?;
        device_socket::conversation_origin_check(origin)?;
        let assets =
            BrowserAssets::load(sdk_directory.ok_or("Conversation SDK directory required")?)
                .map_err(|_| "Conversation SDK package unavailable")?;
        assets.require_owner_setup()?;
        Ok(Some(Self {
            assets,
            wss_origin: origin.to_owned(),
        }))
    }

    /// Replaces (rather than duplicates) the ordinary device-stream router. Existing owner
    /// cookies/CSRF, account socket budgets and sealed execution checks stay authoritative.
    pub fn router(
        self,
        owner: OwnerConversationsState,
        socket: DeviceSocketState,
        sockets_per_account: usize,
        billing_enabled: bool,
    ) -> Result<Router, &'static str> {
        let device = device_socket::router_with_conversations_and_account_share(
            socket.clone(),
            &self.wss_origin,
            sockets_per_account,
        )?;
        Ok(super::router_with_browser_sdk(owner.clone(), self.assets)
            .merge(owner_host::router(owner.clone()))
            .merge(confirmed_http::router(owner, socket, billing_enabled))
            .merge(crate::owner_ui::conversation_router())
            .merge(device))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn disabled_configuration_never_reads_an_sdk_or_enables_a_socket() {
        assert!(
            Startup::load(
                false,
                Some(Path::new("unavailable-package")),
                Some("invalid")
            )
            .unwrap()
            .is_none()
        );
    }
    #[test]
    fn enabled_configuration_rejects_missing_or_untrusted_endpoints_before_package_access() {
        assert!(Startup::load(true, None, None).is_err());
        for origin in [
            "http://example.org",
            "ws://example.org",
            "wss://example.org/path",
            "wss://example.org?credential=fixture",
        ] {
            assert!(Startup::load(true, None, Some(origin)).is_err());
        }
        assert!(Startup::load(true, None, Some("wss://example.org")).is_err());
    }

    #[tokio::test]
    async fn ordinary_surface_is_absent_until_explicit_mount_and_delivers_concrete_setup_without_cache()
     {
        use axum::{
            body::Body,
            http::{Request, StatusCode, header},
        };
        use tower::ServiceExt;
        let request = || {
            Request::builder()
                .uri("/owner/conversation")
                .body(Body::empty())
                .unwrap()
        };
        assert_eq!(
            crate::owner_ui::router()
                .oneshot(request())
                .await
                .unwrap()
                .status(),
            StatusCode::NOT_FOUND
        );
        let enabled = crate::owner_ui::router().merge(crate::owner_ui::conversation_router());
        let page = enabled.clone().oneshot(request()).await.unwrap();
        assert_eq!(page.status(), StatusCode::OK);
        assert_eq!(page.headers()[header::CACHE_CONTROL], "no-store");
        assert!(page.headers().contains_key(header::CONTENT_SECURITY_POLICY));
        for path in [
            "conversation.js",
            "conversation-core.js",
            "conversation-bootstrap.js",
            "conversation-owner-adapter.js",
            "conversation-owner-setup.js",
            "conversation.css",
        ] {
            let response = enabled
                .clone()
                .oneshot(
                    Request::builder()
                        .uri(format!("/owner/{path}"))
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::OK, "{path}");
            assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
        }
    }
    #[tokio::test]
    async fn actual_startup_mount_delivers_package_and_refuses_api_bearers() {
        use axum::{
            body::Body,
            http::{Request, StatusCode, header},
        };
        use std::sync::{Arc, atomic::AtomicBool};
        use tower::ServiceExt;
        let package =
            std::env::temp_dir().join(format!("conversation-startup-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(package.join("sdk")).unwrap();
        for name in [
            "conversation-custody",
            "conversation-archive-custody",
            "draft02-manifest",
            "conversation-refresh-proposal",
            "conversation-activation-proposal",
        ] {
            std::fs::write(
                package.join(format!("sdk/{name}.js")),
                b"export const fixture = true;",
            )
            .unwrap();
        }
        let startup = Startup::load(true, Some(&package), Some("wss://example.org"))
            .unwrap()
            .unwrap();
        std::fs::remove_dir_all(&package).unwrap();
        let hasher = Arc::new(crate::auth::TokenHasher::new(crate::test_keys::key(91)).unwrap());
        let owner = OwnerConversationsState {
            database_url: "unavailable".into(),
            auth_hasher: hasher.clone(),
            canonical_origin: "https://example.org".into(),
        };
        let socket = DeviceSocketState {
            database_url: owner.database_url.clone(),
            site_id: "fixture".into(),
            instance_id: "fixture".into(),
            deployment_epoch: 1,
            enrollment_hasher: Arc::new(
                crate::enrollment::EnrollmentHasher::new(crate::test_keys::key(92)).unwrap(),
            ),
            auth_hasher: hasher,
            alpha_policy: Arc::new(
                crate::alpha_policy::AlphaPolicy::parse(None, None, None).unwrap(),
            ),
            dispatch_runtime_enabled: false,
            sealed_dispatch_enabled: false,
            inbound_pilot_enabled: false,
            line_opt_out_enabled: false,
            sms_line_activation_enabled: false,
            mms_spike_policy: Arc::new(
                device_socket::MmsSpikePolicy::parse(None, None, None).unwrap(),
            ),
            draining: Arc::new(AtomicBool::new(false)),
            drain_notify: Arc::new(tokio::sync::Notify::new()),
        };
        let router = startup.router(owner, socket, 1, false).unwrap();
        for path in [
            "/owner/conversation",
            "/owner/conversation-owner-setup.js",
            "/v1/owner/conversation-sdk/sdk/draft02-manifest.js",
        ] {
            let response = router
                .clone()
                .oneshot(Request::builder().uri(path).body(Body::empty()).unwrap())
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::OK, "{path}");
            assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
        }
        for path in [
            "/v1/owner/conversation",
            "/v1/owner/conversation/bootstrap",
            "/v1/owner/conversation/activation",
            "/v1/owner/conversation/enrollment",
            "/v1/owner/conversation/send",
        ] {
            let response = router
                .clone()
                .oneshot(
                    Request::builder()
                        .method("POST")
                        .uri(path)
                        .header(header::AUTHORIZATION, "Bearer fixture")
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::UNAUTHORIZED, "{path}");
            assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
        }
    }
}

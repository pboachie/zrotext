// SPDX-License-Identifier: AGPL-3.0-only
//! Public coarse capabilities from immutable server configuration. This route
//! does not inspect account existence, reveal prices/secrets or grant access.
use super::hosted::{
    Deployment,
    namespace::{Gate, Mode},
};
use crate::http_auth::RegistrationPolicy;
use axum::{Json, Router, extract::State as ExtractState, http::header, routing::get};
use serde::Serialize;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BillingVisibility {
    Disabled,
    Test,
    Live,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum RegistrationVisibility {
    Closed,
    InviteOnly,
    Open,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum DeploymentVisibility {
    Hosted,
    SelfHosted,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
struct Availability {
    schema_version: u8,
    deployment: DeploymentVisibility,
    registration: RegistrationVisibility,
    billing: BillingVisibility,
    checkout_available: bool,
    plan_catalog_available: bool,
}

#[derive(Clone)]
pub struct State {
    view: Availability,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AvailabilityError {
    ContradictoryConfiguration,
    UnverifiedNamespace,
}

impl State {
    /// Root/runtime owns these values. Route-mounted and approved-catalog
    /// booleans must describe actual runtime capabilities, never browser input.
    pub fn new(
        deployment: Deployment,
        registration_policy: &RegistrationPolicy,
        verification_ready: bool,
        billing: BillingVisibility,
        checkout_route_mounted: bool,
        plan_catalog_configured: bool,
        verified_gate: Option<&Gate>,
    ) -> Result<Self, AvailabilityError> {
        let self_hosted = deployment == Deployment::SelfHosted;
        if self_hosted
            && (billing != BillingVisibility::Disabled
                || checkout_route_mounted
                || plan_catalog_configured
                || verified_gate.is_some())
        {
            return Err(AvailabilityError::ContradictoryConfiguration);
        }
        if billing == BillingVisibility::Disabled
            && (checkout_route_mounted || verified_gate.is_some())
        {
            return Err(AvailabilityError::ContradictoryConfiguration);
        }
        let expected_mode = match billing {
            BillingVisibility::Disabled => None,
            BillingVisibility::Test => Some(Mode::Test),
            BillingVisibility::Live => Some(Mode::Live),
        };
        let namespace_verified = match verified_gate {
            Some(gate) => {
                let marker = gate
                    .marker()
                    .map_err(|_| AvailabilityError::UnverifiedNamespace)?;
                if Some(marker.namespace.mode()) != expected_mode {
                    return Err(AvailabilityError::UnverifiedNamespace);
                }
                true
            }
            None => false,
        };
        if billing == BillingVisibility::Live && !namespace_verified {
            return Err(AvailabilityError::UnverifiedNamespace);
        }
        let registration = if !verification_ready {
            RegistrationVisibility::Closed
        } else {
            match registration_policy {
                RegistrationPolicy::Closed => RegistrationVisibility::Closed,
                RegistrationPolicy::Allowlist { .. } => RegistrationVisibility::InviteOnly,
                RegistrationPolicy::Open => RegistrationVisibility::Open,
            }
        };
        Ok(Self {
            view: Availability {
                schema_version: 1,
                deployment: if self_hosted {
                    DeploymentVisibility::SelfHosted
                } else {
                    DeploymentVisibility::Hosted
                },
                registration,
                billing,
                checkout_available: checkout_route_mounted
                    && plan_catalog_configured
                    && namespace_verified,
                plan_catalog_available: plan_catalog_configured,
            },
        })
    }
}

/// Relative route; ROOT owns nesting it at /v1/service after source review.
pub fn router(state: State) -> Router {
    Router::new()
        .route("/availability", get(read))
        .with_state(state)
}

async fn read(ExtractState(state): ExtractState<State>) -> impl axum::response::IntoResponse {
    (
        [
            (header::CACHE_CONTROL, "no-store"),
            (header::REFERRER_POLICY, "no-referrer"),
            (header::X_CONTENT_TYPE_OPTIONS, "nosniff"),
        ],
        Json(state.view),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::billing::hosted::namespace::{Marker, Namespace, ProviderIdentity};
    use axum::{
        body::{Body, to_bytes},
        http::{Request, StatusCode},
    };
    use tower::ServiceExt;

    fn gate(mode: Mode) -> Gate {
        let namespace = Namespace::new([1; 16], mode, "acct_fixture").unwrap();
        Gate::verify(
            true,
            &namespace,
            1,
            &Marker {
                namespace: namespace.clone(),
                policy_revision: 1,
                enabled: true,
            },
            &ProviderIdentity {
                mode,
                provider_account: "acct_fixture".into(),
            },
        )
        .unwrap()
    }

    #[test]
    fn registration_remains_closed_without_a_ready_verification_dispatcher() {
        let state = State::new(
            Deployment::HostedPaid,
            &RegistrationPolicy::Open,
            false,
            BillingVisibility::Disabled,
            false,
            false,
            None,
        )
        .unwrap();
        assert_eq!(state.view.registration, RegistrationVisibility::Closed);
        assert!(!state.view.checkout_available);
    }

    #[test]
    fn invite_visibility_reveals_no_address_allowlist_or_invitation_key() {
        let policy = RegistrationPolicy::Allowlist {
            emails: ["invited@example.test".into()].into(),
            domains: Default::default(),
            enrollment_key: [3; 32],
        };
        let state = State::new(
            Deployment::HostedPaid,
            &policy,
            true,
            BillingVisibility::Disabled,
            false,
            false,
            None,
        )
        .unwrap();
        assert_eq!(state.view.registration, RegistrationVisibility::InviteOnly);
        let json = serde_json::to_string(&state.view).unwrap();
        assert!(!json.contains("invited@example.test"));
        assert!(!json.contains("enrollment"));
    }

    #[test]
    fn test_checkout_needs_mounted_route_approved_catalog_and_verified_namespace() {
        for mounted in [false, true] {
            for catalog in [false, true] {
                for verified in [false, true] {
                    let gate = gate(Mode::Test);
                    let state = State::new(
                        Deployment::HostedPaid,
                        &RegistrationPolicy::Open,
                        true,
                        BillingVisibility::Test,
                        mounted,
                        catalog,
                        verified.then_some(&gate),
                    )
                    .unwrap();
                    assert_eq!(
                        state.view.checkout_available,
                        mounted && catalog && verified
                    );
                }
            }
        }
    }

    #[test]
    fn self_hosted_configuration_is_independent_and_cannot_advertise_billing() {
        let state = State::new(
            Deployment::SelfHosted,
            &RegistrationPolicy::Open,
            true,
            BillingVisibility::Disabled,
            false,
            false,
            None,
        )
        .unwrap();
        assert_eq!(state.view.deployment, DeploymentVisibility::SelfHosted);
        assert_eq!(state.view.registration, RegistrationVisibility::Open);
        assert!(!state.view.checkout_available);
        assert!(!state.view.plan_catalog_available);
        assert!(
            State::new(
                Deployment::SelfHosted,
                &RegistrationPolicy::Closed,
                false,
                BillingVisibility::Test,
                false,
                false,
                None
            )
            .is_err()
        );
    }

    #[test]
    fn live_requires_a_live_gate_and_cannot_borrow_a_test_proof() {
        assert!(
            State::new(
                Deployment::HostedPaid,
                &RegistrationPolicy::Open,
                true,
                BillingVisibility::Live,
                true,
                true,
                None
            )
            .is_err()
        );
        assert!(
            State::new(
                Deployment::HostedPaid,
                &RegistrationPolicy::Open,
                true,
                BillingVisibility::Live,
                true,
                true,
                Some(&gate(Mode::Test))
            )
            .is_err()
        );
        let state = State::new(
            Deployment::HostedPaid,
            &RegistrationPolicy::Closed,
            false,
            BillingVisibility::Live,
            false,
            false,
            Some(&gate(Mode::Live)),
        )
        .unwrap();
        assert!(!state.view.checkout_available);
    }

    #[tokio::test]
    async fn public_route_returns_only_exact_coarse_no_store_fields_without_auth() {
        let state = State::new(
            Deployment::HostedPaid,
            &RegistrationPolicy::Closed,
            false,
            BillingVisibility::Disabled,
            false,
            false,
            None,
        )
        .unwrap();
        let response = router(state)
            .oneshot(
                Request::builder()
                    .uri("/availability")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
        let value: serde_json::Value =
            serde_json::from_slice(&to_bytes(response.into_body(), 4096).await.unwrap()).unwrap();
        assert_eq!(
            value,
            serde_json::json!({ "schema_version": 1, "deployment": "hosted",
            "registration": "closed", "billing": "disabled", "checkout_available": false,
            "plan_catalog_available": false })
        );
    }
}

// SPDX-License-Identifier: AGPL-3.0-only
use super::*;

mod caller;

#[test]
fn disabled_observation_needs_no_key_and_live_billing_is_refused() {
    assert!(
        TestUsageReconciler::configured(false, false, None)
            .unwrap()
            .is_none()
    );
    assert!(TestUsageReconciler::configured(true, false, None).is_err());
    assert!(TestUsageReconciler::configured(true, true, None).is_err());
    assert!(TestUsageReconciler::configured(true, true, Some("unsupported".into())).is_err());
}

#[test]
fn identifiers_cannot_change_provider_paths() {
    for value in [
        "mtr_",
        "mtr_other/period",
        "mtr_../customer",
        "mtr_other?customer=foreign",
    ] {
        assert!(!identifier(value, "mtr_"));
    }
    assert!(identifier("mtr_test_synthetic", "mtr_"));
}

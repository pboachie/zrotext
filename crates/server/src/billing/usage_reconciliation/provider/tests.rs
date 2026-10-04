// SPDX-License-Identifier: AGPL-3.0-only
use super::*;
use serde_json::json;

fn scope() -> Scope {
    Scope {
        account: Uuid::new_v4(),
        policy: 1,
        period: "2024-01-01".into(),
        customer: "cus_synthetic".into(),
        meter: "mtr_test_synthetic".into(),
        event_name: "gateway_submit".into(),
        start: 1704067200,
        end: 1706745600,
        invoice: Some("in_synthetic".into()),
        subscription: Some("sub_synthetic".into()),
        invoice_binding: None,
    }
}

fn summary(scope: &Scope) -> Value {
    json!({"object":"list","has_more":false,"data":[{"id":"mtrusg_test_synthetic", "object":"billing.meter_event_summary",
        "livemode":false,"meter":scope.meter,"start_time":scope.start,"end_time":scope.end,"aggregated_value":3}]})
}

#[test]
fn complete_summary_binds_meter_period_and_integral_units() {
    let scope = scope();
    let valid = summary(&scope);
    assert_eq!(parse_summary(&valid, &scope).unwrap(), 3);
    for (field, value) in [
        ("livemode", json!(true)),
        ("meter", json!("mtr_foreign")),
        ("start_time", json!(scope.start + 60)),
        ("end_time", json!(scope.end + 60)),
        ("aggregated_value", json!(-1)),
        ("aggregated_value", json!(1.5)),
        ("aggregated_value", json!(18446744073709551615u64)),
        ("object", json!("unrelated")),
    ] {
        let mut altered = valid.clone();
        altered["data"][0][field] = value;
        assert!(
            parse_summary(&altered, &scope).is_err(),
            "accepted substituted {field}"
        );
    }
    let mut incomplete = valid.clone();
    incomplete["has_more"] = json!(true);
    assert!(parse_summary(&incomplete, &scope).is_err());
    let mut duplicate = valid.clone();
    duplicate["data"]
        .as_array_mut()
        .unwrap()
        .push(valid["data"][0].clone());
    assert!(parse_summary(&duplicate, &scope).is_err());
    assert_eq!(
        parse_summary(&json!({"object":"list","has_more":false,"data":[]}), &scope).unwrap(),
        0
    );
    assert!(parse_summary(&json!({"object":"list","data":[]}), &scope).is_err());
}

#[test]
fn invoices_require_exact_trusted_customer_subscription_and_finalized_status() {
    let scope = scope();
    let valid = json!({"id":scope.invoice,"object":"invoice","customer":scope.customer,"livemode":false,
        "status":"open","parent":{"type":"subscription_details","subscription_details":{"subscription":scope.subscription}}});
    invoice_identity(&valid, &scope).unwrap();
    for (field, value) in [
        ("customer", json!("cus_foreign")),
        ("id", json!("in_foreign")),
        ("livemode", json!(true)),
        ("status", json!("draft")),
        ("status", json!("void")),
        ("object", json!("unrelated")),
    ] {
        let mut altered = valid.clone();
        altered[field] = value;
        assert!(
            invoice_identity(&altered, &scope).is_err(),
            "accepted substituted {field}"
        );
    }
    let mut altered = valid;
    altered["parent"]["subscription_details"]["subscription"] = json!("sub_foreign");
    assert!(invoice_identity(&altered, &scope).is_err());
}

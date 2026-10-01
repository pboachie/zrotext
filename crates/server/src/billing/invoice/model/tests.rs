// SPDX-License-Identifier: AGPL-3.0-only
use super::*;
use serde_json::json;

fn fixture() -> (Value, Value) {
    (
        json!({"id":"sub_fixture1","object":"subscription","livemode":false,
          "customer":"cus_fixture1","status":"active","latest_invoice":"in_fixture1",
          "cancel_at":null,"cancel_at_period_end":false,
          "items":{"object":"list","has_more":false,"data":[{"id":"si_fixture1",
            "quantity":1,"price":{"id":"price_fixture1"},
            "current_period_start":1000,"current_period_end":2000}]}}),
        json!({"id":"in_fixture1","object":"invoice","livemode":false,
          "customer":"cus_fixture1","status":"paid","billing_reason":"subscription_cycle",
          "parent":{"type":"subscription_details","subscription_details":{"subscription":"sub_fixture1"}},
          "lines":{"object":"list","has_more":false,"data":[{"id":"il_fixture1",
            "parent":{"type":"subscription_item_details","subscription_item_details":{
              "subscription_item":"si_fixture1","proration":false}},
            "period":{"start":1000,"end":2000},
            "pricing":{"price_details":{"price":"price_fixture1"}}}]}}),
    )
}

fn observed(sub: &Value, invoice: &Value) -> Result<Observation, BillingError> {
    parse(
        &serde_json::to_vec(sub).unwrap(),
        &serde_json::to_vec(invoice).unwrap(),
    )
}

#[test]
fn exact_non_prorated_current_paid_renewal_establishes_its_item_period() {
    let (sub, inv) = fixture();
    let current = observed(&sub, &inv).unwrap();
    assert!(current.can_establish_period());
    assert_eq!(current.period, Period::new(1_000_000, 2_000_000).unwrap());
    assert!(!current.period.contains(2_000_000));
    assert!(current.period.contains(1_000_000));
}

#[test]
fn invoice_account_customer_item_price_and_period_substitution_are_refused() {
    let (sub, inv) = fixture();
    for (pointer, replacement) in [
        ("/livemode", json!(true)),
        ("/customer", json!("cus_other1")),
        ("/id", json!("in_old1")),
        (
            "/parent/subscription_details/subscription",
            json!("sub_other1"),
        ),
        (
            "/lines/data/0/parent/subscription_item_details/subscription_item",
            json!("si_other1"),
        ),
        (
            "/lines/data/0/pricing/price_details/price",
            json!("price_other1"),
        ),
        ("/lines/data/0/period/start", json!(999)),
        (
            "/lines/data/0/parent/subscription_item_details/proration",
            json!(true),
        ),
        ("/lines/has_more", json!(true)),
    ] {
        let mut wrong = inv.clone();
        *wrong.pointer_mut(pointer).unwrap() = replacement;
        assert!(observed(&sub, &wrong).is_err(), "{pointer}");
    }
}

#[test]
fn paid_adjustment_never_establishes_a_new_period_or_duplicates_renewal() {
    let (sub, mut invoice) = fixture();
    invoice["billing_reason"] = json!("subscription_update");
    invoice["lines"]["data"][0]["parent"]["subscription_item_details"]["proration"] = json!(true);
    invoice["lines"]["data"][0]["period"]["start"] = json!(1500);
    assert!(!observed(&sub, &invoice).unwrap().can_establish_period());
    invoice["billing_reason"] = json!("subscription_cycle");
    assert!(observed(&sub, &invoice).is_err());
}

#[test]
fn invoice_top_level_period_and_totals_cannot_replace_line_authority() {
    let (sub, mut invoice) = fixture();
    invoice["period_start"] = json!(5);
    invoice["period_end"] = json!(6);
    invoice["amount_paid"] = json!(0);
    invoice["amount_due"] = json!(0);
    let current = observed(&sub, &invoice).unwrap();
    assert_eq!(current.period, Period::new(1_000_000, 2_000_000).unwrap());
    // Zero-cost finalized paid invoices are legitimate; status and identity,
    // not a guessed amount threshold, bind the renewal.
    assert!(current.can_establish_period());
}

#[test]
fn unbounded_or_incomplete_item_periods_are_refused_and_cancellation_changes_state() {
    let (sub, inv) = fixture();
    for (pointer, value) in [
        ("/items/has_more", json!(true)),
        ("/items/data/0/quantity", json!(2)),
        ("/items/data/0/current_period_start", json!(0)),
        ("/items/data/0/current_period_end", json!(i64::MAX)),
        ("/items/data/0/current_period_end", json!(1000)),
    ] {
        let mut wrong = sub.clone();
        *wrong.pointer_mut(pointer).unwrap() = value;
        assert!(observed(&wrong, &inv).is_err(), "{pointer}");
    }
    let first = observed(&sub, &inv).unwrap();
    let mut cancelled = sub;
    cancelled["cancel_at"] = json!(1500);
    cancelled["cancel_at_period_end"] = json!(true);
    assert!(!first.same_current_state(&observed(&cancelled, &inv).unwrap()));
}

#[test]
fn an_open_or_failed_invoice_never_grants_a_budget_period() {
    let (mut sub, mut inv) = fixture();
    inv["status"] = json!("open");
    sub["status"] = json!("past_due");
    assert!(!observed(&sub, &inv).unwrap().can_establish_period());
    sub["status"] = json!("active");
    assert!(!observed(&sub, &inv).unwrap().can_establish_period());
}

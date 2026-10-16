// SPDX-License-Identifier: AGPL-3.0-only
use super::*;
use serde_json::json;
#[test]
fn invoice_service_line_binds_price_item_and_period_without_using_collection_window() {
    let o = options(Mode::Live);
    let fake = fixture::Fake::new(Mode::Live);
    fake.subscription(1_000_000, "active");
    let v = fake.inner.lock().unwrap().invoice.clone();
    let s = provider::Subscription {
        id: "sub_fixture".into(),
        item: "si_fixture".into(),
        price: "price_fixture".into(),
        invoice: "in_fixture".into(),
        status: super::super::super::policy::SubscriptionStatus::Active,
        start: 999400,
        end: 1086400,
    };
    assert_ne!(v["period_end"], s.end);
    assert_eq!(
        provider::validate_invoice(&v, &o, "cus_fixture", &s),
        Ok(())
    );
    for case in 0..12 {
        let mut bad = v.clone();
        match case {
            0 => bad["lines"]["has_more"] = json!(true),
            1 => bad["lines"]["data"] = json!([]),
            2 => bad["lines"]["data"]
                .as_array_mut()
                .unwrap()
                .push(v["lines"]["data"][0].clone()),
            3 => {
                bad["lines"]["data"][0]["parent"]["subscription_item_details"]["subscription_item"] =
                    json!("si_foreign")
            }
            4 => {
                bad["lines"]["data"][0]["parent"]["subscription_item_details"]["subscription"] =
                    json!("sub_foreign")
            }
            5 => {
                bad["lines"]["data"][0]["parent"]["subscription_item_details"]["proration"] =
                    json!(true)
            }
            6 => {
                bad["lines"]["data"][0]["pricing"]["price_details"]["price"] =
                    json!("price_foreign")
            }
            7 => bad["lines"]["data"][0]["period"]["start"] = json!(999399),
            8 => bad["lines"]["data"][0]["period"]["end"] = json!(1086401),
            9 => bad["lines"]["data"][0]["livemode"] = json!(false),
            10 => bad["customer"] = json!("cus_foreign"),
            _ => bad["lines"]["data"][0]["invoice"] = json!("in_foreign"),
        }
        assert!(
            provider::validate_invoice(&bad, &o, "cus_fixture", &s).is_err(),
            "case {case}"
        );
    }
}

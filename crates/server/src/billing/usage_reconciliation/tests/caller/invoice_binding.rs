// SPDX-License-Identifier: AGPL-3.0-only
use super::*;

#[tokio::test]
async fn exact_invoice_line_item_and_price_are_required_even_for_the_same_meter() {
    for (price_id, line_id, item_id) in [
        ("price_Other", "il_Synthetic", "si_Synthetic"),
        ("price_Synthetic", "il_Other", "si_Synthetic"),
        ("price_Synthetic", "il_Synthetic", "si_Other"),
    ] {
        let mut bound = scope();
        bound.invoice_binding = Some((price_id.into(), line_id.into(), item_id.into()));
        let mut usage = line("il_Synthetic", 1);
        usage["parent"]["subscription_item_details"]["subscription_item"] = json!("si_Synthetic");
        let replies = vec![
            reply("/v1/billing/meters/mtr_Synthetic", meter()),
            reply(
                "/v1/billing/meters/mtr_Synthetic/event_summaries",
                summary(1),
            ),
            reply("/v1/invoices/in_Synthetic", invoice(vec![usage], false)),
            reply("/v1/prices/price_Synthetic", price()),
        ];
        let (worker, server) = tls(replies).await;
        assert!(worker.observe(&bound).await.is_err());
        assert_eq!(server.await.unwrap().len(), 4);
    }
}

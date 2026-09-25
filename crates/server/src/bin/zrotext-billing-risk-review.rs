// SPDX-License-Identifier: AGPL-3.0-only
//! Local operator command for signed Stripe TEST-mode risks awaiting review.
//! Only GET provider reads are made; no checkout, refund or dispute mutation.

use std::{env, error::Error};
use zeroize::Zeroizing;
use zrotext_server::billing::review::{
    ReviewPage, ReviewResult, list_review_required, review_with_stripe,
};

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let arguments = env::args().skip(1).collect::<Vec<_>>();
    let database_url = env::var("DATABASE_URL")?;
    let (mut db, connection) = zrotext_server::runtime_db::connect(&database_url).await?;
    tokio::spawn(async move {
        let _ = connection.await;
    });
    match arguments.as_slice() {
        [mode] if mode == "list" => {
            print_page(list_review_required(&db, None).await?);
        }
        [mode, flag, after] if mode == "list" && flag == "--after" => {
            print_page(list_review_required(&db, Some(after)).await?);
        }
        [mode, event_id, flag, operator_id] if mode == "resolve" && flag == "--operator" => {
            let key = Zeroizing::new(env::var("STRIPE_BILLING_RECONCILIATION_KEY")?);
            let result = review_with_stripe(&mut db, &key, event_id, operator_id, false).await?;
            print_result(event_id, result);
        }
        [mode, event_id, flag, operator_id, close] if mode == "resolve" && flag == "--operator" && close == "--close-failed-refund" => {
            let key = Zeroizing::new(env::var("STRIPE_BILLING_RECONCILIATION_KEY")?);
            let result = review_with_stripe(&mut db, &key, event_id, operator_id, true).await?;
            print_result(event_id, result);
        }
        _ => return Err("usage: zrotext-billing-risk-review list [--after evt_ID] | resolve evt_ID --operator ID [--close-failed-refund]".into()),
    }
    Ok(())
}

fn print_page(page: ReviewPage) {
    for row in page.items {
        println!(
            "{} {} customer_attributed={} account_bound={}",
            row.event_id, row.event_type, row.customer_attributed, row.account_bound
        );
    }
    if let Some(cursor) = page.next_after {
        println!("next_after={cursor}");
    }
}

fn print_result(event_id: &str, result: ReviewResult) {
    let state = match result {
        ReviewResult::Held => "held",
        ReviewResult::AttributedUnbound => {
            "attributed_unbound; rerun after trusted customer binding"
        }
        ReviewResult::ClosedFailedRefund => "closed_failed_refund",
        ReviewResult::ClosureNeedsApproval => {
            "failed refund verified; rerun with --close-failed-refund to close"
        }
        ReviewResult::AlreadyResolved => "already_resolved",
    };
    println!("{event_id}: {state}");
}

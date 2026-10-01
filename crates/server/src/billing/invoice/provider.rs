// SPDX-License-Identifier: AGPL-3.0-only
use super::super::{BillingError, is_test_api_key, risk::STRIPE_API_VERSION, valid_id, worker};
use super::{CurrentInvoice, model};
use reqwest::Client;

async fn read(http: &Client, key: &str, base: &str, path: &str) -> Result<Vec<u8>, BillingError> {
    let mut response = http
        .get(format!("{base}/v1/{path}"))
        .bearer_auth(key)
        .header("Stripe-Version", STRIPE_API_VERSION)
        .send()
        .await
        .map_err(|_| worker::ProviderFailure::Transport)?;
    if !response.status().is_success() {
        return Err(worker::provider_failure_from_status(&response).into());
    }
    let mut body = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|_| worker::ProviderFailure::Transport)?
    {
        if body.len().saturating_add(chunk.len()) > 64 * 1024 {
            return Err(worker::ProviderFailure::InvalidResponse.into());
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

pub(super) async fn fetch(
    http: &Client,
    key: &str,
    base: &str,
    subscription_id: &str,
) -> Result<CurrentInvoice, BillingError> {
    if !is_test_api_key(key) {
        return Err(BillingError::InvalidEvent);
    }
    valid_id(subscription_id, "sub_")?;
    let sub_path = format!("subscriptions/{subscription_id}");
    let sub = read(http, key, base, &sub_path).await?;
    let snapshot = worker::parse_subscription(&sub)?;
    if snapshot.subscription_id != subscription_id {
        return Err(BillingError::TenantConflict);
    }
    let invoice_id = snapshot
        .latest_invoice_id
        .as_ref()
        .ok_or(BillingError::InvalidEvent)?;
    let invoice_path = format!("invoices/{invoice_id}");
    let invoice = read(http, key, base, &invoice_path)
        .await
        .map_err(invoice_error)?;
    let observation = model::parse(&sub, &invoice)?;
    // Subscription and invoice are independent provider objects. Re-read both
    // to refuse a mixed price, period, cancellation, or payment observation.
    let final_sub = read(http, key, base, &sub_path).await?;
    let final_invoice = read(http, key, base, &invoice_path)
        .await
        .map_err(invoice_error)?;
    let final_observation = model::parse(&final_sub, &final_invoice)?;
    if !observation.same_current_state(&final_observation) {
        return Err(worker::ProviderFailure::InvalidResponse.into());
    }
    Ok(CurrentInvoice {
        observation: final_observation,
    })
}

fn invoice_error(error: BillingError) -> BillingError {
    match error {
        // A missing invoice is not evidence that its subscription was deleted.
        BillingError::Provider(worker::ProviderFailure::HttpStatus(404)) => {
            worker::ProviderFailure::InvalidResponse.into()
        }
        other => other,
    }
}

#[cfg(test)]
mod tests;

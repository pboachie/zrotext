// SPDX-License-Identifier: AGPL-3.0-only
use super::*;

async fn stalled_response(timeout: Option<Duration>) {
    let listener = tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
        .await
        .unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let server = tokio::spawn(async move {
        let (_socket, _) = listener.accept().await.unwrap();
        std::future::pending::<()>().await;
    });
    let provider = match timeout {
        Some(timeout) => Provider::fake_with_timeout(base, timeout),
        None => Provider::fake(base),
    };
    let expected = timeout.unwrap_or(Duration::from_secs(2));
    let started = tokio::time::Instant::now();
    let result = tokio::time::timeout(
        expected + Duration::from_secs(1),
        provider.get("rk_test_fixture_read", "/v1/account"),
    )
    .await;
    let elapsed = started.elapsed();
    server.abort();
    let _ = server.await;
    assert_eq!(result.unwrap(), Err(Error::Provider));
    assert!(
        elapsed >= expected,
        "the connected response must actually time out"
    );
    // A timeout also retains the provider's existing fail-closed pause.
    assert!(provider.paused_until.load(Ordering::Acquire) > 0);
}

#[tokio::test]
async fn default_fake_request_still_times_out_after_two_seconds() {
    stalled_response(None).await;
}

#[tokio::test]
async fn explicit_fake_request_timeout_still_fails_closed() {
    stalled_response(Some(Duration::from_millis(50))).await;
}

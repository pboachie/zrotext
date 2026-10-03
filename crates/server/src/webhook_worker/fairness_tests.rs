// SPDX-License-Identifier: AGPL-3.0-only
use super::*;
use std::sync::Mutex;

#[tokio::test]
async fn continuously_due_sealed_work_cannot_starve_legacy_across_single_delivery_calls() {
    let calls = Mutex::new(Vec::new());
    let mut preferred = false;
    for _ in 0..6 {
        assert!(
            fair_dispatch(true, &mut preferred, |sealed| {
                calls.lock().unwrap().push(sealed);
                std::future::ready(Ok(true))
            })
            .await
            .unwrap()
        );
    }
    assert_eq!(
        *calls.lock().unwrap(),
        vec![false, true, false, true, false, true]
    );
}

#[tokio::test]
async fn empty_preferred_lane_falls_back_without_second_success_and_disabled_never_calls_sealed() {
    let calls = Mutex::new(Vec::new());
    let mut preferred = true;
    assert!(
        fair_dispatch(true, &mut preferred, |sealed| {
            calls.lock().unwrap().push(sealed);
            std::future::ready(Ok(!sealed))
        })
        .await
        .unwrap()
    );
    assert_eq!(*calls.lock().unwrap(), vec![true, false]);
    calls.lock().unwrap().clear();
    preferred = true;
    assert!(
        fair_dispatch(false, &mut preferred, |sealed| {
            assert!(!sealed);
            calls.lock().unwrap().push(sealed);
            std::future::ready(Ok(true))
        })
        .await
        .unwrap()
    );
    assert_eq!(*calls.lock().unwrap(), vec![false]);
    assert!(preferred);
}

#[tokio::test]
async fn alternating_batches_preserve_exact_limit_one_cursor_and_stop_before_next_dispatch_on_drain()
 {
    use std::sync::atomic::{AtomicBool, Ordering};
    let draining = AtomicBool::new(false);
    let calls = Mutex::new(Vec::new());
    let mut cursor = false;
    for _ in 0..4 {
        assert_eq!(
            fair_batch(&mut cursor, 1, &draining, |sealed| {
                calls.lock().unwrap().push(sealed);
                std::future::ready(Ok(true))
            })
            .await
            .unwrap(),
            1
        );
    }
    assert_eq!(*calls.lock().unwrap(), vec![false, true, false, true]);
    calls.lock().unwrap().clear();
    assert_eq!(
        fair_batch(&mut cursor, 3, &draining, |sealed| {
            calls.lock().unwrap().push(sealed);
            std::future::ready(Ok(true))
        })
        .await
        .unwrap(),
        3
    );
    assert_eq!(*calls.lock().unwrap(), vec![false, true, false]);
    calls.lock().unwrap().clear();
    assert_eq!(
        fair_batch(&mut cursor, 9, &draining, |sealed| {
            let mut calls = calls.lock().unwrap();
            calls.push(sealed);
            if calls.len() == 2 {
                draining.store(true, Ordering::Release);
            }
            std::future::ready(Ok(true))
        })
        .await
        .unwrap(),
        2
    );
    assert_eq!(calls.lock().unwrap().len(), 2);
    assert_eq!(
        fair_batch(&mut cursor, 9, &draining, |_| async {
            panic!("draining must not dispatch")
        })
        .await
        .unwrap(),
        0
    );
}

#[tokio::test]
async fn already_deferred_legacy_item_consumes_one_slot_then_next_lane_runs_but_database_failure_aborts()
 {
    use std::sync::atomic::AtomicBool;
    let stopped = AtomicBool::new(false);
    let mut cursor = false;
    let calls = Mutex::new(Vec::new());
    assert_eq!(
        fair_batch(&mut cursor, 2, &stopped, |sealed| {
            calls.lock().unwrap().push(sealed);
            std::future::ready(if sealed {
                Ok(true)
            } else {
                legacy_tick(Err(WorkerError::Secret))
            })
        })
        .await
        .unwrap(),
        2
    );
    assert_eq!(*calls.lock().unwrap(), vec![false, true]);
    assert!(matches!(
        legacy_tick(Err(WorkerError::Storage(inbound::InboundError::StaleLease))),
        Ok(true)
    ));
    calls.lock().unwrap().clear();
    cursor = false;
    assert!(matches!(
        fair_batch(&mut cursor, 2, &stopped, |sealed| {
            calls.lock().unwrap().push(sealed);
            std::future::ready(legacy_tick(Err(WorkerError::Database)))
        })
        .await,
        Err(WorkerError::Database)
    ));
    assert_eq!(*calls.lock().unwrap(), vec![false]);
}

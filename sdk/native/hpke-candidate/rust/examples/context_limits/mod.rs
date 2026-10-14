use std::sync::{
    Arc, Condvar, Mutex,
    atomic::{AtomicBool, Ordering},
    mpsc,
};
use std::time::{Duration, Instant};
use zrotext_hpke_candidate::{
    Error,
    workflow_context::{WorkflowContextRole, WorkflowContextScope, bounded},
};

// Only public installed APIs are used. Blocked authority never supplies a grant.
pub fn run() {
    let scope = WorkflowContextScope {
        kind: 1,
        account: [1; 16],
        device: [1; 16],
        line: [1; 16],
        interval: [1; 16],
        context: [1; 16],
        binding_generation: 1,
        revision: 1,
        expires: 10000,
        trust_generation: 1,
        manifest_version: 1,
        peer_digest: [1; 32],
        reader: [1; 32],
        manifest_digest: [1; 32],
    };
    let mut checks = 0;
    let cancelled = bounded::Cancellation::default();
    cancelled.cancel();
    let called = Arc::new(AtomicBool::new(false));
    let seen = called.clone();
    assert!(
        bounded::seal(
            &cancelled,
            move || {
                seen.store(true, Ordering::SeqCst);
                Err(Error::Authentication)
            },
            scope.clone(),
            WorkflowContextRole::Owner,
            &[1]
        )
        .is_err()
    );
    assert!(!called.load(Ordering::SeqCst));
    checks += 1;
    let gate = Arc::new((Mutex::new(false), Condvar::new()));
    let (settled_tx, settled_rx) = mpsc::channel();
    let mut first = None;
    let start = Instant::now();
    for i in 0..4 {
        let cancel = bounded::Cancellation::default();
        let worker_cancel = cancel.clone();
        let gate = gate.clone();
        let scope = scope.clone();
        let settled = settled_tx.clone();
        let (entered_tx, entered_rx) = mpsc::sync_channel(0);
        let handle = std::thread::spawn(move || {
            bounded::seal(
                &worker_cancel,
                move || {
                    entered_tx.send(()).unwrap();
                    let (lock, condition) = &*gate;
                    let mut released = lock.lock().unwrap();
                    while !*released {
                        released = condition.wait(released).unwrap();
                    }
                    settled.send(()).unwrap();
                    Err(Error::Authentication)
                },
                scope,
                WorkflowContextRole::Owner,
                &[1],
            )
            .is_err()
        });
        entered_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("authority did not start");
        if i == 0 {
            first = Some(handle);
        } else {
            cancel.cancel();
            assert!(handle.join().unwrap());
            checks += 1;
        }
    }
    assert!(first.unwrap().join().unwrap());
    assert!(start.elapsed() >= Duration::from_secs(9) && start.elapsed() < Duration::from_secs(12));
    checks += 1;
    let seen = called.clone();
    assert!(
        bounded::seal(
            &bounded::Cancellation::default(),
            move || {
                seen.store(true, Ordering::SeqCst);
                Err(Error::Authentication)
            },
            scope.clone(),
            WorkflowContextRole::Owner,
            &[1]
        )
        .is_err()
    );
    assert!(!called.load(Ordering::SeqCst));
    checks += 1;
    *gate.0.lock().unwrap() = true;
    gate.1.notify_all();
    for _ in 0..4 {
        settled_rx.recv_timeout(Duration::from_secs(2)).unwrap();
    }
    let end = Instant::now() + Duration::from_secs(2);
    while !called.load(Ordering::SeqCst) && Instant::now() < end {
        let seen = called.clone();
        assert!(
            bounded::seal(
                &bounded::Cancellation::default(),
                move || {
                    seen.store(true, Ordering::SeqCst);
                    Err(Error::Authentication)
                },
                scope.clone(),
                WorkflowContextRole::Owner,
                &[1]
            )
            .is_err()
        );
        if !called.load(Ordering::SeqCst) {
            std::thread::sleep(Duration::from_millis(1));
        }
    }
    assert!(called.load(Ordering::SeqCst));
    checks += 1;
    println!("{}", serde_json::json!({"installed_context_limits":checks}));
}

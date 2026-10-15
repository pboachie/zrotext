use p256::elliptic_curve::sec1::ToSec1Point;
use std::{
    sync::{
        Arc, Condvar, Mutex,
        atomic::{AtomicUsize, Ordering},
        mpsc,
    },
    time::{Duration, Instant},
};
use zrotext_hpke_candidate::{
    owner_template::{context::*, *},
    workflow_context::WorkflowContextScope,
};

// Public installed APIs only. Held callbacks never supply current authority.
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
    let binding = OwnerBinding {
        account: scope.account,
        device: scope.device,
        line: scope.line,
        interval: scope.interval,
        session: [1; 16],
        generation: 1,
        peer: "+12".into(),
        phone_reader: [1; 32],
        archive_reader: scope.reader,
    };
    let mut wire = scope.aad().unwrap();
    let key = p256::SecretKey::from_slice(&[1; 32]).unwrap();
    wire.extend(key.public_key().to_sec1_point(false).as_bytes());
    wire.extend(17u32.to_be_bytes());
    wire.extend([0; 17]);
    let make = |current: CurrentSource| {
        OwnerWorkflowContextClient::new(
            ContextOptions {
                origin: "https://example.test".into(),
                binding: binding.clone(),
                context: scope.context,
                kind: 1,
                enabled: true,
                timeout: Duration::from_secs(10),
                additional_roots: vec![],
                current,
                session: Arc::new(|_| {
                    Ok(OwnerSession {
                        origin: "https://example.test".into(),
                        cookie: "synthetic-owner=opaque".into(),
                        csrf: "synthetic-csrf".into(),
                    })
                }),
            },
            Arc::new(|_, _| Ok(())),
        )
        .unwrap()
    };
    let request = "00000000-0000-0000-0000-000000000041";
    let called = Arc::new(AtomicUsize::new(0));
    let seen = called.clone();
    let closed = make(Arc::new(move |_| {
        seen.fetch_add(1, Ordering::SeqCst);
        Err(OwnerError::OwnerChanged)
    }));
    closed.close();
    assert!(closed.prepare(request, 0, scope.clone(), &wire).is_err());
    assert_eq!(called.load(Ordering::SeqCst), 0);
    let mut checks = 1;
    let gate = Arc::new((Mutex::new(false), Condvar::new()));
    let (entered_tx, entered_rx) = mpsc::channel();
    let (settled_tx, settled_rx) = mpsc::channel();
    let mut clients = vec![];
    let mut results = vec![];
    for _ in 0..8 {
        let held = gate.clone();
        let entered = entered_tx.clone();
        let settled = settled_tx.clone();
        let client = make(Arc::new(move |_| {
            entered.send(()).unwrap();
            let (mut ready, wake) = (held.0.lock().unwrap(), &held.1);
            while !*ready {
                ready = wake.wait(ready).unwrap();
            }
            settled.send(()).unwrap();
            Err(OwnerError::OwnerChanged)
        }));
        let worker = client.clone();
        let selected = scope.clone();
        let bytes = wire.clone();
        let (tx, rx) = mpsc::channel();
        std::thread::spawn(move || {
            let start = Instant::now();
            let error = worker
                .prepare(request, 0, selected, &bytes)
                .err()
                .expect("blocked source accepted");
            tx.send((error, start.elapsed())).unwrap();
        });
        entered_rx.recv_timeout(Duration::from_secs(2)).unwrap();
        clients.push(client);
        results.push(rx);
    }
    for i in 1..8 {
        let start = Instant::now();
        clients[i].close();
        let (error, _) = results[i].recv_timeout(Duration::from_secs(1)).unwrap();
        assert_eq!(error.state, "refused");
        assert!(start.elapsed() < Duration::from_secs(1));
        checks += 1;
    }
    let source = || {
        let seen = called.clone();
        Arc::new(move |_: &OwnerCall| {
            seen.fetch_add(1, Ordering::SeqCst);
            Err(OwnerError::OwnerChanged)
        }) as CurrentSource
    };
    let ninth = make(source());
    let error = ninth
        .prepare(request, 0, scope.clone(), &wire)
        .err()
        .unwrap();
    assert_eq!(error.code, "capacity");
    assert_eq!(called.load(Ordering::SeqCst), 0);
    ninth.close();
    checks += 1;
    let (error, elapsed) = results[0].recv_timeout(Duration::from_secs(12)).unwrap();
    assert_eq!(error.state, "refused");
    assert!(elapsed >= Duration::from_secs(9) && elapsed < Duration::from_secs(12));
    checks += 1;
    let ninth = make(source());
    assert_eq!(
        ninth
            .prepare(request, 0, scope.clone(), &wire)
            .err()
            .unwrap()
            .code,
        "capacity"
    );
    assert_eq!(called.load(Ordering::SeqCst), 0);
    ninth.close();
    *gate.0.lock().unwrap() = true;
    gate.1.notify_all();
    for _ in 0..8 {
        settled_rx.recv_timeout(Duration::from_secs(2)).unwrap();
    }
    let end = Instant::now() + Duration::from_secs(2);
    while called.load(Ordering::SeqCst) == 0 && Instant::now() < end {
        let recovered = make(source());
        assert!(recovered.prepare(request, 0, scope.clone(), &wire).is_err());
        recovered.close();
        if called.load(Ordering::SeqCst) == 0 {
            std::thread::sleep(Duration::from_millis(1));
        }
    }
    assert_eq!(called.load(Ordering::SeqCst), 1);
    checks += 1;
    assert_eq!(checks, 11);
    println!("{{\"installed_owner_context_limits\":{checks}}}");
}

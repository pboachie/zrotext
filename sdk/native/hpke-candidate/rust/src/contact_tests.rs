use super::*;
fn dummy() -> (Statement, Expected) {
    (
        Statement {
            raw: vec![],
            account: [0; 16],
            origin: String::new(),
            fingerprint: [0; 32],
            manifest_digest: [0; 32],
            reader_id: [0; 32],
            digest: [0; 32],
            root_writer_id: [0; 32],
            reader_point: [0; 65],
            root_point: [0; 65],
            version: 0,
            reader_generation: 0,
        },
        Expected {
            account: [0; 16],
            origin: String::new(),
            root_fingerprint: [0; 32],
            contact: [0; 16],
            routing_digest: [0; 32],
        },
    )
}
#[test]
fn cancellation_capacity_and_fixed_deadline_retain_workers() {
    struct Tracked(Arc<AtomicUsize>);
    impl Drop for Tracked {
        fn drop(&mut self) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }
    let dropped = Arc::new(AtomicUsize::new(0));
    let (s, e) = dummy();
    let cancel = Cancellation::default();
    cancel.cancel();
    let tracked = Tracked(dropped.clone());
    assert!(
        produce(&s, &e, vec![], &cancel, move |_, _, _| {
            drop(tracked);
            panic!("pre-cancel signed")
        })
        .is_err()
    );
    assert_eq!(
        dropped.load(Ordering::SeqCst),
        1,
        "non-admission retained owned closure"
    );
    let mut workers = Vec::new();
    let mut releases = Vec::new();
    let mut cancellations = Vec::new();
    for _ in 0..4 {
        let (s, e) = dummy();
        let cancellation = Cancellation::default();
        cancellations.push(cancellation.clone());
        let (tx, rx) = mpsc::channel();
        let (release, held) = mpsc::channel();
        releases.push(release);
        workers.push(std::thread::spawn(move || {
            produce(&s, &e, vec![], &cancellation, move |_, _, _| {
                tx.send(()).unwrap();
                held.recv().unwrap();
                Err(Error::Shape)
            })
        }));
        rx.recv_timeout(Duration::from_secs(2)).unwrap();
    }
    for c in cancellations {
        c.cancel()
    }
    for worker in workers {
        assert!(worker.join().unwrap().is_err())
    }
    assert_eq!(OUTSTANDING.load(Ordering::SeqCst), 4);
    let tracked = Tracked(dropped.clone());
    assert!(
        produce(&s, &e, vec![], &Cancellation::default(), move |_, _, _| {
            drop(tracked);
            panic!("capacity signed")
        })
        .is_err()
    );
    assert_eq!(
        dropped.load(Ordering::SeqCst),
        2,
        "capacity refusal retained owned closure"
    );
    for release in releases {
        release.send(()).unwrap()
    }
    let settle = Instant::now() + Duration::from_secs(2);
    while OUTSTANDING.load(Ordering::SeqCst) != 0 {
        assert!(Instant::now() < settle);
        std::thread::sleep(Duration::from_millis(1))
    }
    let (tx, rx) = mpsc::channel();
    let (release, held) = mpsc::channel();
    let (s, e) = dummy();
    let began = Instant::now();
    let worker = std::thread::spawn(move || {
        produce(&s, &e, vec![], &Cancellation::default(), move |_, _, _| {
            tx.send(()).unwrap();
            held.recv().unwrap();
            Err(Error::Shape)
        })
    });
    rx.recv_timeout(Duration::from_secs(2)).unwrap();
    // Real fixed production deadline, with no test-only clock or timeout override.
    assert!(worker.join().unwrap().is_err());
    assert!(began.elapsed() >= Duration::from_secs(9));
    assert!(began.elapsed() < Duration::from_secs(12));
    assert_eq!(OUTSTANDING.load(Ordering::SeqCst), 1);
    release.send(()).unwrap();
    let settle = Instant::now() + Duration::from_secs(2);
    while OUTSTANDING.load(Ordering::SeqCst) != 0 {
        assert!(Instant::now() < settle);
        std::thread::sleep(Duration::from_millis(1))
    }
}

//! Four-slot, ten-second foreground bounds. Native work is not force-interrupted;
//! its permit and owned buffers remain held until actual worker settlement.
use super::*;
use std::sync::{
    Arc,
    atomic::{AtomicBool, AtomicUsize, Ordering},
    mpsc,
};
use std::time::{Duration, Instant};

#[derive(Clone, Default)]
pub struct Cancellation(Arc<AtomicBool>);
impl Cancellation {
    pub fn cancel(&self) {
        self.0.store(true, Ordering::SeqCst);
    }
    fn check(&self, deadline: Instant) -> Result<(), Error> {
        if self.0.load(Ordering::SeqCst) || Instant::now() >= deadline {
            Err(Error::Authentication)
        } else {
            Ok(())
        }
    }
}
static OUTSTANDING: AtomicUsize = AtomicUsize::new(0);
struct Permit;
impl Drop for Permit {
    fn drop(&mut self) {
        OUTSTANDING.fetch_sub(1, Ordering::SeqCst);
    }
}
fn execute(
    cancel: &Cancellation,
    work: impl FnOnce(Instant, Cancellation) -> Result<Zeroizing<Vec<u8>>, Error> + Send + 'static,
) -> Result<Zeroizing<Vec<u8>>, Error> {
    let deadline = Instant::now() + Duration::from_secs(10);
    cancel.check(deadline)?;
    OUTSTANDING
        .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |n| {
            (n < 4).then_some(n + 1)
        })
        .map_err(|_| Error::Authentication)?;
    let permit = Permit;
    let token = cancel.clone();
    let (tx, rx) = mpsc::sync_channel(0);
    std::thread::Builder::new()
        .name("workflow-context".into())
        .spawn(move || {
            let _permit = permit;
            let result = token
                .check(deadline)
                .and_then(|()| work(deadline, token.clone()))
                .and_then(|value| {
                    token.check(deadline)?;
                    Ok(value)
                });
            // A disconnected receiver drops (and zeroizes) any late plaintext.
            let _ = tx.send(result);
        })
        .map_err(|_| Error::Authentication)?;
    loop {
        cancel.check(deadline)?;
        match rx.recv_timeout(Duration::from_millis(10)) {
            Ok(value) => {
                cancel.check(deadline)?;
                return value;
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {}
            Err(mpsc::RecvTimeoutError::Disconnected) => return Err(Error::Authentication),
        }
    }
}
fn current(
    source: &mut impl FnMut() -> Result<(Arc<Manifest>, u64), Error>,
    s: &WorkflowContextScope,
    role: WorkflowContextRole,
    floor: u64,
    deadline: Instant,
    cancel: &Cancellation,
) -> Result<(Arc<Manifest>, u64), Error> {
    cancel.check(deadline)?;
    let (m, now) = source()?;
    cancel.check(deadline)?;
    if now < floor {
        return Err(Error::Authentication);
    }
    authority(&m, s, role, now)?;
    Ok((m, now))
}
fn operation(
    mut source: impl FnMut() -> Result<(Arc<Manifest>, u64), Error>,
    s: &WorkflowContextScope,
    role: WorkflowContextRole,
    deadline: Instant,
    cancel: &Cancellation,
    work: impl FnOnce(&Manifest, u64) -> Result<Zeroizing<Vec<u8>>, Error>,
) -> Result<Zeroizing<Vec<u8>>, Error> {
    let (m, now) = current(&mut source, s, role, 0, deadline, cancel)?;
    let out = work(&m, now)?;
    let (latest, _) = current(&mut source, s, role, now, deadline, cancel)?;
    if latest.root != m.root || latest.enrolled != m.enrolled {
        return Err(Error::Authentication);
    }
    Ok(out)
}
/// Uses genuine owned manifest tokens, never a structural authority substitute.
pub fn seal(
    cancel: &Cancellation,
    source: impl FnMut() -> Result<(Arc<Manifest>, u64), Error> + Send + 'static,
    scope: WorkflowContextScope,
    role: WorkflowContextRole,
    content: &[u8],
) -> Result<Zeroizing<Vec<u8>>, Error> {
    if !(1..=32768).contains(&content.len()) {
        return Err(Error::Shape);
    }
    let plain = Zeroizing::new(content.to_vec());
    execute(cancel, move |deadline, cancel| {
        operation(source, &scope, role, deadline, &cancel, |m, now| {
            seal_workflow_context(m, &scope, role, now, &plain).map(Zeroizing::new)
        })
    })
}
pub fn open_software(
    cancel: &Cancellation,
    source: impl FnMut() -> Result<(Arc<Manifest>, u64), Error> + Send + 'static,
    scope: WorkflowContextScope,
    role: WorkflowContextRole,
    scalar: &[u8],
    envelope: &[u8],
) -> Result<Zeroizing<Vec<u8>>, Error> {
    if scalar.len() != 32 || !(308..=33075).contains(&envelope.len()) {
        return Err(Error::Shape);
    }
    let secret = Zeroizing::new(scalar.to_vec());
    let wire = envelope.to_vec();
    execute(cancel, move |deadline, cancel| {
        operation(source, &scope, role, deadline, &cancel, |m, now| {
            open_software_workflow_context(m, &scope, role, now, &secret, &wire)
        })
    })
}
#[cfg(windows)]
pub fn open_protected(
    cancel: &Cancellation,
    source: impl FnMut() -> Result<(Arc<Manifest>, u64), Error> + Send + 'static,
    scope: WorkflowContextScope,
    role: WorkflowContextRole,
    recipient: Arc<crate::cng::HardwareRecipient>,
    envelope: &[u8],
) -> Result<Zeroizing<Vec<u8>>, Error> {
    if !(308..=33075).contains(&envelope.len()) {
        return Err(Error::Shape);
    }
    let wire = envelope.to_vec();
    execute(cancel, move |deadline, cancel| {
        let mut selected = None;
        let out = operation(source, &scope, role, deadline, &cancel, |m, now| {
            selected = Some(authority(m, &scope, role, now)?);
            open_protected_workflow_context(m, &scope, role, now, &recipient, &wire)
        })?;
        // Borrowed provider must still be qualified/live at publication.
        let point = recipient
            .public_point()
            .map_err(|_| Error::ProtectedUnavailable)?;
        cancel.check(deadline)?;
        if Some(point) != selected {
            return Err(Error::ProtectedUnavailable);
        }
        Ok(out)
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn cancellation_deadline_and_retained_admission() {
        let mut release = Vec::new();
        for _ in 0..4 {
            let cancel = Cancellation::default();
            let worker_cancel = cancel.clone();
            let (entered_tx, entered_rx) = mpsc::channel();
            let (release_tx, release_rx) = mpsc::channel();
            release.push(release_tx);
            let foreground = std::thread::spawn(move || {
                execute(&worker_cancel, move |_, _| {
                    entered_tx.send(()).unwrap();
                    release_rx.recv().unwrap();
                    Ok(Zeroizing::new(vec![7; 32]))
                })
            });
            entered_rx.recv_timeout(Duration::from_secs(1)).unwrap();
            cancel.cancel();
            assert!(foreground.join().unwrap().is_err());
        }
        assert_eq!(OUTSTANDING.load(Ordering::SeqCst), 4);
        assert!(execute(&Cancellation::default(), |_, _| panic!("fifth admitted")).is_err());
        for channel in release {
            channel.send(()).unwrap()
        }
        let until = Instant::now() + Duration::from_secs(1);
        while OUTSTANDING.load(Ordering::SeqCst) > 0 && Instant::now() < until {
            std::thread::sleep(Duration::from_millis(1))
        }
        assert_eq!(OUTSTANDING.load(Ordering::SeqCst), 0);
        let (tx, rx) = mpsc::channel();
        let start = Instant::now();
        let result = execute(&Cancellation::default(), move |_, _| {
            rx.recv().unwrap();
            Ok(Zeroizing::new(vec![9]))
        });
        assert!(result.is_err());
        assert!(start.elapsed() >= Duration::from_secs(9));
        assert!(start.elapsed() < Duration::from_secs(12));
        assert_eq!(OUTSTANDING.load(Ordering::SeqCst), 1);
        tx.send(()).unwrap();
        let until = Instant::now() + Duration::from_secs(1);
        while OUTSTANDING.load(Ordering::SeqCst) > 0 && Instant::now() < until {
            std::thread::sleep(Duration::from_millis(1))
        }
        assert_eq!(OUTSTANDING.load(Ordering::SeqCst), 0);
    }
}

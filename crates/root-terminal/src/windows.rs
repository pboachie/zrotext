// SPDX-License-Identifier: AGPL-3.0-only
use crate::{Error, Result, SensitiveLine, input::Builder};
use std::{
    mem::{size_of, zeroed},
    os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle},
    ptr::{null, null_mut},
    sync::{
        Mutex, MutexGuard,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};
use windows_sys::Win32::{
    Foundation::*,
    Storage::FileSystem::{FILE_TYPE_CHAR, GetFileType},
    System::{Console::*, LibraryLoader::*, RemoteDesktop::*, Threading::*},
};
use zeroize::Zeroizing;

static EXCLUSIVE: Mutex<()> = Mutex::new(());
static CANCELLED: AtomicBool = AtomicBool::new(false);
static ACTIVE: AtomicBool = AtomicBool::new(false);
static POISONED: AtomicBool = AtomicBool::new(false);
const STANDARD: [u32; 3] = [STD_INPUT_HANDLE, STD_OUTPUT_HANDLE, STD_ERROR_HANDLE];
type ReadInput = unsafe extern "system" fn(HANDLE, *mut INPUT_RECORD, u32, *mut u32, u16) -> i32;

// No allocation, locks, console APIs or borrowed handle pointers in this callback.
unsafe extern "system" fn control(kind: u32) -> i32 {
    if ACTIVE.load(Ordering::SeqCst) && matches!(kind, CTRL_C_EVENT | CTRL_BREAK_EVENT) {
        CANCELLED.store(true, Ordering::SeqCst);
        1
    } else {
        0
    }
}

fn mode(handle: HANDLE) -> Result<u32> {
    let mut mode = 0;
    // SAFETY: handle is borrowed and output is live for the duration of the call.
    if unsafe { GetConsoleMode(handle, &mut mode) } == 0 {
        Err(Error::Unsupported)
    } else {
        Ok(mode)
    }
}

fn active_session() -> Result<()> {
    // SAFETY: WTS owns the returned buffers; validate length before reading and
    // free on every successful query. No user/session identifiers are logged.
    unsafe {
        let mut session = 0;
        if ProcessIdToSessionId(GetCurrentProcessId(), &mut session) == 0 || session == 0 {
            return Err(Error::Unsupported);
        }
        for (class, width) in [(WTSClientProtocolType, 2), (WTSConnectState, 4)] {
            let mut buffer = null_mut();
            let mut length = 0;
            if WTSQuerySessionInformationW(
                WTS_CURRENT_SERVER_HANDLE,
                session,
                class,
                &mut buffer,
                &mut length,
            ) == 0
            {
                return Err(Error::Unsupported);
            }
            let valid = !buffer.is_null()
                && length == width
                && std::slice::from_raw_parts(buffer.cast::<u8>(), width as usize)
                    .iter()
                    .all(|byte| *byte == 0);
            WTSFreeMemory(buffer.cast());
            if !valid {
                return Err(Error::Unsupported);
            }
        }
        Ok(())
    }
}

fn reader() -> Result<ReadInput> {
    resolve_reader(c"ReadConsoleInputExW")
}

fn resolve_reader(symbol: &std::ffi::CStr) -> Result<ReadInput> {
    let name: Vec<u16> = "kernel32.dll".encode_utf16().chain(Some(0)).collect();
    // SAFETY: pin an already loaded system module before retaining its export.
    // The ABI (including USHORT flags) is Microsoft's documented ExW signature.
    unsafe {
        let mut module = null_mut();
        if GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_PIN, name.as_ptr(), &mut module) == 0 {
            return Err(Error::Unsupported);
        }
        let address = GetProcAddress(module, symbol.as_ptr().cast()).ok_or(Error::Unsupported)?;
        Ok(std::mem::transmute::<
            unsafe extern "system" fn() -> isize,
            ReadInput,
        >(address))
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Fault {
    SetMode,
    Read,
    Write,
    ShortWrite,
    Restore,
    Unregister,
}

/// Single-use ownership of console mode and cooperative cancellation handling.
/// Caller must ensure no other attached process consumes this console's input.
/// Console/WTS checks do not attest physical presence or absence of recording.
pub struct Session {
    handles: [OwnedHandle; 3],
    originals: [HANDLE; 3],
    original_mode: u32,
    expected_modes: [u32; 3],
    read: ReadInput,
    attempted_mode: bool,
    registered: bool,
    owned: bool,
    failed: bool,
    fault: Option<Fault>,
    _exclusive: MutexGuard<'static, ()>,
}

impl Session {
    /// Reject queued input without consuming it or changing any console mode.
    pub fn acquire() -> Result<Self> {
        Self::acquire_inner(None)
    }

    fn acquire_inner(fault: Option<Fault>) -> Result<Self> {
        if POISONED.load(Ordering::SeqCst) {
            return Err(Error::Poisoned);
        }
        let exclusive = EXCLUSIVE.try_lock().map_err(|_| Error::Busy)?;
        if POISONED.load(Ordering::SeqCst) {
            return Err(Error::Poisoned);
        }
        active_session()?;
        let read = reader()?;
        let mut handles = Vec::new();
        let mut originals = [null_mut(); 3];
        let mut modes = [0; 3];
        for (index, standard) in STANDARD.into_iter().enumerate() {
            // SAFETY: standard handles remain borrowed; duplicates are separately
            // owned, have no inheritance, and are closed by OwnedHandle.
            unsafe {
                let handle = GetStdHandle(standard);
                if handle.is_null()
                    || handle == INVALID_HANDLE_VALUE
                    || GetFileType(handle) != FILE_TYPE_CHAR
                {
                    return Err(Error::Unsupported);
                }
                let mut duplicate = null_mut();
                if DuplicateHandle(
                    GetCurrentProcess(),
                    handle,
                    GetCurrentProcess(),
                    &mut duplicate,
                    0,
                    0,
                    DUPLICATE_SAME_ACCESS,
                ) == 0
                {
                    return Err(Error::Unsupported);
                }
                let duplicate = OwnedHandle::from_raw_handle(duplicate);
                modes[index] = mode(duplicate.as_raw_handle())?;
                if index == 0 {
                    let mut queued = 0;
                    if GetNumberOfConsoleInputEvents(duplicate.as_raw_handle(), &mut queued) == 0 {
                        return Err(Error::Unsupported);
                    }
                    if queued != 0 {
                        return Err(Error::Busy);
                    }
                } else {
                    let mut info = zeroed();
                    if GetConsoleScreenBufferInfo(duplicate.as_raw_handle(), &mut info) == 0 {
                        return Err(Error::Unsupported);
                    }
                }
                originals[index] = handle;
                handles.push(duplicate);
            }
        }
        let mut session = Self {
            handles: handles.try_into().map_err(|_| Error::Unsupported)?,
            originals,
            original_mode: modes[0],
            expected_modes: modes,
            read,
            attempted_mode: false,
            registered: false,
            owned: false,
            failed: false,
            fault,
            _exclusive: exclusive,
        };
        session.check()?;
        // Recheck immediately before taking ownership; no flushing on this path.
        let mut queued = 0;
        if unsafe { GetNumberOfConsoleInputEvents(session.input(), &mut queued) } == 0 {
            return Err(Error::Unsupported);
        }
        if queued != 0 {
            return Err(Error::Busy);
        }
        CANCELLED.store(false, Ordering::SeqCst);
        ACTIVE.store(true, Ordering::SeqCst);
        // SAFETY: callback has static lifetime and does not borrow session memory.
        if unsafe { SetConsoleCtrlHandler(Some(control), 1) } == 0 {
            ACTIVE.store(false, Ordering::SeqCst);
            return Err(Error::Io);
        }
        session.registered = true;
        session.attempted_mode = true;
        let requested = (modes[0] | ENABLE_EXTENDED_FLAGS)
            & !(ENABLE_ECHO_INPUT
                | ENABLE_LINE_INPUT
                | ENABLE_PROCESSED_INPUT
                | ENABLE_QUICK_EDIT_MODE
                | ENABLE_VIRTUAL_TERMINAL_INPUT);
        if session.fault == Some(Fault::SetMode)
            || unsafe { SetConsoleMode(session.input(), requested) } == 0
        {
            session.cleanup()?;
            return Err(Error::Io);
        }
        session.expected_modes[0] = requested;
        if session.check().is_err() {
            session.cleanup()?;
            return Err(Error::Unsupported);
        }
        session.owned = true;
        Ok(session)
    }

    fn input(&self) -> HANDLE {
        self.handles[0].as_raw_handle()
    }

    fn check(&self) -> Result<()> {
        for (index, standard) in STANDARD.into_iter().enumerate() {
            // SAFETY: standard handle values are inspected, never taken as owned.
            if unsafe { GetStdHandle(standard) } != self.originals[index]
                || mode(self.handles[index].as_raw_handle())? != self.expected_modes[index]
            {
                return Err(Error::Unsupported);
            }
        }
        Ok(())
    }

    /// Public ASCII prompts only, at most 512 bytes; callers must not pass secrets.
    /// This is not a consent or secret-reveal ceremony.
    pub fn write_public_prompt(&mut self, prompt: &str) -> Result<()> {
        let result = (|| {
            if self.failed
                || prompt.len() > 512
                || prompt
                    .bytes()
                    .any(|b| !(32..=126).contains(&b) && b != b'\n' && b != b'\r')
            {
                return Err(Error::Rejected);
            }
            self.check()?;
            if CANCELLED.load(Ordering::SeqCst) {
                return Err(Error::Cancelled);
            }
            let text: Vec<u16> = prompt.encode_utf16().collect();
            let mut offset = 0;
            while offset < text.len() {
                if self.fault == Some(Fault::Write) {
                    return Err(Error::Io);
                }
                let mut written = 0;
                let requested = if self.fault == Some(Fault::ShortWrite) {
                    (text.len() - offset).min(3)
                } else {
                    text.len() - offset
                };
                // SAFETY: UTF-16 slice stays live, length fits the fixed limit.
                if unsafe {
                    WriteConsoleW(
                        self.handles[1].as_raw_handle(),
                        text[offset..].as_ptr().cast(),
                        requested as u32,
                        &mut written,
                        null(),
                    )
                } == 0
                    || written == 0
                    || written as usize > text.len() - offset
                {
                    return Err(Error::Io);
                }
                offset += written as usize;
                self.check()?;
            }
            Ok(())
        })();
        if result.is_err() {
            self.failed = true;
        }
        result
    }

    /// One printable-ASCII line, with no echo. Modes and handlers are restored
    /// before any result is returned. Queued tail input is discarded on cleanup.
    pub fn read(mut self, limit: usize, timeout: Duration) -> Result<SensitiveLine> {
        let result = self.read_inner(limit, timeout);
        self.cleanup()?;
        if CANCELLED.load(Ordering::SeqCst) {
            return Err(Error::Cancelled);
        }
        result
    }

    fn read_inner(&mut self, limit: usize, timeout: Duration) -> Result<SensitiveLine> {
        if self.failed || timeout.is_zero() || timeout > Duration::from_secs(300) {
            return Err(Error::Rejected);
        }
        let mut builder = Builder::new(limit)?;
        let start = Instant::now();
        let mut events = 0;
        loop {
            self.check()?;
            if CANCELLED.load(Ordering::SeqCst) {
                return Err(Error::Cancelled);
            }
            let Some(remaining) = timeout.checked_sub(start.elapsed()) else {
                return Err(Error::TimedOut);
            };
            let wait = remaining.as_millis().clamp(1, 50) as u32;
            // SAFETY: retained console input handle supports wait operations.
            let signalled = unsafe { WaitForSingleObject(self.input(), wait) };
            if signalled == WAIT_TIMEOUT {
                continue;
            }
            if signalled != WAIT_OBJECT_0 || self.fault == Some(Fault::Read) {
                return Err(Error::Io);
            }
            // Windows INPUT_RECORD is 20 bytes, alignment four; use aligned
            // zeroizing storage including union/padding and no copied raw record.
            const {
                assert!(size_of::<INPUT_RECORD>() == 20);
                assert!(std::mem::align_of::<INPUT_RECORD>() == 4);
            }
            let mut words = Zeroizing::new([0_u32; 5]);
            let mut count = 0;
            let record = words.as_mut_ptr().cast::<INPUT_RECORD>();
            // SAFETY: checked native ABI, aligned initialized storage, capacity 1.
            if unsafe { (self.read)(self.input(), record, 1, &mut count, 2) } == 0 || count > 1 {
                return Err(Error::Io);
            }
            if count == 0 {
                continue;
            }
            events += 1;
            if events > 4096 {
                return Err(Error::Rejected);
            }
            self.check()?;
            // SAFETY: only access KeyEvent union arm after checking EventType.
            let done = unsafe {
                if (*record).EventType == KEY_EVENT as u16 {
                    let key = &(*record).Event.KeyEvent;
                    builder.key(
                        key.bKeyDown != 0,
                        key.uChar.UnicodeChar,
                        key.wVirtualKeyCode,
                        key.wRepeatCount,
                    )?
                } else {
                    false
                }
            };
            if done {
                active_session()?;
                self.check()?;
                if start.elapsed() >= timeout {
                    return Err(Error::TimedOut);
                }
                return Ok(builder.finish());
            }
        }
    }

    fn cleanup(&mut self) -> Result<()> {
        let mut failed = false;
        // SAFETY: retained handles survive all cleanup calls. We only discard
        // queued events after successful acquisition of exclusive input ownership.
        unsafe {
            if self.owned {
                failed |= FlushConsoleInputBuffer(self.input()) == 0;
                self.owned = false;
            }
            if self.attempted_mode {
                failed |= self.fault == Some(Fault::Restore)
                    || SetConsoleMode(self.input(), self.original_mode) == 0;
                failed |= mode(self.input()) != Ok(self.original_mode);
                self.attempted_mode = false;
            }
            if self.registered {
                ACTIVE.store(false, Ordering::SeqCst);
                let removed = SetConsoleCtrlHandler(Some(control), 0) != 0;
                failed |= !removed || self.fault == Some(Fault::Unregister);
                self.registered = false;
            }
        }
        if failed {
            POISONED.store(true, Ordering::SeqCst);
            Err(Error::RestorationFailed)
        } else {
            Ok(())
        }
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        let _ = self.cleanup();
    }
}

#[cfg(test)]
mod tests;

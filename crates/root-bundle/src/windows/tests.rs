use super::*;
use crate::tests::bundle;
use std::{
    path::PathBuf,
    sync::atomic::{AtomicUsize, Ordering},
};

/// Fixed per-user root for test directories: `AppData\Local\Temp` under the
/// account's profile directory, resolved from the process token by the OS
/// rather than from the TEMP/TMP environment, so every test path descends
/// from a controlled root. `userenv` keeps the suite free of user32, which a
/// disposable CI account's second logon cannot initialize.
fn test_root() -> PathBuf {
    use std::os::windows::{ffi::OsStringExt, io::FromRawHandle};
    use windows_sys::Win32::{
        Security::TOKEN_QUERY,
        System::Threading::{GetCurrentProcess, OpenProcessToken},
        UI::Shell::GetUserProfileDirectoryW,
    };
    // SAFETY: the token handle is owned and closed on drop; the profile path
    // is written into a caller-sized buffer whose returned length is bounded.
    let profile = unsafe {
        let mut raw = std::mem::MaybeUninit::uninit();
        assert_ne!(
            OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, raw.as_mut_ptr()),
            0
        );
        let token = std::os::windows::io::OwnedHandle::from_raw_handle(raw.assume_init());
        let mut buffer = vec![0_u16; 1024];
        let mut length = buffer.len() as u32;
        assert_ne!(
            GetUserProfileDirectoryW(
                std::os::windows::io::AsRawHandle::as_raw_handle(&token),
                buffer.as_mut_ptr(),
                &mut length
            ),
            0,
            "resolve the profile directory"
        );
        let length = buffer
            .iter()
            .take(length as usize)
            .take_while(|&&c| c != 0)
            .count();
        PathBuf::from(std::ffi::OsString::from_wide(&buffer[..length]))
    };
    let root = profile.join("AppData").join("Local").join("Temp");
    std::fs::create_dir_all(&root).unwrap();
    root
}
struct Temp(PathBuf);
impl Temp {
    fn new() -> Self {
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let name = format!(
            "zrotext-bundle-test-{}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        );
        let path = test_root().join(name);
        std::fs::create_dir(&path).unwrap();
        Self(path)
    }
    fn store(&self) -> Store {
        Store::open(&self.0).unwrap()
    }
    fn directory(&self) -> PathBuf {
        self.0.join("zrotext-root-bundles")
    }
}
impl Drop for Temp {
    fn drop(&mut self) {
        assert!(self.0.starts_with(test_root()));
        // Rust remove_dir_all removes links themselves, not their targets.
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[test]
fn native_publish_reopens_destination_and_preserves_permissions_and_bytes() {
    let temp = Temp::new();
    let store = temp.store();
    let bundle = bundle();
    store.publish(&bundle).unwrap();
    store.reconcile(&bundle).unwrap();
    drop(store);
    temp.store().reconcile(&bundle).unwrap();
    assert_eq!(
        std::fs::read(temp.directory().join(bundle.name()).join("backup.ztrb")).unwrap(),
        bundle.backup
    );
}

#[test]
fn native_short_writes_are_completed_and_collision_never_overwrites() {
    let temp = Temp::new();
    let store = temp.store();
    let bundle = bundle();
    let mut count = 0;
    store
        .publish_with(&bundle, &mut |event| {
            if event == Event::Write {
                count += 1;
                Ok(3)
            } else {
                Ok(usize::MAX)
            }
        })
        .unwrap();
    assert!(count > 100);
    assert_eq!(store.publish(&bundle), Err(Error::Collision));
    store.reconcile(&bundle).unwrap();
}

#[test]
fn native_write_flush_and_before_rename_failures_keep_only_pending_data() {
    for fail in [Event::Write, Event::Flush, Event::BeforeRename] {
        let temp = Temp::new();
        let store = temp.store();
        let bundle = bundle();
        let mut writes = 0;
        let result = store.publish_with(&bundle, &mut |event| {
            if event == Event::Write {
                writes += 1;
            }
            if event == fail && (fail != Event::Write || writes > 1) {
                Err(Error::Storage)
            } else {
                Ok(7)
            }
        });
        assert_eq!(result, Err(Error::Storage));
        assert!(!temp.directory().join(bundle.name()).exists());
        assert!(
            temp.directory()
                .join(format!("pending-{}", bundle.name()))
                .exists()
        );
        assert_eq!(store.publish(&bundle), Err(Error::Collision));
    }
}

#[test]
fn native_after_rename_failures_are_indeterminate_and_reconcilable() {
    for fail in [Event::AfterRename, Event::BeforeReopen] {
        let temp = Temp::new();
        let store = temp.store();
        let bundle = bundle();
        assert_eq!(
            store.publish_with(&bundle, &mut |event| if event == fail {
                Err(Error::Storage)
            } else {
                Ok(usize::MAX)
            }),
            Err(Error::Indeterminate)
        );
        store.reconcile(&bundle).unwrap();
    }
}

#[test]
fn native_concurrent_publish_has_one_winner() {
    let temp = Temp::new();
    let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
    let threads: Vec<_> = (0..2)
        .map(|_| {
            let path = temp.0.clone();
            let barrier = barrier.clone();
            std::thread::spawn(move || {
                let store = Store::open(&path).unwrap();
                barrier.wait();
                store.publish(&bundle())
            })
        })
        .collect();
    let results: Vec<_> = threads
        .into_iter()
        .map(|thread| thread.join().unwrap())
        .collect();
    assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
    // A racing exclusive open may report collision or sharing failure, both closed.
    assert_eq!(results.iter().filter(|result| result.is_err()).count(), 1);
    temp.store().reconcile(&bundle()).unwrap();
}

#[test]
fn native_retained_parent_cannot_be_renamed() {
    let temp = Temp::new();
    let store = temp.store();
    assert!(std::fs::rename(&temp.0, temp.0.with_extension("moved")).is_err());
    store.publish(&bundle()).unwrap();
}

#[test]
fn native_reconcile_rejects_hardlinks_oversize_and_byte_changes() {
    for fault in 0..3 {
        let temp = Temp::new();
        let store = temp.store();
        let bundle = bundle();
        store.publish(&bundle).unwrap();
        let file = temp.directory().join(bundle.name()).join("backup.ztrb");
        match fault {
            0 => std::fs::hard_link(&file, temp.0.join("alias")).unwrap(),
            1 => std::fs::write(&file, vec![0; 749]).unwrap(),
            _ => {
                let mut bytes = bundle.backup.clone();
                bytes[100] ^= 1;
                std::fs::write(&file, bytes).unwrap();
            }
        }
        assert_eq!(store.reconcile(&bundle), Err(Error::UnsafeStore));
    }
}

#[test]
fn unsafe_paths_and_stream_aliases_are_rejected() {
    for name in [
        "", ".", "..", "name.", "name ", "x:y", "NUL", "con.txt", "COM1", "LPT9", "a/b", "a\\b",
        "é",
    ] {
        assert!(!component(name), "{name}");
    }
    for path in ["relative", "", "C:relative"] {
        assert!(path_parts(Path::new(path)).is_err());
    }
    let temp = Temp::new();
    for leaf in ["..", "file:stream", "NUL", "trailing."] {
        assert!(path_parts(&temp.0.join(leaf)).is_err());
    }
}

#[test]
fn native_broad_existing_store_permissions_are_rejected() {
    let temp = Temp::new();
    std::fs::create_dir(temp.directory()).unwrap();
    assert!(matches!(Store::open(&temp.0), Err(Error::UnsafeStore)));
}

#[test]
fn native_reopened_child_identity_must_match_even_with_identical_bytes() {
    let temp = Temp::new();
    let store = temp.store();
    let bundle = bundle();
    let result = store.publish_with(&bundle, &mut |event| {
        if event == Event::BeforeReopen {
            let path = temp.directory().join(bundle.name()).join("backup.ztrb");
            std::fs::rename(&path, temp.0.join("original-backup")).unwrap();
            let directory = relative(
                Some(&store.directory),
                &bundle.name(),
                true,
                false,
                7,
                None,
                false,
            )
            .unwrap();
            let mut replacement = relative(
                Some(&directory),
                "backup.ztrb",
                false,
                true,
                1,
                Some(&store.security),
                false,
            )
            .unwrap();
            replacement.write_all(&bundle.backup).unwrap();
            replacement.sync_all().unwrap();
            store.security.check(&replacement).unwrap();
        }
        Ok(usize::MAX)
    });
    assert_eq!(result, Err(Error::Indeterminate));
    // Same bytes and correct permissions are independently reconcilable, but
    // cannot satisfy publication's original-child identity check.
    store.reconcile(&bundle).unwrap();
}

#[test]
fn native_destination_directory_identity_is_required() {
    let temp = Temp::new();
    let store = temp.store();
    let bundle = bundle();
    store.publish(&bundle).unwrap();
    let directory = relative(
        Some(&store.directory),
        &bundle.name(),
        true,
        false,
        3,
        None,
        false,
    )
    .unwrap();
    let child_ids: Vec<_> = [("backup.ztrb", 748), ("public.ztrc", 645)]
        .into_iter()
        .map(|(leaf, maximum)| {
            let file = relative(Some(&directory), leaf, false, false, 1, None, false).unwrap();
            inspect(&file, false, maximum).unwrap()
        })
        .collect();
    assert_eq!(
        store.verify(&bundle, Some((store.identity, &child_ids))),
        Err(Error::UnsafeStore)
    );
}

#[test]
fn native_zero_write_does_not_publish() {
    let temp = Temp::new();
    let store = temp.store();
    let bundle = bundle();
    assert_eq!(
        store.publish_with(&bundle, &mut |event| Ok(if event == Event::Write {
            0
        } else {
            usize::MAX
        })),
        Err(Error::Storage)
    );
    assert!(!temp.directory().join(bundle.name()).exists());
}

#[test]
fn native_null_dacl_after_publication_is_rejected() {
    let temp = Temp::new();
    let store = temp.store();
    let bundle = bundle();
    let result = store.publish_with(&bundle, &mut |event| {
        if event == Event::BeforeReopen {
            use std::os::windows::fs::OpenOptionsExt;
            let path = temp.directory().join(bundle.name()).join("backup.ztrb");
            let file = std::fs::OpenOptions::new()
                .access_mode(0x60000)
                .open(&path)
                .unwrap();
            // SAFETY: test deliberately removes the DACL from its synthetic file.
            unsafe {
                assert_eq!(
                    SetSecurityInfo(
                        file.as_raw_handle(),
                        SE_FILE_OBJECT,
                        DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                        null_mut(),
                        null_mut(),
                        null_mut(),
                        null()
                    ),
                    0
                );
            }
        }
        Ok(usize::MAX)
    });
    assert_eq!(result, Err(Error::Indeterminate));
    assert_eq!(store.reconcile(&bundle), Err(Error::UnsafeStore));
}

fn junction(path: &Path, target: &Path) {
    use std::os::windows::ffi::OsStrExt;
    let path: Vec<u16> = path.as_os_str().encode_wide().chain(Some(0)).collect();
    let substitute: Vec<u16> = format!("\\??\\{}", target.display())
        .encode_utf16()
        .collect();
    let display: Vec<u16> = target.as_os_str().encode_wide().collect();
    let mut payload = Vec::new();
    for value in [
        0,
        (substitute.len() * 2) as u16,
        (substitute.len() * 2 + 2) as u16,
        (display.len() * 2) as u16,
    ] {
        payload.extend(value.to_le_bytes());
    }
    for value in substitute
        .into_iter()
        .chain(Some(0))
        .chain(display)
        .chain(Some(0))
    {
        payload.extend(value.to_le_bytes());
    }
    let mut buffer = 0xa0000003_u32.to_le_bytes().to_vec();
    buffer.extend((payload.len() as u16).to_le_bytes());
    buffer.extend(0_u16.to_le_bytes());
    buffer.extend(payload);
    // SAFETY: fixture-only Win32 creation/IOCTL with live buffers and owned handle.
    unsafe {
        let raw = CreateFileW(
            path.as_ptr(),
            0x40000000,
            7,
            null(),
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
            null_mut(),
        );
        assert_ne!(raw, windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE);
        let file = File::from_raw_handle(raw);
        let mut returned = 0;
        assert_ne!(
            windows_sys::Win32::System::IO::DeviceIoControl(
                file.as_raw_handle(),
                0x900a4,
                buffer.as_ptr().cast(),
                buffer.len() as u32,
                null_mut(),
                0,
                &mut returned,
                null_mut()
            ),
            0
        );
    }
}

#[test]
fn native_junction_ancestors_are_rejected_without_writing_into_target() {
    let temp = Temp::new();
    let other = Temp::new();
    let link = temp.0.join("redirect");
    std::fs::create_dir(&link).unwrap();
    junction(&link, &other.0);
    assert!(Store::open(&link).is_err());
    assert!(!other.directory().exists());
    std::fs::remove_dir(&link).unwrap();
}

#[test]
fn native_junction_mutation_of_retained_empty_parent_fails_closed() {
    let temp = Temp::new();
    let other = Temp::new();
    let parent = relative(
        None,
        &format!("\\??\\{}", temp.0.display()),
        true,
        false,
        3,
        None,
        false,
    )
    .unwrap();
    let before = inspect(&parent, true, 0).unwrap();
    junction(&temp.0, &other.0);
    assert_eq!(inspect(&parent, true, 0), Err(Error::UnsafeStore));
    assert!(
        relative(
            Some(&parent),
            "child",
            true,
            true,
            1,
            Some(&Security::current().unwrap()),
            false
        )
        .is_err()
    );
    assert!(!other.0.join("child").exists());
    assert_ne!(before.index, 0);
    drop(parent);
    std::fs::remove_dir(&temp.0).unwrap();
}

#[test]
fn native_rename_failure_with_open_child_is_indeterminate() {
    let temp = Temp::new();
    let store = temp.store();
    let bundle = bundle();
    let mut held = None;
    let result = store.publish_with(&bundle, &mut |event| {
        if event == Event::BeforeRename {
            held = Some(
                File::open(
                    temp.directory()
                        .join(format!("pending-{}", bundle.name()))
                        .join("backup.ztrb"),
                )
                .unwrap(),
            );
        }
        Ok(usize::MAX)
    });
    assert_eq!(result, Err(Error::Indeterminate));
    assert!(!temp.directory().join(bundle.name()).exists());
    drop(held);
}

#[test]
fn owner_ace_check_rejects_malformed_or_mismatched_entries() {
    // S-1-5-18 as the expected owner and S-1-5-19 as a different SID.
    let owner: [u8; 12] = [1, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0];
    let other: [u8; 12] = [1, 1, 0, 0, 0, 0, 0, 5, 19, 0, 0, 0];
    let ace = |kind: u8, flags: u8, size: u16, mask: u32, sid: &[u8]| {
        let mut bytes = vec![kind, flags];
        bytes.extend_from_slice(&size.to_le_bytes());
        bytes.extend_from_slice(&mask.to_le_bytes());
        bytes.extend_from_slice(sid);
        // Extra readable bytes: a lying size or sub-authority count must be
        // refused by the size checks, not rescued by the buffer length.
        bytes.extend_from_slice(&[0; 16]);
        bytes
    };
    let check = |mut bytes: Vec<u8>| {
        let mut expected = owner;
        // SAFETY: the synthetic ACE buffer outlives the call and holds at
        // least an ACE header; the expected SID is well formed.
        unsafe {
            allowed_owner_ace(
                std::ptr::NonNull::new(bytes.as_mut_ptr()).unwrap(),
                expected.as_mut_ptr().cast(),
            )
        }
    };
    assert!(check(ace(0, 0, 20, FILE_ALL_ACCESS, &owner)));
    assert!(!check(ace(1, 0, 20, FILE_ALL_ACCESS, &owner)), "deny ACE");
    assert!(
        !check(ace(0, 3, 20, FILE_ALL_ACCESS, &owner)),
        "inheritance flags"
    );
    assert!(
        !check(ace(0, 0, 20, FILE_ALL_ACCESS & !1, &owner)),
        "reduced mask"
    );
    assert!(!check(ace(0, 0, 20, FILE_ALL_ACCESS, &other)), "other SID");
    assert!(
        !check(ace(0, 0, 12, FILE_ALL_ACCESS, &owner)),
        "size ends before SID header"
    );
    assert!(
        !check(ace(0, 0, 16, FILE_ALL_ACCESS, &owner)),
        "size ends inside SID"
    );
    let mut longer = owner;
    longer[1] = 2;
    assert!(
        !check(ace(0, 0, 20, FILE_ALL_ACCESS, &longer)),
        "sub-authorities past ACE size"
    );
}

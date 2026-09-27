// SPDX-License-Identifier: AGPL-3.0-only
//! Test-only launcher. Never shipped in either executable or library.
use std::{
    mem::{size_of, zeroed},
    os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle},
    ptr::{null, null_mut},
};
use windows_sys::Win32::{Foundation::*, Security::*, System::Threading::*};

unsafe fn elevated(token: HANDLE) -> bool {
    let mut value: TOKEN_ELEVATION = unsafe { zeroed() };
    let mut length = 0;
    assert_ne!(
        unsafe {
            GetTokenInformation(
                token,
                TokenElevation,
                (&mut value as *mut TOKEN_ELEVATION).cast(),
                size_of::<TOKEN_ELEVATION>() as u32,
                &mut length,
            )
        },
        0,
        "query actual child-launch token elevation"
    );
    assert_eq!(length as usize, size_of::<TOKEN_ELEVATION>());
    value.TokenIsElevated != 0
}

/// Caller provides live terminated buffers and valid initialized native structs.
pub(crate) unsafe fn create(
    application: *const u16,
    command: *mut u16,
    environment: *const std::ffi::c_void,
    startup: *const STARTUPINFOW,
    process: *mut PROCESS_INFORMATION,
    production_eligible: fn() -> bool,
) -> i32 {
    unsafe {
        let mut raw = null_mut();
        assert_ne!(
            OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut raw),
            0
        );
        let token = OwnedHandle::from_raw_handle(raw);
        let flags = CREATE_NEW_CONSOLE | CREATE_UNICODE_ENVIRONMENT;
        if !elevated(token.as_raw_handle()) {
            return CreateProcessW(
                application,
                command,
                null(),
                null(),
                0,
                flags,
                environment,
                null(),
                startup,
                process,
            );
        }
        eprintln!("native launcher: parent is elevated; requiring a genuine limited primary token");
        assert!(
            !production_eligible(),
            "production preflight must reject the elevated parent"
        );
        let mut linked: TOKEN_LINKED_TOKEN = zeroed();
        let mut length = 0;
        assert_ne!(
            GetTokenInformation(
                token.as_raw_handle(),
                TokenLinkedToken,
                (&mut linked as *mut TOKEN_LINKED_TOKEN).cast(),
                size_of::<TOKEN_LINKED_TOKEN>() as u32,
                &mut length
            ),
            0,
            "elevated test runner has no usable limited linked token; native eligibility gate remains unsatisfied (OS error {})",
            GetLastError()
        );
        let linked = OwnedHandle::from_raw_handle(linked.LinkedToken);
        assert_eq!(length as usize, size_of::<TOKEN_LINKED_TOKEN>());
        assert!(
            !elevated(linked.as_raw_handle()),
            "linked token must actually be non-elevated"
        );
        let mut kind: TOKEN_TYPE = 0;
        assert_ne!(
            GetTokenInformation(
                linked.as_raw_handle(),
                TokenType,
                (&mut kind as *mut TOKEN_TYPE).cast(),
                size_of::<TOKEN_TYPE>() as u32,
                &mut length
            ),
            0,
            "query linked token type (OS error {})",
            GetLastError()
        );
        assert_eq!(length as usize, size_of::<TOKEN_TYPE>());
        assert_eq!(kind, TokenPrimary, "linked token must be PRIMARY");
        // Same user's limited primary token, no alternate credentials, profile
        // loading, inherited handles, or fallback if Windows refuses this launch.
        let created = CreateProcessWithTokenW(
            linked.as_raw_handle(),
            0,
            application,
            command,
            flags,
            environment,
            null(),
            startup,
            process,
        );
        assert_ne!(
            created,
            0,
            "limited primary token launch refused; QUERY/DUPLICATE/ASSIGN_PRIMARY and existing SeImpersonate are required (OS error {})",
            GetLastError()
        );
        created
    }
}

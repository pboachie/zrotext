// SPDX-License-Identifier: AGPL-3.0-only
//! Test-only launcher. Never shipped in either executable or library.
//!
//! Hidden native test children must never run with administrator rights, so
//! production eligibility is exercised for real. A non-elevated parent launches
//! directly. An elevated parent uses its existing limited linked token when
//! Windows provides one (UAC). Hosts without a linked token, such as the
//! GitHub-hosted runner, get a UAC-equivalent reduced-rights token of the same
//! account in the same session. Either token must pass `limited_violations`
//! before launch, and each child re-checks its own token.
use std::{
    mem::{size_of, zeroed},
    os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle},
    ptr::{null, null_mut},
};
use windows_sys::Win32::{Foundation::*, Security::*, System::Threading::*};

const SE_GROUP_ENABLED: u32 = 0x4;
const SE_GROUP_USE_FOR_DENY_ONLY: u32 = 0x10;
const SE_GROUP_INTEGRITY: u32 = 0x20;
/// S-1-5-32-544, BUILTIN\Administrators.
const ADMINISTRATORS: [u8; 16] = [1, 2, 0, 0, 0, 0, 0, 5, 32, 0, 0, 0, 32, 2, 0, 0];
/// S-1-16-8192, Medium mandatory level.
const MEDIUM_INTEGRITY: [u8; 12] = [1, 1, 0, 0, 0, 0, 0, 16, 0, 0x20, 0, 0];
const MEDIUM_RID: u32 = 0x2000;
/// Privileges a standard (UAC-filtered) user never holds.
const ADMIN_PRIVILEGES: [&str; 10] = [
    "SeDebugPrivilege",
    "SeTakeOwnershipPrivilege",
    "SeBackupPrivilege",
    "SeRestorePrivilege",
    "SeLoadDriverPrivilege",
    "SeTcbPrivilege",
    "SeSecurityPrivilege",
    "SeImpersonatePrivilege",
    "SeAssignPrimaryTokenPrivilege",
    "SeSystemEnvironmentPrivilege",
];

/// Observed properties of a token that decide whether it has admin rights.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct TokenFacts {
    pub elevated: bool,
    pub primary: bool,
    pub integrity_rid: u32,
    pub administrators_enabled: bool,
    pub admin_privileges: bool,
}

/// Every reason the token could still act as an administrator; empty means
/// genuinely limited. Kept pure so each refusal is unit tested.
pub(crate) fn limited_violations(facts: TokenFacts) -> Vec<&'static str> {
    let mut found = Vec::new();
    if facts.elevated {
        found.push("elevated");
    }
    if !facts.primary {
        found.push("not-primary");
    }
    if facts.integrity_rid > MEDIUM_RID {
        found.push("integrity-above-medium");
    }
    if facts.administrators_enabled {
        found.push("administrators-enabled");
    }
    if facts.admin_privileges {
        found.push("admin-privileges");
    }
    found
}

fn wide(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(Some(0)).collect()
}

/// Caller passes a live token handle with TOKEN_QUERY.
/// Returns the aligned buffer itself: token information holds pointers into
/// it (SIDs, ACLs), so it must stay alive and unmoved while those are read.
unsafe fn query(token: HANDLE, class: TOKEN_INFORMATION_CLASS) -> Vec<u64> {
    unsafe {
        let mut needed = 0;
        GetTokenInformation(token, class, null_mut(), 0, &mut needed);
        assert!(
            needed > 0 && needed <= 65536,
            "token information size (OS error {})",
            GetLastError()
        );
        // u64 backing keeps the SID/LUID structures suitably aligned.
        let mut buffer = vec![0_u64; (needed as usize).div_ceil(8)];
        assert_ne!(
            GetTokenInformation(
                token,
                class,
                buffer.as_mut_ptr().cast(),
                needed,
                &mut needed
            ),
            0,
            "query token information (OS error {})",
            GetLastError()
        );
        buffer
    }
}

/// Caller passes a valid SID pointer.
unsafe fn sid_bytes(sid: PSID) -> Vec<u8> {
    unsafe { std::slice::from_raw_parts(sid.cast::<u8>(), GetLengthSid(sid) as usize).to_vec() }
}

/// Caller passes a live token handle with TOKEN_QUERY.
pub(crate) unsafe fn facts(token: HANDLE) -> TokenFacts {
    unsafe {
        let elevation = query(token, TokenElevation);
        let kind = query(token, TokenType);
        let label = query(token, TokenIntegrityLevel);
        let label = &*label.as_ptr().cast::<TOKEN_MANDATORY_LABEL>();
        let rid = {
            let sid = sid_bytes(label.Label.Sid);
            u32::from_le_bytes(sid[sid.len() - 4..].try_into().unwrap())
        };
        let groups = query(token, TokenGroups);
        let groups = &*groups.as_ptr().cast::<TOKEN_GROUPS>();
        let groups = std::slice::from_raw_parts(groups.Groups.as_ptr(), groups.GroupCount as usize);
        let administrators_enabled = groups.iter().any(|group| {
            sid_bytes(group.Sid) == ADMINISTRATORS
                && group.Attributes & SE_GROUP_USE_FOR_DENY_ONLY == 0
                && group.Attributes & SE_GROUP_ENABLED != 0
        });
        let privileges = query(token, TokenPrivileges);
        let privileges = &*privileges.as_ptr().cast::<TOKEN_PRIVILEGES>();
        let privileges = std::slice::from_raw_parts(
            privileges.Privileges.as_ptr(),
            privileges.PrivilegeCount as usize,
        );
        let admin_privileges = ADMIN_PRIVILEGES.iter().any(|name| {
            let mut luid = zeroed::<LUID>();
            LookupPrivilegeValueW(null(), wide(name).as_ptr(), &mut luid) != 0
                && privileges.iter().any(|held| {
                    held.Luid.LowPart == luid.LowPart && held.Luid.HighPart == luid.HighPart
                })
        });
        TokenFacts {
            elevated: *elevation.as_ptr().cast::<u32>() != 0,
            primary: *kind.as_ptr().cast::<i32>() == TokenPrimary,
            integrity_rid: rid,
            administrators_enabled,
            admin_privileges,
        }
    }
}

fn current_token(access: TOKEN_ACCESS_MASK) -> OwnedHandle {
    let mut raw = null_mut();
    // SAFETY: the current process pseudo-handle is always valid.
    assert_ne!(
        unsafe { OpenProcessToken(GetCurrentProcess(), access, &mut raw) },
        0
    );
    // SAFETY: OpenProcessToken returned an owned handle.
    unsafe { OwnedHandle::from_raw_handle(raw) }
}

/// Called first in every hidden child: a test must never silently run with
/// administrator rights, whatever the launcher did.
pub(crate) fn assert_current_process_limited() {
    let token = current_token(TOKEN_QUERY);
    // SAFETY: owned token handle opened with TOKEN_QUERY.
    let facts = unsafe { facts(token.as_raw_handle()) };
    assert_eq!(
        limited_violations(facts),
        Vec::<&str>::new(),
        "native test child must not hold administrator rights"
    );
}

/// UAC-equivalent reduced-rights primary token of the caller's own account in
/// the same logon session: BUILTIN\Administrators deny-only, administrator
/// privileges removed (LUA_TOKEN) and Medium integrity.
pub(crate) fn reduced_rights_token() -> OwnedHandle {
    let own =
        current_token(TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY | TOKEN_ADJUST_DEFAULT);
    // SAFETY: valid owned token, fixed well-formed SID buffers that outlive
    // each call, and checked return values.
    unsafe {
        let mut administrators = ADMINISTRATORS;
        let disable = SID_AND_ATTRIBUTES {
            Sid: administrators.as_mut_ptr().cast(),
            Attributes: 0,
        };
        let mut raw = null_mut();
        assert_ne!(
            CreateRestrictedToken(
                own.as_raw_handle(),
                LUA_TOKEN,
                1,
                &disable,
                0,
                null(),
                0,
                null(),
                &mut raw
            ),
            0,
            "create reduced-rights token (OS error {})",
            GetLastError()
        );
        let token = OwnedHandle::from_raw_handle(raw);
        let mut medium = MEDIUM_INTEGRITY;
        let label = TOKEN_MANDATORY_LABEL {
            Label: SID_AND_ATTRIBUTES {
                Sid: medium.as_mut_ptr().cast(),
                Attributes: SE_GROUP_INTEGRITY,
            },
        };
        assert_ne!(
            SetTokenInformation(
                token.as_raw_handle(),
                TokenIntegrityLevel,
                (&label as *const TOKEN_MANDATORY_LABEL).cast(),
                (size_of::<TOKEN_MANDATORY_LABEL>() + medium.len()) as u32,
            ),
            0,
            "lower reduced-rights token to Medium integrity (OS error {})",
            GetLastError()
        );
        set_standard_default_dacl(token.as_raw_handle());
        token
    }
}

/// Whether the token's default DACL, which new child processes inherit, lets
/// the token's own user open them.
///
/// Caller passes a live token handle with TOKEN_QUERY.
pub(crate) unsafe fn default_dacl_grants_user(token: HANDLE) -> bool {
    unsafe {
        let user = query(token, TokenUser);
        let user = sid_bytes((*user.as_ptr().cast::<TOKEN_USER>()).User.Sid);
        let dacl = query(token, TokenDefaultDacl);
        let acl = (*dacl.as_ptr().cast::<TOKEN_DEFAULT_DACL>()).DefaultDacl;
        if acl.is_null() {
            return false;
        }
        (0..u32::from((*acl).AceCount)).any(|index| {
            let mut ace = null_mut();
            GetAce(acl, index, &mut ace) != 0 && {
                let ace = &*ace.cast::<ACCESS_ALLOWED_ACE>();
                ace.Header.AceType == 0 // ACCESS_ALLOWED_ACE_TYPE
                    && ace.Mask & 0x1000_0000 != 0
                    && sid_bytes((&ace.SidStart as *const u32).cast_mut().cast()) == user
            }
        })
    }
}

/// An elevated token's default DACL grants only Administrators and SYSTEM.
/// With Administrators deny-only, the child could not open its own process to
/// start its console host (STATUS_DLL_INIT_FAILED). Use the default DACL of a
/// standard token instead: the user and SYSTEM full access, the logon session
/// read and execute.
///
/// Caller passes a live primary token opened with TOKEN_QUERY and
/// TOKEN_ADJUST_DEFAULT.
unsafe fn set_standard_default_dacl(token: HANDLE) {
    const GENERIC_ALL: u32 = 0x1000_0000;
    const GENERIC_READ_EXECUTE: u32 = 0x8000_0000 | 0x2000_0000;
    /// S-1-5-18, LocalSystem.
    const SYSTEM: [u8; 12] = [1, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0];
    unsafe {
        let user = query(token, TokenUser);
        let user = sid_bytes((*user.as_ptr().cast::<TOKEN_USER>()).User.Sid);
        let groups = query(token, TokenLogonSid);
        let groups = &*groups.as_ptr().cast::<TOKEN_GROUPS>();
        assert_eq!(groups.GroupCount, 1, "exactly one logon session SID");
        let logon = sid_bytes(groups.Groups[0].Sid);
        let entries = [
            (user, GENERIC_ALL),
            (SYSTEM.to_vec(), GENERIC_ALL),
            (logon, GENERIC_READ_EXECUTE),
        ];
        let size = size_of::<ACL>()
            + entries
                .iter()
                .map(|(sid, _)| size_of::<ACCESS_ALLOWED_ACE>() - size_of::<u32>() + sid.len())
                .sum::<usize>();
        let mut buffer = vec![0_u64; size.div_ceil(8)];
        let acl = buffer.as_mut_ptr().cast::<ACL>();
        assert_ne!(InitializeAcl(acl, size as u32, ACL_REVISION), 0);
        for (sid, mask) in &entries {
            let mut sid = sid.clone();
            assert_ne!(
                AddAccessAllowedAce(acl, ACL_REVISION, *mask, sid.as_mut_ptr().cast()),
                0,
                "build standard default DACL (OS error {})",
                GetLastError()
            );
        }
        let value = TOKEN_DEFAULT_DACL { DefaultDacl: acl };
        assert_ne!(
            SetTokenInformation(
                token,
                TokenDefaultDacl,
                (&value as *const TOKEN_DEFAULT_DACL).cast(),
                size_of::<TOKEN_DEFAULT_DACL>() as u32,
            ),
            0,
            "set standard default DACL (OS error {})",
            GetLastError()
        );
    }
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
        let token = current_token(TOKEN_QUERY);
        let flags = CREATE_NEW_CONSOLE | CREATE_UNICODE_ENVIRONMENT;
        if !facts(token.as_raw_handle()).elevated {
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
        assert!(
            !production_eligible(),
            "production preflight must reject the elevated parent"
        );
        let mut linked: TOKEN_LINKED_TOKEN = zeroed();
        let mut length = 0;
        let has_linked = GetTokenInformation(
            token.as_raw_handle(),
            TokenLinkedToken,
            (&mut linked as *mut TOKEN_LINKED_TOKEN).cast(),
            size_of::<TOKEN_LINKED_TOKEN>() as u32,
            &mut length,
        ) != 0;
        let (limited, linked) = if has_linked {
            (OwnedHandle::from_raw_handle(linked.LinkedToken), true)
        } else {
            (reduced_rights_token(), false)
        };
        assert_eq!(
            limited_violations(facts(limited.as_raw_handle())),
            Vec::<&str>::new(),
            "child launch token must be genuinely limited"
        );
        // Same account and session; no alternate credentials, profile loading,
        // inherited handles or fallback if Windows refuses the launch.
        let created = if linked {
            CreateProcessWithTokenW(
                limited.as_raw_handle(),
                0,
                application,
                command,
                flags,
                environment,
                null(),
                startup,
                process,
            )
        } else {
            CreateProcessAsUserW(
                limited.as_raw_handle(),
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
            )
        };
        assert_ne!(
            created,
            0,
            "limited child launch refused (OS error {})",
            GetLastError()
        );
        created
    }
}

#[cfg(test)]
mod launcher_tests {
    use super::*;

    const LIMITED: TokenFacts = TokenFacts {
        elevated: false,
        primary: true,
        integrity_rid: MEDIUM_RID,
        administrators_enabled: false,
        admin_privileges: false,
    };

    #[test]
    fn launcher_refuses_every_administrator_signal() {
        assert!(limited_violations(LIMITED).is_empty());
        assert!(
            limited_violations(TokenFacts {
                integrity_rid: 0x1000,
                ..LIMITED
            })
            .is_empty()
        );
        for (facts, reason) in [
            (
                TokenFacts {
                    elevated: true,
                    ..LIMITED
                },
                "elevated",
            ),
            (
                TokenFacts {
                    primary: false,
                    ..LIMITED
                },
                "not-primary",
            ),
            (
                TokenFacts {
                    integrity_rid: 0x3000,
                    ..LIMITED
                },
                "integrity-above-medium",
            ),
            (
                TokenFacts {
                    administrators_enabled: true,
                    ..LIMITED
                },
                "administrators-enabled",
            ),
            (
                TokenFacts {
                    admin_privileges: true,
                    ..LIMITED
                },
                "admin-privileges",
            ),
        ] {
            assert_eq!(limited_violations(facts), [reason]);
        }
    }

    #[test]
    fn launcher_reduced_rights_token_is_genuinely_limited() {
        // Works whether the test runner is elevated or not: the derived token
        // must pass the same check the launcher and every child enforce.
        let token = reduced_rights_token();
        // SAFETY: owned token returned by reduced_rights_token.
        let facts = unsafe { facts(token.as_raw_handle()) };
        assert_eq!(limited_violations(facts), Vec::<&str>::new());
        assert!(facts.integrity_rid <= MEDIUM_RID);
        // Children must be able to open themselves (console host start-up).
        // SAFETY: owned token returned by reduced_rights_token.
        assert!(unsafe { default_dacl_grants_user(token.as_raw_handle()) });
    }
}

// SPDX-License-Identifier: AGPL-3.0-only
//! Archive-only output boundary using the reviewed root-bundle native checks.
//! Owns exclusively created files and pinned NTFS ancestor handles until commit.

use std::{
    ffi::c_void,
    fs::File,
    io::{Read, Seek, SeekFrom, Write},
    mem::{size_of, zeroed},
    os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle},
    path::Path,
    ptr::{null, null_mut},
};
use windows_sys::{
    Wdk::{Foundation::OBJECT_ATTRIBUTES, Storage::FileSystem::*},
    Win32::{
        Foundation::{HANDLE, LocalFree, UNICODE_STRING},
        Security::{Authorization::*, *},
        Storage::FileSystem::*,
        System::{IO::IO_STATUS_BLOCK, Threading::*},
    },
};
use zeroize::Zeroizing;
use zrotext_root_bundle::Error;
use zrotext_root_material::archive_init::PreparedArchive;

type Result<T> = std::result::Result<T, Error>;
const DIRECTORY_READ: u32 = 0x0012_00a0; // READ_CONTROL | SYNCHRONIZE | TRAVERSE | READ_ATTRIBUTES
const DELETE_ACCESS: u32 = 0x0001_0000;
const FILE_READ: u32 = 0x0012_0089;
const FILE_WRITE: u32 = 0x0012_019f;

struct LocalAllocation(*mut c_void);
impl Drop for LocalAllocation {
    fn drop(&mut self) {
        // SAFETY: these buffers come only from APIs documenting LocalFree ownership.
        unsafe {
            LocalFree(self.0);
        }
    }
}

struct Security(LocalAllocation);
impl Security {
    fn current() -> Result<Self> {
        // SAFETY: output pointers and sized, aligned buffers remain live across calls.
        unsafe {
            let mut raw = null_mut();
            if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut raw) == 0 {
                return Err(Error::UnsafeStore);
            }
            let token = OwnedHandle::from_raw_handle(raw);
            let mut needed = 0;
            GetTokenInformation(token.as_raw_handle(), TokenUser, null_mut(), 0, &mut needed);
            if needed < size_of::<TOKEN_USER>() as u32 || needed > 4096 {
                return Err(Error::UnsafeStore);
            }
            let mut bytes = vec![0_usize; (needed as usize).div_ceil(size_of::<usize>())];
            if GetTokenInformation(
                token.as_raw_handle(),
                TokenUser,
                bytes.as_mut_ptr().cast(),
                needed,
                &mut needed,
            ) == 0
            {
                return Err(Error::UnsafeStore);
            }
            let user = &*bytes.as_ptr().cast::<TOKEN_USER>();
            let mut text = null_mut();
            if ConvertSidToStringSidW(user.User.Sid, &mut text) == 0 {
                return Err(Error::UnsafeStore);
            }
            let text_owner = LocalAllocation(text.cast());
            let mut length = 0;
            while length < 192 && *text.add(length) != 0 {
                length += 1;
            }
            if length == 192 {
                return Err(Error::UnsafeStore);
            }
            let sid = String::from_utf16(std::slice::from_raw_parts(text, length))
                .map_err(|_| Error::UnsafeStore)?;
            drop(text_owner);
            let sddl: Vec<u16> = format!("O:{sid}D:P(A;;FA;;;{sid})")
                .encode_utf16()
                .chain(Some(0))
                .collect();
            let mut descriptor = null_mut();
            if ConvertStringSecurityDescriptorToSecurityDescriptorW(
                sddl.as_ptr(),
                1,
                &mut descriptor,
                null_mut(),
            ) == 0
            {
                return Err(Error::UnsafeStore);
            }
            Ok(Self(LocalAllocation(descriptor)))
        }
    }

    fn check(&self, file: &File) -> Result<()> {
        // SAFETY: GetSecurityInfo owns the returned descriptor; all interior
        // owner/ACL/ACE pointers are consumed before freeing that allocation.
        unsafe {
            let mut owner = null_mut();
            let mut acl = null_mut();
            let mut descriptor = null_mut();
            if GetSecurityInfo(
                file.as_raw_handle(),
                SE_FILE_OBJECT,
                OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
                &mut owner,
                null_mut(),
                &mut acl,
                null_mut(),
                &mut descriptor,
            ) != 0
            {
                return Err(Error::UnsafeStore);
            }
            let allocation = LocalAllocation(descriptor);
            let mut control = 0;
            let mut revision = 0;
            let mut expected_owner = null_mut();
            let mut defaulted = 0;
            // The ACE count comes from GetAclInformation rather than reading
            // the ACL header through the returned pointer.
            let mut sizes: ACL_SIZE_INFORMATION = zeroed();
            if GetSecurityDescriptorControl(descriptor, &mut control, &mut revision) == 0
                || control & SE_DACL_PROTECTED == 0
                || control & SE_DACL_PRESENT == 0
                || GetSecurityDescriptorOwner(self.0.0, &mut expected_owner, &mut defaulted) == 0
                || owner.is_null()
                || EqualSid(owner, expected_owner) == 0
                || acl.is_null()
                || IsValidAcl(acl) == 0
                || GetAclInformation(
                    acl,
                    (&mut sizes as *mut ACL_SIZE_INFORMATION).cast(),
                    size_of::<ACL_SIZE_INFORMATION>() as u32,
                    AclSizeInformation,
                ) == 0
                || sizes.AceCount != 1
            {
                return Err(Error::UnsafeStore);
            }
            let mut ace = std::mem::MaybeUninit::<*mut c_void>::uninit();
            if GetAce(acl, 0, ace.as_mut_ptr()) == 0 {
                return Err(Error::UnsafeStore);
            }
            let Some(ace) = std::ptr::NonNull::new(ace.assume_init().cast::<u8>()) else {
                return Err(Error::UnsafeStore);
            };
            if !allowed_owner_ace(ace, expected_owner) {
                return Err(Error::UnsafeStore);
            }
            drop(allocation);
            Ok(())
        }
    }
}

/// Checks the single DACL entry: an inheritance-free ACCESS_ALLOWED ACE for
/// exactly FILE_ALL_ACCESS whose SID, bounded by the ACE's own declared size,
/// equals `owner`. Every read is an unaligned copy inside that size; nothing
/// is read before the header shows the ACE is large enough.
///
/// Caller passes an ACE returned by GetAce for an ACL accepted by IsValidAcl,
/// whose allocation stays live for this call, and a valid owner SID.
unsafe fn allowed_owner_ace(ace: std::ptr::NonNull<u8>, owner: PSID) -> bool {
    const ACCESS_ALLOWED_ACE_TYPE: u8 = 0;
    const MASK: usize = std::mem::offset_of!(ACCESS_ALLOWED_ACE, Mask);
    const SID: usize = std::mem::offset_of!(ACCESS_ALLOWED_ACE, SidStart);
    /// Revision, sub-authority count and 6-byte identifier authority.
    const SID_HEADER: usize = 8;
    // SAFETY: the caller guarantees at least an ACE header is readable; each
    // later read is checked against the ACE's declared size first.
    unsafe {
        let header = ace
            .cast::<windows_sys::Win32::Security::ACE_HEADER>()
            .as_ptr()
            .read_unaligned();
        let size = usize::from(header.AceSize);
        if header.AceType != ACCESS_ALLOWED_ACE_TYPE
            || header.AceFlags != 0
            || size < SID + SID_HEADER
        {
            return false;
        }
        let mask = ace.add(MASK).cast::<u32>().as_ptr().read_unaligned();
        let sid = ace.add(SID);
        let sid_length = SID_HEADER + 4 * usize::from(sid.add(1).as_ptr().read());
        mask == FILE_ALL_ACCESS
            && SID + sid_length <= size
            && IsValidSid(sid.as_ptr().cast()) != 0
            && GetLengthSid(sid.as_ptr().cast()) as usize == sid_length
            && EqualSid(sid.as_ptr().cast(), owner) != 0
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Identity {
    volume: u32,
    index: u64,
}

fn inspect(file: &File, directory: bool, max_size: u64) -> Result<Identity> {
    // SAFETY: fixed-size output structure is initialized and writable.
    unsafe {
        let mut info: BY_HANDLE_FILE_INFORMATION = zeroed();
        if GetFileType(file.as_raw_handle()) != FILE_TYPE_DISK
            || GetFileInformationByHandle(file.as_raw_handle(), &mut info) == 0
        {
            return Err(Error::UnsafeStore);
        }
        let forbidden =
            FILE_ATTRIBUTE_REPARSE_POINT | FILE_ATTRIBUTE_OFFLINE | FILE_ATTRIBUTE_DEVICE;
        if info.dwFileAttributes & forbidden != 0
            || (info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY != 0) != directory
            || info.nNumberOfLinks != 1
            || (!directory
                && ((u64::from(info.nFileSizeHigh) << 32) | u64::from(info.nFileSizeLow))
                    > max_size)
        {
            return Err(Error::UnsafeStore);
        }
        Ok(Identity {
            volume: info.dwVolumeSerialNumber,
            index: (u64::from(info.nFileIndexHigh) << 32) | u64::from(info.nFileIndexLow),
        })
    }
}

fn component(value: &str) -> bool {
    if value.is_empty()
        || value.len() > 128
        || !value.is_ascii()
        || value
            .bytes()
            .any(|b| b < 32 || b == 127 || b"<>:\"/\\|?*".contains(&b))
        || value.ends_with(['.', ' '])
    {
        return false;
    }
    let stem = value.split('.').next().unwrap().to_ascii_uppercase();
    !matches!(stem.as_str(), "CON" | "PRN" | "AUX" | "NUL" | "CLOCK$")
        && !(stem.len() == 4
            && (stem.starts_with("COM") || stem.starts_with("LPT"))
            && matches!(stem.as_bytes()[3], b'1'..=b'9'))
}

fn path_parts(path: &Path) -> Result<(String, Vec<&str>)> {
    let text = path.to_str().ok_or(Error::UnsafeStore)?;
    let bytes = text.as_bytes();
    if text.len() > 260
        || bytes.len() < 3
        || !bytes[0].is_ascii_alphabetic()
        || &bytes[1..3] != b":\\"
    {
        return Err(Error::UnsafeStore);
    }
    let parts: Vec<_> = text[3..].split('\\').collect();
    if parts.iter().any(|part| !component(part)) {
        return Err(Error::UnsafeStore);
    }
    Ok((format!("\\??\\{}", &text[..3]), parts))
}

fn relative(
    parent: Option<&File>,
    name: &str,
    directory: bool,
    create: bool,
    share: u32,
    security: Option<&Security>,
    delete: bool,
) -> Result<File> {
    if parent.is_some() && !component(name) {
        return Err(Error::InvalidInput);
    }
    let mut name: Vec<u16> = name.encode_utf16().collect();
    let length = u16::try_from(name.len() * 2).map_err(|_| Error::InvalidInput)?;
    let mut unicode = UNICODE_STRING {
        Length: length,
        MaximumLength: length,
        Buffer: name.as_mut_ptr(),
    };
    let attributes = OBJECT_ATTRIBUTES {
        Length: size_of::<OBJECT_ATTRIBUTES>() as u32,
        RootDirectory: parent.map_or(null_mut(), AsRawHandle::as_raw_handle),
        ObjectName: &mut unicode,
        Attributes: 0x40, // OBJ_CASE_INSENSITIVE; deliberately not OBJ_INHERIT.
        SecurityDescriptor: security.map_or(null(), |s| s.0.0.cast()),
        SecurityQualityOfService: null_mut(),
    };
    // SAFETY: all pointers reference live allocations with correct ABI alignment;
    // NtCreateFile returns an owned handle only on success.
    unsafe {
        let mut status: IO_STATUS_BLOCK = zeroed();
        let mut handle: HANDLE = null_mut();
        let access = if directory {
            DIRECTORY_READ
        } else if create {
            FILE_WRITE
        } else {
            FILE_READ
        };
        let code = NtCreateFile(
            &mut handle,
            access | if delete { DELETE_ACCESS } else { 0 },
            &attributes,
            &mut status,
            null(),
            0,
            share,
            if create { FILE_CREATE } else { FILE_OPEN },
            FILE_OPEN_REPARSE_POINT
                | FILE_SYNCHRONOUS_IO_NONALERT
                | if directory {
                    FILE_DIRECTORY_FILE
                } else {
                    FILE_NON_DIRECTORY_FILE
                },
            null(),
            0,
        );
        if code < 0 {
            return Err(if code as u32 == 0xc000_0035 {
                Error::Collision
            } else {
                Error::Storage
            });
        }
        Ok(File::from_raw_handle(handle))
    }
}

fn fixed_ntfs(root: &File) -> Result<()> {
    // SAFETY: output buffers are fixed, bounded UTF-16 arrays, passed by capacity.
    unsafe {
        let mut fs = [0_u16; 32];
        if GetVolumeInformationByHandleW(
            root.as_raw_handle(),
            null_mut(),
            0,
            null_mut(),
            null_mut(),
            null_mut(),
            fs.as_mut_ptr(),
            fs.len() as u32,
        ) == 0
            || fs[..5] != [78, 84, 70, 83, 0]
        {
            return Err(Error::UnsafeStore);
        }
        let mut path = [0_u16; 128];
        let length = GetFinalPathNameByHandleW(
            root.as_raw_handle(),
            path.as_mut_ptr(),
            path.len() as u32,
            VOLUME_NAME_GUID,
        );
        if length == 0 || length as usize >= path.len() {
            return Err(Error::UnsafeStore);
        }
        let name = String::from_utf16(&path[..length as usize]).map_err(|_| Error::UnsafeStore)?;
        if !name.starts_with("\\\\?\\Volume{")
            || !name.ends_with("}\\")
            || GetDriveTypeW(path.as_ptr()) != 3
        /* DRIVE_FIXED */
        {
            return Err(Error::UnsafeStore);
        }
        Ok(())
    }
}

/// Syntax only; no filesystem access or secret input.
pub(super) fn validate_path(path: &str) -> Result<()> {
    path_parts(Path::new(path))?;
    Ok(())
}

struct ReservedFile {
    ancestors: Vec<(File, Identity)>,
    file: File,
    identity: Option<Identity>,
    security: Security,
    maximum: u64,
    keep: bool,
}
impl ReservedFile {
    fn create(path: &str, maximum: u64) -> Result<Self> {
        let (anchor, parts) = path_parts(Path::new(path))?;
        let (leaf, parents) = parts.split_last().ok_or(Error::UnsafeStore)?;
        let security = Security::current()?;
        let root = relative(None, &anchor, true, false, 3, None, false)?;
        fixed_ntfs(&root)?;
        let root_id = inspect(&root, true, 0)?;
        let mut ancestors = vec![(root, root_id)];
        for component in parents {
            let (parent, id) = ancestors.last().unwrap();
            let next = relative(Some(parent), component, true, false, 3, None, false)?;
            let identity = inspect(&next, true, 0)?;
            if inspect(parent, true, 0)? != *id || identity.volume != root_id.volume {
                return Err(Error::UnsafeStore);
            }
            ancestors.push((next, identity));
        }
        let file = relative(
            Some(&ancestors.last().unwrap().0),
            leaf,
            false,
            true,
            0,
            Some(&security),
            true,
        )?;
        let mut reserved = Self {
            ancestors,
            file,
            identity: None,
            security,
            maximum,
            keep: false,
        };
        let id = inspect(&reserved.file, false, maximum)?;
        if id.volume != root_id.volume {
            return Err(Error::UnsafeStore);
        }
        reserved.identity = Some(id);
        reserved.check()?;
        Ok(reserved)
    }
    fn check(&self) -> Result<()> {
        for (file, id) in &self.ancestors {
            if inspect(file, true, 0)? != *id {
                return Err(Error::UnsafeStore);
            }
        }
        if self.identity != Some(inspect(&self.file, false, self.maximum)?) {
            return Err(Error::UnsafeStore);
        }
        self.security.check(&self.file)
    }
    fn write(&mut self, bytes: &[u8]) -> Result<()> {
        if bytes.len() as u64 > self.maximum {
            return Err(Error::InvalidInput);
        }
        self.check()?;
        self.file.write_all(bytes).map_err(|_| Error::Storage)?;
        self.file.sync_all().map_err(|_| Error::Storage)?;
        self.check()
    }
    fn read_public(&mut self, expected: &[u8]) -> Result<Vec<u8>> {
        self.check()?;
        self.file
            .seek(SeekFrom::Start(0))
            .map_err(|_| Error::Storage)?;
        let mut bytes = Vec::new();
        (&mut self.file)
            .take(self.maximum + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| Error::Storage)?;
        if bytes != expected {
            return Err(Error::Storage);
        }
        self.check()?;
        Ok(bytes)
    }
    fn read_recovery(
        &mut self,
    ) -> Result<zrotext_root_material::archive_backup::ArchiveRecoverySecret> {
        self.check()?;
        self.file
            .seek(SeekFrom::Start(0))
            .map_err(|_| Error::Storage)?;
        let mut bytes = Zeroizing::new([0; 32]);
        self.file
            .read_exact(bytes.as_mut())
            .map_err(|_| Error::Storage)?;
        let mut extra = [0; 1];
        if self.file.read(&mut extra).map_err(|_| Error::Storage)? != 0 {
            return Err(Error::Storage);
        }
        self.check()?;
        Ok(zrotext_root_material::archive_backup::ArchiveRecoverySecret::new(bytes))
    }
}
impl Drop for ReservedFile {
    fn drop(&mut self) {
        if !self.keep {
            // SAFETY: DELETE access belongs to our exclusively FILE_CREATE-owned
            // handle. This marks only our new file for deletion, never a path or
            // pre-existing destination. Failure remains an indeterminate output.
            unsafe {
                let disposition = FILE_DISPOSITION_INFORMATION { DeleteFile: true };
                let mut status: IO_STATUS_BLOCK = zeroed();
                NtSetInformationFile(
                    self.file.as_raw_handle(),
                    &mut status,
                    (&disposition as *const FILE_DISPOSITION_INFORMATION).cast(),
                    size_of::<FILE_DISPOSITION_INFORMATION>() as u32,
                    FileDispositionInformation,
                );
            }
        }
    }
}

/// Typed three-file transaction. Never adopts existing files; the recovery file
/// is a protected current-user-only raw32 file, distinct from both public files.
/// Handles deny concurrent read/write/delete while publication is in progress.
pub(super) struct Outputs {
    archive: ReservedFile,
    receipt: ReservedFile,
    recovery: ReservedFile,
}
#[derive(Clone, Copy)]
pub(super) enum Boundary {
    Public,
    Private,
    Commit,
}
impl Outputs {
    pub(super) fn reserve(archive: &str, receipt: &str, recovery: &str) -> Result<Self> {
        if [archive, receipt, recovery]
            .iter()
            .enumerate()
            .any(|(n, p)| {
                [archive, receipt, recovery][..n]
                    .iter()
                    .any(|other| p.eq_ignore_ascii_case(other))
            })
        {
            return Err(Error::InvalidInput);
        }
        Ok(Self {
            archive: ReservedFile::create(archive, 845)?,
            receipt: ReservedFile::create(receipt, 1536)?,
            recovery: ReservedFile::create(recovery, 32)?,
        })
    }
    pub(super) fn publish(
        mut self,
        prepared: &PreparedArchive,
        check: &mut impl FnMut(Boundary) -> Result<()>,
    ) -> Result<()> {
        check(Boundary::Public)?;
        self.archive.write(prepared.encrypted_backup())?;
        let receipt = prepared.public_receipt();
        self.receipt.write(&receipt)?;
        check(Boundary::Private)?;
        self.recovery.write(prepared.recovery_bytes())?;
        let encrypted = self.archive.read_public(prepared.encrypted_backup())?;
        self.receipt.read_public(&receipt)?;
        let recovery = self.recovery.read_recovery()?;
        prepared
            .verify_recovery(&encrypted, recovery)
            .map_err(|_| Error::Storage)?;
        self.archive.check()?;
        self.receipt.check()?;
        self.recovery.check()?;
        check(Boundary::Commit)?;
        self.archive.keep = true;
        self.receipt.keep = true;
        self.recovery.keep = true;
        Ok(())
    }
}

#[cfg(test)]
pub(super) fn assert_protected(path: &Path) {
    let file = File::open(path).unwrap();
    Security::current().unwrap().check(&file).unwrap();
}

#[cfg(test)]
pub(super) fn fixture_directory_permissions(path: &Path, writable: bool) {
    use std::os::windows::fs::OpenOptionsExt;
    let file = std::fs::OpenOptions::new()
        .access_mode(0x00060000)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS)
        .open(path)
        .unwrap();
    let security = Security::current().unwrap();
    // SAFETY: the caller supplies only its validated synthetic fixture directory;
    // descriptor and its one owner ACE remain alive during handle-based application.
    unsafe {
        let mut present = 0;
        let mut defaulted = 0;
        let mut acl = null_mut();
        assert_ne!(
            GetSecurityDescriptorDacl(security.0.0, &mut present, &mut acl, &mut defaulted),
            0
        );
        assert_eq!(present, 1);
        if !writable {
            let mut ace = null_mut();
            assert_ne!(GetAce(acl, 0, &mut ace), 0);
            let mut owner = null_mut();
            assert_ne!(
                GetSecurityDescriptorOwner(security.0.0, &mut owner, &mut defaulted),
                0
            );
            fixture_readonly_owner_ace(ace, owner).unwrap();
        }
        assert_eq!(
            SetSecurityInfo(
                file.as_raw_handle(),
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                null_mut(),
                null_mut(),
                acl,
                null_mut()
            ),
            0
        );
    }
}

/// Fixture-only mutation of the exact generated current-owner ACE. Reject the
/// pointer/header/type/size/SID before touching its bounded permission mask.
#[cfg(test)]
unsafe fn fixture_readonly_owner_ace(ace: *mut c_void, owner: PSID) -> Result<()> {
    let ace = std::ptr::NonNull::new(ace.cast::<u8>()).ok_or(Error::UnsafeStore)?;
    if owner.is_null() {
        return Err(Error::UnsafeStore);
    }
    const MASK: usize = std::mem::offset_of!(ACCESS_ALLOWED_ACE, Mask);
    // SAFETY: GetAce supplies a readable header; malformed regression inputs
    // also own at least that header. No mask write occurs until its size and
    // the complete generated current-owner allowed ACE have been verified.
    unsafe {
        let header = ace
            .cast::<windows_sys::Win32::Security::ACE_HEADER>()
            .as_ptr()
            .read_unaligned();
        if usize::from(header.AceSize) < MASK + size_of::<u32>() || !allowed_owner_ace(ace, owner) {
            return Err(Error::UnsafeStore);
        }
        ace.add(MASK)
            .cast::<u32>()
            .as_ptr()
            .write_unaligned(DIRECTORY_READ);
    }
    Ok(())
}

#[cfg(test)]
pub(super) fn fixture_readonly_ace_rejected(bytes: Option<&mut [u8]>) -> bool {
    let security = Security::current().unwrap();
    let mut owner = null_mut();
    let mut defaulted = 0;
    // SAFETY: descriptor owns the valid expected SID until the checked mutation
    // returns. Test input owns a full readable header and its advertised bytes.
    unsafe {
        assert_ne!(
            GetSecurityDescriptorOwner(security.0.0, &mut owner, &mut defaulted),
            0
        );
        let pointer = bytes.map_or(null_mut(), |bytes| {
            assert!(bytes.len() >= size_of::<windows_sys::Win32::Security::ACE_HEADER>());
            bytes.as_mut_ptr().cast()
        });
        fixture_readonly_owner_ace(pointer, owner).is_err()
    }
}

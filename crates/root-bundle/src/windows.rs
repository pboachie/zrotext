// SPDX-License-Identifier: AGPL-3.0-only
//! Narrow handle-relative native boundary. All pointers refer to live owned
//! allocations; names are single validated components, except the volume anchor.

use super::{EncryptedBundle, Error};
use std::{
    ffi::c_void,
    fs::File,
    io::{Read, Write},
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
            if GetSecurityDescriptorControl(descriptor, &mut control, &mut revision) == 0
                || control & SE_DACL_PROTECTED == 0
                || control & SE_DACL_PRESENT == 0
                || GetSecurityDescriptorOwner(self.0.0, &mut expected_owner, &mut defaulted) == 0
                || owner.is_null()
                || EqualSid(owner, expected_owner) == 0
                || acl.is_null()
                || (*acl).AceCount != 1
            {
                return Err(Error::UnsafeStore);
            }
            let mut ace = null_mut();
            if GetAce(acl, 0, &mut ace) == 0 || ace.is_null() {
                return Err(Error::UnsafeStore);
            }
            let allowed = &*ace.cast::<ACCESS_ALLOWED_ACE>();
            if allowed.Header.AceType != 0
                || allowed.Header.AceFlags != 0
                || allowed.Mask != FILE_ALL_ACCESS
                || EqualSid(
                    std::ptr::addr_of!(allowed.SidStart).cast_mut().cast(),
                    expected_owner,
                ) == 0
            {
                return Err(Error::UnsafeStore);
            }
            drop(allocation);
            Ok(())
        }
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
    if text.len() > 4096
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

#[derive(Clone, Copy, PartialEq, Eq)]
enum Event {
    Write,
    Flush,
    BeforeRename,
    AfterRename,
    BeforeReopen,
}

/// Retains the validated volume/ancestor/store handles for its whole lifetime.
/// Opens or exclusively creates `zrotext-root-bundles` under an existing parent.
/// Parent must be a bounded ASCII absolute drive path on fixed local NTFS.
pub struct Store {
    ancestors: Vec<(File, Identity)>,
    directory: File,
    identity: Identity,
    security: Security,
}

impl Store {
    pub fn open(parent: &Path) -> Result<Self> {
        Self::open_inner(parent, true)
    }

    /// Open an existing store without creating any directories.
    pub fn open_existing(parent: &Path) -> Result<Self> {
        Self::open_inner(parent, false)
    }

    fn open_inner(parent: &Path, create: bool) -> Result<Self> {
        let (anchor, parts) = path_parts(parent)?;
        let security = Security::current()?;
        let root = relative(None, &anchor, true, false, 3, None, false)?;
        fixed_ntfs(&root)?;
        let root_id = inspect(&root, true, 0)?;
        let mut ancestors = vec![(root, root_id)];
        for part in parts {
            let (parent, previous) = ancestors.last().unwrap();
            let next = relative(Some(parent), part, true, false, 3, None, false)?;
            let identity = inspect(&next, true, 0)?;
            if inspect(parent, true, 0)? != *previous || identity.volume != root_id.volume {
                return Err(Error::UnsafeStore);
            }
            ancestors.push((next, identity));
        }
        let parent = &ancestors.last().unwrap().0;
        let directory = match relative(
            Some(parent),
            "zrotext-root-bundles",
            true,
            create,
            3,
            if create { Some(&security) } else { None },
            false,
        ) {
            Err(Error::Collision) => relative(
                Some(parent),
                "zrotext-root-bundles",
                true,
                false,
                3,
                None,
                false,
            )?,
            result => result?,
        };
        let identity = inspect(&directory, true, 0)?;
        security.check(&directory)?;
        if identity.volume != root_id.volume {
            return Err(Error::UnsafeStore);
        }
        let store = Self {
            ancestors,
            directory,
            identity,
            security,
        };
        store.check()?;
        Ok(store)
    }

    fn check(&self) -> Result<()> {
        for (file, identity) in &self.ancestors {
            if inspect(file, true, 0)? != *identity {
                return Err(Error::UnsafeStore);
            }
        }
        if inspect(&self.directory, true, 0)? != self.identity {
            return Err(Error::UnsafeStore);
        }
        self.security.check(&self.directory)
    }

    fn check_directory(&self, directory: &File, expected: Identity) -> Result<()> {
        self.check()?;
        if inspect(directory, true, 0)? != expected || expected.volume != self.identity.volume {
            return Err(Error::UnsafeStore);
        }
        self.security.check(directory)
    }

    /// Exclusive publication; never replaces a pending or published name.
    /// An error can leave encrypted/public pending files. Do not delete blindly.
    pub fn publish(&self, bundle: &EncryptedBundle) -> Result<()> {
        self.publish_with(bundle, &mut |_| Ok(usize::MAX))
    }

    fn publish_with(
        &self,
        bundle: &EncryptedBundle,
        hook: &mut impl FnMut(Event) -> Result<usize>,
    ) -> Result<()> {
        self.check()?;
        let name = bundle.name();
        let stage = relative(
            Some(&self.directory),
            &format!("pending-{name}"),
            true,
            true,
            1,
            Some(&self.security),
            true,
        )?;
        let stage_id = inspect(&stage, true, 0)?;
        self.check_directory(&stage, stage_id)?;
        let mut child_ids = Vec::new();
        for (leaf, bytes, maximum) in [
            ("backup.ztrb", &bundle.backup, 748),
            ("public.ztrc", &bundle.card, 645),
        ] {
            let mut file = relative(
                Some(&stage),
                leaf,
                false,
                true,
                1,
                Some(&self.security),
                false,
            )?;
            let id = inspect(&file, false, maximum)?;
            self.security.check(&file)?;
            self.check_directory(&stage, stage_id)?;
            if id.volume != stage_id.volume {
                return Err(Error::UnsafeStore);
            }
            let mut remaining = bytes.as_slice();
            while !remaining.is_empty() {
                let limit = hook(Event::Write)?.min(remaining.len());
                if limit == 0 {
                    return Err(Error::Storage);
                }
                let written = file
                    .write(&remaining[..limit])
                    .map_err(|_| Error::Storage)?;
                if written == 0 {
                    return Err(Error::Storage);
                }
                remaining = &remaining[written..];
            }
            hook(Event::Flush)?;
            file.sync_all().map_err(|_| Error::Storage)?;
            self.security.check(&file)?;
            if inspect(&file, false, maximum)? != id {
                return Err(Error::UnsafeStore);
            }
            drop(file);
            self.read_child(&stage, leaf, bytes, maximum, Some(id))?;
            self.check_directory(&stage, stage_id)?;
            child_ids.push(id);
        }
        hook(Event::BeforeRename)?;
        self.check_directory(&stage, stage_id)?;
        rename(&stage, &self.directory, &name)?;
        // Everything after rename is indeterminate on failure: namespace change
        // may have succeeded. Never infer success solely from the retained stage.
        (|| {
            hook(Event::AfterRename)?;
            self.check_directory(&stage, stage_id)?;
            hook(Event::BeforeReopen)?;
            self.verify(bundle, Some((stage_id, &child_ids)))
        })()
        .map_err(|_| Error::Indeterminate)
    }

    /// Independently inspect an existing destination against exact intended bytes.
    /// Success proves a complete matching bundle now, not who created it, a
    /// successful restore, anti-rollback, or durability after power loss.
    pub fn reconcile(&self, bundle: &EncryptedBundle) -> Result<()> {
        self.verify(bundle, None)
    }

    /// Read one immutable bundle using an independently supplied identity.
    /// Framing and digest checks do not authenticate the encrypted root.
    pub fn read_bundle(
        &self,
        backup_id: &[u8; 16],
        expected: &zrotext_root_material::root_backup::ExpectedIdentity,
    ) -> Result<EncryptedBundle> {
        self.check()?;
        if *backup_id == [0; 16] {
            return Err(Error::InvalidInput);
        }
        let name = format!(
            "bundle-{}",
            backup_id
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>()
        );
        let directory = relative(Some(&self.directory), &name, true, false, 3, None, false)?;
        let id = inspect(&directory, true, 0)?;
        self.check_directory(&directory, id)?;
        // Retain both child handles, denying writes and deletion throughout validation.
        let mut backup = relative(
            Some(&directory),
            "backup.ztrb",
            false,
            false,
            1,
            None,
            false,
        )?;
        let mut card = relative(
            Some(&directory),
            "public.ztrc",
            false,
            false,
            1,
            None,
            false,
        )?;
        let backup_identity = inspect(&backup, false, 748)?;
        let card_identity = inspect(&card, false, 645)?;
        for file in [&backup, &card] {
            self.security.check(file)?;
        }
        if backup_identity.volume != self.identity.volume
            || card_identity.volume != self.identity.volume
        {
            return Err(Error::UnsafeStore);
        }
        let mut backup_bytes = Vec::new();
        let mut card_bytes = Vec::new();
        (&mut backup)
            .take(749)
            .read_to_end(&mut backup_bytes)
            .map_err(|_| Error::Storage)?;
        (&mut card)
            .take(646)
            .read_to_end(&mut card_bytes)
            .map_err(|_| Error::Storage)?;
        let bundle = EncryptedBundle::new(&backup_bytes, &card_bytes, expected)?;
        if bundle.id != *backup_id
            || inspect(&backup, false, 748)? != backup_identity
            || inspect(&card, false, 645)? != card_identity
        {
            return Err(Error::UnsafeStore);
        }
        self.security.check(&backup)?;
        self.security.check(&card)?;
        self.check_directory(&directory, id)?;
        self.check()?;
        Ok(bundle)
    }

    fn verify(
        &self,
        bundle: &EncryptedBundle,
        expected: Option<(Identity, &[Identity])>,
    ) -> Result<()> {
        self.check()?;
        // Share DELETE only on this second inspection handle to coexist with
        // our stage handle's DELETE access. The retained stage still denies it.
        let directory = relative(
            Some(&self.directory),
            &bundle.name(),
            true,
            false,
            if expected.is_some() { 7 } else { 3 },
            None,
            false,
        )?;
        let id = inspect(&directory, true, 0)?;
        if expected.is_some_and(|(identity, _)| identity != id) {
            return Err(Error::UnsafeStore);
        }
        self.check_directory(&directory, id)?;
        self.read_child(
            &directory,
            "backup.ztrb",
            &bundle.backup,
            748,
            expected.map(|(_, ids)| ids[0]),
        )?;
        self.read_child(
            &directory,
            "public.ztrc",
            &bundle.card,
            645,
            expected.map(|(_, ids)| ids[1]),
        )?;
        self.check_directory(&directory, id)
    }

    fn read_child(
        &self,
        directory: &File,
        name: &str,
        bytes: &[u8],
        maximum: u64,
        expected: Option<Identity>,
    ) -> Result<()> {
        let directory_id = inspect(directory, true, 0)?;
        self.check_directory(directory, directory_id)?;
        let mut file = relative(Some(directory), name, false, false, 1, None, false)?;
        let id = inspect(&file, false, maximum)?;
        self.security.check(&file)?;
        if id.volume != self.identity.volume || expected.is_some_and(|expected| id != expected) {
            return Err(Error::UnsafeStore);
        }
        let mut actual = Vec::new();
        (&mut file)
            .take(maximum + 1)
            .read_to_end(&mut actual)
            .map_err(|_| Error::Storage)?;
        if actual != bytes || inspect(&file, false, maximum)? != id {
            return Err(Error::UnsafeStore);
        }
        self.security.check(&file)?;
        self.check_directory(directory, directory_id)
    }
}

fn rename(stage: &File, parent: &File, name: &str) -> Result<()> {
    if !component(name) {
        return Err(Error::InvalidInput);
    }
    let name: Vec<u16> = name.encode_utf16().collect();
    let bytes = size_of::<FILE_RENAME_INFORMATION>() + name.len() * 2;
    let mut buffer = vec![0_usize; bytes.div_ceil(size_of::<usize>())];
    // SAFETY: allocation is aligned for the native struct and includes sufficient
    // trailing storage for the complete UTF-16 filename. No replacement flags.
    unsafe {
        let info = buffer.as_mut_ptr().cast::<FILE_RENAME_INFORMATION>();
        (*info).RootDirectory = parent.as_raw_handle();
        (*info).FileNameLength = (name.len() * 2) as u32;
        std::ptr::copy_nonoverlapping(
            name.as_ptr(),
            std::ptr::addr_of_mut!((*info).FileName).cast(),
            name.len(),
        );
        let mut status: IO_STATUS_BLOCK = zeroed();
        let code = NtSetInformationFile(
            stage.as_raw_handle(),
            &mut status,
            info.cast(),
            bytes as u32,
            FileRenameInformation,
        );
        if code < 0 {
            return Err(if code as u32 == 0xc000_0035 {
                Error::Collision
            } else {
                Error::Indeterminate
            });
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests;

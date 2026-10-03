// SPDX-License-Identifier: AGPL-3.0-only
use std::{
    fs, io,
    io::Write,
    path::{Path, PathBuf},
};
use uuid::Uuid;

#[derive(PartialEq)]
struct Identity {
    #[cfg(unix)]
    dev: u64,
    #[cfg(unix)]
    ino: u64,
    #[cfg(windows)]
    volume: u64,
    #[cfg(windows)]
    file_id: [u8; 16],
    #[cfg(not(any(unix, windows)))]
    created: std::time::SystemTime,
}
fn identity(path: &Path) -> io::Result<Identity> {
    #[cfg(not(windows))]
    let metadata = fs::symlink_metadata(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        Ok(Identity {
            dev: metadata.dev(),
            ino: metadata.ino(),
        })
    }
    #[cfg(windows)]
    {
        use std::os::windows::{fs::OpenOptionsExt, io::AsRawHandle};
        #[repr(C)]
        struct FileIdInfo {
            volume: u64,
            file_id: [u8; 16],
        }
        #[link(name = "kernel32")]
        unsafe extern "system" {
            fn GetFileInformationByHandleEx(
                handle: *mut std::ffi::c_void,
                class: i32,
                information: *mut std::ffi::c_void,
                size: u32,
            ) -> i32;
        }
        // BACKUP_SEMANTICS permits directories; OPEN_REPARSE_POINT avoids
        // following a replacement link. FileIdInfo=18 includes a 128-bit ID
        // plus volume identity, unlike creation timestamps which can collide.
        let file = fs::OpenOptions::new()
            .read(true)
            .custom_flags(0x02000000 | 0x00200000)
            .open(path)?;
        let mut information = FileIdInfo {
            volume: 0,
            file_id: [0; 16],
        };
        // SAFETY: the borrowed handle remains open during the synchronous call;
        // the correctly sized repr(C) output buffer is exclusively borrowed.
        let result = unsafe {
            GetFileInformationByHandleEx(
                file.as_raw_handle(),
                18,
                (&mut information as *mut FileIdInfo).cast(),
                std::mem::size_of::<FileIdInfo>() as u32,
            )
        };
        if result == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(Identity {
            volume: information.volume,
            file_id: information.file_id,
        })
    }
    #[cfg(not(any(unix, windows)))]
    {
        Ok(Identity {
            created: metadata.created()?,
        })
    }
}
fn checked(path: &Path) -> io::Result<()> {
    let metadata = fs::symlink_metadata(path)?;
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        if metadata.file_attributes() & 0x400 != 0 {
            return Err(io::Error::other("reparse fixture directory"));
        }
    }
    if !metadata.is_dir() || metadata.file_type().is_symlink() || fs::canonicalize(path)? != path {
        return Err(io::Error::other("unsafe fixture directory"));
    }
    Ok(())
}
pub(super) struct Scratch {
    anchor: PathBuf,
    pub(super) path: PathBuf,
    marker: Uuid,
    anchor_identity: Identity,
    child_identity: Identity,
    marker_identity: Identity,
}
impl Scratch {
    pub(super) fn create() -> io::Result<Self> {
        Self::configured(&std::env::temp_dir())
    }
    fn configured(raw: &Path) -> io::Result<Self> {
        // Reject raw traversal before even inspecting the configured anchor.
        // This intentionally also refuses legitimate names containing two dots.
        let raw = raw
            .to_str()
            .ok_or_else(|| io::Error::other("non-Unicode fixture anchor"))?;
        if raw.contains("..") {
            return Err(io::Error::other("traversing fixture anchor"));
        }
        let raw = PathBuf::from(raw);
        if !raw.is_absolute() {
            return Err(io::Error::other("relative fixture anchor"));
        }
        let metadata = fs::symlink_metadata(&raw)?;
        if metadata.file_type().is_symlink() {
            return Err(io::Error::other("linked fixture anchor"));
        }
        #[cfg(windows)]
        {
            use std::os::windows::fs::MetadataExt;
            if metadata.file_attributes() & 0x400 != 0 {
                return Err(io::Error::other("reparse fixture anchor"));
            }
        }
        Self::at(&fs::canonicalize(&raw)?)
    }

    fn at(anchor: &Path) -> io::Result<Self> {
        checked(anchor)?;
        let repository = fs::canonicalize(Path::new(env!("CARGO_MANIFEST_DIR")).join("../.."))?;
        if anchor.parent().is_none() || anchor.starts_with(repository) {
            return Err(io::Error::other("unsafe fixture anchor"));
        }
        let marker = Uuid::new_v4();
        let path = anchor.join(format!("zrotext-routine-{marker}"));
        #[cfg(unix)]
        let mut builder = fs::DirBuilder::new();
        #[cfg(not(unix))]
        let builder = fs::DirBuilder::new();
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            builder.mode(0o700);
        }
        builder.create(&path)?;
        let marker_path = path.join(".fixture-owner");
        let mut options = fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        options
            .open(&marker_path)?
            .write_all(marker.to_string().as_bytes())?;
        let marker_identity = identity(&marker_path)?;
        let anchor_identity = identity(anchor)?;
        let child_identity = identity(&path)?;
        Ok(Self {
            anchor: anchor.to_owned(),
            path,
            marker,
            anchor_identity,
            child_identity,
            marker_identity,
        })
    }
    pub(super) fn remove(self) -> io::Result<()> {
        checked(&self.anchor)?;
        checked(&self.path)?;
        if identity(&self.anchor)? != self.anchor_identity
            || identity(&self.path)? != self.child_identity
            || self.path.parent() != Some(self.anchor.as_path())
            || !fs::symlink_metadata(self.path.join(".fixture-owner"))?.is_file()
            || fs::symlink_metadata(self.path.join(".fixture-owner"))?
                .file_type()
                .is_symlink()
            || identity(&self.path.join(".fixture-owner"))? != self.marker_identity
            || fs::read_to_string(self.path.join(".fixture-owner"))? != self.marker.to_string()
        {
            return Err(io::Error::other("fixture ownership changed"));
        }
        fs::remove_dir_all(self.path)
    }
}
#[test]
fn repository_anchor_is_refused_without_creating_scratch() {
    let root = fs::canonicalize(Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")).unwrap();
    assert!(Scratch::at(&root).is_err());
}
#[test]
fn substituted_child_is_preserved_and_refused() {
    let scratch = Scratch::create().unwrap();
    let path = scratch.path.clone();
    fs::remove_dir_all(&path).unwrap();
    fs::create_dir(&path).unwrap();
    fs::write(path.join("sentinel"), b"synthetic").unwrap();
    assert!(scratch.remove().is_err());
    assert!(path.join("sentinel").exists());
    fs::remove_dir_all(path).unwrap();
}

#[test]
fn owned_scratch_removes_only_its_child() {
    let scratch = Scratch::create().unwrap();
    let child = scratch.path.clone();
    let parent = scratch.anchor.clone();
    scratch.remove().unwrap();
    assert!(!child.exists());
    assert!(parent.is_dir());
}
#[test]
fn changed_marker_preserves_child() {
    let scratch = Scratch::create().unwrap();
    let path = scratch.path.clone();
    fs::write(path.join(".fixture-owner"), b"synthetic replacement").unwrap();
    assert!(scratch.remove().is_err());
    assert!(path.exists());
    fs::remove_dir_all(path).unwrap();
}

#[test]
fn raw_traversal_and_relative_anchors_are_refused() {
    assert!(Scratch::configured(Path::new("synthetic/../other")).is_err());
    assert!(Scratch::configured(Path::new("synthetic-relative")).is_err());
    let anchor = std::env::temp_dir();
    assert!(Scratch::configured(&anchor.join("..")).is_err());
}
#[test]
fn filesystem_root_is_refused() {
    let scratch = Scratch::create().unwrap();
    let root = scratch.anchor.ancestors().last().unwrap();
    assert!(Scratch::at(root).is_err());
    scratch.remove().unwrap();
}

#[test]
fn recreated_marker_with_identical_bytes_is_preserved_and_refused() {
    let scratch = Scratch::create().unwrap();
    let path = scratch.path.clone();
    let marker = path.join(".fixture-owner");
    fs::rename(&marker, path.join("retained-original-marker")).unwrap();
    fs::write(&marker, scratch.marker.to_string()).unwrap();
    assert!(scratch.remove().is_err());
    assert!(marker.exists());
    fs::remove_dir_all(path).unwrap();
}
#[cfg(unix)]
#[test]
fn linked_marker_is_preserved_and_refused() {
    let scratch = Scratch::create().unwrap();
    let path = scratch.path.clone();
    let marker = path.join(".fixture-owner");
    let original = path.join("retained-original-marker");
    fs::rename(&marker, &original).unwrap();
    std::os::unix::fs::symlink(&original, &marker).unwrap();
    assert!(scratch.remove().is_err());
    assert!(
        fs::symlink_metadata(&marker)
            .unwrap()
            .file_type()
            .is_symlink()
    );
    fs::remove_dir_all(path).unwrap();
}

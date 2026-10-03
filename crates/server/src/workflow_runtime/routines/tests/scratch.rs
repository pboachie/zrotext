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
    let text = path
        .to_str()
        .ok_or_else(|| io::Error::other("non-Unicode fixture path"))?
        .to_owned();
    if text.contains("..") {
        return Err(io::Error::other("traversing fixture path"));
    }
    if !Path::new(&text).is_absolute() {
        return Err(io::Error::other("relative fixture path"));
    }

    #[cfg(not(windows))]
    let metadata = fs::symlink_metadata(&text)?;
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
            .open(&text)?;
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
    let text = path
        .to_str()
        .ok_or_else(|| io::Error::other("non-Unicode fixture path"))?
        .to_owned();
    if text.contains("..") {
        return Err(io::Error::other("traversing fixture path"));
    }
    if !Path::new(&text).is_absolute() {
        return Err(io::Error::other("relative fixture path"));
    }

    let metadata = fs::symlink_metadata(&text)?;
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        if metadata.file_attributes() & 0x400 != 0 {
            return Err(io::Error::other("reparse fixture directory"));
        }
    }
    if !metadata.is_dir() || metadata.file_type().is_symlink() || fs::canonicalize(&text)? != path {
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
        let raw = raw.to_owned();
        if !Path::new(&raw).is_absolute() {
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
        let normalized = fs::canonicalize(&raw)?;
        let text = normalized
            .to_str()
            .ok_or_else(|| io::Error::other("non-Unicode normalized fixture anchor"))?
            .to_owned();
        if text.contains("..") {
            return Err(io::Error::other("traversing normalized fixture anchor"));
        }
        Self::at(Path::new(&text))
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
        if path.parent() != Some(anchor) {
            return Err(io::Error::other("escaped fixture child"));
        }
        let child_text = path
            .to_str()
            .ok_or_else(|| io::Error::other("non-Unicode fixture child"))?
            .to_owned();
        if child_text.contains("..") {
            return Err(io::Error::other("traversing fixture child"));
        }
        builder.create(&child_text)?;
        checked(&path)?;
        let marker_path = path.join(".fixture-owner");
        let mut options = fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        if marker_path.parent() != Some(path.as_path()) {
            return Err(io::Error::other("escaped fixture marker"));
        }
        let marker_text = marker_path
            .to_str()
            .ok_or_else(|| io::Error::other("non-Unicode fixture marker"))?
            .to_owned();
        if marker_text.contains("..") {
            return Err(io::Error::other("traversing fixture marker"));
        }
        options
            .open(&marker_text)?
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
        let child_text = self
            .path
            .to_str()
            .ok_or_else(|| io::Error::other("non-Unicode fixture child"))?
            .to_owned();
        if child_text.contains("..") {
            return Err(io::Error::other("traversing fixture child"));
        }
        let marker_path = self.path.join(".fixture-owner");
        if marker_path.parent() != Some(self.path.as_path()) || !marker_path.starts_with(&self.path)
        {
            return Err(io::Error::other("escaped fixture marker"));
        }
        let marker_text = marker_path
            .to_str()
            .ok_or_else(|| io::Error::other("non-Unicode fixture marker"))?
            .to_owned();
        if marker_text.contains("..") {
            return Err(io::Error::other("traversing fixture marker"));
        }
        if identity(&self.anchor)? != self.anchor_identity
            || identity(&self.path)? != self.child_identity
            || self.path.parent() != Some(self.anchor.as_path())
            || !fs::symlink_metadata(&marker_text)?.is_file()
            || fs::symlink_metadata(&marker_text)?.file_type().is_symlink()
            || identity(&self.path.join(".fixture-owner"))? != self.marker_identity
            || fs::read_to_string(&marker_text)? != self.marker.to_string()
        {
            return Err(io::Error::other("fixture ownership changed"));
        }
        fs::remove_dir_all(&child_text)
    }
}
#[test]
fn repository_anchor_is_refused_without_creating_scratch() -> io::Result<()> {
    let root = fs::canonicalize(Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")).unwrap();
    assert!(Scratch::at(&root).is_err());
    Ok(())
}
#[test]
fn substituted_child_is_preserved_and_refused() -> io::Result<()> {
    let scratch = Scratch::create().unwrap();
    let path = scratch.path.to_str().unwrap().to_owned();
    if path.contains("..") {
        return Err(io::Error::other("traversing fixture test path"));
    }
    fs::remove_dir_all(&path).unwrap();
    fs::create_dir(&path).unwrap();
    fs::write(Path::new(&path).join("sentinel"), b"synthetic").unwrap();
    assert!(scratch.remove().is_err());
    assert!(Path::new(&path).join("sentinel").exists());
    fs::remove_dir_all(path).unwrap();
    Ok(())
}

#[test]
fn owned_scratch_removes_only_its_child() -> io::Result<()> {
    let scratch = Scratch::create().unwrap();
    let child = scratch.path.to_str().unwrap().to_owned();
    if child.contains("..") {
        return Err(io::Error::other("traversing fixture child"));
    }
    let parent = scratch.anchor.to_str().unwrap().to_owned();
    if parent.contains("..") {
        return Err(io::Error::other("traversing fixture parent"));
    }
    scratch.remove().unwrap();
    assert!(!Path::new(&child).exists());
    assert!(Path::new(&parent).is_dir());
    Ok(())
}
#[test]
fn changed_marker_preserves_child() -> io::Result<()> {
    let scratch = Scratch::create().unwrap();
    let path = scratch.path.to_str().unwrap().to_owned();
    if path.contains("..") {
        return Err(io::Error::other("traversing fixture test path"));
    }
    fs::write(
        Path::new(&path).join(".fixture-owner"),
        b"synthetic replacement",
    )
    .unwrap();
    assert!(scratch.remove().is_err());
    assert!(Path::new(&path).exists());
    fs::remove_dir_all(path).unwrap();
    Ok(())
}

#[test]
fn raw_traversal_and_relative_anchors_are_refused() -> io::Result<()> {
    assert!(Scratch::configured(Path::new("synthetic/../other")).is_err());
    assert!(Scratch::configured(Path::new("synthetic-relative")).is_err());
    let anchor = std::env::temp_dir();
    assert!(Scratch::configured(&anchor.join("..")).is_err());
    Ok(())
}
#[test]
fn filesystem_root_is_refused() -> io::Result<()> {
    let scratch = Scratch::create().unwrap();
    let root = scratch.anchor.ancestors().last().unwrap();
    assert!(Scratch::at(root).is_err());
    scratch.remove().unwrap();
    Ok(())
}

#[test]
fn recreated_marker_with_identical_bytes_is_preserved_and_refused() -> io::Result<()> {
    let scratch = Scratch::create().unwrap();
    let path = scratch.path.to_str().unwrap().to_owned();
    if path.contains("..") {
        return Err(io::Error::other("traversing fixture test path"));
    }
    let marker = Path::new(&path).join(".fixture-owner");
    fs::rename(&marker, Path::new(&path).join("retained-original-marker")).unwrap();
    fs::write(&marker, scratch.marker.to_string()).unwrap();
    assert!(scratch.remove().is_err());
    assert!(marker.exists());
    fs::remove_dir_all(path).unwrap();
    Ok(())
}
#[cfg(unix)]
#[test]
fn linked_marker_is_preserved_and_refused() -> io::Result<()> {
    let scratch = Scratch::create().unwrap();
    let path = scratch.path.to_str().unwrap().to_owned();
    if path.contains("..") {
        return Err(io::Error::other("traversing fixture test path"));
    }
    let marker = Path::new(&path).join(".fixture-owner");
    let original = Path::new(&path).join("retained-original-marker");
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
    Ok(())
}

#[test]
fn direct_filesystem_helpers_refuse_traversal_before_inspection() -> io::Result<()> {
    let scratch = Scratch::create().unwrap();
    // The target exists: identity() would succeed without its lexical guard.
    // Path::join can normalize parent components for Windows verbatim paths.
    let traversing = PathBuf::from(format!(
        "{}{}..{}{}",
        scratch.path.display(),
        std::path::MAIN_SEPARATOR,
        std::path::MAIN_SEPARATOR,
        scratch.path.file_name().unwrap().to_str().unwrap()
    ));
    assert!(checked(&traversing).is_err());
    assert!(identity(&traversing).is_err());
    assert!(checked(Path::new("relative")).is_err());
    assert!(identity(Path::new(".")).is_err());
    scratch.remove().unwrap();
    Ok(())
}
#[test]
fn changed_child_path_cannot_remove_another_owned_scratch() -> io::Result<()> {
    let mut first = Scratch::create().unwrap();
    let second = Scratch::create().unwrap();
    let original = first.path.clone();
    first.path = second.path.clone();
    assert!(first.remove().is_err());
    let second_path = second.path.to_str().unwrap().to_owned();
    if second_path.contains("..") {
        return Err(io::Error::other("traversing second fixture path"));
    }
    assert!(Path::new(&second_path).exists());
    second.remove().unwrap();
    let text = original.to_str().unwrap().to_owned();
    if text.contains("..") {
        return Err(io::Error::other("traversing fixture cleanup path"));
    }
    fs::remove_dir_all(text).unwrap();
    Ok(())
}

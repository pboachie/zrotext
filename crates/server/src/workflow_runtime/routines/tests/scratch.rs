// SPDX-License-Identifier: AGPL-3.0-only
use std::{
    fs, io,
    path::{Path, PathBuf},
};
use uuid::Uuid;

#[derive(PartialEq)]
struct Identity {
    #[cfg(unix)]
    dev: u64,
    #[cfg(unix)]
    ino: u64,
    #[cfg(not(unix))]
    created: std::time::SystemTime,
}
fn identity(path: &Path) -> io::Result<Identity> {
    let metadata = fs::symlink_metadata(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        Ok(Identity {
            dev: metadata.dev(),
            ino: metadata.ino(),
        })
    }
    #[cfg(not(unix))]
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
}
impl Scratch {
    pub(super) fn create() -> io::Result<Self> {
        let raw = std::env::temp_dir();
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
        Self::at(&fs::canonicalize(std::env::temp_dir())?)
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
        fs::write(path.join(".fixture-owner"), marker.to_string())?;
        let anchor_identity = identity(anchor)?;
        let child_identity = identity(&path)?;
        Ok(Self {
            anchor: anchor.to_owned(),
            path,
            marker,
            anchor_identity,
            child_identity,
        })
    }
    pub(super) fn remove(self) -> io::Result<()> {
        checked(&self.anchor)?;
        checked(&self.path)?;
        if identity(&self.anchor)? != self.anchor_identity
            || identity(&self.path)? != self.child_identity
            || self.path.parent() != Some(self.anchor.as_path())
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

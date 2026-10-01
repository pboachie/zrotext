// SPDX-License-Identifier: AGPL-3.0-only
// Included only by native test modules. Never a production key-store locator.
use std::path::{Component, Path, PathBuf};

#[derive(Clone, Copy)]
pub(super) enum Purpose {
    Activation,
    Refresh,
}

fn fixed_root(purpose: Purpose) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("target")
        .join(match purpose {
            Purpose::Activation => "tmp-native-activation",
            Purpose::Refresh => "tmp-native-refresh",
        })
}

fn shape(root: &Path, supplied: &Path, expected: &str) -> Result<(u32, u128, &'static str), ()> {
    let stage = match expected {
        "success" => "success",
        "scope" => "scope",
        "decline" => "decline",
        "token" => "token",
        "interop" => "interop",
        _ => return Err(()),
    };
    let mut components = supplied.strip_prefix(root).map_err(|_| ())?.components();
    let Some(Component::Normal(run)) = components.next() else {
        return Err(());
    };
    let Some(Component::Normal(actual_stage)) = components.next() else {
        return Err(());
    };
    if components.next().is_some() || actual_stage != std::ffi::OsStr::new(stage) {
        return Err(());
    }
    let run = run.to_str().ok_or(())?;
    if run.len() > 50 {
        return Err(());
    }
    let (pid, nanos) = run.split_once('-').ok_or(())?;
    if pid.is_empty()
        || nanos.is_empty()
        || !pid.bytes().all(|b| b.is_ascii_digit())
        || !nanos.bytes().all(|b| b.is_ascii_digit())
    {
        return Err(());
    }
    let pid = pid.parse::<u32>().map_err(|_| ())?;
    let nanos = nanos.parse::<u128>().map_err(|_| ())?;
    if pid == 0 || nanos == 0 || format!("{pid}-{nanos}") != run {
        return Err(());
    }
    Ok((pid, nanos, stage))
}

fn plain_directory(path: &Path) -> Result<(), ()> {
    use std::os::windows::fs::MetadataExt;
    let metadata = std::fs::symlink_metadata(path).map_err(|_| ())?;
    if !metadata.is_dir() || metadata.file_attributes() & 0x0400 != 0 {
        return Err(());
    }
    Ok(())
}

pub(super) fn validated_parent(
    purpose: Purpose,
    supplied: &Path,
    stage: &str,
) -> Result<PathBuf, ()> {
    let root = fixed_root(purpose);
    let (pid, nanos, stage) = shape(&root, supplied, stage)?;
    // Only independently fixed roots, parsed integers and static stage literals
    // reach fixture IO. TEMP supplies no directory or filename string here.
    let run = root.join(format!("{pid}-{nanos}"));
    let parent = run.join(stage);
    for path in [&root, &run, &parent] {
        plain_directory(path)?;
    }
    if supplied.canonicalize().map_err(|_| ())? != parent.canonicalize().map_err(|_| ())?
        || !parent
            .canonicalize()
            .map_err(|_| ())?
            .starts_with(root.canonicalize().map_err(|_| ())?)
    {
        return Err(());
    }
    // Keep ordinary drive spelling: the CLI correctly refuses verbatim/device
    // public paths. GetTempPath2 can disagree with child TEMP under limited tokens.
    Ok(parent)
}

pub(super) fn assert_shape_rejections(purpose: Purpose) {
    let root = fixed_root(purpose);
    let other = match purpose {
        Purpose::Activation => Purpose::Refresh,
        Purpose::Refresh => Purpose::Activation,
    };
    assert!(shape(&root, &fixed_root(other).join("123-456/success"), "success").is_err());
    for stage in ["success", "scope", "decline", "token", "interop"] {
        assert!(shape(&root, &root.join("123-456").join(stage), stage).is_ok());
    }
    for run in [
        "",
        "123",
        "-456",
        "123-",
        "123-456-7",
        "a-456",
        "123-a",
        "0-456",
        "123-0",
        "0123-456",
        "123-0456",
    ] {
        assert!(shape(&root, &root.join(run).join("success"), "success").is_err());
    }
    for run in [
        format!("{}-456", u64::from(u32::MAX) + 1),
        format!("123-{}0", u128::MAX),
    ] {
        assert!(shape(&root, &root.join(run).join("success"), "success").is_err());
    }
    for candidate in [
        root.join("123-456"),
        root.join("123-456/success/extra"),
        root.join("../123-456/success"),
        root.join("123-456/../success"),
        root.join("123-456/unknown"),
        root.with_file_name("other").join("123-456/success"),
    ] {
        assert!(shape(&root, &candidate, "success").is_err());
    }
    assert!(shape(&root, &root.join("123-456/scope"), "success").is_err());
    assert!(shape(&root, &root.join("123-456/unknown"), "unknown").is_err());
}

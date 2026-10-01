// SPDX-License-Identifier: AGPL-3.0-only
//! Explicit packaged public SDK assets. No credentials or arbitrary request-path filesystem reads.
use axum::{
    Router,
    extract::{Path, State},
    http::{StatusCode, header},
    response::{IntoResponse, Response},
    routing::get,
};
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
};
#[derive(Clone)]
pub struct BrowserAssets {
    files: Arc<BTreeMap<String, Vec<u8>>>,
}
impl BrowserAssets {
    /// Verify the literal relative-module graph emitted by the existing browser packager.
    /// An entry stub is insufficient for ordinary setup. Requests never read the filesystem.
    pub fn require_owner_setup(&self) -> Result<(), &'static str> {
        let mut pending = vec![
            "sdk/conversation-custody.js".to_owned(),
            "sdk/conversation-archive-custody.js".to_owned(),
            "sdk/draft02-manifest.js".to_owned(),
            "sdk/conversation-refresh-proposal.js".to_owned(),
            "sdk/conversation-activation-proposal.js".to_owned(),
        ];
        let mut visited = BTreeSet::new();
        while let Some(name) = pending.pop() {
            if !visited.insert(name.clone()) {
                continue;
            }
            let bytes = self
                .files
                .get(&name)
                .ok_or("Conversation SDK module missing")?;
            let source =
                std::str::from_utf8(bytes).map_err(|_| "Conversation SDK module invalid")?;
            let source = without_comments(source);
            for marker in [
                "from \"",
                "from '",
                "import(\"",
                "import('",
                "import \"",
                "import '",
            ] {
                let quote = marker.chars().last().unwrap();
                for rest in source.split(marker).skip(1) {
                    let specifier = rest
                        .split(quote)
                        .next()
                        .ok_or("Conversation SDK import invalid")?;
                    if !specifier.starts_with("./") && !specifier.starts_with("../") {
                        return Err("Conversation SDK import must be packaged");
                    }
                    let mut parts: Vec<&str> = name.split('/').collect();
                    parts.pop();
                    for part in specifier.split('/') {
                        match part {
                            "." => {}
                            ".." => {
                                parts
                                    .pop()
                                    .ok_or("Conversation SDK import escapes package")?;
                            }
                            "" => return Err("Conversation SDK import invalid"),
                            value => parts.push(value),
                        }
                    }
                    let dependency = parts.join("/");
                    if !valid(&dependency) {
                        return Err("Conversation SDK import invalid");
                    }
                    pending.push(dependency);
                }
            }
        }
        Ok(())
    }

    pub fn load(directory: &std::path::Path) -> Result<Self, std::io::Error> {
        let root = directory.canonicalize()?;
        checked_directory(directory, &root)?;
        let mut files = BTreeMap::new();
        let mut total = 0;
        let mut pending = vec![root.clone()];
        let mut visited = BTreeSet::new();
        while let Some(dir) = pending.pop() {
            checked_directory(&dir, &root)?;
            let dir = dir.canonicalize()?;
            // Recheck each popped directory at the read_dir sink, including entries
            // queued during an earlier traversal step. No request chooses this path.
            if !dir.starts_with(&root) {
                return Err(std::io::Error::other("SDK directory escapes package"));
            }
            if !visited.insert(dir.clone()) || visited.len() > 64 {
                return Err(std::io::Error::other("SDK directory cycle or bound"));
            }
            for entry in std::fs::read_dir(&dir)? {
                let entry = entry?;
                let path = entry.path();
                // Validate the exact directory-entry path before inspecting that
                // named object; checking a different canonical value is insufficient.
                if !path.starts_with(&root) {
                    return Err(std::io::Error::other("SDK entry escapes package"));
                }
                // Inspect the entry returned by this checked directory, without
                // following its target or masking filesystem inspection errors.
                if entry.file_type()?.is_symlink() {
                    return Err(std::io::Error::other("SDK symlink refused"));
                }
                let actual = path.canonicalize()?;
                if !actual.starts_with(&root) {
                    return Err(std::io::Error::other("SDK asset escapes package"));
                }
                if actual.is_dir() {
                    pending.push(actual);
                    if pending.len() > 64 {
                        return Err(std::io::Error::other("SDK directory bound"));
                    }
                    continue;
                }
                if path.extension().and_then(|s| s.to_str()) != Some("js") {
                    continue;
                }
                let name = actual
                    .strip_prefix(&root)
                    .map_err(std::io::Error::other)?
                    .to_string_lossy()
                    .replace('\\', "/");
                if !valid(&name) {
                    return Err(std::io::Error::other("SDK asset name refused"));
                }
                if actual.metadata()?.len() > 262144 {
                    return Err(std::io::Error::other("SDK file bound"));
                }
                let bytes = std::fs::read(actual)?;
                total += bytes.len();
                if total > 8388608 || files.len() >= 128 {
                    return Err(std::io::Error::other("SDK package bound"));
                }
                files.insert(name, bytes);
            }
        }
        if !files.contains_key("sdk/conversation-custody.js") {
            return Err(std::io::Error::other("SDK entry point unavailable"));
        }
        Ok(Self {
            files: Arc::new(files),
        })
    }
    pub fn router(self) -> Router {
        Router::new()
            .route("/v1/owner/conversation-sdk/{*asset}", get(asset))
            .with_state(self)
    }
}
fn checked_directory(
    directory: &std::path::Path,
    root: &std::path::Path,
) -> Result<(), std::io::Error> {
    if directory.symlink_metadata()?.file_type().is_symlink() {
        return Err(std::io::Error::other("SDK directory symlink refused"));
    }
    let actual = directory.canonicalize()?;
    if !actual.starts_with(root) || !actual.is_dir() {
        return Err(std::io::Error::other("SDK directory escapes package"));
    }
    Ok(())
}

#[cfg(test)]
pub(super) mod test_files {
    use std::{
        io::Write,
        path::{Path, PathBuf},
    };

    pub(crate) struct Package {
        root: PathBuf,
        namespace: PathBuf,
    }
    impl Package {
        pub(crate) fn new() -> Self {
            let repository = Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../..")
                .canonicalize()
                .unwrap();
            let mut namespace = repository.clone();
            for part in ["target", "conversation-browser-fixtures"] {
                namespace.push(part);
                match std::fs::create_dir(&namespace) {
                    Ok(()) => {}
                    Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                    Err(error) => panic!("fixture namespace: {error}"),
                }
                assert!(
                    !namespace
                        .symlink_metadata()
                        .unwrap()
                        .file_type()
                        .is_symlink()
                );
                assert!(namespace.canonicalize().unwrap().starts_with(&repository));
            }
            let root = namespace.join(uuid::Uuid::new_v4().to_string());
            std::fs::create_dir(&root).unwrap();
            std::fs::create_dir(root.join("sdk")).unwrap();
            Self { root, namespace }
        }
        pub(crate) fn root(&self) -> &Path {
            &self.root
        }
        pub(crate) fn write(&self, name: &str, bytes: &[u8]) -> std::io::Result<()> {
            assert!(super::valid(name));
            let mut file = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(self.root.join(name))?;
            file.write_all(bytes)
        }
    }
    impl Drop for Package {
        fn drop(&mut self) {
            // Only this unique create_dir result is disposable, never its namespace.
            if !self
                .root
                .symlink_metadata()
                .is_ok_and(|m| m.file_type().is_symlink())
                && self
                    .root
                    .canonicalize()
                    .is_ok_and(|p| p.starts_with(&self.namespace))
            {
                std::fs::remove_dir_all(&self.root).unwrap();
            }
        }
    }
}
// Preserve strings and byte positions while ignoring documentation examples. This bounded
// availability check targets literal packaged ESM; it is not a JavaScript trust parser.
fn without_comments(source: &str) -> String {
    let mut code = source.as_bytes().to_vec();
    let mut index = 0;
    let mut quote = None;
    while index < code.len() {
        if let Some(end) = quote {
            if code[index] == b'\\' {
                index += 2;
                continue;
            }
            if code[index] == end {
                quote = None;
            }
        } else if matches!(code[index], b'\'' | b'"' | b'`') {
            quote = Some(code[index]);
        } else if code[index..].starts_with(b"/*") {
            code[index] = b' ';
            code[index + 1] = b' ';
            index += 2;
            while index < code.len() && !code[index..].starts_with(b"*/") {
                if code[index] != b'\n' {
                    code[index] = b' ';
                }
                index += 1;
            }
            if index + 1 < code.len() {
                code[index] = b' ';
                code[index + 1] = b' ';
                index += 2;
            }
            continue;
        } else if code[index..].starts_with(b"//") {
            while index < code.len() && code[index] != b'\n' {
                code[index] = b' ';
                index += 1;
            }
            continue;
        }
        index += 1;
    }
    String::from_utf8(code).expect("comments replaced with ASCII; remaining UTF-8 unchanged")
}
fn valid(name: &str) -> bool {
    name.ends_with(".js")
        && name.split('/').all(|part| {
            !part.is_empty()
                && part != "."
                && part != ".."
                && part
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
        })
}
async fn asset(State(state): State<BrowserAssets>, Path(name): Path<String>) -> Response {
    let Some(bytes) = state.files.get(&name).filter(|_| valid(&name)) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    (
        [
            (header::CONTENT_TYPE, "text/javascript; charset=utf-8"),
            (header::CACHE_CONTROL, "no-store"),
            (header::X_CONTENT_TYPE_OPTIONS, "nosniff"),
        ],
        bytes.clone(),
    )
        .into_response()
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn exact_packaged_entry_only_and_no_request_path_filesystem() {
        let package = test_files::Package::new();
        package
            .write("sdk/conversation-custody.js", b"export const fixture=true;")
            .unwrap();
        let assets = BrowserAssets::load(package.root()).unwrap();
        assert!(assets.files.contains_key("sdk/conversation-custody.js"));
        assert!(assets.require_owner_setup().is_err());
        for name in [
            "../secret.js",
            "sdk/../../secret.js",
            "sdk//x.js",
            "/sdk/x.js",
            "sdk/x.json",
            "sdk/%2e%2e/x.js",
        ] {
            assert!(!valid(name));
        }
    }
    #[test]
    fn package_without_entry_fails_closed() {
        let package = test_files::Package::new();
        assert!(BrowserAssets::load(package.root()).is_err());
    }

    #[test]
    fn popped_directory_is_rechecked_against_exact_package_root() {
        let package = test_files::Package::new();
        let other = test_files::Package::new();
        let root = package.root().canonicalize().unwrap();
        assert!(checked_directory(&package.root().join("sdk"), &root).is_ok());
        assert!(checked_directory(other.root(), &root).is_err());
        package
            .write("sdk/conversation-custody.js", b"export const fixture=true;")
            .unwrap();
        assert!(
            checked_directory(&package.root().join("sdk/conversation-custody.js"), &root).is_err()
        );
        assert_eq!(
            package
                .write("sdk/conversation-custody.js", b"overwrite")
                .unwrap_err()
                .kind(),
            std::io::ErrorKind::AlreadyExists
        );
    }

    #[cfg(unix)]
    #[test]
    fn popped_symlink_directory_is_refused_even_when_target_is_inside_package() {
        let package = test_files::Package::new();
        let root = package.root().canonicalize().unwrap();
        let link = package.root().join("linked-sdk");
        std::os::unix::fs::symlink(package.root().join("sdk"), &link).unwrap();
        assert!(checked_directory(&link, &root).is_err());
        assert!(BrowserAssets::load(&link).is_err());
    }
    #[cfg(unix)]
    #[test]
    fn package_file_symlinks_are_refused_for_inside_and_outside_targets() {
        for outside in [false, true] {
            let package = test_files::Package::new();
            let other = test_files::Package::new();
            package
                .write("sdk/conversation-custody.js", b"export const fixture=true;")
                .unwrap();
            other
                .write("sdk/target.js", b"export const fixture=true;")
                .unwrap();
            let target = if outside {
                other.root().join("sdk/target.js")
            } else {
                package.root().join("sdk/conversation-custody.js")
            };
            std::os::unix::fs::symlink(target, package.root().join("sdk/linked.js")).unwrap();
            assert!(BrowserAssets::load(package.root()).is_err());
        }
    }

    #[cfg(unix)]
    #[test]
    fn broken_package_symlink_is_refused_before_resolving_its_target() {
        let package = test_files::Package::new();
        package
            .write("sdk/conversation-custody.js", b"export const fixture=true;")
            .unwrap();
        std::os::unix::fs::symlink(
            package.root().join("sdk/missing.js"),
            package.root().join("sdk/linked.js"),
        )
        .unwrap();
        let error = BrowserAssets::load(package.root()).err().unwrap();
        assert_eq!(error.to_string(), "SDK symlink refused");
    }

    #[test]
    fn popped_parent_traversal_cannot_reach_a_sibling_package() {
        let package = test_files::Package::new();
        let other = test_files::Package::new();
        let root = package.root().canonicalize().unwrap();
        let candidate = package
            .root()
            .join("..")
            .join(other.root().file_name().unwrap());
        assert!(candidate.starts_with(package.root()));
        assert!(checked_directory(&candidate, &root).is_err());
        assert!(!candidate.canonicalize().unwrap().starts_with(&root));
    }

    #[test]
    fn ordinary_setup_requires_every_transitive_packaged_import() {
        let mut files = BTreeMap::new();
        for name in [
            "conversation-custody",
            "conversation-archive-custody",
            "draft02-manifest",
            "conversation-refresh-proposal",
            "conversation-activation-proposal",
        ] {
            files.insert(format!("sdk/{name}.js"), Vec::new());
        }
        files.insert(
            "sdk/conversation-custody.js".into(),
            b"import { fixture } from '../vendor/core/mod.js';".to_vec(),
        );
        let assets = |files| BrowserAssets {
            files: Arc::new(files),
        };
        assert!(assets(files.clone()).require_owner_setup().is_err());
        files.insert(
            "vendor/core/mod.js".into(),
            b"export { fixture } from '../common/mod.js';".to_vec(),
        );
        assert!(assets(files.clone()).require_owner_setup().is_err());
        files.insert(
            "vendor/common/mod.js".into(),
            b"export const fixture = true;".to_vec(),
        );
        assert!(assets(files.clone()).require_owner_setup().is_ok());
        files.insert(
            "vendor/common/mod.js".into(),
            b"export * from '../../../outside.js';".to_vec(),
        );
        assert!(assets(files).require_owner_setup().is_err());
    }

    #[test]
    fn documentation_import_examples_never_become_runtime_dependencies() {
        let source = "/* import('unpackaged'); */\nimport { fixture } from './actual.js'; // from 'comment'\nconst url = 'https://example.org';";
        let code = without_comments(source);
        assert!(!code.contains("unpackaged"));
        assert!(!code.contains("comment'"));
        assert!(code.contains("from './actual.js'"));
        assert!(code.contains("https://example.org"));
    }
}

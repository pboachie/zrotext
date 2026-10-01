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
        let mut files = BTreeMap::new();
        let mut total = 0;
        let mut pending = vec![root.clone()];
        let mut visited = BTreeSet::new();
        while let Some(dir) = pending.pop() {
            if !visited.insert(dir.clone()) || visited.len() > 64 {
                return Err(std::io::Error::other("SDK directory cycle or bound"));
            }
            for entry in std::fs::read_dir(dir)? {
                let path = entry?.path();
                let actual = path.canonicalize()?;
                if !actual.starts_with(&root) {
                    return Err(std::io::Error::other("SDK asset escapes package"));
                }
                if path.is_symlink() {
                    return Err(std::io::Error::other("SDK symlink refused"));
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
        let root = std::env::temp_dir().join(format!("conversation-sdk-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(root.join("sdk")).unwrap();
        std::fs::write(
            root.join("sdk/conversation-custody.js"),
            b"export const fixture=true;",
        )
        .unwrap();
        let assets = BrowserAssets::load(&root).unwrap();
        std::fs::remove_dir_all(&root).unwrap();
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
        let root = std::env::temp_dir().join(format!("conversation-sdk-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir(&root).unwrap();
        assert!(BrowserAssets::load(&root).is_err());
        std::fs::remove_dir(root).unwrap();
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

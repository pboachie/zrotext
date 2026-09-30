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
}

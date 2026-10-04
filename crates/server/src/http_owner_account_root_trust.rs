// SPDX-License-Identifier: AGPL-3.0-only
//! Independently default-off public assets. No database, key or contact authority.
use axum::{
    Router,
    body::Body,
    extract::RawQuery,
    http::{HeaderValue, Response, header},
    routing::get,
};
use std::{
    collections::BTreeMap,
    fs,
    io::Read,
    path::{Component, Path},
    sync::Arc,
};
const NAMES: [&str; 3] = [
    "draft02-manifest.js",
    "draft02-trust-store.js",
    "contact-reader-statement.js",
];
const MAX_MODULE: u64 = 128 * 1024;
const PAGE: &str = include_str!("../../../web/owner/account-root-trust.html");
const SCRIPT: &str = include_str!("../../../web/owner/account-root-trust.js");
const CSP: &str = "default-src 'none'; script-src 'self'; connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'; object-src 'none'";

/// Disabled never reads a package. Enabling requires actual account composition.
pub fn configured_router(
    enabled: bool,
    directory: Option<&Path>,
    account_routes: bool,
) -> Result<Router, &'static str> {
    if !enabled {
        return Ok(Router::new());
    }
    if !account_routes {
        return Err("Account root review requires configured account routes");
    }
    Ok(Assets::load(directory.ok_or("Account root review SDK directory required")?)?.router())
}
struct Assets {
    modules: BTreeMap<&'static str, Arc<str>>,
}
fn safe_path(path: &Path, directory: bool) -> Result<(), &'static str> {
    if !path.is_absolute() || path.components().any(|c| matches!(c, Component::ParentDir)) {
        return Err("Account trust package path refused");
    }
    for parent in path.ancestors() {
        let metadata =
            fs::symlink_metadata(parent).map_err(|_| "Account trust package unavailable")?;
        if metadata.file_type().is_symlink() {
            return Err("Account trust package link refused");
        }
        #[cfg(windows)]
        {
            use std::os::windows::fs::MetadataExt;
            if metadata.file_attributes() & 0x400 != 0 {
                return Err("Account trust package reparse refused");
            }
        }
    }
    let metadata = fs::metadata(path).map_err(|_| "Account trust package unavailable")?;
    if (directory && !metadata.is_dir()) || (!directory && !metadata.is_file()) {
        return Err("Account trust package type refused");
    }
    Ok(())
}
/// Closed graph inspection, not JS authentication. Trust the maintained build
/// and application-owned public package, not arbitrary operator JS as authority.
fn module_graph(name: &str, source: &str) -> Result<(), &'static str> {
    let required = match name {
        "draft02-manifest.js" => "verifiedAccountArchiveStatementRecords02",
        "draft02-trust-store.js" => "Draft02TrustStore",
        "contact-reader-statement.js" => "verifyContactReaderStatement01",
        _ => return Err("Account trust module refused"),
    };
    if !source.contains(required) {
        return Err("Account trust module stale");
    }
    let mut imports = 0;
    let mut import_tokens = 0;
    let mut declaration = String::new();
    let mut importing = false;
    let mut comment = false;
    for line in source.lines() {
        let line = line.trim();
        if comment {
            if line.contains("*/") {
                comment = false;
            }
            continue;
        }
        if line.starts_with("/*") {
            comment = !line.contains("*/");
            continue;
        }
        if line.starts_with("//") {
            continue;
        }
        // Conservatively refuse import tokens anywhere in executable lines,
        // including inline declarations or dynamic imports with unusual space.
        // This is fixed trusted-build inspection, not a general JS parser.
        import_tokens += line
            .split(|c: char| !c.is_ascii_alphanumeric() && c != '_' && c != '$')
            .filter(|token| *token == "import")
            .count();
        if line.contains("import(")
            || line.contains("import (")
            || (line.starts_with("export ") && line.contains(" from "))
        {
            return Err("Account trust graph refused");
        }
        if line.starts_with("import ") {
            if importing {
                return Err("Account trust graph refused");
            }
            importing = true;
        }
        if importing {
            declaration.push_str(line);
            if line.ends_with(';') {
                let from = declaration
                    .rsplit_once("from ")
                    .ok_or("Account trust graph refused")?
                    .1;
                if from != "\"./draft02-manifest.js\";" && from != "'./draft02-manifest.js';" {
                    return Err("Account trust graph refused");
                }
                imports += 1;
                declaration.clear();
                importing = false;
            }
        }
    }
    if importing || import_tokens != imports || imports != usize::from(name != NAMES[0]) {
        return Err("Account trust graph refused");
    }
    Ok(())
}
impl Assets {
    fn load(directory: &Path) -> Result<Self, &'static str> {
        safe_path(directory, true)?;
        let root = directory
            .canonicalize()
            .map_err(|_| "Account trust package unavailable")?;
        let entries = fs::read_dir(&root)
            .map_err(|_| "Account trust package unavailable")?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| "Account trust package unavailable")?;
        if entries.len() != 1 || entries[0].file_name() != "sdk" {
            return Err("Account trust package graph refused");
        }
        let sdk = root.join("sdk");
        safe_path(&sdk, true)?;
        let entries = fs::read_dir(&sdk)
            .map_err(|_| "Account trust package unavailable")?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| "Account trust package unavailable")?;
        if entries.len() != NAMES.len() {
            return Err("Account trust package graph refused");
        }
        let mut modules = BTreeMap::new();
        for name in NAMES {
            let file = sdk.join(name);
            safe_path(&file, false)?;
            let actual = file
                .canonicalize()
                .map_err(|_| "Account trust package unavailable")?;
            if !actual.starts_with(&root)
                || fs::metadata(&actual)
                    .map_err(|_| "Account trust package unavailable")?
                    .len()
                    > MAX_MODULE
            {
                return Err("Account trust module refused");
            }
            // Bound the stream even when a file grows after metadata inspection.
            let mut bytes = Vec::new();
            fs::File::open(&actual)
                .map_err(|_| "Account trust package unavailable")?
                .take(MAX_MODULE + 1)
                .read_to_end(&mut bytes)
                .map_err(|_| "Account trust package unavailable")?;
            if bytes.is_empty() || bytes.len() as u64 > MAX_MODULE {
                return Err("Account trust module refused");
            }
            let source =
                String::from_utf8(bytes).map_err(|_| "Account trust module encoding refused")?;
            module_graph(name, &source)?;
            modules.insert(name, Arc::from(source));
        }
        Ok(Self { modules })
    }
    fn router(self) -> Router {
        let mut router = Router::new()
            .route(
                "/owner/account/root-trust",
                get(|RawQuery(query): RawQuery| async {
                    checked_asset(query, PAGE, "text/html; charset=utf-8")
                }),
            )
            .route(
                "/owner/account/root-trust.js",
                get(|RawQuery(query): RawQuery| async {
                    checked_asset(query, SCRIPT, "text/javascript; charset=utf-8")
                }),
            );
        for (name, source) in self.modules {
            router = router.route(
                &format!("/v1/owner/account-root-trust-sdk/sdk/{name}"),
                get(move |RawQuery(query): RawQuery| {
                    let source = source.clone();
                    async move {
                        checked_asset(query, source.to_string(), "text/javascript; charset=utf-8")
                    }
                }),
            );
        }
        router
    }
}
fn checked_asset(
    query: Option<String>,
    body: impl Into<Body>,
    mime: &'static str,
) -> Response<Body> {
    if query.is_some() {
        let mut response = asset(Body::empty(), mime);
        *response.status_mut() = axum::http::StatusCode::BAD_REQUEST;
        response
    } else {
        asset(body, mime)
    }
}
fn asset(body: impl Into<Body>, mime: &'static str) -> Response<Body> {
    let mut response = Response::new(body.into());
    for (name, value) in [
        (header::CONTENT_TYPE, mime),
        (header::CACHE_CONTROL, "no-store"),
        (header::CONTENT_SECURITY_POLICY, CSP),
        (header::X_CONTENT_TYPE_OPTIONS, "nosniff"),
        (header::REFERRER_POLICY, "no-referrer"),
    ] {
        response
            .headers_mut()
            .insert(name, HeaderValue::from_static(value));
    }
    response
}
#[cfg(test)]
mod tests;

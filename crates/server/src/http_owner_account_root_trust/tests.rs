// SPDX-License-Identifier: AGPL-3.0-only
use super::*;
use axum::{
    body::to_bytes,
    http::{Request, StatusCode},
};
use tower::ServiceExt;
struct Package(std::path::PathBuf);
impl Package {
    fn new() -> Self {
        let root = std::env::temp_dir().join(format!("account-trust-{}", uuid::Uuid::new_v4()));
        fs::create_dir(&root).unwrap();
        fs::create_dir(root.join("sdk")).unwrap();
        for (name, source) in [
            (
                NAMES[0],
                "export function verifiedAccountArchiveStatementRecords02() {}",
            ),
            (
                NAMES[1],
                "import { fixture } from './draft02-manifest.js';\nexport class Draft02TrustStore {}",
            ),
            (
                NAMES[2],
                "import { fixture } from './draft02-manifest.js';\nexport function verifyContactReaderStatement01() {}",
            ),
        ] {
            fs::write(root.join("sdk").join(name), source).unwrap();
        }
        Self(root)
    }
}
impl Drop for Package {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).unwrap();
    }
}
#[tokio::test]
async fn disabled_real_owner_composition_does_not_mount_or_read_a_package() {
    let router = crate::owner_ui::router()
        .merge(configured_router(false, Some(Path::new("missing")), false).unwrap());
    let response = router
        .oneshot(
            Request::builder()
                .uri("/owner/account/root-trust")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    assert!(configured_router(true, None, false).is_err());
    assert!(configured_router(true, None, true).is_err());
}
#[tokio::test]
async fn enabled_real_owner_composition_serves_only_fixed_public_assets() {
    let p = Package::new();
    let router =
        crate::owner_ui::router().merge(configured_router(true, Some(&p.0), true).unwrap());
    for path in [
        "/owner/account/root-trust",
        "/owner/account/root-trust.js",
        "/v1/owner/account-root-trust-sdk/sdk/draft02-manifest.js",
        "/v1/owner/account-root-trust-sdk/sdk/draft02-trust-store.js",
        "/v1/owner/account-root-trust-sdk/sdk/contact-reader-statement.js",
    ] {
        let response = router
            .clone()
            .oneshot(Request::builder().uri(path).body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
        assert_eq!(
            response.headers()[header::X_CONTENT_TYPE_OPTIONS],
            "nosniff"
        );
        assert_eq!(response.headers()[header::CONTENT_SECURITY_POLICY], CSP);
        assert!(
            !to_bytes(response.into_body(), 65536)
                .await
                .unwrap()
                .is_empty()
        );
        let response = router
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(path)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::METHOD_NOT_ALLOWED);
        let response = router
            .clone()
            .oneshot(
                Request::builder()
                    .uri(format!("{path}?module=other.js"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert!(to_bytes(response.into_body(), 1).await.unwrap().is_empty());
    }
    for path in [
        "/v1/owner/account-root-trust-sdk/sdk/other.js",
        "/v1/owner/account-root-trust-sdk/sdk/%2e%2e/other.js",
        "/owner/account/root-trust/other",
        "/v1/contacts/root",
    ] {
        let response = router
            .clone()
            .oneshot(Request::builder().uri(path).body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }
}
#[test]
fn missing_extra_encoding_and_oversized_modules_refuse_startup() {
    let p = Package::new();
    fs::remove_file(p.0.join("sdk").join(NAMES[0])).unwrap();
    assert!(Assets::load(&p.0).is_err());
    let p = Package::new();
    fs::write(p.0.join("sdk/other.js"), "export const extra=true;").unwrap();
    assert!(Assets::load(&p.0).is_err());
    let p = Package::new();
    fs::write(p.0.join("sdk").join(NAMES[0]), [255]).unwrap();
    assert!(Assets::load(&p.0).is_err());
    let p = Package::new();
    fs::write(
        p.0.join("sdk").join(NAMES[0]),
        vec![b' '; MAX_MODULE as usize + 1],
    )
    .unwrap();
    assert!(Assets::load(&p.0).is_err());
}
#[test]
fn extra_dynamic_side_effect_and_stale_graphs_are_refused() {
    for source in [
        "export const stale=true;",
        "import './other.js';\nexport class Draft02TrustStore {}",
        "import { fixture } from './other.js';\nexport class Draft02TrustStore {}",
        "import { fixture } from './draft02-manifest.js';\nimport { other } from './draft02-manifest.js';\nexport class Draft02TrustStore {}",
        "import { fixture } from './draft02-manifest.js';\nexport class Draft02TrustStore { fetch(){return import('./other.js');} }",
        "import { fixture } from './draft02-manifest.js';\nexport class Draft02TrustStore { fetch(){return import\t('./other.js');} }",
        "import { fixture } from './draft02-manifest.js'; import './other.js';\nexport class Draft02TrustStore {}",
    ] {
        assert!(module_graph(NAMES[1], source).is_err());
    }
}
#[cfg(unix)]
#[test]
fn linked_package_modules_and_ancestors_are_refused() {
    use std::os::unix::fs::symlink;
    let p = Package::new();
    let linked = p.0.join("link");
    symlink(p.0.join("sdk"), &linked).unwrap();
    assert!(safe_path(&linked, true).is_err());
    let original = p.0.join("sdk").join(NAMES[0]);
    fs::remove_file(&original).unwrap();
    symlink(p.0.join("sdk").join(NAMES[1]), &original).unwrap();
    assert!(Assets::load(&p.0).is_err());
}

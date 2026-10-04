// SPDX-License-Identifier: AGPL-3.0-only
//! Preserve process-local database options in the isolated HTTPS fixture.
use std::str::FromStr;
pub(super) fn database_url_with_schema(raw: &str, schema: &str) -> Result<String, ()> {
    if schema.is_empty()
        || !schema
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_')
    {
        return Err(());
    }
    let config = tokio_postgres::Config::from_str(raw).map_err(|_| ())?;
    let mut url = reqwest::Url::parse(raw).map_err(|_| ())?;
    let mut options = config.get_options().unwrap_or_default().to_owned();
    if !options.is_empty() {
        options.push(' ');
    }
    options.push_str("-csearch_path=");
    options.push_str(schema);
    let retained: Vec<(String, String)> = url
        .query_pairs()
        .filter(|(k, _)| k != "options")
        .map(|(k, v)| (k.into_owned(), v.into_owned()))
        .collect();
    url.set_query(None);
    url.query_pairs_mut()
        .extend_pairs(retained)
        .append_pair("options", &options);
    let result = url.to_string();
    let effective = tokio_postgres::Config::from_str(&result).map_err(|_| ())?;
    if effective.get_options() != Some(options.as_str()) {
        return Err(());
    }
    Ok(result)
}
#[test]
fn fixture_preserves_effective_options_and_other_connection_parameters() {
    let raw = "postgresql://localhost/example?options=-cjoin_collapse_limit%3D1&application_name=synthetic_fixture&sslmode=disable";
    let output = database_url_with_schema(raw, "fixture_123").expect("valid fixture URL");
    let config = tokio_postgres::Config::from_str(&output).expect("valid fixture configuration");
    assert_eq!(
        config.get_options(),
        Some("-cjoin_collapse_limit=1 -csearch_path=fixture_123")
    );
    assert_eq!(config.get_application_name(), Some("synthetic_fixture"));
    assert_eq!(
        config.get_ssl_mode(),
        tokio_postgres::config::SslMode::Disable
    );
    assert_eq!(
        reqwest::Url::parse(&output)
            .expect("valid URL")
            .query_pairs()
            .filter(|(k, _)| k == "options")
            .count(),
        1
    );
}
#[test]
fn fixture_without_options_adds_only_owned_schema_option() {
    let output = database_url_with_schema("postgresql://localhost/example", "fixture_123")
        .expect("valid fixture URL");
    assert_eq!(
        tokio_postgres::Config::from_str(&output)
            .expect("valid configuration")
            .get_options(),
        Some("-csearch_path=fixture_123")
    );
}
#[test]
fn fixture_refuses_untrusted_schema_spelling() {
    for schema in [
        "",
        "fixture,public",
        "fixture -cjoin_collapse_limit=1",
        "fixture;",
        "fixture/other",
    ] {
        assert!(database_url_with_schema("postgresql://localhost/example", schema).is_err());
    }
}

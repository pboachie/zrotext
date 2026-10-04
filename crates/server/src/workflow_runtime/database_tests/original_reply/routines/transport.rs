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
    // Tokio's URL parser percent-decodes without form-decoding '+'. Preserve
    // every other raw segment and encode option spaces explicitly as %20.
    let mut retained: Vec<&str> = url
        .query()
        .unwrap_or_default()
        .split('&')
        .filter(|segment| !segment.is_empty() && segment.split('=').next() != Some("options"))
        .collect();
    let mut encoded = String::new();
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    for byte in options.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
            encoded.push(char::from(byte));
        } else {
            encoded.push('%');
            encoded.push(char::from(HEX[usize::from(byte >> 4)]));
            encoded.push(char::from(HEX[usize::from(byte & 15)]));
        }
    }
    let option_segment = format!("options={encoded}");
    retained.push(&option_segment);
    let query = retained.join("&");
    url.set_query(Some(&query));
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

#[test]
fn fixture_preserves_literal_plus_and_percent_encoded_spaces() {
    let raw = "postgresql://localhost/example?application_name=synthetic+fixture%20space&options=-capplication_name%3Doption%2Bvalue%20-cjoin_collapse_limit%3D1&sslmode=disable";
    let output = database_url_with_schema(raw, "fixture_123").expect("valid fixture URL");
    let config = tokio_postgres::Config::from_str(&output).expect("valid configuration");
    assert_eq!(
        config.get_application_name(),
        Some("synthetic+fixture space")
    );
    assert_eq!(
        config.get_options(),
        Some("-capplication_name=option+value -cjoin_collapse_limit=1 -csearch_path=fixture_123")
    );
    assert!(output.contains("application_name=synthetic+fixture%20space"));
    assert!(output.contains("option%2Bvalue%20-cjoin_collapse_limit"));
}

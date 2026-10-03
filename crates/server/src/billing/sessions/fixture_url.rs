// SPDX-License-Identifier: AGPL-3.0-only
//! Isolated billing test schemas retain the supplied transport policy.

pub(crate) fn isolated_database_url(base_url: &str, schema: &str) -> String {
    let separator = if base_url.contains('?') { '&' } else { '?' };
    format!("{base_url}{separator}options=-csearch_path%3D{schema}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio_postgres::config::SslMode;

    #[test]
    fn isolated_schema_preserves_explicit_tls_requirement() {
        let config: tokio_postgres::Config = isolated_database_url(
            "postgresql://fixture@localhost/fixture?sslmode=require",
            "billing_fixture",
        )
        .parse()
        .expect("a supplied TLS requirement must remain a valid configuration");
        assert_eq!(config.get_ssl_mode(), SslMode::Require);
        assert_eq!(config.get_options(), Some("-csearch_path=billing_fixture"));
    }

    #[test]
    fn isolated_schema_accepts_a_url_without_query_parameters() {
        let config: tokio_postgres::Config =
            isolated_database_url("postgresql://fixture@localhost/fixture", "billing_fixture")
                .parse()
                .unwrap();
        assert_eq!(config.get_options(), Some("-csearch_path=billing_fixture"));
    }
}

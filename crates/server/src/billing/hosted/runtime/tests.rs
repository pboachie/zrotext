// SPDX-License-Identifier: AGPL-3.0-only
use super::super::namespace::{Mode, Namespace};
use super::*;
mod fixture;
mod integration;
mod invoice;

fn options(mode: Mode) -> Options {
    Options {
        namespace: Namespace::new([1; 16], mode, "acct_fixture").unwrap(),
        policy_revision: 1,
        plan: Plan::new("price_fixture", 10, 2, 7 * 24 * 3600).unwrap(),
        read_key: format!("rk_{}_fixture_read", mode_name(mode)),
        session_key: format!("rk_{}_fixture_session", mode_name(mode)),
        webhook_secret: "whsec_fixture_synthetic".into(),
        webhook_endpoint: "we_fixture".into(),
        portal_configuration: "bpc_fixture".into(),
        runtime_key: [7; 32],
        automatic_tax: false,
    }
}
#[test]
fn isolated_options_require_explicit_distinct_scoped_credentials_and_policy() {
    for mode in [Mode::Test, Mode::Live] {
        let mut o = options(mode);
        assert_eq!(o.validate(), Ok(()));
        o.read_key = o.session_key.clone();
        assert_eq!(o.validate(), Err(Error::Configuration));
    }
    let mut o = options(Mode::Live);
    o.read_key = "rk_test_fixture_read".into();
    assert_eq!(o.validate(), Err(Error::Configuration));
    o = options(Mode::Live);
    o.runtime_key = [0; 32];
    assert_eq!(o.validate(), Err(Error::Configuration));
}

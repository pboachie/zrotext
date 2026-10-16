// SPDX-License-Identifier: AGPL-3.0-only
use super::*;

fn fixture() -> (Scope, CookieKey, Browser, Preparation) {
    let scope = Scope {
        realm: Uuid::parse_str("10000000-0000-4000-8000-000000000001").unwrap(),
        database: [2; 32],
        origin: "https://review.invalid".into(),
        config: [3; 32],
        config_revision: 1,
        key: Sha256::digest([7; 32]).into(),
    };
    let key = CookieKey::new([7; 32], &scope).unwrap();
    let browser = Browser {
        nonce: [8; 32],
        issued: 1000,
        expires: 1000 + 14 * DAY,
    };
    let id = |last: u16| Uuid::from_u128(0x10000000000040008000000000000000 | u128::from(last));
    let prep = Preparation {
        operation: Operation::InitialBootstrap,
        browser: browser.digest(&key, &scope),
        id: id(0xf001),
        request: id(0xf002),
        generation: 1,
        prepared: 1100,
        create_deadline: 301100,
        delivery_deadline: 604801100,
        alias: "pilot".into(),
        identities: Identities {
            principal: Uuid::nil(),
            credential: Uuid::nil(),
            revision: 0,
            broker_session: id(0xf003),
            event: id(0xf004),
            owner_session: id(0xf005),
            account: id(0xf006),
            user: id(0xf007),
        },
        target: [0; 32],
        candidates: Candidates {
            csrf: Zeroizing::new([10; 32]),
            broker: Zeroizing::new([11; 32]),
            broker_csrf: Zeroizing::new([12; 32]),
            owner: Zeroizing::new([13; 32]),
            owner_csrf: Zeroizing::new([14; 32]),
            locator: Zeroizing::new([15; 32]),
        },
    };
    (scope, key, browser, prep)
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[test]
fn canonical_cookie_bytes_match_independent_hmac_vectors() {
    let v: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../../protocol/v1/vectors/review-access-cookie-candidate.json"
    ))
    .unwrap();
    let (scope, key, browser, prep) = fixture();
    prep.validate(&browser, &key, &scope, 1100, true).unwrap();
    let b = URL_SAFE_NO_PAD.decode(browser.seal(&key, &scope)).unwrap();
    assert_eq!(
        b.len() - 32,
        v["browser_payload_length"].as_u64().unwrap() as usize
    );
    assert_eq!(hex(&b[b.len() - 32..]), v["browser_mac_hex"]);
    assert_eq!(hex(&browser.digest(&key, &scope)), v["browser_digest_hex"]);
    let raw = prep.bytes(&scope);
    assert_eq!(
        raw.len(),
        v["initial_preparation_payload_length"].as_u64().unwrap() as usize
    );
    assert_eq!(
        hex(&Sha256::digest(&*raw)),
        v["initial_preparation_sha256_hex"]
    );
    let p = URL_SAFE_NO_PAD.decode(prep.seal(&key, &scope)).unwrap();
    assert_eq!(hex(&p[p.len() - 32..]), v["initial_preparation_mac_hex"]);
    assert_eq!(hex(&prep.commitment(&key, &scope)), v["request_digest_hex"]);
    for (name, digest) in [
        (
            "broker_bearer_digest_hex",
            key.broker_token(
                &scope,
                prep.identities.broker_session,
                &prep.candidates.broker,
            )
            .unwrap(),
        ),
        (
            "broker_csrf_digest_hex",
            key.broker_csrf(
                &scope,
                prep.identities.broker_session,
                &prep.candidates.broker_csrf,
            )
            .unwrap(),
        ),
        (
            "owner_bearer_digest_hex",
            key.owner_token(
                &scope,
                prep.identities.owner_session,
                &prep.candidates.owner,
            )
            .unwrap(),
        ),
        (
            "owner_csrf_digest_hex",
            key.owner_csrf(
                &scope,
                prep.identities.owner_session,
                &prep.candidates.owner_csrf,
            )
            .unwrap(),
        ),
        (
            "locator_digest_hex",
            key.locator(&scope, &prep.candidates.locator).unwrap(),
        ),
    ] {
        assert_eq!(hex(&digest), v[name]);
    }
}

#[test]
fn authentic_frames_reject_scope_substitution_trailing_bytes_and_noncanonical_encoding() {
    let (scope, key, browser, prep) = fixture();
    let original = prep.seal(&key, &scope);
    assert!(Preparation::open(&original, &key, &scope, &browser, 1100, true).is_ok());
    for field in 0..5 {
        let mut altered = scope.clone();
        match field {
            0 => altered.realm = Uuid::new_v4(),
            1 => altered.database = [9; 32],
            2 => altered.origin = "https://other.invalid".into(),
            3 => altered.config = [9; 32],
            _ => altered.key = [9; 32],
        }
        assert!(Preparation::open(&original, &key, &altered, &browser, 1100, true).is_err());
    }
    let mut bytes = prep.bytes(&scope).to_vec();
    bytes.push(0);
    assert!(
        Preparation::open(
            &key.seal(Purpose::Preparation, bytes),
            &key,
            &scope,
            &browser,
            1100,
            true
        )
        .is_err()
    );
    assert!(
        Preparation::open(
            &(original.clone() + "="),
            &key,
            &scope,
            &browser,
            1100,
            true
        )
        .is_err()
    );
    let mut corrupt = URL_SAFE_NO_PAD.decode(&original).unwrap();
    corrupt[10] ^= 1;
    assert!(
        Preparation::open(
            &URL_SAFE_NO_PAD.encode(corrupt),
            &key,
            &scope,
            &browser,
            1100,
            true
        )
        .is_err()
    );
    assert!(Preparation::open(&"x".repeat(4096), &key, &scope, &browser, 1100, true).is_err());
}

#[test]
fn creation_expiry_is_distinct_from_original_committed_delivery_deadline() {
    let (scope, key, browser, prep) = fixture();
    let cookie = prep.seal(&key, &scope);
    assert!(Preparation::open(&cookie, &key, &scope, &browser, 301100, true).is_err());
    assert!(Preparation::open(&cookie, &key, &scope, &browser, 301100, false).is_ok());
    assert!(Preparation::open(&cookie, &key, &scope, &browser, 604801100, false).is_err());
    assert!(Preparation::open(&cookie, &key, &scope, &browser, 1099, false).is_err());
    assert!(Browser::open(&browser.seal(&key, &scope), &key, &scope, browser.expires).is_err());
    assert!(Browser::fresh(i64::MAX as u64).is_err());
}

#[test]
fn closed_branches_refuse_alias_or_identity_or_candidate_omissions() {
    let (scope, key, browser, mut prep) = fixture();
    prep.identities.principal = Uuid::new_v4();
    assert!(prep.validate(&browser, &key, &scope, 1100, true).is_err());
    prep.identities.principal = Uuid::nil();
    prep.identities.credential = Uuid::new_v4();
    assert!(prep.validate(&browser, &key, &scope, 1100, true).is_err());
    prep.identities.credential = Uuid::nil();
    prep.identities.revision = 1;
    assert!(prep.validate(&browser, &key, &scope, 1100, true).is_err());
    prep.identities.revision = 0;
    prep.candidates.locator.fill(0);
    assert!(prep.validate(&browser, &key, &scope, 1100, true).is_err());
    prep.operation = Operation::BrokerForResume;
    assert!(prep.validate(&browser, &key, &scope, 1100, true).is_err());
    prep.identities.owner_session = Uuid::nil();
    prep.identities.account = Uuid::nil();
    prep.identities.user = Uuid::nil();
    prep.candidates.owner.fill(0);
    prep.candidates.owner_csrf.fill(0);
    assert!(prep.validate(&browser, &key, &scope, 1100, true).is_ok());
    prep.alias = "Pilot".into();
    assert!(prep.validate(&browser, &key, &scope, 1100, true).is_err());
    assert!(Operation::try_from(0).is_err());
    assert!(Operation::try_from(6).is_err());
}

#[test]
fn typed_digest_domains_require_session_ids_and_do_not_substitute_credentials() {
    let (scope, key, _, prep) = fixture();
    let id = prep.identities.broker_session;
    assert!(key.broker_token(&scope, Uuid::nil(), &[1; 32]).is_err());
    assert!(key.broker_token(&scope, id, &[0; 32]).is_err());
    let token = key.broker_token(&scope, id, &[1; 32]).unwrap();
    assert_ne!(token, key.broker_csrf(&scope, id, &[1; 32]).unwrap());
    assert_ne!(token, key.owner_token(&scope, id, &[1; 32]).unwrap());
    assert_ne!(
        token,
        key.broker_token(&scope, Uuid::new_v4(), &[1; 32]).unwrap()
    );
}

#[test]
fn locator_selector_matches_independent_vector_and_exports_no_active_credentials() {
    let v: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../../protocol/v1/vectors/review-access-cookie-candidate.json"
    ))
    .unwrap();
    let (scope, key, browser, prep) = fixture();
    let selector = LocatorSelector::from_initial(&prep, &browser, &key, &scope, 1100).unwrap();
    let bytes = selector.bytes(&scope);
    assert_eq!(
        bytes.len(),
        v["locator_selector_payload_length"].as_u64().unwrap() as usize
    );
    assert_eq!(
        hex(&Sha256::digest(&*bytes)),
        v["locator_selector_sha256_hex"]
    );
    let cookie = selector.seal(&key, &scope, 1100).unwrap();
    let raw = URL_SAFE_NO_PAD.decode(&cookie).unwrap();
    assert_eq!(hex(&raw[raw.len() - 32..]), v["locator_selector_mac_hex"]);
    for active in [
        &*prep.candidates.broker,
        &*prep.candidates.broker_csrf,
        &*prep.candidates.owner,
        &*prep.candidates.owner_csrf,
    ] {
        assert!(!bytes.windows(32).any(|part| part == active));
    }
    for identity in [
        prep.identities.broker_session,
        prep.identities.event,
        prep.identities.owner_session,
    ] {
        assert!(!bytes.windows(16).any(|part| part == identity.as_bytes()));
    }
    assert_eq!(
        selector.digest(&key, &scope).unwrap(),
        key.locator(&scope, &prep.candidates.locator).unwrap()
    );
    assert!(LocatorSelector::open(&cookie, &key, &scope, 1100).is_ok());
    assert!(LocatorSelector::open(&cookie, &key, &scope, 1099).is_err());
    let mut revision = scope.clone();
    revision.config_revision += 1;
    assert!(LocatorSelector::open(&cookie, &key, &revision, 1100).is_err());
    let mut config = scope.clone();
    config.config = [9; 32];
    assert!(LocatorSelector::open(&cookie, &key, &config, 1100).is_err());
    assert!(LocatorSelector::open(&prep.seal(&key, &scope), &key, &scope, 1100).is_err());
    assert!(Preparation::open(&cookie, &key, &scope, &browser, 1100, false).is_err());
}

#[test]
fn maximum_origin_selector_roundtrips_without_truncation_or_silent_normalization() {
    let (mut scope, _, _, _) = fixture();
    scope.origin = format!(
        "https://{}.{}.{}.{}",
        "a".repeat(63),
        "b".repeat(63),
        "c".repeat(63),
        "d".repeat(55)
    );
    assert_eq!(scope.origin.len(), 255);
    scope.validate().unwrap();
    let key = CookieKey::new([7; 32], &scope).unwrap();
    let browser = Browser {
        nonce: [8; 32],
        issued: 1000,
        expires: 1000 + 14 * DAY,
    };
    let (_, _, _, mut prep) = fixture();
    prep.browser = browser.digest(&key, &scope);
    let selector = LocatorSelector::from_initial(&prep, &browser, &key, &scope, 1100).unwrap();
    let cookie = selector.seal(&key, &scope, 1100).unwrap();
    assert!(URL_SAFE_NO_PAD.decode(&cookie).unwrap().len() > 512);
    assert!(LocatorSelector::open(&cookie, &key, &scope, 1100).is_ok());
    scope.origin.push('e');
    assert!(scope.validate().is_err());
    assert!(LocatorSelector::open(&cookie, &key, &scope, 1100).is_err());
    let oversized = key.seal(Purpose::LocatorSelector, vec![1; MAX_FRAME]);
    assert!(LocatorSelector::open(&oversized, &key, &scope, 1100).is_err());
}

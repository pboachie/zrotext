// SPDX-License-Identifier: AGPL-3.0-only
// Public geometry and scope from synthetic fixtures only. Independently framed.
use super::*;
fn point(n: u8) -> [u8; 65] {
    let mut scalar = [0; 32];
    scalar[31] = n;
    p256::ecdsa::SigningKey::from_slice(&scalar)
        .unwrap()
        .verifying_key()
        .to_sec1_point(false)
        .as_bytes()
        .try_into()
        .unwrap()
}
pub(super) fn fixture(issued_ms: u64, expires_ms: u64) -> (Expected, Statement, Vec<u8>) {
    let root_pin: [u8; 94] = [
        b"ZTRP\x02".as_slice(),
        &[1; 16],
        &1u64.to_be_bytes(),
        &point(1),
    ]
    .concat()
    .try_into()
    .unwrap();
    let root_fingerprint =
        Sha256::digest([b"ZTSE/root-pin/v2\0".as_slice(), &root_pin].concat()).into();
    let scope = Scope {
        account: [1; 16],
        user: [2; 16],
        owner_session: [3; 16],
        device: [4; 16],
        line: [5; 16],
        next_generation: 1,
        challenge: [6; 16],
        nonce: [7; 32],
        issued_ms,
        expires_ms,
        approval_fingerprint: Sha256::digest(point(2)).into(),
        paired_signing_fingerprint: Sha256::digest(point(4)).into(),
        connection_epoch: 8,
        deployment_epoch: 9,
        site_id: "site-fixture".into(),
        instance_id: "instance-fixture".into(),
        origin: "https://owner.invalid".into(),
    };
    let expected = Expected {
        identity: ExpectedIdentity {
            account_id: scope.account,
            origin: scope.origin.clone(),
            root_fingerprint,
        },
        root_pin,
        scope: scope.clone(),
    };
    let statement = Statement::new(scope, root_pin, root_fingerprint, point(2)).unwrap();
    let unsigned = [
        b"ZTSE/line/owner-key/register/v1\0".as_slice(),
        &[1; 16],
        &[2; 16],
        &[3; 16],
        &[4; 16],
        &[5; 16],
        &1u64.to_be_bytes(),
        &[6; 16],
        &[7; 32],
        &issued_ms.to_be_bytes(),
        &expires_ms.to_be_bytes(),
        &root_pin,
        &root_fingerprint,
        &point(2),
        &Sha256::digest(point(2)),
        &Sha256::digest(point(4)),
        &8u64.to_be_bytes(),
        &9u64.to_be_bytes(),
        &12u16.to_be_bytes(),
        b"site-fixture",
        &16u16.to_be_bytes(),
        b"instance-fixture",
        &21u16.to_be_bytes(),
        b"https://owner.invalid",
    ]
    .concat();
    (expected, statement, unsigned)
}

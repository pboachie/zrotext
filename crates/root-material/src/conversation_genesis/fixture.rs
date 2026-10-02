// SPDX-License-Identifier: AGPL-3.0-only
// Test-only independently encoded fixture, shared by library and console tests.
use super::*;
use zeroize::Zeroizing;
fn point(n: u8) -> [u8; 65] {
    let mut bytes = [0; 32];
    bytes[31] = n;
    p256::ecdsa::SigningKey::from_slice(&bytes)
        .unwrap()
        .verifying_key()
        .to_sec1_point(false)
        .as_bytes()
        .try_into()
        .unwrap()
}
fn id(role: u8, point: &[u8; 65]) -> [u8; 32] {
    Sha256::digest(
        [
            b"ZTSE/key/v1\0".as_slice(),
            if role <= 3 { &[0, 16] } else { &[1, 1] },
            point,
        ]
        .concat(),
    )
    .into()
}
pub(super) fn fixture(issued_ms: u64, expires_ms: u64) -> (RootSecret, Expected, Vec<u8>, Vec<u8>) {
    let mut scalar = [0; 32];
    scalar[31] = 1;
    let root = RootSecret::new(Zeroizing::new(scalar)).unwrap();
    let pin: [u8; 94] = [
        b"ZTRP\x02".as_slice(),
        &[1; 16],
        &1u64.to_be_bytes(),
        &point(1),
    ]
    .concat()
    .try_into()
    .unwrap();
    let identity = ExpectedIdentity {
        account_id: [1; 16],
        origin: "https://owner.invalid".into(),
        root_fingerprint: root_fingerprint(&pin, &[1; 16]).unwrap(),
    };
    let scope = Scope {
        account: [1; 16],
        session: [2; 16],
        device: [4; 16],
        line: [5; 16],
        device_signing_fingerprint: Sha256::digest(point(4)).into(),
        generation: 1,
        peer: "+12".into(),
        origin: identity.origin.clone(),
        fingerprint: identity.root_fingerprint,
        issued_ms,
        expires_ms,
    };
    let expected = Expected {
        identity,
        scope: scope.clone(),
        root_pin: pin,
        phone_reader: point(2),
        archive_reader: point(3),
        phone_signer: point(4),
    };
    let mut unsigned = [
        b"ZTMA\x02".as_slice(),
        &scope.account,
        &1u64.to_be_bytes(),
        &1u64.to_be_bytes(),
        &issued_ms.to_be_bytes(),
        &expires_ms.to_be_bytes(),
        &[0; 32],
        &point(1),
        &[4],
    ]
    .concat();
    for (role, n, bits) in [(1, 2, 4u16), (2, 3, 12), (4, 4, 2), (6, 1, 0)] {
        unsigned.extend(
            [
                &[role][..],
                id(role, &point(n)).as_slice(),
                &point(n),
                if matches!(role, 1 | 4) {
                    &scope.device
                } else {
                    &[0; 16]
                },
                if matches!(role, 1 | 4) {
                    &scope.line
                } else {
                    &[0; 16]
                },
                &bits.to_be_bytes(),
                &issued_ms.to_be_bytes(),
                &expires_ms.to_be_bytes(),
                &[1],
            ]
            .concat(),
        );
    }
    let mut proposal = [
        b"ZTCG\x01".as_slice(),
        &scope.account,
        &scope.session,
        &scope.device,
        &scope.line,
        &scope.device_signing_fingerprint,
        &scope.generation.to_be_bytes(),
        &[scope.peer.len() as u8],
        scope.peer.as_bytes(),
        &(scope.origin.len() as u16).to_be_bytes(),
        scope.origin.as_bytes(),
        &scope.fingerprint,
        &pin,
        &issued_ms.to_be_bytes(),
        &expires_ms.to_be_bytes(),
        &(unsigned.len() as u16).to_be_bytes(),
    ]
    .concat();
    proposal.extend_from_slice(&unsigned);
    (root, expected, proposal, unsigned)
}

// SPDX-License-Identifier: AGPL-3.0-only
use super::*;
use p256::{
    ecdsa::{Signature, SigningKey, signature::Signer},
    elliptic_curve::Generate,
};
use rand::rng;

// Synthetic encoding answers. The r=1,s=1 DER below is only a concatenation
// fixture; genuine test-only signatures are constructed separately.
const ENCODING_DER: &[u8] = &[0x30, 6, 2, 1, 1, 2, 1, 1];

struct Literal {
    name: &'static str,
    purpose: PurposeV2,
    generation: i64,
    observation_hex: &'static str,
    device_hex: &'static str,
    owner_hex: &'static str,
    device_digest_hex: &'static str,
    owner_digest_hex: &'static str,
}

const LITERALS: [Literal; 11] = [
    Literal {
        name: "sms-physical-selected-peer-esim-active",
        purpose: PurposeV2::Sms,
        generation: 1,
        observation_hex: "0021000200000007010000000000004000800000000000001000000000000040008000000000000020000000000000000000000000000040008000000000000040000000000000000100000000000040008000000000000041893205abddcccbe664fcbba578beba84ba4a3354c5df1b39adc67d0dab5cc017",
        device_hex: "5a54534d532f6c696e652f6465766963652d636f6e6669726d2f7632000201000000000000400080000000000000010000000000004000800000000000000200000000000040008000000000000003000000000000000100000000000040008000000000000004000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f0021000200000007010000000000004000800000000000001000000000000040008000000000000020000000000000000000000000000040008000000000000040000000000000000100000000000040008000000000000041893205abddcccbe664fcbba578beba84ba4a3354c5df1b39adc67d0dab5cc017",
        owner_hex: "5a54534d532f6c696e652f6f776e65722d617070726f76652f7632005a54534d532f6c696e652f6465766963652d636f6e6669726d2f7632000201000000000000400080000000000000010000000000004000800000000000000200000000000040008000000000000003000000000000000100000000000040008000000000000004000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f0021000200000007010000000000004000800000000000001000000000000040008000000000000020000000000000000000000000000040008000000000000040000000000000000100000000000040008000000000000041893205abddcccbe664fcbba578beba84ba4a3354c5df1b39adc67d0dab5cc01757093944c2f730f5d554173cb3555795c1a4f68c647be0ff8e3adb840b757675",
        device_digest_hex: "e1e4c9902ff670bf2753a6925bd55eb7f570abba9d78faed351b8387e906520f",
        owner_digest_hex: "5c652b67739f8c83381a446f82893836da29bbf05009f2f5490134c6f00358d9",
    },
    Literal {
        name: "sms-esim-selected-peer-physical-active",
        purpose: PurposeV2::Sms,
        generation: 1,
        observation_hex: "002100020000000b020000000000004000800000000000001100000000000040008000000000000021000000000000000100000000000040008000000000000040000000000000000100000000000040008000000000000041893205abddcccbe664fcbba578beba84ba4a3354c5df1b39adc67d0dab5cc017",
        device_hex: "5a54534d532f6c696e652f6465766963652d636f6e6669726d2f7632000201000000000000400080000000000000010000000000004000800000000000000200000000000040008000000000000003000000000000000100000000000040008000000000000004000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f002100020000000b020000000000004000800000000000001100000000000040008000000000000021000000000000000100000000000040008000000000000040000000000000000100000000000040008000000000000041893205abddcccbe664fcbba578beba84ba4a3354c5df1b39adc67d0dab5cc017",
        owner_hex: "5a54534d532f6c696e652f6f776e65722d617070726f76652f7632005a54534d532f6c696e652f6465766963652d636f6e6669726d2f7632000201000000000000400080000000000000010000000000004000800000000000000200000000000040008000000000000003000000000000000100000000000040008000000000000004000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f002100020000000b020000000000004000800000000000001100000000000040008000000000000021000000000000000100000000000040008000000000000040000000000000000100000000000040008000000000000041893205abddcccbe664fcbba578beba84ba4a3354c5df1b39adc67d0dab5cc01757093944c2f730f5d554173cb3555795c1a4f68c647be0ff8e3adb840b757675",
        device_digest_hex: "12ecb11560785f4440d8a6c29031a824d27d67ccfc72d1d8d2d7912f4d54beb1",
        owner_digest_hex: "18e1e1b43373262986b0fa34be8fccc9a527558fa70abb5e26b7058d64094ba8",
    },
    Literal {
        name: "sms-dual-esim-same-card-slot-port0-selected",
        purpose: PurposeV2::Sms,
        generation: 1,
        observation_hex: "00210002000000090200000000000040008000000000000012000000000000400080000000000000220000000000000000000000000000400080000000000000400000000000000001000000000000400080000000000000415cb5c1ffe46f30a376a458db0df5a22c56a81524beb26f9ccb9dbfb1f6edcd2b",
        device_hex: "5a54534d532f6c696e652f6465766963652d636f6e6669726d2f7632000201000000000000400080000000000000010000000000004000800000000000000200000000000040008000000000000003000000000000000100000000000040008000000000000004000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f00210002000000090200000000000040008000000000000012000000000000400080000000000000220000000000000000000000000000400080000000000000400000000000000001000000000000400080000000000000415cb5c1ffe46f30a376a458db0df5a22c56a81524beb26f9ccb9dbfb1f6edcd2b",
        owner_hex: "5a54534d532f6c696e652f6f776e65722d617070726f76652f7632005a54534d532f6c696e652f6465766963652d636f6e6669726d2f7632000201000000000000400080000000000000010000000000004000800000000000000200000000000040008000000000000003000000000000000100000000000040008000000000000004000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f00210002000000090200000000000040008000000000000012000000000000400080000000000000220000000000000000000000000000400080000000000000400000000000000001000000000000400080000000000000415cb5c1ffe46f30a376a458db0df5a22c56a81524beb26f9ccb9dbfb1f6edcd2b57093944c2f730f5d554173cb3555795c1a4f68c647be0ff8e3adb840b757675",
        device_digest_hex: "24dfca4f9a61ba0f9b95d4d1e8d4a74a6fffb686f28995c2757f6284e1aed199",
        owner_digest_hex: "5e361f22385e579650a5c4968e0028213bbfdcb88e6647ea6534042ddd42cbab",
    },
    Literal {
        name: "sms-dual-esim-same-card-slot-port1-selected",
        purpose: PurposeV2::Sms,
        generation: 1,
        observation_hex: "002100020000000a0200000000000040008000000000000012000000000000400080000000000000230000000100000000000000000000400080000000000000400000000000000001000000000000400080000000000000415cb5c1ffe46f30a376a458db0df5a22c56a81524beb26f9ccb9dbfb1f6edcd2b",
        device_hex: "5a54534d532f6c696e652f6465766963652d636f6e6669726d2f7632000201000000000000400080000000000000010000000000004000800000000000000200000000000040008000000000000003000000000000000100000000000040008000000000000004000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f002100020000000a0200000000000040008000000000000012000000000000400080000000000000230000000100000000000000000000400080000000000000400000000000000001000000000000400080000000000000415cb5c1ffe46f30a376a458db0df5a22c56a81524beb26f9ccb9dbfb1f6edcd2b",
        owner_hex: "5a54534d532f6c696e652f6f776e65722d617070726f76652f7632005a54534d532f6c696e652f6465766963652d636f6e6669726d2f7632000201000000000000400080000000000000010000000000004000800000000000000200000000000040008000000000000003000000000000000100000000000040008000000000000004000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f002100020000000a0200000000000040008000000000000012000000000000400080000000000000230000000100000000000000000000400080000000000000400000000000000001000000000000400080000000000000415cb5c1ffe46f30a376a458db0df5a22c56a81524beb26f9ccb9dbfb1f6edcd2b57093944c2f730f5d554173cb3555795c1a4f68c647be0ff8e3adb840b757675",
        device_digest_hex: "d050c43940833d993d3770fbab2b595a15333ec40daaaa43508fe8f56c27bbdd",
        owner_digest_hex: "9c7a6595c827fbaff5927e804d8c36564a6706a0effdfcac9753aa0b63051bbb",
    },
    Literal {
        name: "sealed-physical-selected-peer-esim-active",
        purpose: PurposeV2::Sealed,
        generation: 1,
        observation_hex: "0021000200000007010000000000004000800000000000001000000000000040008000000000000020000000000000000000000000000040008000000000000040000000000000000100000000000040008000000000000041893205abddcccbe664fcbba578beba84ba4a3354c5df1b39adc67d0dab5cc017",
        device_hex: "5a5453452f6c696e652f6465766963652d636f6e6669726d2f7632000202000000000000400080000000000000010000000000004000800000000000000200000000000040008000000000000003000000000000000100000000000040008000000000000004000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f0021000200000007010000000000004000800000000000001000000000000040008000000000000020000000000000000000000000000040008000000000000040000000000000000100000000000040008000000000000041893205abddcccbe664fcbba578beba84ba4a3354c5df1b39adc67d0dab5cc017",
        owner_hex: "5a5453452f6c696e652f6f776e65722d617070726f76652f7632005a5453452f6c696e652f6465766963652d636f6e6669726d2f7632000202000000000000400080000000000000010000000000004000800000000000000200000000000040008000000000000003000000000000000100000000000040008000000000000004000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f0021000200000007010000000000004000800000000000001000000000000040008000000000000020000000000000000000000000000040008000000000000040000000000000000100000000000040008000000000000041893205abddcccbe664fcbba578beba84ba4a3354c5df1b39adc67d0dab5cc01757093944c2f730f5d554173cb3555795c1a4f68c647be0ff8e3adb840b757675",
        device_digest_hex: "3c7b1130229eddcb39caa89d0598a1ac9e7b6730b8460166dec979eba4e5d782",
        owner_digest_hex: "c6981ff23c0f8142bcea2b1f021b41dd3770e6a0e0dd7ee664cfb55a1d43c9b0",
    },
    Literal {
        name: "sealed-esim-selected-peer-physical-active",
        purpose: PurposeV2::Sealed,
        generation: 1,
        observation_hex: "002100020000000b020000000000004000800000000000001100000000000040008000000000000021000000000000000100000000000040008000000000000040000000000000000100000000000040008000000000000041893205abddcccbe664fcbba578beba84ba4a3354c5df1b39adc67d0dab5cc017",
        device_hex: "5a5453452f6c696e652f6465766963652d636f6e6669726d2f7632000202000000000000400080000000000000010000000000004000800000000000000200000000000040008000000000000003000000000000000100000000000040008000000000000004000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f002100020000000b020000000000004000800000000000001100000000000040008000000000000021000000000000000100000000000040008000000000000040000000000000000100000000000040008000000000000041893205abddcccbe664fcbba578beba84ba4a3354c5df1b39adc67d0dab5cc017",
        owner_hex: "5a5453452f6c696e652f6f776e65722d617070726f76652f7632005a5453452f6c696e652f6465766963652d636f6e6669726d2f7632000202000000000000400080000000000000010000000000004000800000000000000200000000000040008000000000000003000000000000000100000000000040008000000000000004000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f002100020000000b020000000000004000800000000000001100000000000040008000000000000021000000000000000100000000000040008000000000000040000000000000000100000000000040008000000000000041893205abddcccbe664fcbba578beba84ba4a3354c5df1b39adc67d0dab5cc01757093944c2f730f5d554173cb3555795c1a4f68c647be0ff8e3adb840b757675",
        device_digest_hex: "9a40d2c8c783a7935ff8e1ddd606f32e07d65f640247f6693e64d476ea6e9cda",
        owner_digest_hex: "19e9fa31dc4673cb740987861d7c80cb509d341b022d8f4fa8afff4ce9a4f38f",
    },
    Literal {
        name: "sealed-dual-esim-same-card-slot-port0-selected",
        purpose: PurposeV2::Sealed,
        generation: 1,
        observation_hex: "00210002000000090200000000000040008000000000000012000000000000400080000000000000220000000000000000000000000000400080000000000000400000000000000001000000000000400080000000000000415cb5c1ffe46f30a376a458db0df5a22c56a81524beb26f9ccb9dbfb1f6edcd2b",
        device_hex: "5a5453452f6c696e652f6465766963652d636f6e6669726d2f7632000202000000000000400080000000000000010000000000004000800000000000000200000000000040008000000000000003000000000000000100000000000040008000000000000004000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f00210002000000090200000000000040008000000000000012000000000000400080000000000000220000000000000000000000000000400080000000000000400000000000000001000000000000400080000000000000415cb5c1ffe46f30a376a458db0df5a22c56a81524beb26f9ccb9dbfb1f6edcd2b",
        owner_hex: "5a5453452f6c696e652f6f776e65722d617070726f76652f7632005a5453452f6c696e652f6465766963652d636f6e6669726d2f7632000202000000000000400080000000000000010000000000004000800000000000000200000000000040008000000000000003000000000000000100000000000040008000000000000004000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f00210002000000090200000000000040008000000000000012000000000000400080000000000000220000000000000000000000000000400080000000000000400000000000000001000000000000400080000000000000415cb5c1ffe46f30a376a458db0df5a22c56a81524beb26f9ccb9dbfb1f6edcd2b57093944c2f730f5d554173cb3555795c1a4f68c647be0ff8e3adb840b757675",
        device_digest_hex: "eac8994b3c118e5878ad18f37df567eab5f7b65522f0f4d55f6d95ba338e4860",
        owner_digest_hex: "53726b301e35af2b5098ebf9c8a017bc3a7cd4b5c8f65a047a3c1de7f71384e5",
    },
    Literal {
        name: "sealed-dual-esim-same-card-slot-port1-selected",
        purpose: PurposeV2::Sealed,
        generation: 1,
        observation_hex: "002100020000000a0200000000000040008000000000000012000000000000400080000000000000230000000100000000000000000000400080000000000000400000000000000001000000000000400080000000000000415cb5c1ffe46f30a376a458db0df5a22c56a81524beb26f9ccb9dbfb1f6edcd2b",
        device_hex: "5a5453452f6c696e652f6465766963652d636f6e6669726d2f7632000202000000000000400080000000000000010000000000004000800000000000000200000000000040008000000000000003000000000000000100000000000040008000000000000004000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f002100020000000a0200000000000040008000000000000012000000000000400080000000000000230000000100000000000000000000400080000000000000400000000000000001000000000000400080000000000000415cb5c1ffe46f30a376a458db0df5a22c56a81524beb26f9ccb9dbfb1f6edcd2b",
        owner_hex: "5a5453452f6c696e652f6f776e65722d617070726f76652f7632005a5453452f6c696e652f6465766963652d636f6e6669726d2f7632000202000000000000400080000000000000010000000000004000800000000000000200000000000040008000000000000003000000000000000100000000000040008000000000000004000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f002100020000000a0200000000000040008000000000000012000000000000400080000000000000230000000100000000000000000000400080000000000000400000000000000001000000000000400080000000000000415cb5c1ffe46f30a376a458db0df5a22c56a81524beb26f9ccb9dbfb1f6edcd2b57093944c2f730f5d554173cb3555795c1a4f68c647be0ff8e3adb840b757675",
        device_digest_hex: "c0b1f74cee7b85f6dd1e3adf9011e1340936a1f0bf39a0f84588e4dae0d0fe0f",
        owner_digest_hex: "4be99a8e1ca49dd4a73e5a5576432ffbaf3f4ee1eea4255d4cc7ad2c5e003ee5",
    },
    Literal {
        name: "sms-count256-encoding-boundary-not-hardware-claim",
        purpose: PurposeV2::Sms,
        generation: 1,
        observation_hex: "00210100000000ff02000000000000400080000000000001ff000000000000400080000000000010ff00000000000000ff00000000000040008000000000000040000000000000000100000000000040008000000000000041db974c0a6bc2a924e87c076d5e5391ea1d4620636b185019a2b4122af3acb55b",
        device_hex: "5a54534d532f6c696e652f6465766963652d636f6e6669726d2f7632000201000000000000400080000000000000010000000000004000800000000000000200000000000040008000000000000003000000000000000100000000000040008000000000000004000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f00210100000000ff02000000000000400080000000000001ff000000000000400080000000000010ff00000000000000ff00000000000040008000000000000040000000000000000100000000000040008000000000000041db974c0a6bc2a924e87c076d5e5391ea1d4620636b185019a2b4122af3acb55b",
        owner_hex: "5a54534d532f6c696e652f6f776e65722d617070726f76652f7632005a54534d532f6c696e652f6465766963652d636f6e6669726d2f7632000201000000000000400080000000000000010000000000004000800000000000000200000000000040008000000000000003000000000000000100000000000040008000000000000004000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f00210100000000ff02000000000000400080000000000001ff000000000000400080000000000010ff00000000000000ff00000000000040008000000000000040000000000000000100000000000040008000000000000041db974c0a6bc2a924e87c076d5e5391ea1d4620636b185019a2b4122af3acb55b57093944c2f730f5d554173cb3555795c1a4f68c647be0ff8e3adb840b757675",
        device_digest_hex: "79f8e1349fd5f206a863b8a8bfda18f6a6d41cb14f43fb56c78e24dfa6579f02",
        owner_digest_hex: "6957bc7523d693619ef51ff6f69186223c761ab8660043429bdd64e5df89133d",
    },
    Literal {
        name: "sealed-positive-i64-maximum-encoding-boundary",
        purpose: PurposeV2::Sealed,
        generation: i64::MAX,
        observation_hex: "002100020000000a0200000000000040008000000000000012000000000000400080000000000000230000000100000000000000000000400080000000000000407fffffffffffffff00000000000040008000000000000041a10f35a0ef007c113f0a889b0442984aa728fbf2022427bacaf7e8f5bf10b403",
        device_hex: "5a5453452f6c696e652f6465766963652d636f6e6669726d2f76320002020000000000004000800000000000000100000000000040008000000000000002000000000000400080000000000000037fffffffffffffff00000000000040008000000000000004000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f002100020000000a0200000000000040008000000000000012000000000000400080000000000000230000000100000000000000000000400080000000000000407fffffffffffffff00000000000040008000000000000041a10f35a0ef007c113f0a889b0442984aa728fbf2022427bacaf7e8f5bf10b403",
        owner_hex: "5a5453452f6c696e652f6f776e65722d617070726f76652f7632005a5453452f6c696e652f6465766963652d636f6e6669726d2f76320002020000000000004000800000000000000100000000000040008000000000000002000000000000400080000000000000037fffffffffffffff00000000000040008000000000000004000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f002100020000000a0200000000000040008000000000000012000000000000400080000000000000230000000100000000000000000000400080000000000000407fffffffffffffff00000000000040008000000000000041a10f35a0ef007c113f0a889b0442984aa728fbf2022427bacaf7e8f5bf10b40357093944c2f730f5d554173cb3555795c1a4f68c647be0ff8e3adb840b757675",
        device_digest_hex: "110ea36ec8cc8f42c9f3867689dfaa4bcedd51c195e099f9d82c3c5bce2b2be9",
        owner_digest_hex: "671e6b565948b1fb2e64700a334e03b2743e33e2810daab06f3a0e2b62d4fe51",
    },
    Literal {
        name: "sms-same-count-peer-replacement",
        purpose: PurposeV2::Sms,
        generation: 1,
        observation_hex: "0021000200000007010000000000004000800000000000001000000000000040008000000000000020000000000000000000000000000040008000000000000040000000000000000100000000000040008000000000000041db062bc2f8535bbf32bc07507505e67745611fc360c480cda114f3e52ea1f20b",
        device_hex: "5a54534d532f6c696e652f6465766963652d636f6e6669726d2f7632000201000000000000400080000000000000010000000000004000800000000000000200000000000040008000000000000003000000000000000100000000000040008000000000000004000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f0021000200000007010000000000004000800000000000001000000000000040008000000000000020000000000000000000000000000040008000000000000040000000000000000100000000000040008000000000000041db062bc2f8535bbf32bc07507505e67745611fc360c480cda114f3e52ea1f20b",
        owner_hex: "5a54534d532f6c696e652f6f776e65722d617070726f76652f7632005a54534d532f6c696e652f6465766963652d636f6e6669726d2f7632000201000000000000400080000000000000010000000000004000800000000000000200000000000040008000000000000003000000000000000100000000000040008000000000000004000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f0021000200000007010000000000004000800000000000001000000000000040008000000000000020000000000000000000000000000040008000000000000040000000000000000100000000000040008000000000000041db062bc2f8535bbf32bc07507505e67745611fc360c480cda114f3e52ea1f20b57093944c2f730f5d554173cb3555795c1a4f68c647be0ff8e3adb840b757675",
        device_digest_hex: "f9126ccf1dc360944224bd1caab82a57637f86c25b18960968c318d5258b278b",
        owner_digest_hex: "73a14696ec33a3716831b6bd39a7882a126b6cd39c53350cc809ad0f4c5693c3",
    },
];

fn unhex(text: &str) -> Vec<u8> {
    fn digit(byte: u8) -> u8 {
        match byte {
            b'0'..=b'9' => byte - b'0',
            b'a'..=b'f' => byte - b'a' + 10,
            _ => panic!("invalid synthetic hex"),
        }
    }
    assert_eq!(text.len() % 2, 0);
    text.as_bytes()
        .chunks_exact(2)
        .map(|pair| digit(pair[0]) * 16 + digit(pair[1]))
        .collect()
}

fn challenge(generation: i64) -> LineChallenge {
    let id = |suffix| Uuid::from_u128(0x40008000000000000000 | suffix);
    LineChallenge {
        account_id: id(1),
        line_id: id(2),
        device_id: id(3),
        generation,
        id: id(4),
        nonce: std::array::from_fn(|index| index as u8),
    }
}

fn raw_observation() -> [u8; OBSERVATION_BYTES] {
    unhex(LITERALS[0].observation_hex).try_into().unwrap()
}

fn observation() -> ObservationV2 {
    ObservationV2::decode(&raw_observation()).unwrap()
}

struct SignedDeclarations {
    device: DeviceStatementBytesV2,
    owner: OwnerStatementBytesV2,
    device_key: Vec<u8>,
    owner_key: Vec<u8>,
    device_der: Vec<u8>,
    owner_der: Vec<u8>,
}

fn signed(purpose: PurposeV2) -> SignedDeclarations {
    let device_key = SigningKey::generate_from_rng(&mut rng());
    let owner_key = SigningKey::generate_from_rng(&mut rng());
    let device = device_statement(purpose, &challenge(1), &observation()).unwrap();
    let signature: Signature = device_key.sign(&device.bytes());
    let device_der = signature.to_der().as_bytes().to_vec();
    let owner = owner_statement(&device, &device_der).unwrap();
    let signature: Signature = owner_key.sign(&owner.bytes());
    let owner_der = signature.to_der().as_bytes().to_vec();
    SignedDeclarations {
        device,
        owner,
        device_key: device_key
            .verifying_key()
            .to_encoded_point(false)
            .as_bytes()
            .to_vec(),
        owner_key: owner_key
            .verifying_key()
            .to_encoded_point(false)
            .as_bytes()
            .to_vec(),
        device_der,
        owner_der,
    }
}

#[test]
fn every_literal_has_exact_observation_device_and_owner_bytes() {
    for literal in &LITERALS {
        let raw = unhex(literal.observation_hex);
        let observation = ObservationV2::decode(&raw).unwrap();
        assert_eq!(
            observation.encode().as_slice(),
            raw.as_slice(),
            "{}",
            literal.name
        );
        let device = device_statement(
            literal.purpose,
            &challenge(literal.generation),
            &observation,
        )
        .unwrap();
        assert_eq!(
            device.bytes(),
            unhex(literal.device_hex),
            "{}",
            literal.name
        );
        assert_eq!(device.purpose(), literal.purpose);
        assert_eq!(
            digest(&device.bytes()).as_slice(),
            unhex(literal.device_digest_hex)
        );
        assert!(
            DeviceStatementBytesV2::decode(literal.purpose, &device.bytes()).unwrap() == device
        );
        let owner = owner_statement(&device, ENCODING_DER).unwrap();
        assert_eq!(owner.bytes(), unhex(literal.owner_hex), "{}", literal.name);
        assert_eq!(owner.purpose(), literal.purpose);
        assert_eq!(
            digest(&owner.bytes()).as_slice(),
            unhex(literal.owner_digest_hex)
        );
        let mut combined = device.bytes();
        combined.extend_from_slice(ENCODING_DER);
        assert_eq!(
            proof_digest(&device, ENCODING_DER).unwrap(),
            digest(&combined)
        );
    }
}

#[test]
fn decoded_observation_preserves_the_complete_declared_selection() {
    let value = observation();
    assert_eq!(value.android_api_level(), 33);
    assert_eq!(value.active_subscription_count(), 2);
    assert_eq!(value.selected_subscription_id(), 7);
    assert_eq!(value.selected_kind(), SelectedKindV2::Physical);
    assert_eq!(
        value.selected_card_token(),
        Uuid::from_u128(0x40008000000000000010)
    );
    assert_eq!(
        value.selected_profile_token(),
        Uuid::from_u128(0x40008000000000000020)
    );
    assert_eq!(value.selected_port_index(), 0);
    assert_eq!(value.selected_slot_index(), 0);
    assert_eq!(
        value.monitor_lifetime_id(),
        Uuid::from_u128(0x40008000000000000040)
    );
    assert_eq!(value.observer_epoch(), 1);
    assert_eq!(
        value.selected_lease_id(),
        Uuid::from_u128(0x40008000000000000041)
    );
    assert_eq!(
        value.complete_set_sha256().as_slice(),
        &raw_observation()[89..]
    );
}

#[test]
fn shared_card_and_slot_keep_distinct_esim_profiles_and_ports() {
    let first = ObservationV2::decode(&unhex(LITERALS[2].observation_hex)).unwrap();
    let second = ObservationV2::decode(&unhex(LITERALS[3].observation_hex)).unwrap();
    assert_eq!(first.selected_kind(), SelectedKindV2::Embedded);
    assert_eq!(second.selected_kind(), SelectedKindV2::Embedded);
    assert_eq!(first.active_subscription_count(), 2);
    assert_eq!(second.active_subscription_count(), 2);
    assert_eq!(first.selected_card_token(), second.selected_card_token());
    assert_eq!(first.selected_slot_index(), second.selected_slot_index());
    assert_ne!(
        first.selected_profile_token(),
        second.selected_profile_token()
    );
    assert_ne!(first.selected_port_index(), second.selected_port_index());
    assert_eq!(first.complete_set_sha256(), second.complete_set_sha256());
}

#[test]
fn same_count_peer_replacement_changes_the_signed_declaration() {
    let first = observation();
    let replacement = ObservationV2::decode(&unhex(LITERALS[10].observation_hex)).unwrap();
    assert_eq!(
        first.active_subscription_count(),
        replacement.active_subscription_count()
    );
    assert_eq!(
        first.selected_profile_token(),
        replacement.selected_profile_token()
    );
    assert_ne!(
        first.complete_set_sha256(),
        replacement.complete_set_sha256()
    );
    assert!(
        device_statement(PurposeV2::Sms, &challenge(1), &first).unwrap()
            != device_statement(PurposeV2::Sms, &challenge(1), &replacement).unwrap()
    );
}

#[test]
fn observation_refuses_truncation_and_trailing_bytes() {
    let raw = raw_observation();
    for length in 0..OBSERVATION_BYTES {
        assert!(ObservationV2::decode(&raw[..length]).is_err());
    }
    let mut extra = raw.to_vec();
    extra.push(0);
    assert!(ObservationV2::decode(&extra).is_err());
}

#[test]
fn observation_refuses_old_api_and_out_of_range_counts() {
    for api in [0u16, 28, 31, 32] {
        let mut raw = raw_observation();
        raw[..2].copy_from_slice(&api.to_be_bytes());
        assert!(ObservationV2::decode(&raw).is_err());
    }
    for count in [0u16, 257, u16::MAX] {
        let mut raw = raw_observation();
        raw[2..4].copy_from_slice(&count.to_be_bytes());
        assert!(ObservationV2::decode(&raw).is_err());
    }
}

#[test]
fn observation_refuses_unknown_kind_negative_mapping_and_epoch() {
    for kind in [0, 3, u8::MAX] {
        let mut raw = raw_observation();
        raw[8] = kind;
        assert!(ObservationV2::decode(&raw).is_err());
    }
    for offset in [4, 41, 45] {
        for value in [-1i32, i32::MIN] {
            let mut raw = raw_observation();
            raw[offset..offset + 4].copy_from_slice(&value.to_be_bytes());
            assert!(ObservationV2::decode(&raw).is_err());
        }
    }
    for epoch in [0i64, -1, i64::MIN] {
        let mut raw = raw_observation();
        raw[65..73].copy_from_slice(&epoch.to_be_bytes());
        assert!(ObservationV2::decode(&raw).is_err());
    }
}

#[test]
fn observation_refuses_nil_tokens_and_accepts_nonnil_without_uuid_version_inference() {
    for offset in [9, 25, 49, 73] {
        let mut raw = raw_observation();
        raw[offset..offset + 16].fill(0);
        assert!(ObservationV2::decode(&raw).is_err());
    }
    let mut raw = raw_observation();
    raw[9..25].copy_from_slice(Uuid::from_u128(1).as_bytes());
    assert_eq!(
        ObservationV2::decode(&raw).unwrap().selected_card_token(),
        Uuid::from_u128(1)
    );
}

#[test]
fn observation_encodes_unsigned_counts_and_positive_integer_maxima() {
    let mut raw = raw_observation();
    raw[..2].copy_from_slice(&u16::MAX.to_be_bytes());
    raw[2..4].copy_from_slice(&256u16.to_be_bytes());
    for offset in [4, 41, 45] {
        raw[offset..offset + 4].copy_from_slice(&i32::MAX.to_be_bytes());
    }
    raw[65..73].copy_from_slice(&i64::MAX.to_be_bytes());
    let value = ObservationV2::decode(&raw).unwrap();
    assert_eq!(value.encode(), raw);
    assert_eq!(value.active_subscription_count(), 256);
    assert_eq!(value.observer_epoch(), i64::MAX);
    assert_eq!(value.selected_subscription_id(), i32::MAX);
}

#[test]
fn declaration_codec_does_not_claim_nonce_issuance_or_digest_preimage() {
    let mut raw = raw_observation();
    raw[89..].fill(0);
    let value = ObservationV2::decode(&raw).unwrap();
    assert_eq!(value.complete_set_sha256(), [0; 32]);
    let mut fields = challenge(1);
    fields.nonce.fill(0);
    for purpose in [PurposeV2::Sms, PurposeV2::Sealed] {
        let device = device_statement(purpose, &fields, &value).unwrap();
        assert!(DeviceStatementBytesV2::decode(purpose, &device.bytes()).is_ok());
    }
}

#[test]
fn challenge_encoding_refuses_nil_identities_and_nonpositive_generation() {
    for field in 0..4 {
        let mut value = challenge(1);
        match field {
            0 => value.account_id = Uuid::nil(),
            1 => value.line_id = Uuid::nil(),
            2 => value.device_id = Uuid::nil(),
            _ => value.id = Uuid::nil(),
        }
        for purpose in [PurposeV2::Sms, PurposeV2::Sealed] {
            assert!(device_statement(purpose, &value, &observation()).is_err());
        }
    }
    for generation in [0, -1, i64::MIN] {
        assert!(device_statement(PurposeV2::Sms, &challenge(generation), &observation()).is_err());
    }
}

#[test]
fn device_decode_refuses_wrong_domain_version_purpose_and_length() {
    for purpose in [PurposeV2::Sms, PurposeV2::Sealed] {
        let statement = device_statement(purpose, &challenge(1), &observation()).unwrap();
        let raw = statement.bytes();
        let other = if purpose == PurposeV2::Sms {
            PurposeV2::Sealed
        } else {
            PurposeV2::Sms
        };
        assert!(DeviceStatementBytesV2::decode(other, &raw).is_err());
        for offset in [
            0,
            purpose.device_domain().len(),
            purpose.device_domain().len() + 1,
        ] {
            let mut changed = raw.clone();
            changed[offset] ^= 1;
            assert!(DeviceStatementBytesV2::decode(purpose, &changed).is_err());
        }
        for length in 0..raw.len() {
            assert!(DeviceStatementBytesV2::decode(purpose, &raw[..length]).is_err());
        }
        let mut trailing = raw.clone();
        trailing.push(0);
        assert!(DeviceStatementBytesV2::decode(purpose, &trailing).is_err());
    }
}

#[test]
fn device_decode_revalidates_challenge_and_observation_fields() {
    for purpose in [PurposeV2::Sms, PurposeV2::Sealed] {
        let raw = device_statement(purpose, &challenge(1), &observation())
            .unwrap()
            .bytes();
        let start = purpose.device_domain().len() + 2;
        for offset in [0, 16, 32, 56] {
            let mut changed = raw.clone();
            changed[start + offset..start + offset + 16].fill(0);
            assert!(DeviceStatementBytesV2::decode(purpose, &changed).is_err());
        }
        for generation in [0i64, -1, i64::MIN] {
            let mut changed = raw.clone();
            changed[start + 48..start + 56].copy_from_slice(&generation.to_be_bytes());
            assert!(DeviceStatementBytesV2::decode(purpose, &changed).is_err());
        }
        let mut changed = raw.clone();
        changed[start + CHALLENGE_BYTES + 8] = 3;
        assert!(DeviceStatementBytesV2::decode(purpose, &changed).is_err());
    }
}

#[test]
fn input_and_returned_byte_copies_cannot_mutate_prior_encodings() {
    let mut raw = raw_observation();
    let value = ObservationV2::decode(&raw).unwrap();
    raw.fill(0);
    assert_eq!(value.encode(), raw_observation());
    let mut returned = value.encode();
    returned.fill(0);
    let mut fields = challenge(1);
    let device = device_statement(PurposeV2::Sms, &fields, &value).unwrap();
    let mut bytes = device.bytes();
    let decoded = DeviceStatementBytesV2::decode(PurposeV2::Sms, &bytes).unwrap();
    let owner = owner_statement(&decoded, ENCODING_DER).unwrap();
    fields.nonce.fill(0);
    bytes.fill(0);
    let mut owner_copy = owner.bytes();
    owner_copy.fill(0);
    let mut digest_copy = value.complete_set_sha256();
    digest_copy.fill(0);
    assert_eq!(device.bytes(), unhex(LITERALS[0].device_hex));
    assert_eq!(decoded.bytes(), device.bytes());
    assert_eq!(owner.bytes(), unhex(LITERALS[0].owner_hex));
    assert_eq!(value.encode(), raw_observation());
}

#[test]
fn owner_and_audit_digest_refuse_malformed_noncanonical_or_oversized_der() {
    let device = device_statement(PurposeV2::Sms, &challenge(1), &observation()).unwrap();
    let cases = [
        vec![],
        vec![0; 7],
        vec![0; 81],
        vec![0x30, 7, 2, 2, 0, 1, 2, 1, 1],
        vec![0x30, 6, 2, 1, 0, 2, 1, 1],
        vec![0x30, 6, 2, 1, 0x80, 2, 1, 1],
        vec![0x31, 6, 2, 1, 1, 2, 1, 1],
        vec![0x30, 5, 2, 1, 1, 2, 1, 1],
        vec![0x30, 0x81, 6, 2, 1, 1, 2, 1, 1],
        vec![0x30, 6, 2, 1, 1, 2, 1, 1, 0],
    ];
    for der in cases {
        assert!(owner_statement(&device, &der).is_err());
        assert!(proof_digest(&device, &der).is_err());
    }
}

#[test]
fn genuine_device_and_owner_signatures_verify_for_each_distinct_purpose() {
    for purpose in [PurposeV2::Sms, PurposeV2::Sealed] {
        let value = signed(purpose);
        assert!(verify_device_signature(
            &value.device_key,
            &value.device,
            &value.device_der
        ));
        assert!(verify_owner_signature(
            &value.owner_key,
            &value.owner,
            &value.owner_der
        ));
        assert!(!verify_device_signature(
            &value.owner_key,
            &value.device,
            &value.device_der
        ));
        assert!(!verify_owner_signature(
            &value.device_key,
            &value.owner,
            &value.owner_der
        ));
        assert!(!verify_device_signature(
            &value.device_key,
            &value.device,
            &value.owner_der
        ));
        assert!(!verify_owner_signature(
            &value.owner_key,
            &value.owner,
            &value.device_der
        ));
        assert!(!verify_device_signature(
            &value.device_key,
            &value.device,
            ENCODING_DER
        ));
    }
}

#[test]
fn signatures_refuse_cross_purpose_transcripts() {
    for purpose in [PurposeV2::Sms, PurposeV2::Sealed] {
        let value = signed(purpose);
        let other = if purpose == PurposeV2::Sms {
            PurposeV2::Sealed
        } else {
            PurposeV2::Sms
        };
        let device = device_statement(other, &challenge(1), &observation()).unwrap();
        let owner = owner_statement(&device, &value.device_der).unwrap();
        assert!(!verify_device_signature(
            &value.device_key,
            &device,
            &value.device_der
        ));
        assert!(!verify_owner_signature(
            &value.owner_key,
            &owner,
            &value.owner_der
        ));
    }
}

#[test]
fn device_signature_binds_every_original_challenge_identity_generation_and_nonce() {
    for purpose in [PurposeV2::Sms, PurposeV2::Sealed] {
        let value = signed(purpose);
        for field in 0..6 {
            let mut fields = challenge(1);
            match field {
                0 => fields.account_id = Uuid::from_u128(99),
                1 => fields.line_id = Uuid::from_u128(99),
                2 => fields.device_id = Uuid::from_u128(99),
                3 => fields.id = Uuid::from_u128(99),
                4 => fields.generation = 2,
                _ => fields.nonce[0] ^= 1,
            }
            let changed = device_statement(purpose, &fields, &observation()).unwrap();
            assert!(!verify_device_signature(
                &value.device_key,
                &changed,
                &value.device_der
            ));
        }
    }
}

#[test]
fn device_signature_binds_every_observation_field_including_peer_commitment() {
    for purpose in [PurposeV2::Sms, PurposeV2::Sealed] {
        let value = signed(purpose);
        for offset in [1, 3, 7, 8, 24, 40, 44, 48, 64, 72, 88, 120] {
            let mut raw = raw_observation();
            match offset {
                1 => raw[..2].copy_from_slice(&34u16.to_be_bytes()),
                8 => raw[8] = 2,
                72 => raw[65..73].copy_from_slice(&2i64.to_be_bytes()),
                _ => raw[offset] ^= 1,
            }
            let changed = ObservationV2::decode(&raw).unwrap();
            let device = device_statement(purpose, &challenge(1), &changed).unwrap();
            assert!(!verify_device_signature(
                &value.device_key,
                &device,
                &value.device_der
            ));
        }
    }
}

#[test]
fn owner_signature_binds_the_exact_canonical_device_signature_digest() {
    for purpose in [PurposeV2::Sms, PurposeV2::Sealed] {
        let value = signed(purpose);
        let changed_owner = owner_statement(&value.device, ENCODING_DER).unwrap();
        assert!(!verify_owner_signature(
            &value.owner_key,
            &changed_owner,
            &value.owner_der
        ));
        assert_ne!(
            proof_digest(&value.device, &value.device_der).unwrap(),
            proof_digest(&value.device, ENCODING_DER).unwrap()
        );
    }
}

#[test]
fn signature_adapters_refuse_bad_keys_trailing_and_noncanonical_der() {
    for purpose in [PurposeV2::Sms, PurposeV2::Sealed] {
        let value = signed(purpose);
        for key in [vec![], vec![0; 65], vec![4; 64]] {
            assert!(!verify_device_signature(
                &key,
                &value.device,
                &value.device_der
            ));
            assert!(!verify_owner_signature(
                &key,
                &value.owner,
                &value.owner_der
            ));
        }
        let mut device_trailing = value.device_der.clone();
        device_trailing.push(0);
        let mut owner_trailing = value.owner_der.clone();
        owner_trailing.push(0);
        assert!(!verify_device_signature(
            &value.device_key,
            &value.device,
            &device_trailing
        ));
        assert!(!verify_owner_signature(
            &value.owner_key,
            &value.owner,
            &owner_trailing
        ));
        let noncanonical = [0x30, 7, 2, 2, 0, 1, 2, 1, 1];
        assert!(!verify_device_signature(
            &value.device_key,
            &value.device,
            &noncanonical
        ));
        assert!(!verify_owner_signature(
            &value.owner_key,
            &value.owner,
            &noncanonical
        ));
    }
}

#[test]
fn v2_decode_refuses_v1_bytes_and_v1_still_refuses_multiple_subscriptions() {
    let fields = challenge(1);
    let legacy = super::super::sms_device_line_statement(
        &fields,
        super::super::SimObservation {
            android_api_level: 28,
            active_subscription_count: 1,
            selected_subscription_id: 7,
        },
    )
    .unwrap();
    assert_eq!(legacy.len(), 140);
    assert!(DeviceStatementBytesV2::decode(PurposeV2::Sms, &legacy).is_err());
    assert!(
        super::super::sms_device_line_statement(
            &fields,
            super::super::SimObservation {
                android_api_level: 33,
                active_subscription_count: 2,
                selected_subscription_id: 7,
            }
        )
        .is_err()
    );
}

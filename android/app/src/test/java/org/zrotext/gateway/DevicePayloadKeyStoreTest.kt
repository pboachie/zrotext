// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertThrows
import org.junit.Test

class DevicePayloadKeyStoreTest {
    @Test fun sealedPayloadFloorExcludesApi28Through30() {
        for (api in 28..30) {
            assertThrows(IllegalArgumentException::class.java) {
                DevicePayloadKeyStore.requireSupportedSdk(api)
            }
        }
        DevicePayloadKeyStore.requireSupportedSdk(31)
    }

    @Test fun rfcP256PointHasDraftKeyIdAndInvalidPointsFail() {
        // RFC 9180 Appendix A.3.1 recipient point; expected digest computed separately.
        val point = hex("04fe8c19ce0905191ebc298a9245792531f26f0cece2460639e8bc39cb7f706a8" +
            "26a779b4cf969b8a0e539c7f62fb3d30ad6aa8f80e30f1d128aafd68a2ce72ea0")
        assertArrayEquals(hex("94d899599eb561fa19bf9d1bf19aad69634844069e08b0466fc3736840758851"),
            DevicePayloadKeyStore.keyId(point))
        assertThrows(IllegalArgumentException::class.java) { DevicePayloadKeyStore.keyId(point.copyOf(64)) }
        assertThrows(IllegalArgumentException::class.java) {
            DevicePayloadKeyStore.keyId(point.clone().apply { this[0] = 2 })
        }
        assertThrows(IllegalArgumentException::class.java) {
            DevicePayloadKeyStore.keyId(point.clone().apply { this[64] = (this[64].toInt() xor 1).toByte() })
        }
    }

    private fun hex(value: String): ByteArray = value.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
}

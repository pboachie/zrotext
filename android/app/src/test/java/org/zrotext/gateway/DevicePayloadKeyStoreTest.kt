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

    @Test fun scopedPublicMetadataIsDefensiveAndExpiresWithoutRetainingAHandle() {
        val point = hex("04fe8c19ce0905191ebc298a9245792531f26f0cece2460639e8bc39cb7f706a8" +
            "26a779b4cf969b8a0e539c7f62fb3d30ad6aa8f80e30f1d128aafd68a2ce72ea0")
        val id = DevicePayloadKeyStore.keyId(point)
        val identity = DevicePayloadPublic(point, id, PayloadKeySecurity.SOFTWARE)
        point.fill(0); id.fill(0)
        val pin = identity.keyId
        val source = object : PayloadKeyCustodySource<DevicePayloadPublic> {
            override fun load() = identity
            override fun keyId(material: DevicePayloadPublic) = material.keyId
            override fun requireSameIdentity(initial: DevicePayloadPublic, current: DevicePayloadPublic) =
                DevicePayloadKeyStore.requireSamePublicIdentity(initial, current)
        }
        val store = object : PayloadKeyRecordStore {
            override fun <T> locked(operation: (PayloadKeyRecordAccess) -> T): T =
                operation(object : PayloadKeyRecordAccess {
                    override fun read() = PayloadKeyRecord.Bound(pin)
                    override fun write(record: PayloadKeyRecord) = error("Unexpected write")
                })
        }
        val saved = PayloadKeyLifecycle(store).scopedExisting(pin, source) { material, scope ->
            ScopedPayloadRecipient(scope, material).also { recipient ->
                recipient.publicIdentity().point.fill(0)
                recipient.publicIdentity().keyId.fill(0)
                assertArrayEquals(pin, recipient.publicIdentity().keyId)
                recipient.revalidateLocalIdentity()
            }
        }
        assertThrows(IllegalStateException::class.java) { saved.publicIdentity() }
        assertThrows(IllegalStateException::class.java) { saved.revalidateLocalIdentity() }
    }

    @Test fun actualPublicIdentityComparisonRefusesPointKeyIdAndSecurityChanges() {
        val point = hex("04fe8c19ce0905191ebc298a9245792531f26f0cece2460639e8bc39cb7f706a8" +
            "26a779b4cf969b8a0e539c7f62fb3d30ad6aa8f80e30f1d128aafd68a2ce72ea0")
        val id = DevicePayloadKeyStore.keyId(point)
        val initial = DevicePayloadPublic(point, id, PayloadKeySecurity.SOFTWARE)
        DevicePayloadKeyStore.requireSamePublicIdentity(initial,
            DevicePayloadPublic(point, id, PayloadKeySecurity.SOFTWARE))
        for (changed in listOf(
            DevicePayloadPublic(point.clone().apply { this[64] = (this[64].toInt() xor 1).toByte() }, id, PayloadKeySecurity.SOFTWARE),
            DevicePayloadPublic(point, id.clone().apply { this[0] = (this[0].toInt() xor 1).toByte() }, PayloadKeySecurity.SOFTWARE),
            DevicePayloadPublic(point, id, PayloadKeySecurity.TRUSTED_ENVIRONMENT))) {
            assertThrows(IllegalStateException::class.java) {
                DevicePayloadKeyStore.requireSamePublicIdentity(initial, changed)
            }
        }
    }

    private fun hex(value: String): ByteArray = value.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
}

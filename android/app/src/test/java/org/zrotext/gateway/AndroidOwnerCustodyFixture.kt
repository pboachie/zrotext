// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import java.nio.ByteBuffer
import java.util.UUID

/** Synthetic public framing for managed lifecycle tests; fake ciphertext proves no cryptography. */
internal object AndroidOwnerCustodyFixture {
    val account: UUID = UUID.fromString("11111111-1111-4111-8111-111111111111")
    val user: UUID = UUID.fromString("22222222-2222-4222-8222-222222222222")
    val session: UUID = UUID.fromString("33333333-3333-4333-8333-333333333333")
    const val origin = "https://owner.invalid"
    val token get() = ("ZTRK1-" + "AAAA-".repeat(13) + "00000000").toByteArray(Charsets.US_ASCII)
    val kit: AndroidOwnerCustodyKit get() {
        val originBytes = origin.toByteArray(Charsets.US_ASCII)
        val pin = ByteBuffer.allocate(94).put(byteArrayOf(90, 84, 82, 80, 2)).put(uuid(account)).putLong(1)
            .put(4).put(ByteArray(64) { 7 }).array()
        val fingerprint = AndroidOwnerCustodyKit.hash("ZTSE/root-pin/v2\u0000".toByteArray() + pin)
        val backup = ByteBuffer.allocate(236 + originBytes.size).put(byteArrayOf(90, 84, 82, 66, 1, 1))
            .put(uuid(UUID.fromString("44444444-4444-4444-8444-444444444444"))).put(uuid(account)).putLong(1)
            .put(fingerprint).putShort(originBytes.size.toShort()).put(originBytes).array()
        ByteBuffer.wrap(backup, 184 + originBytes.size, 4).putInt(48)
        val card = ByteBuffer.allocate(133 + originBytes.size).put(byteArrayOf(90, 84, 82, 67, 1))
            .putShort(originBytes.size.toShort()).put(originBytes).put(pin).put(AndroidOwnerCustodyKit.hash(backup)).array()
        return AndroidOwnerCustodyKit(backup, card)
    }
    fun authority() = AndroidOwnerCustodyAuthority(account, user, session, 2000, 100, 0)
    fun uuid(id: UUID): ByteArray = ByteBuffer.allocate(16).putLong(id.mostSignificantBits).putLong(id.leastSignificantBits).array()
    fun challenge(): ByteArray {
        val originBytes = origin.toByteArray()
        return ByteBuffer.allocate(151 + originBytes.size).put(byteArrayOf(90, 84, 82, 69, 1))
            .put(uuid(account)).put(uuid(user)).put(uuid(session))
            .put(uuid(UUID.fromString("55555555-5555-4555-8555-555555555555")))
            .put(ByteArray(32) { 9 }).put(kit.identity.fingerprintBytes()).putLong(1000).putLong(61000)
            .putShort(originBytes.size.toShort()).put(originBytes).array()
    }
}

// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import java.security.MessageDigest
import java.util.UUID
import org.junit.Assert.*
import org.junit.Test

/** Configured names only. No origin object is an authentication or effect capability. */
class Profile03OriginsTest {
    private val account = UUID(0, 1)
    private val device = UUID(0, 2)
    private fun sha(value: String) = MessageDigest.getInstance("SHA-256").digest(value.toByteArray())
    private fun session(origin: Profile03Origins) = SealedDispatchExecutor.Session(account, device, 7, 1, UUID(0, 3), origin.routingHash)
    private fun replacement(original: SealedDispatchExecutor.Session, accountId: UUID = original.accountId,
        deviceId: UUID = original.deviceId, originHash: String = original.originHash) =
        SealedDispatchExecutor.Session(accountId, deviceId, original.connectionEpoch, original.deploymentEpoch, original.sessionId, originHash)

    @Test fun actualStreamDerivationKeepsCanonicalHttpsAndExistingWssIdentitiesDistinct() {
        for ((stream, protocol, routing) in listOf(
            Triple("wss://Gateway.example.test/device?profile=3", "https://gateway.example.test", "wss://gateway.example.test:443"),
            Triple("wss://gateway.example.test:443/other", "https://gateway.example.test", "wss://gateway.example.test:443"),
            Triple("wss://gateway.example.test:9443/device", "https://gateway.example.test:9443", "wss://gateway.example.test:9443"))) {
            val actual = Profile03Origins.fromStream(account, device, stream)
            assertEquals(protocol, actual.protocolOrigin)
            assertArrayEquals(sha(protocol), actual.protocolDigest())
            assertEquals(Draft02OutboundPreparation.hex(sha(routing)), actual.routingHash)
            assertNotEquals(actual.protocolHash, actual.routingHash)
            assertEquals(EvidenceIdentity.fromStream(account, device, stream), actual.routing)
            actual.requireProtocol(sha(protocol), session(actual))
            val bytes = actual.protocolDigest(); bytes.fill(0)
            assertArrayEquals(sha(protocol), actual.protocolDigest())
        }
    }

    @Test fun anotherHostPortAccountDeviceOrProtocolDigestCannotRebindTheSession() {
        val actual = Profile03Origins.fromStream(account, device, "wss://gateway.example.test/device")
        for (stream in listOf("wss://other.example.test/device", "wss://gateway.example.test:9443/device")) {
            val other = Profile03Origins.fromStream(account, device, stream)
            assertThrows(IllegalArgumentException::class.java) { actual.requireSession(session(other)) }
            assertThrows(IllegalArgumentException::class.java) { actual.requireProtocol(other.protocolDigest(), session(actual)) }
        }
        val original = session(actual)
        assertThrows(IllegalArgumentException::class.java) { actual.requireSession(replacement(original, accountId = UUID(0, 9))) }
        assertThrows(IllegalArgumentException::class.java) { actual.requireSession(replacement(original, deviceId = UUID(0, 9))) }
        assertThrows(IllegalArgumentException::class.java) { actual.requireProtocol(sha("wss://gateway.example.test:443"), original) }
        assertThrows(IllegalArgumentException::class.java) { actual.requireSession(replacement(original, originHash = actual.protocolHash)) }
    }

    @Test fun schemesUserInfoFragmentsAndNoncanonicalProtocolNamesRefuse() {
        for (stream in listOf("https://gateway.example.test/device", "ws://gateway.example.test/device",
            "wss://user@gateway.example.test/device", "wss://:secret@gateway.example.test/device",
            "wss://@gateway.example.test/device", "wss://gateway.example.test:0/device",
            "wss://gateway.example.test:65536/device", "wss://gateway.example.test/device#other"))
            assertThrows(IllegalArgumentException::class.java) { Profile03Origins.fromStream(account, device, stream) }
        for (protocol in listOf("wss://gateway.example.test", "http://gateway.example.test", "https://gateway.example.test/",
            "https://gateway.example.test/path", "https://gateway.example.test?query=1", "https://gateway.example.test:443"))
            assertThrows(IllegalArgumentException::class.java) { Profile03Origins.fromProtocol(account, device, protocol) }
        val actual = Profile03Origins.fromProtocol(account, device, "https://gateway.example.test")
        assertEquals(EvidenceIdentity.fromStream(account, device, "wss://gateway.example.test/device").originHash, actual.routingHash)
    }
}

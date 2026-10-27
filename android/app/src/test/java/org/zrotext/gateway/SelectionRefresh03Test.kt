// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import java.math.BigInteger
import java.nio.ByteBuffer
import java.util.UUID
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

/** Real synthetic public proofs only; no held owner, database acceptance, custody or live permit. */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34], application = android.app.Application::class)
class SelectionRefresh03Test {
    @Test fun independentPublicVectorMatchesAndroidExactProofsAndAllThreeSignatures() {
        val vector = javaClass.classLoader!!.getResourceAsStream("sealed-profile03-selection-refresh-01.json")!!.use {
            org.json.JSONObject(it.bufferedReader().readText())
        }
        fun value(name: String) = vector.getString(name).chunked(2).map { it.toInt(16).toByte() }.toByteArray()
        val core = SelectionRefresh03.Core.decode(value("core"))
        val bundle = SelectionRefresh03.Bundle.verify(value("bundle"), core.bytes(), value("observation"),
            value("device_signing_point"), value("owner_approval_point"))
        assertArrayEquals(value("bundle_sha256"), bundle.sha256())
        assertArrayEquals(value("device_transcript"), SelectionRefresh03.deviceTranscript(core, value("observation")))
        assertArrayEquals(value("owner_transcript"), SelectionRefresh03.ownerTranscript(core, value("observation"), value("device_signature")))
        val installed = SelectionRefresh03.installedTranscript(bundle, value("device_session_digest"))
        assertArrayEquals(value("installed_transcript"), installed)
        assertTrue(ConversationContentCrypto.verifyRaw(value("installed_signature"), value("device_signing_point"), installed))
    }
    private class Fixture : AutoCloseable {
        val f = Profile03ExecutionFixture()
        val observation = checkNotNull(f.line.owner.capture()).observation().bytes()
        val devicePoint = Profile03ExecutionFixture.point(f.enrollment)
        val ownerPoint = Profile03ExecutionFixture.point(f.approval)
        val sessionDigest = Profile03SessionTime.Identity(f.session, "synthetic-site", "synthetic-instance")
            .deviceSessionDigest(devicePoint)
        val core = SelectionRefresh03.Core.decode(ByteBuffer.allocate(496)
            .put(byteArrayOf(90, 84, 83, 82, 1, 3, 3, 0)).put(f.account).put(f.device).put(f.lineId)
            .put(Profile03ExecutionFixture.uuid(UUID(0, 77))).put(Profile03ExecutionFixture.uuid(f.newBinding))
            .putLong(2).putLong(1).putLong(2).putLong(3)
            .put(f.accepted.electionCommitment).put(f.accepted.electionBundleSha256)
            .put(Profile03ExecutionFixture.keyId(f.reader, false)).put(Profile03ExecutionFixture.keyId(f.enrollment, true))
            .put(Profile03ExecutionFixture.keyId(f.approval, true)).put(f.fingerprint).put(f.authority.digest)
            .put(sessionDigest).put(Profile03ExecutionFixture.sha(ReviewedIntent03.framed("ZTSE/line/payload-profile/owner-session/v1",
                f.account + Profile03ExecutionFixture.uuid(f.ownerUser) + Profile03ExecutionFixture.uuid(f.ownerSession))))
            .put(f.origins.protocolDigest()).put(ByteArray(32) { 42 })
            .putLong(f.now).putLong(f.now + 120_000).putLong(0).array())
        val device = Profile03ExecutionFixture.rawSign(f.enrollment, SelectionRefresh03.deviceTranscript(core, observation))
        val owner = Profile03ExecutionFixture.rawSign(f.approval, SelectionRefresh03.ownerTranscript(core, observation, device))
        val bytes = core.bytes() + observation + device + owner
        fun verify(input: ByteArray = bytes, expectedCore: ByteArray = core.bytes(), expectedObservation: ByteArray = observation) =
            SelectionRefresh03.Bundle.verify(input, expectedCore, expectedObservation, devicePoint, ownerPoint)
        override fun close() = f.close()
    }
    @Test fun distinctCore496Bundle745AndInstalledPayload80PreserveExactOwnedPublicEvidence() = Fixture().use { v ->
        val input = v.bytes.copyOf()
        val bundle = v.verify(input)
        assertEquals(745, bundle.bytes().size)
        assertEquals(v.f.newBinding, bundle.core.binding)
        assertEquals(v.f.line.selected, SelectionRefresh03.selectedSubscription(bundle.observation()))
        bundle.core.requireCurrent(v.f.now)
        assertTrue(runCatching { bundle.core.requireCurrent(v.core.expiresMs) }.isFailure)
        input.fill(0); bundle.bytes().fill(0); bundle.observation().fill(0)
        assertArrayEquals(v.bytes, bundle.bytes())
        val installed = SelectionRefresh03.installedTranscript(bundle, v.sessionDigest)
        val label = "ZTSE/line/payload-profile/selection-refresh/installed/v1\u0000".toByteArray(Charsets.US_ASCII)
        assertArrayEquals(label, installed.copyOfRange(0, label.size))
        assertEquals(80, ByteBuffer.wrap(installed, label.size, 4).int)
        assertArrayEquals(Profile03ExecutionFixture.uuid(v.core.refresh), installed.copyOfRange(label.size + 4, label.size + 20))
        assertArrayEquals(bundle.sha256(), installed.copyOfRange(label.size + 20, label.size + 52))
        assertArrayEquals(v.sessionDigest, installed.copyOfRange(label.size + 52, installed.size))
    }
    @Test fun noncanonicalCoreWidthsHeadersReservedCountersDigestsAndLifetimesRefuse() = Fixture().use { v ->
        val cases = mutableListOf(v.core.bytes() + byteArrayOf(0), v.core.bytes().copyOf(495))
        for (at in listOf(0, 4, 5, 6, 7, 488, 495)) cases.add(v.core.bytes().apply { this[at] = (this[at].toInt() xor 1).toByte() })
        for (at in listOf(88, 96, 104, 112)) for (number in listOf(0L, -1L))
            cases.add(v.core.bytes().apply { ByteBuffer.wrap(this).putLong(at, number) })
        for (at in 120 until 472 step 32) cases.add(v.core.bytes().apply { fill(0, at, at + 32) })
        cases.add(v.core.bytes().apply { ByteBuffer.wrap(this).putLong(480, v.core.issuedMs) })
        cases.add(v.core.bytes().apply { ByteBuffer.wrap(this).putLong(480, v.core.issuedMs + 300_001) })
        for (bytes in cases) assertTrue(runCatching { SelectionRefresh03.Core.decode(bytes) }.isFailure)
    }
    @Test fun changedExpectedCoreObservationAndReceivedSignaturesCannotSubstituteCurrentContext() = Fixture().use { v ->
        for (at in listOf(8, 24, 40, 56, 72, 88, 120, 184, 216, 248, 280, 312, 344, 376, 408, 440, 472, 496, 616, 617, 680, 681, 744)) {
            assertTrue("offset $at", runCatching { v.verify(v.bytes.copyOf().apply { this[at] = (this[at].toInt() xor 1).toByte() }) }.isFailure)
        }
        assertTrue(runCatching { v.verify(v.bytes + byteArrayOf(0)) }.isFailure)
        assertTrue(runCatching { v.verify(expectedCore = v.core.bytes().apply { this[440] = 43 }) }.isFailure)
        assertTrue(runCatching { v.verify(expectedObservation = v.observation.copyOf().apply { this[120] = 77 }) }.isFailure)
        assertTrue(runCatching { SelectionRefresh03.installedTranscript(v.verify(), ByteArray(32) { 7 }) }.isFailure)
    }
    @Test fun mathematicallyValidHighSAndCrossOperationDeviceProofsAreRejectedWithoutNormalization() = Fixture().use { v ->
        val order = BigInteger("FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551", 16)
        val high = order.subtract(BigInteger(1, v.device.copyOfRange(32, 64))).toByteArray().let { bytes ->
            if (bytes.size == 33) bytes.copyOfRange(1, 33) else ByteArray(32 - bytes.size) + bytes
        }
        val highDevice = v.device.copyOfRange(0, 32) + high
        val validOwner = Profile03ExecutionFixture.rawSign(v.f.approval,
            SelectionRefresh03.ownerTranscript(v.core, v.observation, highDevice))
        assertTrue(runCatching { v.verify(v.core.bytes() + v.observation + highDevice + validOwner) }.isFailure)
        val wrong = Profile03ExecutionFixture.rawSign(v.f.enrollment,
            ReviewedIntent03.framed("ZTSE/line/payload-profile/device/v1", v.core.bytes() + v.observation))
        val wrongOwner = Profile03ExecutionFixture.rawSign(v.f.approval,
            SelectionRefresh03.ownerTranscript(v.core, v.observation, wrong))
        assertTrue(runCatching { v.verify(v.core.bytes() + v.observation + wrong + wrongOwner) }.isFailure)
    }
}

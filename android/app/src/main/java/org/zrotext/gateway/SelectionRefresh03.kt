// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import java.nio.ByteBuffer
import java.security.MessageDigest
import java.util.UUID

/** Distinct public refresh03 proof grammar. Decoding/signature verification cannot approve a
 * SIM, authenticate a server receipt, select a binding/session or publish an opaque live lease.
 */
internal object SelectionRefresh03 {
    class Core private constructor(private val owned: ByteArray) {
        fun bytes() = owned.copyOf()
        val account get() = id(owned, 8)
        val device get() = id(owned, 24)
        val line get() = id(owned, 40)
        val refresh get() = id(owned, 56)
        val binding get() = id(owned, 72)
        val bindingGeneration get() = number(owned, 88)
        val vaultGeneration get() = number(owned, 96)
        val manifestVersion get() = number(owned, 104)
        val selectionEpoch get() = number(owned, 112)
        val electionDigest get() = digest(120)
        val electionBundleSha256 get() = digest(152)
        val readerKeyId get() = digest(184)
        val deviceSigningKeyId get() = digest(216)
        val approvalKeyId get() = digest(248)
        val rootFingerprint get() = digest(280)
        val manifestDigest get() = digest(312)
        val deviceSessionDigest get() = digest(344)
        val ownerSessionDigest get() = digest(376)
        val originDigest get() = digest(408)
        val issuedMs get() = number(owned, 472)
        val expiresMs get() = number(owned, 480)
        private fun digest(at: Int) = owned.copyOfRange(at, at + 32)
        fun requireCurrent(now: Long) { require(now in issuedMs until expiresMs) }
        override fun toString() = "SelectionRefresh03Core(public-context-only)"
        companion object {
            fun decode(input: ByteArray): Core {
                require(input.size == 496)
                val bytes = input.copyOf()
                require(bytes.copyOfRange(0, 8).contentEquals(byteArrayOf(90, 84, 83, 82, 1, 3, 3, 0)) &&
                    bytes.copyOfRange(488, 496).all { it == 0.toByte() })
                for (at in listOf(8, 24, 40, 56, 72)) require(id(bytes, at) != UUID(0, 0))
                for (at in listOf(88, 96, 104, 112, 472, 480)) require(number(bytes, at) > 0)
                for (at in 120 until 472 step 32) require(bytes.copyOfRange(at, at + 32).any { it != 0.toByte() })
                require(number(bytes, 480) > number(bytes, 472) && number(bytes, 480) - number(bytes, 472) <= 300_000)
                return Core(bytes)
            }
        }
    }
    class Bundle private constructor(val core: Core, private val observation: ByteArray,
        private val device: ByteArray, private val owner: ByteArray, private val exact: ByteArray) {
        fun bytes() = exact.copyOf()
        fun observation() = observation.copyOf()
        fun deviceSignature() = device.copyOf()
        fun ownerSignature() = owner.copyOf()
        fun sha256() = sha(exact)
        override fun toString() = "SelectionRefresh03Bundle(verified-public-proof-only)"
        companion object {
            fun verify(input: ByteArray, expectedCore: ByteArray, expectedObservation: ByteArray,
                devicePoint: ByteArray, originalApprovalPoint: ByteArray): Bundle {
                require(input.size == 745 && expectedCore.size == 496 && expectedObservation.size == 121)
                val bytes = input.copyOf()
                val core = Core.decode(bytes.copyOfRange(0, 496))
                val observation = bytes.copyOfRange(496, 617)
                LineActivationV2Observation.decode(observation)
                require(same(core.bytes(), expectedCore) && same(observation, expectedObservation) &&
                    same(core.deviceSigningKeyId, signingId(devicePoint)) && same(core.approvalKeyId, signingId(originalApprovalPoint)))
                val device = bytes.copyOfRange(617, 681)
                val owner = bytes.copyOfRange(681, 745)
                require(ConversationContentCrypto.verifyRaw(device, devicePoint, deviceTranscript(core, observation)) &&
                    ConversationContentCrypto.verifyRaw(owner, originalApprovalPoint, ownerTranscript(core, observation, device)))
                return Bundle(core, observation, device, owner, bytes)
            }
        }
    }
    fun deviceTranscript(core: Core, observation: ByteArray): ByteArray {
        val owned = observation.copyOf()
        LineActivationV2Observation.decode(owned)
        return ReviewedIntent03.framed("ZTSE/line/payload-profile/selection-refresh/device/v1", core.bytes() + owned)
    }
    fun ownerTranscript(core: Core, observation: ByteArray, deviceSignature: ByteArray): ByteArray {
        require(deviceSignature.size == 64)
        LineActivationV2Observation.decode(observation)
        return ReviewedIntent03.framed("ZTSE/line/payload-profile/selection-refresh/owner/v1",
            core.bytes() + observation + sha(deviceSignature))
    }
    fun installedTranscript(bundle: Bundle, actualDeviceSessionDigest: ByteArray): ByteArray {
        require(actualDeviceSessionDigest.size == 32 && same(bundle.core.deviceSessionDigest, actualDeviceSessionDigest))
        return ReviewedIntent03.framed("ZTSE/line/payload-profile/selection-refresh/installed/v1",
            ReviewedIntent03.uuid(bundle.core.refresh) + bundle.sha256() + actualDeviceSessionDigest)
    }
    fun selectedSubscription(observation: ByteArray): Int {
        LineActivationV2Observation.decode(observation)
        return ByteBuffer.wrap(observation, 4, 4).int
    }
    private fun id(bytes: ByteArray, at: Int) = ByteBuffer.wrap(bytes, at, 16).let { UUID(it.long, it.long) }
    private fun number(bytes: ByteArray, at: Int) = ByteBuffer.wrap(bytes, at, 8).long
    private fun sha(bytes: ByteArray) = MessageDigest.getInstance("SHA-256").digest(bytes)
    private fun same(a: ByteArray, b: ByteArray) = MessageDigest.isEqual(a, b)
    private fun signingId(point: ByteArray): ByteArray {
        DevicePayloadKeyStore.decodePoint(point)
        return sha("ZTSE/key/v1\u0000".toByteArray(Charsets.US_ASCII) + byteArrayOf(1, 1) + point)
    }
}

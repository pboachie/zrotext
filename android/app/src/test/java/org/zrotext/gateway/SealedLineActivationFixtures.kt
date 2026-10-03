// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import org.json.JSONObject
import java.security.KeyPairGenerator
import java.security.Signature
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec
import java.util.UUID

/** Test-only JVM P-256 fixtures. No Android Keystore, provisioned credentials or radio. */
internal class SealedLineActivationFixture {
    private fun id(n: Long) = UUID(0, n)
    val challenge = SealedLineChallenge(42, id(4), id(1), id(2), id(3), 7, ByteArray(32) { 5 }, 31_000)
    private val key = KeyPairGenerator.getInstance("EC").apply { initialize(ECGenParameterSpec("secp256r1")) }.generateKeyPair()
    var point = DevicePayloadKeyStore.encodePoint(key.public as ECPublicKey)
    val selection = SealedLineAcceptance(challenge.accountId, challenge.deviceId, challenge.lineId,
        challenge.generation, 7, SealedLineActivationTranscript.digest(point))
    var api = 31
    var selected = 7
    var cards: List<ActiveSimCard>? = listOf(ActiveSimCard(7, 42))
    var now = 1000L
    var afterSign: () -> Unit = {}
    var pointReads = 0
    var duringPointRead: () -> Unit = {}
    var signatures = 0
    var current = true
    var installOk = true
    var commitOk = true
    var afterInstall: () -> Unit = {}
    var installedProof: PreparedSealedLineActivation? = null
    var stored: SealedLineActivationSnapshot? = null
    val events = mutableListOf<String>()
    val device = SealedLineActivationDevice({ api }, { selected }, { cards }, {
        pointReads += 1; duringPointRead(); point.copyOf()
    },
        { c, level, subscription, _ ->
            signatures += 1
            Signature.getInstance("SHA256withECDSA").run {
                initSign(key.private); update(SealedLineActivationTranscript.deviceStatement(c, level, subscription)); sign()
            }.also { afterSign() }
        }, { now })
    val persistence = object : SealedLineReceiptPersistence {
        override fun read() = stored
        override fun write(snapshot: SealedLineActivationSnapshot): Boolean {
            events += "commit"
            if (!commitOk) return false
            stored = SealedLineActivationReceiptCodec.decode(SealedLineActivationReceiptCodec.encode(snapshot))
            return true
        }
    }
    fun provider(epoch: Long = challenge.connectionEpoch) = SealedLineActivationProvider(selection,
        challenge.accountId, challenge.deviceId, epoch, device, persistence, { proof ->
            events += "install"
            if (installOk) installedProof = proof
            afterInstall(); installOk
        }, { proof -> installedProof?.let { it.challenge.accountId == proof.challenge.accountId &&
            it.challenge.deviceId == proof.challenge.deviceId && it.challenge.lineId == proof.challenge.lineId &&
            it.challenge.generation == proof.challenge.generation && it.sim == proof.sim } == true }, { current })
    fun start(provider: SealedLineActivationProvider): Pair<String, SealedLineActivationReceipt> {
        val frame = checkNotNull(provider.accept(SealedLineActivationFrames.Incoming.Challenge(challenge)))
        val parsed = JSONObject(frame)
        val receipt = receipt(SealedLineActivationFrames.variableBytes(parsed, "signature_der", 8, 72))
        provider.accept(SealedLineActivationFrames.Incoming.ProofAck(
            SealedLineActivationFrames.Ack(challenge.connectionEpoch, challenge.challengeId, true)))
        return frame to receipt
    }
    fun receipt(signature: ByteArray, epoch: Long = challenge.connectionEpoch) = SealedLineActivationReceipt(epoch,
        challenge.challengeId, challenge.accountId, challenge.lineId, challenge.deviceId, challenge.generation,
        SealedLineActivationTranscript.digest(SealedLineActivationTranscript.deviceStatement(challenge, 31, 7)),
        SealedLineActivationTranscript.digest(signature))
    fun activated(receipt: SealedLineActivationReceipt) = SealedLineActivationFrames.Incoming.Activated(receipt)
    fun reepoch(r: SealedLineActivationReceipt, epoch: Long) = SealedLineActivationReceipt(epoch, r.challengeId,
        r.accountId, r.lineId, r.deviceId, r.generation, r.statementDigest(), r.signatureDigest())
}

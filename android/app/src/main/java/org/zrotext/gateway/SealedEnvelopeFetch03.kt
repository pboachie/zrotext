// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import java.math.BigInteger
import java.nio.ByteBuffer
import java.security.Signature
import java.util.Base64

/** Pure public evidence. Verification never authorizes a session, fetch, preparation or effect. */
internal object SealedEnvelopeFetch03 {
    private val domain = "ZT/sealed-envelope-fetch/v3\u0000".toByteArray(Charsets.US_ASCII)
    private val order = BigInteger("FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551", 16)
    const val TRANSCRIPT_SIZE = 362

    class Fetch internal constructor(val grant: SealedDispatch03Frames.Grant, signatureDer: ByteArray) {
        private val signature = signatureDer.also { require(it.size in 8..71) }.copyOf()
        init { requireCanonicalDer(signature) }
        val signatureDer: ByteArray get() = signature.copyOf()
        fun json(): String = "{\"grant\":${grant.json()},\"signature_der\":\"${Base64.getUrlEncoder().withoutPadding().encodeToString(signature)}\"}"
        override fun toString() = "Fetch03(public-evidence-only)"
    }

    fun parse(rawJson: String): Fetch {
        val fields = Dispatch03Json.objectValue(rawJson)
        require(fields.keys == setOf("grant", "signature_der")) { "Closed Fetch03" }
        val nested = fields["grant"] as? Map<*, *> ?: throw IllegalArgumentException("Grant object")
        val grant = SealedDispatch03Frames.grant(Dispatch03Json.objectText(nested))
        val der = SealedDispatch03Frames.decodeCanonical(SealedDispatch03Frames.text(fields, "signature_der"), 8, 71)
        return Fetch(grant, der)
    }

    /** Exact domain + six control bytes + five UUIDs + seven signed-range u64 + six digests. */
    fun transcript(grant: SealedDispatch03Frames.Grant): ByteArray {
        val out = ByteBuffer.allocate(TRANSCRIPT_SIZE).put(domain)
            .put(byteArrayOf(1, 3, 3, 3, 1, grant.segmentCount.toByte()))
        for (id in listOf(grant.accountId, grant.deviceId, grant.lineId, grant.messageId, grant.attemptId)) {
            out.putLong(id.mostSignificantBits).putLong(id.leastSignificantBits)
        }
        for (value in longArrayOf(grant.connectionEpoch, grant.deploymentEpoch, grant.bindingGeneration,
            grant.attemptGeneration, grant.expiresAtMs, grant.trustGeneration, grant.manifestVersion)) out.putLong(value)
        for (digest in listOf(grant.readerKeyId, grant.envelopeSha256, grant.unsignedSha256,
            grant.manifestDigest, grant.rootFingerprint, grant.electionDigest)) out.put(digest)
        check(out.position() == TRANSCRIPT_SIZE)
        return out.array()
    }

    /** Select the signing point independently: no point/authority is inferred from received Grant03. */
    fun verify(fetch: Fetch, independentlySelectedPoint: ByteArray): Boolean {
        require(independentlySelectedPoint.size == 65) { "P-256 point width" }
        val point = independentlySelectedPoint.copyOf()
        val signature = fetch.signatureDer
        requireCanonicalDer(signature)
        val bytes = transcript(fetch.grant)
        return Signature.getInstance("SHA256withECDSA").run {
            initVerify(DevicePayloadKeyStore.decodePoint(point))
            update(bytes)
            verify(signature)
        }
    }

    /** Refuse high-s or nonminimal received evidence. Never normalize a received signature. */
    internal fun requireCanonicalDer(signature: ByteArray) {
        require(signature.size in 8..71 && signature[0] == 0x30.toByte() &&
            (signature[1].toInt() and 255) == signature.size - 2) { "DER sequence" }
        var at = 2
        fun scalar(): BigInteger {
            require(at + 2 <= signature.size && signature[at++] == 2.toByte()) { "DER INTEGER" }
            val count = signature[at++].toInt() and 255
            require(count in 1..33 && at + count <= signature.size) { "DER scalar length" }
            val first = signature[at].toInt() and 255
            require(first < 128 && (count == 1 || first != 0 || (signature[at + 1].toInt() and 255) >= 128)) { "DER positive minimal scalar" }
            val value = BigInteger(1, signature.copyOfRange(at, at + count))
            at += count
            require(value.signum() > 0 && value < order) { "P-256 scalar range" }
            return value
        }
        scalar()
        val s = scalar()
        require(at == signature.size && s <= order.shiftRight(1)) { "DER exact EOF/low-s" }
    }
}

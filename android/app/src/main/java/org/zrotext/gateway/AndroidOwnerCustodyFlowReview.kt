// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import java.nio.ByteBuffer
import java.util.UUID
import org.json.JSONObject

internal enum class AndroidOwnerCustodyFlowKind(val nativeKind: Int, val label: String, val maximum: Int) {
    LINE(1, "Register session line approval key", 1024),
    ARCHIVE(2, "Create separate encrypted archive kit", 0),
    GENESIS(3, "Install first reader manifest", 2048),
    ACTIVATION(4, "Sign preserved-record activation successor", 20480),
    REFRESH(5, "Sign bounded role-5 reply successor", 20480)
}

/** These bytes come from authenticated current issue/bootstrap composition plus independent
 * phone/archive comparisons. A second imported JSON file cannot construct this authority.
 */
internal class AndroidOwnerCustodyFlowExpected private constructor(bytes: ByteArray) {
    private val encoded = bytes.copyOf()
    fun bytes() = encoded.copyOf()
    init { require(encoded.size in 2..4096) }
    companion object {
        fun fromAuthenticatedComposition(bytes: ByteArray) = AndroidOwnerCustodyFlowExpected(bytes)
    }
}

/** Display only after native returns the exact immutable proposal and independently expected
 * context. Parsing is public framing, never owner authentication or signing authorization.
 */
internal data class AndroidOwnerCustodyFlowReview(val kind: AndroidOwnerCustodyFlowKind,
    val account: UUID, val user: UUID?, val session: UUID?, val origin: String, val fingerprint: String,
    val issuedMs: Long, val expiresMs: Long, val details: List<Pair<String, String>>) {
    fun disclosure(): String = buildString {
        append("Operation: ${kind.label}\nAccount: $account\nHTTPS origin: $origin\nRoot generation: 1\nRoot fingerprint: $fingerprint\n")
        user?.let { append("Owner user: $it\n") }; session?.let { append("Owner session: $it\n") }
        append("Issued UTC milliseconds: $issuedMs\nExpiry UTC milliseconds: $expiresMs")
        details.forEach { (label, value) -> append("\n$label: $value") }
    }
    companion object {
        fun parse(kind: AndroidOwnerCustodyFlowKind, proposal: ByteArray, expectedJson: ByteArray): AndroidOwnerCustodyFlowReview {
            require(proposal.size <= kind.maximum && expectedJson.size in 2..4096)
            if (kind == AndroidOwnerCustodyFlowKind.ARCHIVE) {
                require(proposal.isEmpty())
                val expected = JSONObject(Charsets.UTF_8.newDecoder().decode(ByteBuffer.wrap(expectedJson)).toString())
                val pin = unhex(expected.getString("root_pin"), 94)
                require(pin.copyOfRange(0, 5).contentEquals(byteArrayOf(90, 84, 82, 80, 2)) && ByteBuffer.wrap(pin, 21, 8).long == 1L)
                val account = uuid(pin.copyOfRange(5, 21))
                val fingerprint = AndroidOwnerCustodyKit.hex(AndroidOwnerCustodyKit.hash("ZTSE/root-pin/v2\u0000".toByteArray() + pin))
                val issued = expected.getLong("issued_ms"); val expires = expected.getLong("expires_ms")
                require(issued > 0 && expires > issued && expires - issued <= 300000)
                // Origin is provided separately by the independent root identity at controller use.
                return AndroidOwnerCustodyFlowReview(kind, account, null, null, "", fingerprint, issued, expires,
                    listOf("Local archive creation operation" to uuid(unhex(expected.getString("operation_id"), 16)).toString(),
                        "Separate recovery" to "New high-entropy archive recovery material; root token is not reused"))
            }
            val c = Cursor(proposal)
            val details = ArrayList<Pair<String, String>>()
            fun detail(label: String, value: String) { details += label to value }
            val account: UUID; val session: UUID; var user: UUID? = null
            val origin: String; val fingerprint: String; val issued: Long; val expires: Long
            if (kind == AndroidOwnerCustodyFlowKind.LINE) {
                c.magic("ZTSE/line/owner-key/register/v1\u0000".toByteArray())
                account = c.uuid(); user = c.uuid(); session = c.uuid()
                detail("Paired device", c.uuid().toString()); detail("Line", c.uuid().toString())
                detail("Next binding generation", c.number().toString()); detail("Challenge", c.uuid().toString())
                detail("Challenge nonce", c.hex(32)); issued = c.number(); expires = c.number()
                detail("Root pin", c.hex(94)); fingerprint = c.hex(32)
                detail("New session approval point", c.hex(65)); detail("New session approval fingerprint", c.hex(32))
                detail("Paired phone signing fingerprint", c.hex(32))
                detail("Connection epoch", c.number().toString()); detail("Deployment epoch", c.number().toString())
                detail("Site", c.text16(128)); detail("Instance", c.text16(128)); origin = c.text16(255)
                require(expires > issued && expires - issued <= 300000)
            } else {
                c.magic(byteArrayOf(90, 84, 67, when (kind) {
                    AndroidOwnerCustodyFlowKind.GENESIS -> 71
                    AndroidOwnerCustodyFlowKind.ACTIVATION -> 65
                    AndroidOwnerCustodyFlowKind.REFRESH -> 70
                    else -> error("Typed proposal required")
                }.toByte(), 1))
                account = c.uuid(); session = c.uuid()
                if (kind == AndroidOwnerCustodyFlowKind.REFRESH) detail("Current content interval", c.uuid().toString())
                detail("Paired device", c.uuid().toString()); detail("Line", c.uuid().toString())
                if (kind == AndroidOwnerCustodyFlowKind.GENESIS) detail("Paired phone signing fingerprint", c.hex(32))
                detail("Line binding generation", c.number().toString())
                val peer = c.text8(16); require(Regex("\\+[1-9][0-9]{1,14}").matches(peer)); detail("Exact peer", peer)
                origin = c.text16(512); fingerprint = c.hex(32)
                if (kind == AndroidOwnerCustodyFlowKind.GENESIS) {
                    detail("Root pin", c.hex(94)); issued = c.number(); expires = c.number()
                    require(expires > issued && expires - issued <= 86400000)
                    val unsigned = c.sized(9751); manifest(unsigned)
                    detail("Manifest version", ByteBuffer.wrap(unsigned, 29, 8).long.toString())
                    detail("Unsigned manifest SHA256", AndroidOwnerCustodyKit.hex(AndroidOwnerCustodyKit.hash(unsigned)))
                    val expected = JSONObject(Charsets.UTF_8.newDecoder().decode(ByteBuffer.wrap(expectedJson)).toString())
                    for ((key, label) in listOf("phone_reader" to "Independently compared phone reader point", "phone_signer" to "Independently compared phone signer point",
                        "archive_reader" to "Independently recovered archive point", "archive_backup_sha256" to "Independently retained encrypted archive SHA256"))
                        detail(label, expected.getString(key))
                } else {
                    detail("Independent predecessor version", c.number().toString()); detail("Independent predecessor digest", c.hex(32))
                    detail("Phone reader key ID", c.hex(32)); detail("Archive reader key ID", c.hex(32))
                    detail(if (kind == AndroidOwnerCustodyFlowKind.ACTIVATION) "Phone signer key ID" else "New role-5 signer key ID", c.hex(32))
                    var selectedIssued = 0L; var signerUntil = Long.MAX_VALUE
                    if (kind == AndroidOwnerCustodyFlowKind.REFRESH) {
                        detail("New session signer point", c.hex(65)); signerUntil = c.number(); detail("Session signer expiry UTC milliseconds", signerUntil.toString())
                    } else selectedIssued = c.number()
                    val predecessor = c.sized(9751); require(predecessor.size >= 215); manifest(predecessor.copyOfRange(0, predecessor.size - 64))
                    val unsigned = c.sized(9751); manifest(unsigned)
                    issued = ByteBuffer.wrap(unsigned, 37, 8).long
                    expires = minOf(ByteBuffer.wrap(unsigned, 45, 8).long, signerUntil)
                    require(kind != AndroidOwnerCustodyFlowKind.ACTIVATION || selectedIssued == issued)
                    detail("Successor version", ByteBuffer.wrap(unsigned, 29, 8).long.toString())
                    detail("Unsigned successor SHA256", AndroidOwnerCustodyKit.hex(AndroidOwnerCustodyKit.hash(unsigned)))
                }
            }
            c.end(); require(issued > 0 && expires > issued)
            AndroidOwnerCustodyIdentity(account, origin, fingerprint)
            return AndroidOwnerCustodyFlowReview(kind, account, user, session, origin, fingerprint, issued, expires, details.toList())
        }
        private fun manifest(bytes: ByteArray) {
            require(bytes.size in 151..9751 && bytes.copyOfRange(0, 5).contentEquals(byteArrayOf(90, 84, 77, 65, 2)))
            val count = bytes[150].toInt() and 255
            require(count in 1..64 && bytes.size == 151 + count * 149)
            require(ByteBuffer.wrap(bytes, 37, 8).long > 0 && ByteBuffer.wrap(bytes, 45, 8).long > ByteBuffer.wrap(bytes, 37, 8).long)
        }
        private fun uuid(bytes: ByteArray): UUID { val b = ByteBuffer.wrap(bytes); return UUID(b.long, b.long).also { require(it != UUID(0, 0)) } }
        internal fun unhex(text: String, size: Int): ByteArray { require(text.matches(Regex("[0-9a-f]{${size * 2}}"))); return text.chunked(2).map { it.toInt(16).toByte() }.toByteArray() }
        private class Cursor(private val bytes: ByteArray) {
            private var at = 0
            fun take(n: Int): ByteArray { require(n >= 0 && n <= bytes.size - at); return bytes.copyOfRange(at, at + n).also { at += n } }
            fun magic(expected: ByteArray) { require(take(expected.size).contentEquals(expected)) }
            fun uuid() = uuid(take(16))
            fun hex(n: Int) = AndroidOwnerCustodyKit.hex(take(n))
            fun number() = ByteBuffer.wrap(take(8)).long.also { require(it > 0) }
            fun sized(maximum: Int): ByteArray { val n = ByteBuffer.wrap(take(2)).short.toInt() and 65535; require(n in 1..maximum); return take(n) }
            private fun text(bytes: ByteArray) = Charsets.UTF_8.newDecoder().decode(ByteBuffer.wrap(bytes)).toString()
            fun text16(max: Int) = text(sized(max))
            fun text8(max: Int): String { val n = take(1)[0].toInt() and 255; require(n in 1..max); return text(take(n)) }
            fun end() { require(at == bytes.size) }
        }
    }
}

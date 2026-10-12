// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import java.util.Base64
import java.util.UUID

/** Syntax only. No session, installed binding, election, grant consumption or radio authority. */
internal object SealedDispatch03Frames {
    private val header = listOf("v", "type", "grant_version", "envelope_profile", "manifest_profile")
    private val grantUuids = listOf("account_id", "device_id", "line_id", "message_id", "attempt_id")
    private val grantLongs = listOf("connection_epoch", "deployment_epoch", "binding_generation",
        "attempt_generation", "expires_at_ms", "trust_generation", "manifest_version")
    private val grantDigests = listOf("reader_key_id", "envelope_sha256", "unsigned_sha256",
        "manifest_digest", "root_fingerprint", "election_digest")
    private val readyLongs = listOf("connection_epoch", "deployment_epoch", "binding_generation",
        "trust_generation", "manifest_version")
    private val readyDigests = listOf("reader_key_id", "manifest_digest", "root_fingerprint", "election_digest")
    private val grantNames = header + listOf("reader_role", "segment_count") + grantUuids + grantLongs + grantDigests
    private val readyNames = header + "line_id" + readyLongs + readyDigests

    class Grant internal constructor(rawJson: String) {
        private val node = Dispatch03Json.objectValue(rawJson)
        private val values = checked(node, grantNames, "sealed_execution_grant", grantUuids, grantLongs, grantDigests)
        init {
            require(number(node, "reader_role") == 1L && number(node, "segment_count") in 1L..6L) { "Grant reader/segments" }
        }
        val accountId: UUID get() = uuid("account_id")
        val deviceId: UUID get() = uuid("device_id")
        val lineId: UUID get() = uuid("line_id")
        val messageId: UUID get() = uuid("message_id")
        val attemptId: UUID get() = uuid("attempt_id")
        val connectionEpoch: Long get() = integer("connection_epoch")
        val deploymentEpoch: Long get() = integer("deployment_epoch")
        val bindingGeneration: Long get() = integer("binding_generation")
        val attemptGeneration: Long get() = integer("attempt_generation")
        val expiresAtMs: Long get() = integer("expires_at_ms")
        val trustGeneration: Long get() = integer("trust_generation")
        val manifestVersion: Long get() = integer("manifest_version")
        val segmentCount: Int get() = integer("segment_count").toInt()
        val readerKeyId: ByteArray get() = digest("reader_key_id")
        val envelopeSha256: ByteArray get() = digest("envelope_sha256")
        val unsignedSha256: ByteArray get() = digest("unsigned_sha256")
        val manifestDigest: ByteArray get() = digest("manifest_digest")
        val rootFingerprint: ByteArray get() = digest("root_fingerprint")
        val electionDigest: ByteArray get() = digest("election_digest")
        internal fun uuid(name: String): UUID = UUID.fromString(values.getValue(name))
        internal fun integer(name: String): Long = values.getValue(name).toLong()
        internal fun digest(name: String): ByteArray = Base64.getUrlDecoder().decode(values.getValue(name))
        fun json(): String = frameJson(values, grantNames, grantLongs + listOf("v", "grant_version", "envelope_profile",
            "manifest_profile", "reader_role", "segment_count"))
        override fun toString() = "Grant03(syntax-only)"
    }

    class Ready internal constructor(rawJson: String) {
        private val node = Dispatch03Json.objectValue(rawJson)
        private val values = checked(node, readyNames, "sealed_ready", listOf("line_id"), readyLongs, readyDigests)
        val lineId: UUID get() = UUID.fromString(values.getValue("line_id"))
        val connectionEpoch: Long get() = values.getValue("connection_epoch").toLong()
        val deploymentEpoch: Long get() = values.getValue("deployment_epoch").toLong()
        val bindingGeneration: Long get() = values.getValue("binding_generation").toLong()
        val trustGeneration: Long get() = values.getValue("trust_generation").toLong()
        val manifestVersion: Long get() = values.getValue("manifest_version").toLong()
        val readerKeyId: ByteArray get() = Base64.getUrlDecoder().decode(values.getValue("reader_key_id"))
        val manifestDigest: ByteArray get() = Base64.getUrlDecoder().decode(values.getValue("manifest_digest"))
        val rootFingerprint: ByteArray get() = Base64.getUrlDecoder().decode(values.getValue("root_fingerprint"))
        val electionDigest: ByteArray get() = Base64.getUrlDecoder().decode(values.getValue("election_digest"))
        fun json(): String = frameJson(values, readyNames, readyLongs + listOf("v", "grant_version", "envelope_profile", "manifest_profile"))
        override fun toString() = "Ready03(syntax-only)"
    }

    fun grant(rawJson: String): Grant = Grant(rawJson)
    fun ready(rawJson: String): Ready = Ready(rawJson)

    private fun checked(node: Map<String, Any>, names: List<String>, type: String,
                        uuids: List<String>, longs: List<String>, digests: List<String>): Map<String, String> {
        require(node.keys == names.toSet()) { "Closed03 field set" }
        require(number(node, "v") == 1L && text(node, "type") == type &&
            number(node, "grant_version") == 3L && number(node, "envelope_profile") == 3L &&
            number(node, "manifest_profile") == 3L) { "Profile03 frame header" }
        for (name in uuids) {
            val value = text(node, name)
            require(value.length == 36 && UUID.fromString(value).let { it != UUID(0, 0) && it.toString() == value }) { "Canonical UUID" }
        }
        for (name in longs) require(number(node, name) > 0) { "Positive signed64" }
        for (name in digests) decodeCanonical(text(node, name), 32, 32)
        val owned = LinkedHashMap<String, String>()
        for (name in names) owned[name] = when (val value = node.getValue(name)) {
            is String -> value
            is Dispatch03Json.Integer -> value.value.toString()
            else -> throw IllegalArgumentException("Scalar field")
        }
        return owned
    }

    internal fun text(node: Map<String, Any>, name: String): String =
        node[name] as? String ?: throw IllegalArgumentException("String field")
    private fun number(node: Map<String, Any>, name: String): Long =
        (node[name] as? Dispatch03Json.Integer)?.value ?: throw IllegalArgumentException("Integer field")
    internal fun decodeCanonical(value: String, min: Int, max: Int): ByteArray {
        require(value.length in ((min * 8 + 5) / 6)..((max * 8 + 5) / 6) &&
            value.all { it in 'A'..'Z' || it in 'a'..'z' || it in '0'..'9' || it == '-' || it == '_' }) { "Base64url shape" }
        val bytes = Base64.getUrlDecoder().decode(value)
        require(bytes.size in min..max && Base64.getUrlEncoder().withoutPadding().encodeToString(bytes) == value) { "Canonical base64url" }
        return bytes
    }
    private fun frameJson(values: Map<String, String>, names: List<String>, numbers: List<String>): String =
        names.joinToString(",", "{", "}") { name ->
            val value = values.getValue(name)
            "\"$name\":" + if (name in numbers) value else "\"$value\""
        }
}

/** Small bounded raw parser: retain integer tokens, detect decoded duplicate names before projection.
 * Only objects, ASCII strings and canonical nonnegative integral literals are part of this grammar. */
internal object Dispatch03Json {
    data class Integer(val value: Long)
    fun objectValue(raw: String): Map<String, Any> = Reader(raw).read()

    /** Re-encode only an already parsed nested object, preserving scalar types for closed validation. */
    internal fun objectText(fields: Map<*, *>): String {
        fun quote(value: String): String = "\"" + value.replace("\\", "\\\\").replace("\"", "\\\"") + "\""
        return fields.entries.joinToString(",", "{", "}") { (key, value) ->
            require(key is String)
            quote(key) + ":" + when (value) {
                is String -> quote(value)
                is Integer -> value.value.toString()
                else -> throw IllegalArgumentException("Scalar grant field")
            }
        }
    }

    private class Reader(private val raw: String) {
        private var at = 0
        init { require(raw.length in 2..16_384) { "JSON size" } }
        fun read(): Map<String, Any> {
            val value = obj(0)
            whitespace()
            require(at == raw.length) { "Trailing JSON" }
            return value
        }
        private fun obj(depth: Int): Map<String, Any> {
            require(depth <= 1) { "JSON depth" }
            take('{')
            val fields = LinkedHashMap<String, Any>()
            whitespace()
            if (peek('}')) { at++; return fields }
            while (true) {
                require(fields.size < 25) { "JSON field bound" }
                val name = string()
                require(name.length <= 64 && !fields.containsKey(name)) { "Duplicate JSON field" }
                take(':'); whitespace()
                val value: Any = when {
                    peek('"') -> string()
                    peek('{') -> obj(depth + 1)
                    at < raw.length && raw[at] in '0'..'9' -> integer()
                    else -> throw IllegalArgumentException("Unsupported JSON value")
                }
                fields[name] = value
                whitespace()
                if (peek('}')) { at++; return fields }
                take(',')
            }
        }
        private fun string(): String {
            take('"')
            val out = StringBuilder()
            while (at < raw.length) {
                val ch = raw[at++]
                if (ch == '"') return out.toString()
                val decoded = if (ch == '\\') {
                    require(at < raw.length) { "Truncated JSON escape" }
                    when (val escaped = raw[at++]) {
                        '"', '\\', '/' -> escaped
                        'u' -> {
                            require(at + 4 <= raw.length) { "Truncated unicode escape" }
                            val hex = raw.substring(at, at + 4)
                            require(hex.all { it in '0'..'9' || it in 'a'..'f' || it in 'A'..'F' })
                            at += 4; hex.toInt(16).toChar()
                        }
                        else -> throw IllegalArgumentException("Unsupported string escape")
                    }
                } else ch
                require(decoded in ' '..'~' && out.length < 256) { "ASCII string bound" }
                out.append(decoded)
            }
            throw IllegalArgumentException("Unclosed JSON string")
        }
        private fun integer(): Integer {
            val start = at
            while (at < raw.length && raw[at] in '0'..'9') at++
            require(at - start <= 19 && (at - start == 1 || raw[start] != '0')) { "Canonical integer" }
            return Integer(raw.substring(start, at).toLongOrNull() ?: throw IllegalArgumentException("Signed64 overflow"))
        }
        private fun take(ch: Char) {
            whitespace(); require(peek(ch)) { "JSON delimiter" }; at++
        }
        private fun peek(ch: Char) = at < raw.length && raw[at] == ch
        private fun whitespace() { while (at < raw.length && raw[at] in " \t\r\n") at++ }
    }
}

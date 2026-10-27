// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import java.nio.ByteBuffer

/** Ordinary device-control parser, deliberately separate from profile03's closed nullable
 * grammar. The outer wire is still capped at the existing4096 bytes. Each actual DTO must
 * additionally require its exact fields/types; parsing a candidate grants no authority. */
internal object ProtectionOriginJson {
    const val MAX_BYTES = 4096
    data class Integer(val value: Long)
    data object Null
    fun objectValue(bytes: ByteArray): Map<String, Any> {
        require(bytes.size in 2..MAX_BYTES)
        return Reader(Charsets.UTF_8.newDecoder().decode(ByteBuffer.wrap(bytes.copyOf())).toString()).read()
    }
    fun render(fields: Map<String, Any>): ByteArray {
        fun value(node: Any, depth: Int): String = when (node) {
            is String -> org.json.JSONObject.quote(node)
            is Integer -> node.value.also { require(it > 0) }.toString()
            Null -> "null"
            is Map<*, *> -> {
                require(depth <= 3 && node.size <= 16)
                node.entries.joinToString(",", "{", "}") {
                    require(it.key is String && it.value != null)
                    org.json.JSONObject.quote(it.key as String) + ":" + value(checkNotNull(it.value), depth + 1)
                }
            }
            else -> error("Unsupported protection-control JSON value")
        }
        return value(fields, 0).toByteArray(Charsets.UTF_8).also { require(it.size <= MAX_BYTES) }
    }
    private class Reader(private val raw: String) {
        private var at = 0
        fun read(): Map<String, Any> = obj(0).also { whitespace(); require(at == raw.length) }
        private fun obj(depth: Int): Map<String, Any> {
            require(depth <= 3); take('{'); whitespace()
            val fields = LinkedHashMap<String, Any>()
            if (peek('}')) { at++; return fields }
            while (true) {
                require(fields.size < 16)
                val name = string()
                require(name.length in 1..64 && name.all { it in ' '..'~' } && !fields.containsKey(name))
                take(':'); whitespace()
                fields[name] = when {
                    peek('"') -> string()
                    peek('{') -> obj(depth + 1)
                    raw.startsWith("null", at) -> { at += 4; Null }
                    at < raw.length && raw[at] in '0'..'9' -> integer()
                    else -> error("Unsupported protection-control JSON scalar")
                }
                whitespace(); if (peek('}')) { at++; return fields }; take(',')
            }
        }
        private fun integer(): Integer {
            val start = at
            while (at < raw.length && raw[at] in '0'..'9') at++
            val text = raw.substring(start, at)
            require(text.length in 1..19 && text[0] != '0')
            return Integer(text.toLong().also { require(it > 0) })
        }
        private fun string(): String {
            take('"'); val out = StringBuilder()
            while (at < raw.length) {
                val ch = raw[at++]
                if (ch == '"') return out.toString().also {
                    require(Charsets.UTF_8.newEncoder().encode(java.nio.CharBuffer.wrap(it)).remaining() <= MAX_BYTES)
                }
                val decoded = if (ch == '\\') {
                    require(at < raw.length)
                    when (val escaped = raw[at++]) {
                        '"', '\\', '/' -> escaped
                        'u' -> {
                            require(at + 4 <= raw.length)
                            val hex = raw.substring(at, at + 4)
                            require(hex.all { it in '0'..'9' || it in 'a'..'f' || it in 'A'..'F' })
                            at += 4; hex.toInt(16).toChar()
                        }
                        else -> error("Unsupported protection-control JSON escape")
                    }
                } else ch
                require(!decoded.isISOControl() && decoded != '\uFEFF' && out.length < MAX_BYTES)
                out.append(decoded)
            }
            error("Unterminated protection-control JSON string")
        }
        private fun whitespace() { while (at < raw.length && raw[at] in " \t\r\n") at++ }
        private fun peek(ch: Char) = at < raw.length && raw[at] == ch
        private fun take(ch: Char) { whitespace(); require(peek(ch)); at++ }
    }
}

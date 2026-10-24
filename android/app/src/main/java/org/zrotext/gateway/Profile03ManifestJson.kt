// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import java.nio.ByteBuffer

/** Separate additive decoder. Legacy first-only Profile03Json keeps its closed grammar.
 * Only history.entries admits an array and history.complete admits a Boolean. No null,
 * fractional/coerced number, duplicate field, unknown collection or trailing text survives. */
internal object Profile03ManifestJson {
    fun objectValue(bytes: ByteArray): Map<String, Any> {
        require(bytes.size in 2..Profile03Json.MAX_BYTES)
        return Reader(Charsets.UTF_8.newDecoder().decode(ByteBuffer.wrap(bytes.copyOf())).toString()).read()
    }
    fun render(fields: Map<String, Any>): ByteArray {
        fun value(node: Any, field: String? = null, depth: Int = 0): String = when (node) {
            is String -> org.json.JSONObject.quote(node)
            is Profile03Json.Integer -> node.value.toString()
            is Boolean -> { require(field == "complete" && depth in 1..2); node.toString() }
            is Map<*, *> -> {
                require(depth <= 3 && node.size <= 64)
                node.entries.joinToString(",", "{", "}") {
                    require(it.key is String && it.value != null)
                    org.json.JSONObject.quote(it.key as String) + ":" + value(checkNotNull(it.value), it.key as String, depth + 1)
                }
            }
            is List<*> -> {
                require(field == "entries" && depth in 1..2 && node.size <= 8 && node.all { it is Map<*, *> })
                node.joinToString(",", "[", "]") { value(checkNotNull(it), depth = depth) }
            }
            else -> error("Manifest JSON scalar")
        }
        return value(fields).toByteArray(Charsets.UTF_8).also { require(it.size <= Profile03Json.MAX_BYTES) }
    }
    private class Reader(private val raw: String) {
        private var at = 0
        fun read(): Map<String, Any> = obj(0).also { whitespace(); require(at == raw.length) }
        private fun obj(depth: Int): Map<String, Any> {
            require(depth <= 3); take('{'); whitespace()
            val fields = LinkedHashMap<String, Any>()
            if (peek('}')) { at++; return fields }
            while (true) {
                require(fields.size < 64)
                val name = string(); require(name.length in 1..64 && name.all { it in ' '..'~' } && !fields.containsKey(name))
                take(':'); whitespace()
                fields[name] = when {
                    peek('"') -> string()
                    peek('{') -> obj(depth + 1)
                    peek('[') -> { require(name == "entries" && depth in 0..1); entries(depth + 1) }
                    raw.startsWith("true", at) -> { require(name == "complete" && depth in 0..1); at += 4; true }
                    raw.startsWith("false", at) -> { require(name == "complete" && depth in 0..1); at += 5; false }
                    at < raw.length && raw[at] in '0'..'9' -> integer()
                    else -> error("Manifest JSON value")
                }
                whitespace(); if (peek('}')) { at++; return fields }; take(',')
            }
        }
        private fun entries(depth: Int): List<Map<String, Any>> {
            take('['); whitespace(); val result = ArrayList<Map<String, Any>>()
            if (peek(']')) { at++; return result }
            while (true) {
                require(result.size < 8 && peek('{')); result.add(obj(depth)); whitespace()
                if (peek(']')) { at++; return result }; take(','); whitespace()
            }
        }
        private fun integer(): Profile03Json.Integer {
            val start = at
            while (at < raw.length && raw[at] in '0'..'9') at++
            val number = raw.substring(start, at)
            require(number.length <= 19 && (number.length == 1 || number[0] != '0'))
            return Profile03Json.Integer(number.toLong().also { require(it >= 0) })
        }
        private fun string(): String {
            take('"'); val out = StringBuilder()
            while (at < raw.length) {
                val ch = raw[at++]
                if (ch == '"') {
                    return out.toString().also { require(Charsets.UTF_8.newEncoder().encode(java.nio.CharBuffer.wrap(it)).remaining() <= 70_000) }
                }
                val decoded = if (ch == '\\') {
                    require(at < raw.length)
                    when (val escaped = raw[at++]) {
                        '"', '\\', '/' -> escaped
                        'u' -> {
                            require(at + 4 <= raw.length)
                            val hex = raw.substring(at, at + 4); require(hex.all { it in '0'..'9' || it in 'a'..'f' || it in 'A'..'F' })
                            at += 4; hex.toInt(16).toChar()
                        }
                        else -> error("Manifest JSON escape")
                    }
                } else ch
                require(!decoded.isISOControl() && decoded != '\uFEFF' && out.length < 70_000); out.append(decoded)
            }
            error("Unterminated manifest JSON text")
        }
        private fun whitespace() { while (at < raw.length && raw[at] in " \t\r\n") at++ }
        private fun peek(ch: Char) = at < raw.length && raw[at] == ch
        private fun take(ch: Char) { whitespace(); require(peek(ch)); at++ }
    }
}

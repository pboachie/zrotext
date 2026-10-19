// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import java.nio.ByteBuffer

/** Bounded strict wire decoder, before JSONObject can erase duplicate names or coerce numbers. */
internal object Profile03Json {
    data class Integer(val value: Long)
    const val MAX_BYTES = 192 * 1024
    fun objectValue(bytes: ByteArray): Map<String, Any> {
        require(bytes.size in 2..MAX_BYTES)
        val text = Charsets.UTF_8.newDecoder().decode(ByteBuffer.wrap(bytes.copyOf())).toString()
        return Reader(text).read()
    }
    fun render(fields: Map<String, Any>): ByteArray {
        fun value(node: Any): String = when (node) {
            is String -> org.json.JSONObject.quote(node)
            is Integer -> node.value.toString()
            is Map<*, *> -> node.entries.joinToString(",", "{", "}") {
                require(it.key is String && it.value != null)
                org.json.JSONObject.quote(it.key as String) + ":" + value(checkNotNull(it.value))
            }
            else -> error("Profile03 scalar")
        }
        return value(fields).toByteArray(Charsets.UTF_8).also { require(it.size <= MAX_BYTES) }
    }
    fun text(fields: Map<String, Any>, name: String) = fields[name] as? String ?: error("Profile03 text field")
    fun decimal(fields: Map<String, Any>, name: String): Long {
        val raw = text(fields, name)
        require(raw.matches(Regex("[1-9][0-9]{0,18}")))
        return raw.toLong().also { require(it > 0) }
    }
    fun nonnegativeDecimal(fields: Map<String, Any>, name: String): Long {
        val raw = text(fields, name)
        require(raw.matches(Regex("0|[1-9][0-9]{0,18}")))
        return raw.toLong().also { require(it >= 0) }
    }
    fun binary(fields: Map<String, Any>, name: String, min: Int, max: Int): ByteArray {
        val raw = text(fields, name)
        require(raw.length in ((min * 8 + 5) / 6)..((max * 8 + 5) / 6) &&
            raw.all { it in 'a'..'z' || it in 'A'..'Z' || it in '0'..'9' || it == '-' || it == '_' })
        return java.util.Base64.getUrlDecoder().decode(raw).also {
            require(it.size in min..max && Profile03ElectionEncoding.encode(it) == raw)
        }
    }
    fun nested(fields: Map<String, Any>, name: String): Map<String, Any> {
        val raw = fields[name] as? Map<*, *> ?: error("Profile03 object field")
        return raw.entries.associate { (key, value) -> (key as? String ?: error("Profile03 key")) to checkNotNull(value) }
    }
    private class Reader(private val raw: String) {
        private var at = 0
        fun read(): Map<String, Any> { val result = obj(0); whitespace(); require(at == raw.length); return result }
        private fun obj(depth: Int): Map<String, Any> {
            require(depth <= 4); take('{')
            val fields = LinkedHashMap<String, Any>()
            whitespace()
            if (peek('}')) { at++; return fields }
            while (true) {
                require(fields.size < 64)
                val name = string()
                require(name.length in 1..64 && name.all { it in ' '..'~' } && !fields.containsKey(name))
                take(':'); whitespace()
                fields[name] = when {
                    peek('"') -> string()
                    peek('{') -> obj(depth + 1)
                    at < raw.length && raw[at] in '0'..'9' -> integer()
                    else -> throw IllegalArgumentException("Unsupported Profile03 JSON value")
                }
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
                if (ch == '"') {
                    val value = out.toString()
                    val checked = Charsets.UTF_8.newEncoder().encode(java.nio.CharBuffer.wrap(value))
                    require(checked.remaining() <= 70_000)
                    return value
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
                        else -> throw IllegalArgumentException("Unsupported Profile03 escape")
                    }
                } else ch
                require(!decoded.isISOControl() && decoded != '\uFEFF' && out.length < 70_000)
                out.append(decoded)
            }
            throw IllegalArgumentException("Unclosed Profile03 string")
        }
        private fun integer(): Integer {
            val start = at
            while (at < raw.length && raw[at] in '0'..'9') at++
            require(at - start <= 19 && (at - start == 1 || raw[start] != '0'))
            return Integer(raw.substring(start, at).toLongOrNull() ?: throw IllegalArgumentException("Profile03 overflow"))
        }
        private fun take(ch: Char) { whitespace(); require(peek(ch)); at++ }
        private fun peek(ch: Char) = at < raw.length && raw[at] == ch
        private fun whitespace() { while (at < raw.length && raw[at] in " \t\r\n") at++ }
    }
}

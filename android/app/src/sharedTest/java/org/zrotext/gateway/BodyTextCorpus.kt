// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import org.junit.Assert.*
import org.junit.Test

/** Shared ZT-009 Q9 body-text corpus; the same fixture is consumed by the Rust, TypeScript and Python suites. */
abstract class BodyTextCorpus {
    private val vector: Map<String, Any?> = MiniJson(
        javaClass.classLoader!!.getResourceAsStream("ztse-body-text-01.json")!!
            .bufferedReader().use { it.readText() }
    ).parse() as Map<String, Any?>

    private fun hex(text: String): ByteArray {
        assertEquals(0, text.length % 2)
        return ByteArray(text.length / 2) { index ->
            text.substring(index * 2, index * 2 + 2).toInt(16).toByte()
        }
    }

    /** Rule failures throw IllegalArgumentException; non-strict UTF-8 throws CharacterCodingException. */
    private fun rejected(name: String, raw: ByteArray) {
        try {
            val text = Draft02Body.decodeText(raw)
            text.fill('\u0000')
            fail("Case $name must fail closed")
        } catch (_: IllegalArgumentException) {
        } catch (_: java.nio.charset.CharacterCodingException) {
        }
    }

    @Test fun sharedBodyTextCorpusMatchesTheAndroidReceiveRules() {
        assertEquals("UNAPPROVED_TEST_ONLY", vector["status"])
        assertEquals(32_768, (vector["maxBodyTextBytes"] as Long).toInt())
        val cases = vector["textCases"] as List<*>
        for (case in cases) {
            val entry = case as Map<*, *>
            val name = entry["name"] as String
            val raw = hex(entry["hex"] as String)
            when (entry["verdict"] as String) {
                "accept" -> {
                    val text = Draft02Body.decodeText(raw)
                    try {
                        if (entry.containsKey("text")) assertEquals(name, entry["text"], String(text))
                        if (entry.containsKey("textLength")) {
                            assertEquals(name, (entry["textLength"] as Long).toInt(), text.size)
                        }
                    } finally { text.fill('\u0000') }
                }
                "reject" -> rejected(name, raw)
                else -> fail("Unknown fixture verdict for $name")
            }
        }
    }
}

/**
 * Minimal strict JSON reader for the committed vector fixtures: objects, arrays,
 * strings with standard escapes, numbers and literals only. It exists so the JVM
 * corpus runs without the mockable android.jar's stubbed org.json or a
 * Robolectric sandbox; it is shared-test code, never application code.
 */
internal class MiniJson(private val source: String) {
    private var at = 0

    fun parse(): Any? {
        whitespace()
        val value = value()
        whitespace()
        require(at == source.length) { "trailing content at $at" }
        return value
    }

    private fun whitespace() {
        while (at < source.length && source[at].isWhitespace()) at++
    }

    private fun value(): Any? {
        require(at < source.length) { "unexpected end" }
        return when (source[at]) {
            '{' -> objectValue()
            '[' -> arrayValue()
            '"' -> stringValue()
            else -> literalValue()
        }
    }

    private fun objectValue(): Map<String, Any?> {
        expect('{')
        val result = LinkedHashMap<String, Any?>()
        whitespace()
        if (peek() == '}') { at++; return result }
        while (true) {
            whitespace()
            val key = stringValue()
            whitespace()
            expect(':')
            whitespace()
            result[key] = value()
            whitespace()
            when (peek()) {
                ',' -> at++
                '}' -> { at++; return result }
                else -> throw IllegalArgumentException("bad object separator at $at")
            }
        }
    }

    private fun arrayValue(): List<Any?> {
        expect('[')
        val result = ArrayList<Any?>()
        whitespace()
        if (peek() == ']') { at++; return result }
        while (true) {
            whitespace()
            result.add(value())
            whitespace()
            when (peek()) {
                ',' -> at++
                ']' -> { at++; return result }
                else -> throw IllegalArgumentException("bad array separator at $at")
            }
        }
    }

    private fun stringValue(): String {
        expect('"')
        val text = StringBuilder()
        while (true) {
            require(at < source.length) { "unterminated string" }
            when (val c = source[at++]) {
                '"' -> return text.toString()
                '\\' -> text.append(escape())
                else -> text.append(c)
            }
        }
    }

    private fun escape(): Char {
        require(at < source.length) { "unterminated escape" }
        return when (val c = source[at++]) {
            '"' -> '"'
            '\\' -> '\\'
            '/' -> '/'
            'b' -> '\b'
            'f' -> '\u000C'
            'n' -> '\n'
            'r' -> '\r'
            't' -> '\t'
            'u' -> {
                val digits = source.substring(at, at + 4)
                at += 4
                digits.toInt(16).toChar()
            }
            else -> throw IllegalArgumentException("bad escape \\$c at ${at - 1}")
        }
    }

    private fun literalValue(): Any? {
        val start = at
        while (at < source.length && !source[at].isWhitespace() &&
            source[at] !in ",}]") at++
        val text = source.substring(start, at)
        require(text.isNotEmpty()) { "bad literal at $start" }
        return when (text) {
            "true" -> true
            "false" -> false
            "null" -> null
            else -> text.toLongOrNull() ?: text.toDoubleOrNull()
                ?: throw IllegalArgumentException("bad literal $text at $start")
        }
    }

    private fun expect(c: Char) {
        require(at < source.length && source[at] == c) { "expected $c at $at" }
        at++
    }

    private fun peek(): Char {
        require(at < source.length) { "unexpected end" }
        return source[at]
    }
}

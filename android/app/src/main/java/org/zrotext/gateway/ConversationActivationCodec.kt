// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import java.io.ByteArrayInputStream
import java.io.DataInputStream
import java.nio.ByteBuffer
import java.security.MessageDigest
import java.util.UUID

/** Canonical bytes only, never a trusted activation or a production transport adapter. */
internal object ConversationActivationCodec {
    const val DISCLOSURE = "With your approval, ZROtext transfers encrypted SMS content for this selected phone line and conversation to your paired browser. Stop closes new capture and transfer; retained encrypted content is deleted separately."
    const val READER_DISCLOSURE = "With your approval, ZROtext transfers encrypted SMS content for this selected phone line and conversation to your paired browser and the explicitly listed customer-controlled readers. Stop closes new capture and transfer; retained encrypted content is deleted separately."
    val READER_APPROVE_DOMAIN get() = "zrotext/conversation/approve/v2\u0000".toByteArray(Charsets.US_ASCII)
    val READER_INSTALL_DOMAIN get() = "zrotext/conversation/install/v2\u0000".toByteArray(Charsets.US_ASCII)
    fun readerDisclosureDigest() = MessageDigest.getInstance("SHA-256").digest(READER_DISCLOSURE.toByteArray(Charsets.UTF_8)).joinToString("") { "%02x".format(it.toInt() and 255) }
    fun approveDomain(scope: ConversationCaptureScope) = if(scope.selectedReaders.isEmpty()) APPROVE_DOMAIN else READER_APPROVE_DOMAIN
    fun installDomain(scope: ConversationCaptureScope) = if(scope.selectedReaders.isEmpty()) INSTALL_DOMAIN else READER_INSTALL_DOMAIN
    val APPROVE_DOMAIN get() = "zrotext/conversation/approve/v1\u0000".toByteArray(Charsets.US_ASCII)
    val INSTALL_DOMAIN get() = "zrotext/conversation/install/v1\u0000".toByteArray(Charsets.US_ASCII)
    class Parsed(val scope: ConversationCaptureScope, val signerId: ByteArray, val expiresMs: Long,
                 val predecessorVersion: Long, val predecessorDigest: ByteArray,
                 val site: String, val instance: String, val connectionEpoch: Long, val deploymentEpoch: Long) {
        override fun toString() = "CanonicalConversationActivation(redacted)"
    }

    fun decode(inputBytes: ByteArray): Parsed {
        val bytes = inputBytes.copyOf()
        require(bytes.size in 380..1024)
        val input = DataInputStream(ByteArrayInputStream(bytes.copyOf()))
        fun fixed(n: Int) = ByteArray(n).also(input::readFully)
        fun id(): String {
            val b = ByteBuffer.wrap(fixed(16))
            return UUID(b.long, b.long).toString().also { require(it != UUID(0, 0).toString()) }
        }
        fun positive() = input.readLong().also { require(it > 0) }
        fun text(max: Int): String {
            val size = input.readUnsignedByte()
            require(size in 1..max)
            val b = fixed(size)
            require(b.all { (it.toInt() and 255) in 33..126 })
            return b.toString(Charsets.US_ASCII)
        }
        val magic=fixed(5); require(magic.copyOfRange(0,4).contentEquals(byteArrayOf(0x5a,0x54,0x43,0x41)))
        val format=magic[4].toInt(); require(format in 1..2)
        val account = id(); val device = id(); val line = id(); val generation = positive()
        val interval = id(); val receipt = id(); val session = id()
        require(fixed(32).any { it != 0.toByte() })
        val expiry = positive(); val peer = text(16)
        require(text(64) == "conversation-content-v1")
        val disclosure = fixed(32)
        require(disclosure.contentEquals(MessageDigest.getInstance("SHA-256").digest((if(format==1) DISCLOSURE else READER_DISCLOSURE).toByteArray(Charsets.UTF_8))))
        val reader = fixed(32); val signer = fixed(32); val trustGeneration = positive()
        val predecessorVersion = positive(); val predecessorDigest = fixed(32)
        val activationVersion = positive(); val activationDigest = fixed(32)
        require(predecessorVersion < Long.MAX_VALUE && activationVersion == predecessorVersion + 1)
        val connection = positive(); val deployment = positive(); val site = text(64); val instance = text(64)
        val selected=if(format==1) emptyList() else {
            val count=input.readUnsignedByte(); require(count in 1..6)
            List(count) { ConversationIntegrationReader(id(), id(), fixed(32).joinToString("") { "%02x".format(it.toInt() and 255) }) }
        }
        ConversationIntegrationReader.validate(selected)
        require(input.available() == 0)
        fun hex(b: ByteArray) = b.joinToString("") { "%02x".format(it.toInt() and 255) }
        val digest = MessageDigest.getInstance("SHA-256").digest(transcript(if(format==1) APPROVE_DOMAIN else READER_APPROVE_DOMAIN, bytes))
        val scope = ConversationCaptureScope(account, device, line, generation, peer, interval, receipt, session,
            hex(disclosure), hex(reader), trustGeneration, activationVersion, hex(activationDigest), hex(digest), ConversationReaderSelection(selected))
        return Parsed(scope, signer, expiry, predecessorVersion, predecessorDigest, site, instance, connection, deployment)
    }

    fun transcript(inputDomain: ByteArray, inputStatement: ByteArray): ByteArray {
        val domain = inputDomain.copyOf()
        val statement = inputStatement.copyOf()
        require(statement.size in 380..1024)
        val v2=statement[4]==2.toByte()
        require(if(v2) domain.contentEquals(READER_APPROVE_DOMAIN) || domain.contentEquals(READER_INSTALL_DOMAIN) else domain.contentEquals(APPROVE_DOMAIN) || domain.contentEquals(INSTALL_DOMAIN))
        return domain + ByteBuffer.allocate(4).putInt(statement.size).array() + statement.copyOf()
    }
}

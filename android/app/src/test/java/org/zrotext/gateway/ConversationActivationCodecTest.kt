// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import java.security.MessageDigest
import org.junit.Assert.*
import org.junit.Test

class ConversationActivationCodecTest {
    private val vector = "5a54434101a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b100000000000000013131313131313131313131313131313141414141414141414141414141414141515151515151515151515151515151516161616161616161616161616161616161616161616161616161616161616161000001e8f1c10800032b313217636f6e766572736174696f6e2d636f6e74656e742d7631059d0d3aa72a6b03303e86000241fc71cd452714356f51617ae2bb02c5b85ece717171717171717171717171717171717171717171717171717171717171717181818181818181818181818181818181818181818181818181818181818181810000000000000001000000000000000191919191919191919191919191919191919191919191919191919191919191910000000000000002a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2000000000000000100000000000000010c666978747572652d7369746510666978747572652d696e7374616e6365".chunked(2).map { it.toInt(16).toByte() }.toByteArray()
    @Test fun canonicalServerVectorBindsExactScopeAndDomains() {
        val parsed = ConversationActivationCodec.decode(vector)
        assertEquals("+12", parsed.scope.peer)
        assertEquals(2L, parsed.scope.activationVersion)
        assertEquals("8506fb9cec0957933e156fad8c44fce7fa2328eeac0c363ba36a4e85fa31576a", parsed.scope.transcriptDigest)
        assertEquals("fixture-site", parsed.site)
        assertEquals("fixture-instance", parsed.instance)
        val approve = ConversationActivationCodec.transcript(ConversationActivationCodec.APPROVE_DOMAIN, vector)
        val install = ConversationActivationCodec.transcript(ConversationActivationCodec.INSTALL_DOMAIN, vector)
        assertFalse(approve.contentEquals(install))
        assertFalse(MessageDigest.getInstance("SHA-256").digest(approve).contentEquals(MessageDigest.getInstance("SHA-256").digest(install)))
        for (end in vector.indices) assertThrows(Exception::class.java) { ConversationActivationCodec.decode(vector.copyOf(end)) }
        assertThrows(IllegalArgumentException::class.java) { ConversationActivationCodec.decode(vector + byteArrayOf(0)) }
    }

    @Test fun closedOnlyReconciliationBindsOriginalCanonicalStatement() {
        val parsed=ConversationActivationCodec.decode(vector)
        val phone=ConversationPhoneSession(java.util.UUID.fromString(parsed.scope.accountId),java.util.UUID.fromString(parsed.scope.deviceId),java.util.UUID.randomUUID(),1,1,"11".repeat(32))
        val request=ConversationClosureRequest(phone,java.util.UUID.randomUUID(),parsed.scope)
        val frame=ConversationChannelCodec.reconciliationRequest(request,vector)
        assertEquals(5,frame[5].toInt());assertEquals(vector.size+120,frame.size)
        assertArrayEquals(vector,frame.copyOfRange(120,frame.size))
        assertThrows(IllegalArgumentException::class.java){ConversationChannelCodec.reconciliationRequest(request.copy(scope=parsed.scope.copy(peer="+13")),vector)}
    }

    @Test fun canonicalRecoveryProofUsesExistingProtectedScopeAndReadsLegacy() {
        val scope=ConversationActivationCodec.decode(vector).scope
        val modern=ConversationProtectedInstallation.decode(ConversationProtectedInstallation.encode(scope,vector))
        assertEquals(scope,modern.scope);assertArrayEquals(vector,modern.originalStatement)
        val legacy=ConversationProtectedInstallation.decode(scope.encode())
        assertEquals(scope,legacy.scope);assertNull(legacy.originalStatement)
        assertThrows(IllegalArgumentException::class.java){ConversationProtectedInstallation.encode(scope.copy(peer="+13"),vector)}
    }
    private fun selectedStatement():ByteArray {
        val oldDigest=MessageDigest.getInstance("SHA-256").digest(ConversationActivationCodec.DISCLOSURE.toByteArray())
        val nextDigest=MessageDigest.getInstance("SHA-256").digest(ConversationActivationCodec.READER_DISCLOSURE.toByteArray())
        val base=vector.copyOf();base[4]=2
        val offset=(0..base.size-32).single { base.copyOfRange(it,it+32).contentEquals(oldDigest) }
        nextDigest.copyInto(base,offset)
        return base+byteArrayOf(1)+ByteArray(16){0x22}+ByteArray(16){0x33}+ByteArray(32){0x44}
    }
    @Test fun selectedReadersAreImmutableAndBoundToBothTranscriptDomainsAndProtectedJournal() {
        val statement=selectedStatement();val parsed=ConversationActivationCodec.decode(statement)
        assertEquals(1,parsed.scope.selectedReaders.size)
        assertEquals("44".repeat(32),parsed.scope.selectedReaders.single().keyId)
        assertEquals(parsed.scope,ConversationCaptureScope.decode(parsed.scope.encode()))
        assertArrayEquals(ConversationActivationCodec.READER_APPROVE_DOMAIN,ConversationActivationCodec.approveDomain(parsed.scope))
        assertThrows(IllegalArgumentException::class.java) { ConversationActivationCodec.transcript(ConversationActivationCodec.APPROVE_DOMAIN,statement) }
        val source=parsed.scope.selectedReaders.toMutableList();val selection=ConversationReaderSelection(source);source.clear()
        assertEquals(1,selection.values.size)
        val exposed=selection.values.toMutableList();exposed.clear();assertEquals(1,selection.values.size)
        assertThrows(Exception::class.java) { ConversationActivationCodec.decode(statement.copyOf(statement.size-64)) }
        assertThrows(IllegalArgumentException::class.java) { ConversationActivationCodec.decode(statement+byteArrayOf(0)) }
    }
    @Test fun channelSelectionCannotConsumeFollowingExecutionIdentitiesOrAcceptDuplicateReaders() {
        val scope=ConversationActivationCodec.decode(selectedStatement()).scope
        val session=ConversationPhoneSession(java.util.UUID.fromString(scope.accountId),java.util.UUID.fromString(scope.deviceId),java.util.UUID.randomUUID(),1,1,"11".repeat(32))
        val message=java.util.UUID.randomUUID();val attempt=java.util.UUID.randomUUID()
        val frame=ConversationChannelCodec.executionRequest(session,java.util.UUID.randomUUID(),scope,message,attempt,ByteArray(32){1})
        val parsed=ConversationChannelCodec.parseExecutionRequest(frame,session)
        assertEquals(scope,parsed.scope);assertEquals(message,parsed.message);assertEquals(attempt,parsed.attempt)
        assertThrows(IllegalArgumentException::class.java) { ConversationChannelCodec.parseExecutionRequest(frame+byteArrayOf(0),session) }
        val reader=scope.selectedReaders.single()
        assertThrows(IllegalArgumentException::class.java) { ConversationReaderSelection(listOf(reader,reader)) }
        assertThrows(IllegalArgumentException::class.java) { ConversationReaderSelection(listOf(reader,reader.copy(keyId="55".repeat(32)))) }
        val changed=scope.copy(integrationSelection=ConversationReaderSelection(listOf(reader.copy(readGrantId=java.util.UUID.randomUUID().toString()))))
        assertNotEquals(scope,changed)
    }

    @Test fun maximumSelectionAndZeroDuplicateOrOutOfOrderSelectionsAreClosed() {
        val one=selectedStatement();val base=one.copyOf(one.size-65)
        fun tuple(n:Int)=ByteArray(16){n.toByte()}+ByteArray(16){(n+10).toByte()}+ByteArray(32){(n+20).toByte()}
        val six=base+byteArrayOf(6)+(1..6).fold(ByteArray(0)) { a,n -> a+tuple(n) }
        val parsed=ConversationActivationCodec.decode(six)
        assertEquals(6,parsed.scope.selectedReaders.size)
        assertEquals(parsed.scope,ConversationCaptureScope.decode(parsed.scope.encode()))
        for(bad in listOf(base+byteArrayOf(0),base+byteArrayOf(7),base+byteArrayOf(2)+tuple(2)+tuple(1),base+byteArrayOf(2)+tuple(1)+tuple(1))) {
            assertThrows(Exception::class.java) { ConversationActivationCodec.decode(bad) }
        }
        val session=ConversationPhoneSession(java.util.UUID.fromString(parsed.scope.accountId),java.util.UUID.fromString(parsed.scope.deviceId),java.util.UUID.randomUUID(),1,1,"11".repeat(32))
        val frame=ConversationChannelCodec.executionRequest(session,java.util.UUID.randomUUID(),parsed.scope,java.util.UUID.randomUUID(),java.util.UUID.randomUUID(),ByteArray(32){1})
        assertEquals(parsed.scope,ConversationChannelCodec.parseExecutionRequest(frame,session).scope)
    }

    @Test fun selectedReadersMatchSharedServerCanonicalVectorExactly() {
        val text=javaClass.classLoader!!.getResourceAsStream("conversation-activation-readers.json")!!.bufferedReader().use { it.readText() }
        fun field(name:String)=Regex("\""+name+"\"\\s*:\\s*\"([^\"]*)\"").find(text)!!.groupValues[1]
        fun bytes(name:String)=field(name).chunked(2).map { it.toInt(16).toByte() }.toByteArray()
        val statement=bytes("statement_hex");val parsed=ConversationActivationCodec.decode(statement)
        assertEquals(2,parsed.scope.selectedReaders.size)
        assertEquals(field("approval_digest_hex"),parsed.scope.transcriptDigest)
        assertEquals(field("disclosure_text"),ConversationActivationCodec.READER_DISCLOSURE)
        assertArrayEquals(bytes("approval_transcript_hex"),ConversationActivationCodec.transcript(ConversationActivationCodec.approveDomain(parsed.scope),statement))
        assertArrayEquals(bytes("installation_transcript_hex"),ConversationActivationCodec.transcript(ConversationActivationCodec.installDomain(parsed.scope),statement))
    }

}

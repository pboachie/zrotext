// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import androidx.room.Room
import java.nio.ByteBuffer
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.MessageDigest
import java.security.Signature
import java.security.interfaces.ECPublicKey
import java.util.Base64
import java.util.UUID
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec
import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment
import org.robolectric.annotation.Config

internal object ConversationGrantFixture {
    fun json(session:ConversationPhoneSession,scope:ConversationCaptureScope,message:UUID,attempt:UUID,
             full:ByteArray,reader:ByteArray,unsigned:ByteArray,expires:Long)=JSONObject()
        .put("v",1).put("type","sealed_execution_grant").put("grant_version",1)
        .put("account_id",session.account.toString()).put("device_id",session.device.toString())
        .put("line_id",scope.lineId).put("message_id",message.toString()).put("attempt_id",attempt.toString())
        .put("connection_epoch",session.connectionEpoch).put("deployment_epoch",session.deploymentEpoch)
        .put("binding_generation",scope.bindingGeneration).put("attempt_generation",1)
        .put("reader_role",1).put("reader_key_id",b64(reader)).put("envelope_sha256",b64(full))
        .put("unsigned_sha256",b64(unsigned)).put("expires_at_ms",expires).put("segment_count",6)
    fun rawReply(session:ConversationPhoneSession,nonce:UUID,json:ByteArray):ByteArray {
        val header=ConversationChannelCodec.timeRequest(ConversationTrustedClock.Request(nonce,session)).also{it[5]=19}
        return header+ByteBuffer.allocate(2).putShort(json.size.toShort()).array()+json
    }
    private fun b64(bytes:ByteArray)=Base64.getUrlEncoder().withoutPadding().encodeToString(bytes)
}

/** Real canonical manifest/confirmation crypto with explicit synthetic ciphertext/preparation custody. */
@RunWith(RobolectricTestRunner::class) @Config(sdk=[34])
class ConversationExecutionTransportTest {
    private class Fixture:ConversationContentKeyOperations,AutoCloseable {
        val account=ByteArray(16){1};val device=ByteArray(16){2};val line=ByteArray(16){3};val message=ByteArray(16){4}
        val root=pair();val recipient=pair();val archive=pair();val phoneSigner=pair();val browser=pair()
        val archiveId=id(archive,2);val recipientId=id(recipient,1)
        var now=1_893_456_001_000L
        val deadline=now+20_000
        val authority:Draft02ManifestAuthority
        val scope:ConversationCaptureScope
        val session:ConversationPhoneSession
        val binding:LocalLineBinding
        val db=Room.inMemoryDatabaseBuilder(RuntimeEnvironment.getApplication(),ConversationSendDatabase::class.java).allowMainThreadQueries().build()
        val protection=ConversationExistingJournalProtection {journalKey}
        private val journalKey=KeyGenerator.getInstance("AES").apply{init(256)}.generateKey()
        val cek=ByteArray(32){7}
        val original:ByteArray
        val evidenceHash:String
        val attempt=UUID.randomUUID().toString()
        var live=true;var window=deadline;var local:SealedDispatchExecutor.Local
        var exchanges=0;var preparations=0;var submissions=0
        var edit:(JSONObject)->Unit={};var exchangeHook:()->Unit={};var prepareHook:()->Unit={}
        var throwConsumer=false;var unavailable=false
        val preparedBody="Synthetic reply".toCharArray()
        // Existing ownership-only reflection seam; no new production holder or hardware grant.
        val prepared=Class.forName("org.zrotext.gateway.Draft02OutboundPreparation\$OwnedPrepared")
            .declaredConstructors.single().apply{isAccessible=true}
            .newInstance(preparedBody,1,{Unit}) as Draft02OutboundPreparation.Prepared
        init {
            val pin=ascii("ZTRP")+byteArrayOf(2)+account+long(1)+point(root)
            val records=listOf(1 to recipient,2 to archive,4 to phoneSigner,5 to browser,6 to root).map{(role,key)->
                byteArrayOf(role.toByte())+id(key,role)+point(key)+(if(role==1||role==4)device else ByteArray(16))+
                    (if(role==1||role==4||role==5)line else ByteArray(16))+ByteBuffer.allocate(2).putShort(when(role){1->4;2->12;4->2;5->1;else->0}.toShort()).array()+long(now-1000)+long(now+60_000)+byteArrayOf(1)}
            val unsigned=ascii("ZTMA")+byteArrayOf(2)+account+long(1)+long(1)+long(now-1000)+long(now+60_000)+ByteArray(32)+point(root)+records.size.toByte()+records.fold(ByteArray(0)){a,b->a+b}
            val manifest=unsigned+signature(root,ascii("ZTSE/manifest/v2\u0000")+int(unsigned.size)+unsigned)
            authority=Draft02ManifestAuthority.verify(pin,manifest,Draft02ManifestAuthority.Trust(account,
                sha(ascii("ZTSE/root-pin/v2\u0000")+pin),1,Draft02ManifestAuthority.Position.genesis(ByteArray(32))),now)
            scope=ConversationCaptureScope(uuid(account),uuid(device),uuid(line),1,"+12",uuid(ByteArray(16){5}),
                uuid(ByteArray(16){6}),uuid(ByteArray(16){7}),"01".repeat(32),hex(archiveId),1,1,hex(authority.digest),"02".repeat(32))
            session=ConversationPhoneSession(UUID.fromString(scope.accountId),UUID.fromString(scope.deviceId),UUID.randomUUID(),7,3,"11".repeat(32))
            binding=LocalLineBinding(accountId=scope.accountId,deviceId=scope.deviceId,lineId=scope.lineId,generation=1,
                subscriptionId=3,installedAtMs=1,cardId=4)
            local=SealedDispatchExecutor.Local(binding,recipientId,1,1,hex(authority.digest),hex(sha(ascii(scope.peer))))
            val body=ascii("Synthetic reply")
            val protected=account+message+device+line+long(1)+authority.digest+id(browser,5)+long(now)+long(deadline)+byteArrayOf(1,3)+ascii(scope.peer)
            val header=ascii("ZTSE")+byteArrayOf(2,1,0,0)+ByteBuffer.allocate(2).putShort(protected.size.toShort()).array()
            val nonce=ByteArray(12){8}
            val cipher=Cipher.getInstance("AES/GCM/NoPadding").apply{init(Cipher.ENCRYPT_MODE,SecretKeySpec(cek,"AES"),GCMParameterSpec(128,nonce));updateAAD(ascii("ZTSE/body/v2\u0000")+header+protected)}
            val encrypted=cipher.doFinal(body)
            val wraps=byteArrayOf(1)+recipientId+point(recipient)+ByteArray(48)+byteArrayOf(2)+archiveId+point(archive)+ByteArray(48)
            val unsignedEnvelope=header+protected+nonce+int(encrypted.size)+encrypted+byteArrayOf(2)+wraps
            val envelope=unsignedEnvelope+signature(browser,ascii("ZTSE/sign/v2\u0000")+int(unsignedEnvelope.size)+unsignedEnvelope)
            val confirmation=ascii("ZTCS")+byteArrayOf(1)+account+device+line+bytes(scope.intervalId)+bytes(scope.initiatingSessionId)+message+
                long(1)+long(1)+long(1)+long(deadline)+byteArrayOf(3)+ascii(scope.peer)+id(browser,5)+archiveId+authority.digest+sha(envelope)+sha(body)
            original=ConversationContentCrypto.packConfirmedEvidence(envelope,confirmation,
                signature(browser,ascii("zrotext/conversation/confirm-send/v1\u0000")+int(confirmation.size)+confirmation))
            evidenceHash=hex(sha(original))
        }
        val crypto get()=ConversationContentCrypto(this){if(!live)null else ConversationCryptoCurrent(scope,authority,point(archive),id(browser,5),id(phoneSigner,4),now)}
        override fun recipient()=DevicePayloadPublic(point(recipient),recipientId,PayloadKeySecurity.TRUSTED_ENVIRONMENT)
        override fun sign(unsigned:ByteArray,point:ByteArray)=error("No capture signing")
        override fun open(parts:Draft02OutboundEnvelope.Parts)=cek.copyOf()
        fun retain(claim:Boolean=true) {
            val aad="zrotext-conversation-send-v1:${uuid(message)}:${scope.intervalId}:$evidenceHash"
            val protected=protection.seal(Base64.getEncoder().encodeToString(original),aad)
            db.sends().receive(ConversationSendReceipt(uuid(message),scope.intervalId,evidenceHash,deadline,protected.ciphertext,protected.nonce))
            if(claim)db.sends().claim(uuid(message),attempt)
        }
        fun token(evidence:ByteArray=original)=ConversationClaimedEvidence(uuid(message),attempt,scope,evidenceHash,deadline,evidence)
        fun transport():ConversationExecutionTransport {
            val verifier=crypto
            val wire=object:ConversationAuthenticatedWire {
                override fun currentSession()=if(live)session else null
                override fun exchange(request:ByteArray):ConversationAuthenticatedWire.Reply {
                    exchanges++;val selected=ConversationChannelCodec.parseExecutionRequest(request,session)
                    assertEquals(scope,selected.scope);assertEquals(db.sends().receipt(uuid(message))!!.attempt,selected.attempt.toString())
                    val envelope=ConversationContentCrypto.unpackConfirmedEvidence(original).envelope
                    assertArrayEquals(sha(envelope),selected.envelopeDigest)
                    val json=ConversationGrantFixture.json(session,scope,selected.message,selected.attempt,sha(envelope),recipientId,
                        sha(envelope.copyOfRange(0,envelope.size-64)),deadline-1000).also(edit)
                    exchangeHook()
                    return ConversationAuthenticatedWire.Reply(session,ConversationGrantFixture.rawReply(session,selected.challenge,json.toString().toByteArray()))
                }
            }
            return ConversationExecutionTransport(db.sends(),protection,verifier,wire,{if(!live)null else ConversationExecutionCurrent(
                SealedDispatchExecutor.Session(session.account,session.device,session.connectionEpoch,session.deploymentEpoch,session.session,session.originHash),local,now,window)},
                {selected,fields,envelope,_,_->
                    preparations++;assertEquals(scope,selected);assertEquals(1L,fields.attemptGeneration)
                    assertArrayEquals(ConversationContentCrypto.unpackConfirmedEvidence(original).envelope,envelope)
                    prepareHook();if(unavailable)SealedDispatchExecutor.Unavailable else SealedDispatchExecutor.Ready(prepared)
                },ConversationPreparedSubmission{_,_,_,holder->
                    submissions++;if(throwConsumer)error("Synthetic uncertain submission")
                    holder.consume{assertEquals("Synthetic reply",String(it))};ConversationSubmission.SUBMITTED
                })
        }
        override fun close(){prepared.close();db.close();cek.fill(0);original.fill(0)}
    }
    @Test fun actualProtectedClaimOriginalCiphertextAndBoundReplyReachPreparedHolderOnce()=Fixture().use { f->
        f.retain();val transport=f.transport();val token=f.token()
        assertEquals(ConversationSubmission.SUBMITTED,transport.submitClaimed(token))
        assertEquals(1,f.exchanges);assertEquals(1,f.preparations);assertEquals(1,f.submissions)
        assertTrue(f.preparedBody.all{it=='\u0000'})
        assertThrows(Exception::class.java){f.prepared.consume{fail("Holder replayed")}}
        assertEquals(ConversationSubmission.UNKNOWN,transport.submitClaimed(token))
        assertEquals(ConversationSubmission.UNKNOWN,transport.submitClaimed(f.token()))
        assertEquals(1,f.exchanges)
    }
    @Test fun canonicalConfirmedSenderDurablyClaimsThenProductionEvidencePortPreparesOnce()=Fixture().use { f->
        val capture=Room.inMemoryDatabaseBuilder(RuntimeEnvironment.getApplication(),ConversationCaptureDatabase::class.java).allowMainThreadQueries().build()
        try {
            val activation=object:ConversationActivationVerifier {
                override fun verifiedPreparation(evidence:ByteArray)=f.scope
                override fun verifiedActiveLease(scope:ConversationCaptureScope,challenge:String,evidence:ByteArray)=60000L
            }
            val admission=ConversationCaptureAdmission(capture.journal(),activation,f.protection,{100L},{check(f.live && it==f.scope)})
            admission.prepare(byteArrayOf(1),true);val request=admission.beginRecovery();admission.completeRecovery(request.challenge,byteArrayOf(1))
            val sender=ConversationConfirmedSend(f.db.sends(),admission,f.crypto,f.protection,{f.now},f.transport())
            sender.receiveConfirmed(f.original)
            assertEquals("confirmed",f.db.sends().receipt(uuid(f.message))!!.state)
            assertEquals(ConversationSubmission.SUBMITTED,sender.submitConfirmed(uuid(f.message)))
            assertEquals("submitted",f.db.sends().receipt(uuid(f.message))!!.state)
            assertEquals(1,f.exchanges);assertEquals(1,f.preparations);assertEquals(1,f.submissions)
            assertThrows(Exception::class.java){sender.submitConfirmed(uuid(f.message))}
            assertEquals(1,f.exchanges)
        } finally {capture.close()}
    }
    @Test fun heldExecutionGrantCannotDelayStopAndLateValidReplyNeverPreparesOrConsumes()=Fixture().use { f->
        val capture=Room.inMemoryDatabaseBuilder(RuntimeEnvironment.getApplication(),ConversationCaptureDatabase::class.java).allowMainThreadQueries().build()
        val held=java.util.concurrent.CountDownLatch(1);val release=java.util.concurrent.CountDownLatch(1)
        val stopped=java.util.concurrent.CountDownLatch(1)
        val executor=java.util.concurrent.Executors.newFixedThreadPool(2)
        try {
            val activation=object:ConversationActivationVerifier {
                override fun verifiedPreparation(evidence:ByteArray)=f.scope
                override fun verifiedActiveLease(scope:ConversationCaptureScope,challenge:String,evidence:ByteArray)=60000L
            }
            val admission=ConversationCaptureAdmission(capture.journal(),activation,f.protection,{100L},{check(f.live && it==f.scope)})
            admission.prepare(byteArrayOf(1),true);val request=admission.beginRecovery();admission.completeRecovery(request.challenge,byteArrayOf(1))
            f.exchangeHook={held.countDown();check(release.await(5,java.util.concurrent.TimeUnit.SECONDS))}
            val sender=ConversationConfirmedSend(f.db.sends(),admission,f.crypto,f.protection,{f.now},f.transport())
            sender.receiveConfirmed(f.original)
            val send=executor.submit<ConversationSubmission>{sender.submitConfirmed(uuid(f.message))}
            assertTrue(held.await(2,java.util.concurrent.TimeUnit.SECONDS))
            assertEquals("claimed",f.db.sends().receipt(uuid(f.message))!!.state)
            val stop=executor.submit{sender.close(f.scope.intervalId);stopped.countDown()}
            assertTrue("Stop must disable actual admission before the held grant is released",
                stopped.await(1,java.util.concurrent.TimeUnit.SECONDS))
            assertFalse(admission.captureEligible())
            assertTrue(capture.journal().isClosed(f.scope.intervalId)>0)
            assertEquals(1,f.db.sends().closed(f.scope.intervalId))
            assertEquals(1L,release.count)
            release.countDown()
            assertEquals(ConversationSubmission.UNKNOWN,send.get(3,java.util.concurrent.TimeUnit.SECONDS))
            stop.get(1,java.util.concurrent.TimeUnit.SECONDS)
            assertEquals("unknown",f.db.sends().receipt(uuid(f.message))!!.state)
            assertEquals(0,f.preparations);assertEquals(0,f.submissions)
            assertThrows(Exception::class.java){sender.submitConfirmed(uuid(f.message))}
            assertEquals(1,f.exchanges)
        } finally {release.countDown();executor.shutdown();assertTrue(executor.awaitTermination(5,java.util.concurrent.TimeUnit.SECONDS));capture.close()}
    }
    @Test fun bodyOnlyMissingClaimPurgedProofAndTamperedOriginalNeverRequestGrant() {
        Fixture().use{f->val t=f.transport();assertEquals(ConversationSubmission.UNKNOWN,t.submit(uuid(f.message),f.attempt,f.scope,"Synthetic reply"));assertEquals(0,f.exchanges)}
        Fixture().use{f->f.retain(false);assertEquals(ConversationSubmission.UNKNOWN,f.transport().submitClaimed(f.token()));assertEquals(0,f.exchanges)}
        Fixture().use{f->f.retain();f.db.sends().purgePayloadBefore(f.deadline+1);assertEquals(ConversationSubmission.UNKNOWN,f.transport().submitClaimed(f.token()));assertEquals(0,f.exchanges)}
        Fixture().use{f->f.retain();assertEquals(ConversationSubmission.UNKNOWN,f.transport().submitClaimed(f.token(f.original.copyOf().also{it[it.lastIndex]=(it.last().toInt() xor 1).toByte()})));assertEquals(0,f.exchanges)}
    }
    @Test fun grantIdentityDigestGenerationReaderAndDeadlineTamperCannotPrepare() {
        val edits=listOf<(JSONObject)->Unit>(
            {it.put("account_id",UUID.randomUUID().toString())},{it.put("device_id",UUID.randomUUID().toString())},
            {it.put("line_id",UUID.randomUUID().toString())},{it.put("message_id",UUID.randomUUID().toString())},
            {it.put("attempt_id",UUID.randomUUID().toString())},{it.put("connection_epoch",8)},
            {it.put("deployment_epoch",4)},{it.put("binding_generation",2)},{it.put("attempt_generation",2)},
            {it.put("reader_key_id",Base64.getUrlEncoder().withoutPadding().encodeToString(ByteArray(32)))},
            {it.put("envelope_sha256",Base64.getUrlEncoder().withoutPadding().encodeToString(ByteArray(32)))},
            {it.put("unsigned_sha256",Base64.getUrlEncoder().withoutPadding().encodeToString(ByteArray(32)))},
            {it.put("expires_at_ms",1_893_456_022_000L)})
        edits.forEach{edit->Fixture().use{f->f.retain();f.edit=edit
            assertEquals(ConversationSubmission.UNKNOWN,f.transport().submitClaimed(f.token()));assertEquals(0,f.preparations);assertEquals(0,f.submissions)}}
    }
    @Test fun sessionRotationLocalReaderWindowAndExpiryAfterWaitRefuseWithoutRetry() {
        val changes=listOf<(Fixture)->Unit>(
            {it.live=false},{it.now=it.deadline},{it.window=it.now+1},
            {it.local=SealedDispatchExecutor.Local(it.binding,ByteArray(32),1,1,hex(it.authority.digest),hex(sha(ascii(it.scope.peer))))})
        changes.forEach{change->Fixture().use{f->f.retain();f.exchangeHook={change(f)};val t=f.transport()
            assertEquals(ConversationSubmission.UNKNOWN,t.submitClaimed(f.token()));assertEquals(0,f.preparations)
            assertEquals(ConversationSubmission.UNKNOWN,t.submitClaimed(f.token()));assertEquals(1,f.exchanges)}}
    }
    @Test fun intervalCloseAfterGrantAndLossAfterPreparationCloseHolderWithoutConsumer() {
        Fixture().use{f->f.retain();f.exchangeHook={f.db.sends().close(f.scope.intervalId)}
            assertEquals(ConversationSubmission.UNKNOWN,f.transport().submitClaimed(f.token()));assertEquals(0,f.preparations)}
        Fixture().use{f->f.retain();f.prepareHook={f.live=false}
            assertEquals(ConversationSubmission.UNKNOWN,f.transport().submitClaimed(f.token()));assertTrue(f.preparedBody.all{it=='\u0000'});assertEquals(0,f.submissions)}
    }
    @Test fun unsupportedPreparationAndUncertainConsumerRemainUnknownAndCloseHolder() {
        Fixture().use{f->f.retain();f.unavailable=true;assertEquals(ConversationSubmission.UNKNOWN,f.transport().submitClaimed(f.token()));assertEquals(0,f.submissions)}
        Fixture().use{f->f.retain();f.throwConsumer=true;val t=f.transport()
            assertEquals(ConversationSubmission.UNKNOWN,t.submitClaimed(f.token()));assertTrue(f.preparedBody.all{it=='\u0000'})
            assertEquals(ConversationSubmission.UNKNOWN,t.submitClaimed(f.token()));assertEquals(1,f.submissions)}
    }
    companion object {
        private fun pair()=KeyPairGenerator.getInstance("EC").apply{initialize(256)}.generateKeyPair()
        private fun point(key:KeyPair)=DevicePayloadKeyStore.encodePoint(key.public as ECPublicKey)
        private fun signature(key:KeyPair,bytes:ByteArray)=Draft01SignaturePrimitive.canonicalRawFromDer(Signature.getInstance("SHA256withECDSA").run{initSign(key.private);update(bytes);sign()})
        private fun ascii(value:String)=value.toByteArray(Charsets.US_ASCII)
        private fun long(value:Long)=ByteBuffer.allocate(8).putLong(value).array()
        private fun int(value:Int)=ByteBuffer.allocate(4).putInt(value).array()
        private fun sha(bytes:ByteArray)=MessageDigest.getInstance("SHA-256").digest(bytes)
        private fun id(key:KeyPair,role:Int)=sha(ascii("ZTSE/key/v1\u0000")+(if(role<=3)byteArrayOf(0,16)else byteArrayOf(1,1))+point(key))
        private fun bytes(value:String)=UUID.fromString(value).let{ByteBuffer.allocate(16).putLong(it.mostSignificantBits).putLong(it.leastSignificantBits).array()}
        private fun uuid(value:ByteArray)=ByteBuffer.wrap(value).let{UUID(it.long,it.long).toString()}
        private fun hex(value:ByteArray)=Draft02OutboundPreparation.hex(value)
    }
}

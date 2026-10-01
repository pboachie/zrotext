// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import androidx.room.Room
import java.nio.ByteBuffer
import java.security.KeyPairGenerator
import java.security.Signature
import java.util.UUID
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.spec.GCMParameterSpec
import org.junit.*
import org.junit.Assert.*
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment
import org.robolectric.annotation.Config

/** State/admission tests; this signed fixture format is not the network confirmation codec. */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [28])
class ConversationConfirmedSendTest {
    private val scope = ConversationCaptureScope(uuid(),uuid(),uuid(),1,"+12",uuid(),uuid(),uuid(),"11".repeat(32),"22".repeat(32),1,2,"33".repeat(32),"44".repeat(32))
    private val authority = object:ConversationActivationVerifier {
        override fun verifiedPreparation(evidence:ByteArray)=scope
        override fun verifiedActiveLease(scope:ConversationCaptureScope,challenge:String,evidence:ByteArray)=60000L
    }
    private val signer=KeyPairGenerator.getInstance("EC").apply{initialize(256)}.generateKeyPair()
    private val key=KeyGenerator.getInstance("AES").apply{init(256)}.generateKey()
    private lateinit var capture:ConversationCaptureDatabase
    private lateinit var db:ConversationSendDatabase
    private lateinit var gate:ConversationCaptureAdmission
    private lateinit var sender:ConversationConfirmedSend
    private var trustedAvailable=true; private var clockThrows=false; private var wall=1000L; private var elapsed=100L; private var allowed=true
    private var submits=0; private var verificationCalls=0
    private var sealHook:()->Unit={}; private var verifyHook:()->Unit={}; private var submitHook:()->Unit={}
    private var guardHook:()->Unit={}
    private var outcome=ConversationSubmission.SUBMITTED
    private var verified=VerifiedConversationSend(scope,uuid(),31000,"Fixture confirmed reply Ω\nExact spaces  ")
    private val protection=object:ConversationJournalProtection {
        override fun seal(value:String,aad:String):InboundVault.Sealed {
            sealHook();val c=Cipher.getInstance("AES/GCM/NoPadding");c.init(Cipher.ENCRYPT_MODE,key);c.updateAAD(aad.toByteArray())
            return InboundVault.Sealed(c.doFinal(value.toByteArray()),c.iv)
        }
        override fun open(value:InboundVault.Sealed,aad:String):String {
            val c=Cipher.getInstance("AES/GCM/NoPadding");c.init(Cipher.DECRYPT_MODE,key,GCMParameterSpec(128,value.nonce));c.updateAAD(aad.toByteArray())
            return c.doFinal(value.ciphertext).toString(Charsets.UTF_8)
        }
    }
    private val verifier=object:ConversationSendVerifier {
        override fun verify(evidence:ByteArray):VerifiedConversationSend {
            verificationCalls++;verifyHook();val b=ByteBuffer.wrap(evidence);val sig=ByteArray(b.int).also(b::get);val content=ByteArray(b.remaining()).also(b::get)
            check(Signature.getInstance("SHA256withECDSA").apply{initVerify(signer.public);update(content)}.verify(sig))
            check(content.toString(Charsets.UTF_8)==payload(verified));return verified
        }
    }
    @Before fun setup() {
        capture=Room.inMemoryDatabaseBuilder(RuntimeEnvironment.getApplication(),ConversationCaptureDatabase::class.java).allowMainThreadQueries().build()
        RuntimeEnvironment.getApplication().deleteDatabase("confirmed-send-test.db")
        db=openDb();gate=ConversationCaptureAdmission(capture.journal(),authority,protection,{elapsed},{guardHook();check(allowed && it==scope)})
        gate.prepare(byteArrayOf(1),true);val request=gate.beginRecovery();gate.completeRecovery(request.challenge,byteArrayOf(1));sender=newSender()
    }
    @After fun cleanup(){db.close();capture.close();RuntimeEnvironment.getApplication().deleteDatabase("confirmed-send-test.db")}
    private fun openDb()=Room.databaseBuilder(RuntimeEnvironment.getApplication(),ConversationSendDatabase::class.java,"confirmed-send-test.db").allowMainThreadQueries().build()
    private fun newSender()=ConversationConfirmedSend(db.sends(),gate,verifier,protection,{if(clockThrows)throw java.io.IOException("fixture clock unavailable");if(trustedAvailable)wall else null},object:ConversationSendTransport {
        override fun submit(message:String,attempt:String,scope:ConversationCaptureScope,body:String):ConversationSubmission {
            assertEquals(verified.message,message);assertEquals(verified.scope,scope);assertEquals(verified.body,body)
            assertEquals("claimed",db.sends().receipt(message)!!.state);assertEquals(attempt,db.sends().receipt(message)!!.attempt)
            submits++;submitHook();return outcome
        }
    })
    private fun payload(v:VerifiedConversationSend)="fixture-confirmed|${v.scope.encode()}|${v.message}|${v.expiresAt}|${v.body}"
    @Test fun deliveryForDifferentRequestedMessageCannotReserveOrSubmit() {
        assertThrows(IllegalStateException::class.java){sender.receiveConfirmed(evidence(),uuid())}
        assertNull(db.sends().receipt(verified.message));assertEquals(0,submits)
    }
    private fun evidence(v:VerifiedConversationSend=verified):ByteArray {
        val content=payload(v).toByteArray();val sig=Signature.getInstance("SHA256withECDSA").apply{initSign(signer.private);update(content)}.sign()
        return ByteBuffer.allocate(4+sig.size+content.size).putInt(sig.size).put(sig).put(content).array()
    }
    private fun receive():ByteArray=evidence().also(sender::receiveConfirmed)
    private fun reopen(){db.close();db=openDb();sender=newSender()}

    @Test fun confirmedCiphertextAndIdentitySurviveReopenWithoutPlaintext(){val input=receive();val row=db.sends().receipt(verified.message)!!;assertFalse(String(row.protectedPayload!!).contains(verified.body));reopen();assertArrayEquals(row.protectedPayload,db.sends().receipt(verified.message)!!.protectedPayload);sender.receiveConfirmed(input);assertArrayEquals(row.protectedPayload,db.sends().receipt(verified.message)!!.protectedPayload)}
    @Test fun duplicateConfirmationNeverRewritesProtectedPayload(){val input=receive();val original=db.sends().receipt(verified.message)!!.protectedPayload!!.copyOf();sender.receiveConfirmed(input);assertArrayEquals(original,db.sends().receipt(verified.message)!!.protectedPayload);assertEquals(1,db.sends().count())}
    @Test fun confirmedIdentityCannotChangeUnderSameMessage(){receive();verified=verified.copy(body="Changed fixture");assertThrows(IllegalStateException::class.java){receive()};assertEquals(0,submits)}
    @Test fun signedWrongPeerCannotEnterSharedScope(){verified=verified.copy(scope=scope.copy(peer="+13"));assertThrows(IllegalStateException::class.java){receive()};assertEquals(0,db.sends().count());assertFalse(gate.captureEligible())}
    @Test fun expiredIntentDoesNotReachJournal(){wall=31000;assertThrows(IllegalStateException::class.java){receive()};assertEquals(0,db.sends().count())}
    @Test fun expiredLeaseAfterEncryptionCannotPersistIntent(){sealHook={elapsed=60100};assertThrows(IllegalStateException::class.java){receive()};assertEquals(0,db.sends().count())}
    @Test fun durableClaimPrecedesOneSubmissionAndReplayNeverCallsTransport(){receive();assertEquals(ConversationSubmission.SUBMITTED,sender.submitConfirmed(verified.message));assertEquals("submitted",db.sends().receipt(verified.message)!!.state);reopen();assertThrows(IllegalStateException::class.java){sender.submitConfirmed(verified.message)};assertEquals(1,submits)}
    @Test fun transportExceptionStaysUnknownAcrossRestart(){receive();submitHook={throw java.io.IOException("fixture transport uncertain")};assertEquals(ConversationSubmission.UNKNOWN,sender.submitConfirmed(verified.message));assertEquals("unknown",db.sends().receipt(verified.message)!!.state);reopen();assertThrows(IllegalStateException::class.java){sender.submitConfirmed(verified.message)};assertEquals(1,submits)}
    @Test fun outcomePersistenceFailureLeavesClaimedFenceAcrossRestart(){receive();submitHook={db.openHelper.writableDatabase.execSQL("PRAGMA query_only=ON")};assertThrows(RuntimeException::class.java){sender.submitConfirmed(verified.message)};assertEquals("claimed",db.sends().receipt(verified.message)!!.state);reopen();assertThrows(IllegalStateException::class.java){sender.submitConfirmed(verified.message)};assertEquals(1,submits)}
    @Test fun failedDurableClaimNeverCallsTransport(){receive();db.openHelper.writableDatabase.execSQL("PRAGMA query_only=ON");assertThrows(RuntimeException::class.java){sender.submitConfirmed(verified.message)};assertEquals(0,submits)}
    @Test fun intentExpiryDuringReverificationKeepsClaimedWithoutSubmitting(){receive();verifyHook={if(verificationCalls>=3)wall=31000};assertThrows(IllegalStateException::class.java){sender.submitConfirmed(verified.message)};assertEquals("claimed",db.sends().receipt(verified.message)!!.state);assertEquals(0,submits)}
    @Test fun revocationDuringReverificationKeepsClaimedWithoutSubmitting(){receive();verifyHook={if(verificationCalls>=3)allowed=false};assertThrows(IllegalStateException::class.java){sender.submitConfirmed(verified.message)};assertEquals("claimed",db.sends().receipt(verified.message)!!.state);assertEquals(0,submits)}
    @Test fun expiryDuringFinalAdmissionQueryCannotReachTransport(){receive();guardHook={if(db.sends().receipt(verified.message)?.state=="claimed")wall=31000};assertThrows(IllegalStateException::class.java){sender.submitConfirmed(verified.message)};assertEquals("claimed",db.sends().receipt(verified.message)!!.state);assertEquals(0,submits)}
    @Test fun clockRollbackDuringReverificationLeavesClaimedAndCannotRecoverSilently(){receive();wall=1100;verifyHook={if(verificationCalls>=3)wall=1000};assertThrows(IllegalStateException::class.java){sender.submitConfirmed(verified.message)};assertEquals("claimed",db.sends().receipt(verified.message)!!.state);assertEquals(0,submits);verifyHook={};wall=1200;verified=verified.copy(message=uuid());assertThrows(IllegalStateException::class.java){receive()};assertEquals(1,db.sends().count())}
    @Test fun throwingClockLatchesUnavailableBeforeJournal(){clockThrows=true;assertThrows(java.io.IOException::class.java){receive()};clockThrows=false;assertThrows(IllegalStateException::class.java){receive()};assertEquals(0,db.sends().count());assertEquals(0,submits)}
    @Test fun restartWithoutFreshTrustedTimeCannotSubmit(){receive();reopen();trustedAvailable=false;assertThrows(IllegalStateException::class.java){sender.submitConfirmed(verified.message)};assertEquals("confirmed",db.sends().receipt(verified.message)!!.state);assertEquals(0,submits)}
    @Test fun purgeRetainsFenceAndReplayCannotRehydrateCiphertext(){val input=receive();assertEquals(1,db.sends().purgePayloadBefore(31001));sender.receiveConfirmed(input);assertNull(db.sends().receipt(verified.message)!!.protectedPayload);assertThrows(IllegalStateException::class.java){sender.submitConfirmed(verified.message)};assertEquals(0,submits)}
    @Test fun closeCancelsPendingAndSharedGateBeforeFurtherSubmission(){receive();sender.close(scope.intervalId);assertEquals("cancelled",db.sends().receipt(verified.message)!!.state);assertNull(db.sends().receipt(verified.message)!!.protectedPayload);assertFalse(gate.captureEligible());assertThrows(IllegalStateException::class.java){sender.submitConfirmed(verified.message)};assertEquals(0,submits)}
    @Test fun sendCloseFailureCannotReopenDurablyClosedCaptureGate(){receive();db.openHelper.writableDatabase.execSQL("PRAGMA query_only=ON");assertThrows(RuntimeException::class.java){sender.close(scope.intervalId)};assertFalse(gate.captureEligible());assertEquals("closed",capture.journal().installation()!!.state);reopen();assertThrows(IllegalStateException::class.java){sender.submitConfirmed(verified.message)};assertEquals(0,submits)}
    @Test fun changedCiphertextFailsBeforeTransport(){receive();db.openHelper.writableDatabase.execSQL("UPDATE conversation_send_receipts SET protectedPayload=zeroblob(length(protectedPayload))");assertThrows(javax.crypto.AEADBadTagException::class.java){sender.submitConfirmed(verified.message)};assertEquals(0,submits)}
    companion object {private fun uuid()=UUID.randomUUID().toString()}
}

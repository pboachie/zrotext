// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import java.nio.ByteBuffer
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.MessageDigest
import java.security.Signature
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec
import java.util.UUID
import javax.crypto.Cipher
import javax.crypto.KeyAgreement
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34])
class ConversationContentCryptoTest {
    @Test fun inboundCaptureNeedsNoReplySignerAndExplicitPreservedSuccessorEnablesReply() {
        val f=Fixture(false); val crypto=f.crypto()
        f.authority.requireDeviceReader(f.account,f.device,f.line,f.recipientId,f.now)
        assertTrue(crypto.sealCapture(f.capture("Inbound before reply enrollment"),1).isNotEmpty())
        assertThrows(Exception::class.java) { crypto.verify(f.evidence("No reply authority")) }
        assertEquals(0,f.openCalls)
        val next=f.replySuccessor()
        next.requireReplySuccessor(f.authority,id(f.browser,5))
        f.live=ConversationCryptoCurrent(f.scope,next,point(f.archive),id(f.browser,5),id(f.phone,4),f.now)
        next.context(Draft02ManifestAuthority.Request(Draft02ManifestAuthority.Direction.OUTBOUND,
            f.account,f.message,f.device,f.line,ascii("+12"),id(f.browser,5),
            listOf(Draft02ManifestAuthority.Reader(1,f.recipientId),Draft02ManifestAuthority.Reader(2,f.archiveId))),f.now)
        assertTrue(crypto.sealCapture(f.capture("Inbound after reply enrollment"),2).isNotEmpty())
        assertEquals("Reply after enrollment",crypto.verify(f.evidence("Reply after enrollment")).body)
    }
    @Test fun replySuccessorCannotReplaceExistingPhoneAuthorityAndReaderCheckRejectsWrongLineOrTime() {
        val f=Fixture(false)
        assertThrows(Exception::class.java) { f.replySuccessor(true).requireReplySuccessor(f.authority,id(f.browser,5)) }
        assertThrows(Exception::class.java) { f.authority.requireDeviceReader(f.account,f.device,ByteArray(16){9},f.recipientId,f.now) }
        assertThrows(Exception::class.java) { f.authority.requireDeviceReader(f.account,f.device,f.line,f.recipientId,f.now+60_000) }
        assertTrue(f.live!!.outboundSignerKeyId.all { it == 0.toByte() })
        assertThrows(Exception::class.java) { f.crypto().verify(f.evidence("Still unavailable")) }
        assertEquals(0,f.openCalls)
    }
    @Test fun captureOwningAuthorityGateCannotDeadlockConcurrentReplyVerification() {
        val f=Fixture();val evidence=f.evidence("Synthetic reply");val capture=f.capture("Synthetic capture")
        val authorityGate=Any()
        val captureEntered=java.util.concurrent.CountDownLatch(1)
        val verifySampling=java.util.concurrent.CountDownLatch(1)
        val failures=java.util.concurrent.ConcurrentLinkedQueue<Throwable>()
        val crypto=ConversationContentCrypto(f) {
            if(Thread.currentThread().name=="reply-verification")verifySampling.countDown()
            synchronized(authorityGate){f.live}
        }
        val captureThread=Thread({try {
            synchronized(authorityGate) {
                captureEntered.countDown()
                check(verifySampling.await(2,java.util.concurrent.TimeUnit.SECONDS))
                crypto.sealCapture(capture,1)
            }
        } catch(error:Throwable){failures.add(error)}},"capture-authority")
        val verifyThread=Thread({try {
            check(captureEntered.await(2,java.util.concurrent.TimeUnit.SECONDS))
            crypto.verify(evidence)
        } catch(error:Throwable){failures.add(error)}},"reply-verification")
        // A regression must fail a bounded assertion rather than leave the test JVM hung.
        captureThread.isDaemon=true;verifyThread.isDaemon=true
        captureThread.start();verifyThread.start()
        captureThread.join(3000);verifyThread.join(3000)
        assertFalse("Capture blocked by verification authority sampling",captureThread.isAlive)
        assertFalse("Verification blocked by capture authority sampling",verifyThread.isAlive)
        assertTrue(failures.toString(),failures.isEmpty())
    }
    @Test fun confirmationMatchesIndependentServerVectorAndContainerRejectsMalformedBounds() {
        val vector=JSONObject(javaClass.classLoader!!.getResourceAsStream("conversation-send.json")!!.bufferedReader().use{it.readText()})
        val bytes=hex(vector.getString("canonical_hex"))
        val c=ConversationContentCrypto.Confirmation.decode(bytes)
        assertEquals(vector.getJSONObject("confirmation").getString("session"),c.session)
        assertArrayEquals(hex(vector.getString("transcript_hex")),c.transcript(bytes))
        val evidence=ConversationContentCrypto.packConfirmedEvidence(ByteArray(557),bytes,ByteArray(64))
        assertArrayEquals(bytes,ConversationContentCrypto.unpackConfirmedEvidence(evidence).confirmation)
        for(bad in listOf(ByteArray(0),evidence+byteArrayOf(0),evidence.copyOf(evidence.size-1),
            evidence.copyOf().also{it[4]=2},evidence.copyOf().also{ByteBuffer.wrap(it).putInt(5,Int.MAX_VALUE)})) {
            assertThrows(Exception::class.java){ConversationContentCrypto.unpackConfirmedEvidence(bad)}
        }
        assertThrows(Exception::class.java){ConversationContentCrypto.Confirmation.decode(bytes+byteArrayOf(0))}
    }

    @Test fun captureIsSignedAndArchiveDecryptsExactBodyWithCanonicalCaptureIdentity() {
        val f=Fixture();val body="Synthetic exact body\n  Spaces";val capture=f.capture(body)
        val envelope=f.crypto().sealCapture(capture,7)
        val unsigned=envelope.copyOfRange(0,envelope.size-64)
        ConversationContentCrypto.checkInboundUnsigned(unsigned,point(f.phone))
        assertTrue(ConversationContentCrypto.verifyRaw(envelope.takeLast(64).toByteArray(),point(f.phone),
            ascii("ZTSE/sign/v2\u0000")+int(unsigned.size)+unsigned))
        val n=ByteBuffer.wrap(envelope,8,2).short.toInt() and 65535
        val protected=envelope.copyOfRange(10,10+n); val at=10+n
        assertArrayEquals(uuid(capture.captureId),protected.copyOfRange(144,160))
        assertEquals(7L,ByteBuffer.wrap(protected,160,8).long)
        val length=ByteBuffer.wrap(envelope,at+12,4).int;val wrapAt=at+16+length+1
        val enc=envelope.copyOfRange(wrapAt+33,wrapAt+98)
        val dh=KeyAgreement.getInstance("ECDH").run{init(f.archive.private);doPhase(DevicePayloadKeyStore.decodePoint(enc),true);generateSecret()}
        val secret=Draft02PublicJcaKeystoreHpke.deriveSharedSecret(dh,enc,point(f.archive))
        val material=Draft02PublicJcaKeystoreHpke.deriveKeyMaterial(secret,ascii("ZTSE/wrap/v2\u0000")+envelope.copyOfRange(0,10)+protected+byteArrayOf(2)+f.archiveId)
        val cek=Cipher.getInstance("AES/GCM/NoPadding").run{init(Cipher.DECRYPT_MODE,SecretKeySpec(material.key,"AES"),GCMParameterSpec(128,material.nonce));doFinal(envelope.copyOfRange(wrapAt+98,wrapAt+146))}
        val opened=Cipher.getInstance("AES/GCM/NoPadding").run{init(Cipher.DECRYPT_MODE,SecretKeySpec(cek,"AES"),GCMParameterSpec(128,envelope.copyOfRange(at,at+12)));updateAAD(ascii("ZTSE/body/v2\u0000")+envelope.copyOfRange(0,10)+protected);doFinal(envelope.copyOfRange(at+16,at+16+length))}
        assertEquals(body,opened.toString(Charsets.UTF_8))
        opened.fill(0);cek.fill(0);material.clear();secret.fill(0);dh.fill(0)
    }

    @Test fun captureRefusesWrongScopeMalformedTextClockLossAndAuthorityChangedDuringSigning() {
        val f=Fixture(); val crypto=f.crypto()
        assertThrows(Exception::class.java){crypto.sealCapture(f.capture("body").copy(scope=f.scope.copy(peer="+13")),1)}
        for(body in listOf("","\u0000","\uFEFFbody","\uD800")) assertThrows(Exception::class.java){crypto.sealCapture(f.capture(body),1)}
        assertThrows(Exception::class.java){crypto.sealCapture(f.capture("body"),0)}
        f.onSign={f.live=f.live!!.let{ConversationCryptoCurrent(it.scope.copy(peer="+13"),it.authority,it.archiveReaderPoint,it.outboundSignerKeyId,it.phoneSignerKeyId,it.trustedNowMs)}}
        assertThrows(Exception::class.java){crypto.sealCapture(f.capture("body"),1)}
        val missing=Fixture();missing.live=null
        assertThrows(Exception::class.java){missing.crypto().sealCapture(missing.capture("body"),1)}
        assertEquals(0,missing.signCalls)
    }

    @Test fun confirmedReplyVerifiesBothSignaturesAndExactDecryptedDigestThenClearsCek() {
        val f=Fixture();val evidence=f.evidence("Synthetic reply\n  exact")
        val verified=f.crypto().verify(evidence)
        assertEquals("Synthetic reply\n  exact",verified.body)
        assertEquals(f.scope,verified.scope)
        assertTrue(f.lastCek!!.all{it==0.toByte()})
        assertFalse(verified.toString().contains(verified.body))
    }

    @Test fun validSignaturesCannotBypassSessionReaderBodyExpiryOrHardwareCustody() {
        for(edit in listOf<(ByteArray)->Unit>(
            {it[69]=(it[69].toInt() xor 1).toByte()}, // Initiating session, signed again.
            {it[169]=(it[169].toInt() xor 1).toByte()}, // Reader ID.
            {it[it.lastIndex]=(it.last().toInt() xor 1).toByte()}, // Plaintext digest.
            {ByteBuffer.wrap(it).putLong(125,1)} // Confirmation expiry.
        )) {val f=Fixture();assertThrows(Exception::class.java){f.crypto().verify(f.evidence("body",edit))}}
        val software=Fixture();software.security=PayloadKeySecurity.SOFTWARE
        assertThrows(Exception::class.java){software.crypto().verify(software.evidence("body"))}
        assertEquals(0,software.openCalls)
        val f=Fixture();f.onOpen={f.live=f.live!!.let{ConversationCryptoCurrent(it.scope,it.authority,it.archiveReaderPoint,it.outboundSignerKeyId,it.phoneSignerKeyId,f.now+30_000)}}
        assertThrows(Exception::class.java){f.crypto().verify(f.evidence("body"))}
        assertTrue(f.lastCek!!.all{it==0.toByte()})
    }

    @Test fun signingBoundaryRejectsWrongProfilePointAndMissingExistingIdentity() {
        val f=Fixture();val valid=f.crypto().sealCapture(f.capture("body"),1).let{it.copyOfRange(0,it.size-64)}
        val store=DeviceSigningKeyStore(org.robolectric.RuntimeEnvironment.getApplication(),"synthetic-missing-conversation-signer")
        assertThrows(Exception::class.java){store.signConversationEnvelope(valid.copyOf().also{it[5]=1},point(f.phone))}
        assertThrows(Exception::class.java){store.signConversationEnvelope(valid,point(f.browser))}
        assertThrows(Exception::class.java){store.signConversationEnvelope(valid,point(f.phone))}
    }

    @Test @Config(sdk = [30]) fun unsupportedApiRefusesBeforeAnyExistingKeyUse() {
        val f=Fixture();val crypto=f.crypto()
        assertThrows(Exception::class.java){crypto.sealCapture(f.capture("body"),1)}
        assertThrows(Exception::class.java){crypto.verify(f.evidence("body"))}
        assertEquals(0,f.signCalls);assertEquals(0,f.openCalls)
    }

    @Test fun clockRegressionRequiresRecoveryEvenIfClockIsRestored() {
        val f=Fixture();val crypto=f.crypto();val evidence=f.evidence("body")
        crypto.verify(evidence)
        val original=f.live!!
        f.live=ConversationCryptoCurrent(original.scope,original.authority,original.archiveReaderPoint,
            original.outboundSignerKeyId,original.phoneSignerKeyId,f.now-1)
        assertThrows(Exception::class.java){crypto.verify(evidence)}
        f.live=original
        assertThrows(Exception::class.java){crypto.verify(evidence)}
    }

    @Test fun highSAndMutatedConfirmationSignaturesAreRefused() {
        val f=Fixture();val evidence=f.evidence("body")
        val parts=ConversationContentCrypto.unpackConfirmedEvidence(evidence)
        val high=parts.signature.copyOf()
        val order=java.math.BigInteger("FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551",16)
        val scalar=(order-java.math.BigInteger(1,high.copyOfRange(32,64))).toByteArray().takeLast(32).toByteArray()
        ByteArray(32-scalar.size).plus(scalar).copyInto(high,32)
        assertThrows(Exception::class.java){f.crypto().verify(ConversationContentCrypto.packConfirmedEvidence(parts.envelope,parts.confirmation,high))}
        val wrong=parts.signature.copyOf().also{it[0]=(it[0].toInt() xor 1).toByte()}
        assertThrows(Exception::class.java){f.crypto().verify(ConversationContentCrypto.packConfirmedEvidence(parts.envelope,parts.confirmation,wrong))}
    }

    @Test fun selectedOriginalReaderAndArchiveOpenTheSameCekAndNoExtraReaderCanLookup() {
        val f=Fixture(selectedReader=true);val envelope=f.crypto().sealCapture(f.capture("Selected original body"),1)
        val n=ByteBuffer.wrap(envelope,8,2).short.toInt() and 65535
        val protected=envelope.copyOfRange(10,10+n);val at=10+n
        val length=ByteBuffer.wrap(envelope,at+12,4).int;val countAt=at+16+length
        assertEquals(2,envelope[countAt].toInt())
        fun openCek(index:Int,key:KeyPair,role:Int):ByteArray {
            val start=countAt+1+index*146;assertEquals(role,envelope[start].toInt())
            assertArrayEquals(id(key,role),envelope.copyOfRange(start+1,start+33))
            val enc=envelope.copyOfRange(start+33,start+98)
            val dh=KeyAgreement.getInstance("ECDH").run{init(key.private);doPhase(DevicePayloadKeyStore.decodePoint(enc),true);generateSecret()}
            val secret=Draft02PublicJcaKeystoreHpke.deriveSharedSecret(dh,enc,point(key))
            val material=Draft02PublicJcaKeystoreHpke.deriveKeyMaterial(secret,ascii("ZTSE/wrap/v2\u0000")+envelope.copyOfRange(0,10)+protected+byteArrayOf(role.toByte())+id(key,role))
            return try { Cipher.getInstance("AES/GCM/NoPadding").run{init(Cipher.DECRYPT_MODE,SecretKeySpec(material.key,"AES"),GCMParameterSpec(128,material.nonce));doFinal(envelope.copyOfRange(start+98,start+146))} }
            finally{material.clear();secret.fill(0);dh.fill(0)}
        }
        val archive=openCek(0,f.archive,2);val customer=openCek(1,f.integration,3)
        try { assertArrayEquals(archive,customer) } finally {archive.fill(0);customer.fill(0)}
        val readers=listOf(Draft02ManifestAuthority.Reader(2,f.archiveId),Draft02ManifestAuthority.Reader(3,id(f.integration,3)))
        val context=f.authority.context(Draft02ManifestAuthority.Request(Draft02ManifestAuthority.Direction.INBOUND,
            f.account,f.message,f.device,f.line,ascii("+12"),id(f.phone,4),readers),f.now)
        assertArrayEquals(point(f.integration),f.authority.readerPoint(context,readers[1],f.now))
        assertThrows(Exception::class.java) { f.authority.readerPoint(context,Draft02ManifestAuthority.Reader(3,ByteArray(32){9}),f.now) }
        assertThrows(Exception::class.java) { f.authority.readerPoint(context,readers[1],f.now+60_000) }
        f.onSign={f.live=null}
        assertThrows(Exception::class.java) { f.crypto().sealCapture(f.capture("Withdraw while signing"),2) }
    }

    @Test fun revokedSelectedManifestReaderRefusesBeforeCaptureSigningWithoutRemovingArchiveRequirement() {
        val f=Fixture(selectedReader=true)
        val next=f.revokedIntegrationSuccessor()
        f.live=ConversationCryptoCurrent(f.scope,next,point(f.archive),id(f.browser,5),id(f.phone,4),f.now)
        assertThrows(Exception::class.java) { f.crypto().sealCapture(f.capture("Revoked reader"),1) }
        assertEquals(0,f.signCalls)
    }

    private class Fixture(includeReply: Boolean = true, selectedReader: Boolean = false):ConversationContentKeyOperations {
        val account=ByteArray(16){1};val device=ByteArray(16){2};val line=ByteArray(16){3};val message=ByteArray(16){4}
        val root=pair();val recipient=pair();val archive=pair();val integration=pair();val phone=pair();val browser=pair()
        val archiveId=id(archive,2);val recipientId=id(recipient,1)
        val now=1_893_456_001_000L
        val pin=ascii("ZTRP")+byteArrayOf(2)+account+long(1)+point(root)
        val manifest:ByteArray
        val authority:Draft02ManifestAuthority
        val scope:ConversationCaptureScope
        var live:ConversationCryptoCurrent?
        var onSign:()->Unit={};var onOpen:()->Unit={};var signCalls=0;var openCalls=0
        var security=PayloadKeySecurity.TRUSTED_ENVIRONMENT;var lastCek:ByteArray?=null
        private var cek=ByteArray(32){7}
        init {
            val records=(listOf(1 to recipient,2 to archive) + (if(selectedReader) listOf(3 to integration) else emptyList()) + listOf(4 to phone) + (if(includeReply) listOf(5 to browser) else emptyList()) + listOf(6 to root)).map{(role,key)->
                byteArrayOf(role.toByte())+id(key,role)+point(key)+(if(role==1||role==4)device else ByteArray(16))+
                    (if(role==1||role==4||role==5)line else ByteArray(16))+ByteBuffer.allocate(2).putShort(when(role){1->4;2->12;3->8;4->2;5->1;else->0}.toShort()).array()+long(now-1000)+long(now+60_000)+byteArrayOf(1)}
            val unsigned=ascii("ZTMA")+byteArrayOf(2)+account+long(1)+long(1)+long(now-1000)+long(now+60_000)+ByteArray(32)+point(root)+records.size.toByte()+records.fold(ByteArray(0)){a,b->a+b}
            manifest=unsigned+signature(root,ascii("ZTSE/manifest/v2\u0000")+int(unsigned.size)+unsigned)
            authority=Draft02ManifestAuthority.verify(pin,manifest,Draft02ManifestAuthority.Trust(account,sha(ascii("ZTSE/root-pin/v2\u0000")+pin),1,Draft02ManifestAuthority.Position.genesis(ByteArray(32))),now)
            scope=ConversationCaptureScope(str(account),str(device),str(line),1,"+12",str(ByteArray(16){5}),str(ByteArray(16){6}),str(ByteArray(16){7}),(if(selectedReader) ConversationActivationCodec.readerDisclosureDigest() else "01".repeat(32)),hex(archiveId),1,1,hex(authority.digest),"02".repeat(32),
                ConversationReaderSelection(if(selectedReader) listOf(ConversationIntegrationReader(str(ByteArray(16){8}),str(ByteArray(16){9}),hex(id(integration,3)))) else emptyList()))
            live=ConversationCryptoCurrent(scope,authority,point(archive),if(includeReply) id(browser,5) else ByteArray(32),id(phone,4),now)
        }
        fun revokedIntegrationSuccessor():Draft02ManifestAuthority {
            val records=manifest.copyOfRange(151,manifest.size-64).asList().chunked(149).map { it.toByteArray() }
            val changed=records.map { record -> record.copyOf().also { if(it[0]==3.toByte()) it[148]=2 } }
            val unsigned=ascii("ZTMA")+byteArrayOf(2)+account+long(1)+long(2)+long(now-1000)+long(now+60_000)+authority.digest+point(root)+changed.size.toByte()+changed.fold(ByteArray(0)){a,b->a+b}
            val signed=unsigned+signature(root,ascii("ZTSE/manifest/v2\u0000")+int(unsigned.size)+unsigned)
            return Draft02ManifestAuthority.verify(pin,signed,Draft02ManifestAuthority.Trust(account,sha(ascii("ZTSE/root-pin/v2\u0000")+pin),1,Draft02ManifestAuthority.Position.after(authority.version,authority.digest)),now)
        }
        fun replySuccessor(wrongPhone: Boolean = false): Draft02ManifestAuthority {
            val original = manifest.copyOfRange(151, manifest.size - 64).asList().chunked(149).map { it.toByteArray() }
            val records = original.toMutableList()
            if(wrongPhone) records[2] = records[2].copyOf().also { it[148] = 2 }
            val record = byteArrayOf(5)+id(browser,5)+point(browser)+ByteArray(16)+line+
                ByteBuffer.allocate(2).putShort(1).array()+long(now-1000)+long(now+60_000)+byteArrayOf(1)
            records.add(records.size-1, record)
            val unsigned=ascii("ZTMA")+byteArrayOf(2)+account+long(1)+long(2)+long(now-1000)+long(now+60_000)+authority.digest+point(root)+records.size.toByte()+records.fold(ByteArray(0)){a,b->a+b}
            val signed=unsigned+signature(root,ascii("ZTSE/manifest/v2\u0000")+int(unsigned.size)+unsigned)
            return Draft02ManifestAuthority.verify(pin,signed,Draft02ManifestAuthority.Trust(account,sha(ascii("ZTSE/root-pin/v2\u0000")+pin),1,Draft02ManifestAuthority.Position.after(authority.version,authority.digest)),now)
        }
        fun crypto()=ConversationContentCrypto(this){live}
        fun capture(body:String)=ConversationCapturedBody(scope,str(message),now,1,body)
        override fun recipient()=DevicePayloadPublic(point(recipient),recipientId,security)
        override fun sign(unsigned:ByteArray,point:ByteArray):ByteArray {signCalls++;assertArrayEquals(ConversationContentCryptoTest.point(phone),point);val result=signature(phone,ascii("ZTSE/sign/v2\u0000")+int(unsigned.size)+unsigned);onSign();return result}
        override fun open(parts:Draft02OutboundEnvelope.Parts):ByteArray {openCalls++;return cek.copyOf().also{lastCek=it;onOpen()}}
        fun evidence(body:String,edit:(ByteArray)->Unit={}):ByteArray {
            val protected=account+message+device+line+long(live!!.authority.version)+live!!.authority.digest+id(browser,5)+long(now)+long(now+20_000)+byteArrayOf(1,3)+ascii("+12")
            val header=ascii("ZTSE")+byteArrayOf(2,1,0,0)+ByteBuffer.allocate(2).putShort(protected.size.toShort()).array()
            val nonce=ByteArray(12){8};val cipher=Cipher.getInstance("AES/GCM/NoPadding");cipher.init(Cipher.ENCRYPT_MODE,SecretKeySpec(cek,"AES"),GCMParameterSpec(128,nonce));cipher.updateAAD(ascii("ZTSE/body/v2\u0000")+header+protected)
            val encrypted=cipher.doFinal(body.toByteArray(Charsets.UTF_8))
            val wraps=byteArrayOf(1)+recipientId+point(recipient)+ByteArray(48)+byteArrayOf(2)+archiveId+point(archive)+ByteArray(48)
            val unsigned=header+protected+nonce+int(encrypted.size)+encrypted+byteArrayOf(2)+wraps
            val envelope=unsigned+signature(browser,ascii("ZTSE/sign/v2\u0000")+int(unsigned.size)+unsigned)
            val confirmation=ascii("ZTCS")+byteArrayOf(1)+account+device+line+uuid(scope.intervalId)+uuid(scope.initiatingSessionId)+message+long(1)+long(1)+long(live!!.authority.version)+long(now+20_000)+byteArrayOf(3)+ascii("+12")+id(browser,5)+archiveId+live!!.authority.digest+sha(envelope)+sha(body.toByteArray(Charsets.UTF_8))
            edit(confirmation)
            return ConversationContentCrypto.packConfirmedEvidence(envelope,confirmation,signature(browser,ascii("zrotext/conversation/confirm-send/v1\u0000")+int(confirmation.size)+confirmation))
        }
    }
    companion object {
        private fun pair()=KeyPairGenerator.getInstance("EC").apply{initialize(ECGenParameterSpec("secp256r1"))}.generateKeyPair()
        private fun point(key:KeyPair)=DevicePayloadKeyStore.encodePoint(key.public as ECPublicKey)
        private fun signature(key:KeyPair,bytes:ByteArray)=Draft01SignaturePrimitive.canonicalRawFromDer(Signature.getInstance("SHA256withECDSA").run{initSign(key.private);update(bytes);sign()})
        private fun ascii(value:String)=value.toByteArray(Charsets.US_ASCII)
        private fun long(value:Long)=ByteBuffer.allocate(8).putLong(value).array()
        private fun int(value:Int)=ByteBuffer.allocate(4).putInt(value).array()
        private fun sha(bytes:ByteArray)=MessageDigest.getInstance("SHA-256").digest(bytes)
        private fun id(key:KeyPair,role:Int)=sha(ascii("ZTSE/key/v1\u0000")+(if(role<=3)byteArrayOf(0,16)else byteArrayOf(1,1))+point(key))
        private fun uuid(value:String)=UUID.fromString(value).let{ByteBuffer.allocate(16).putLong(it.mostSignificantBits).putLong(it.leastSignificantBits).array()}
        private fun str(value:ByteArray)=ByteBuffer.wrap(value).let{UUID(it.long,it.long).toString()}
        private fun hex(value:ByteArray)=value.joinToString(""){"%02x".format(it.toInt() and 255)}
        private fun hex(value:String)=value.chunked(2).map{it.toInt(16).toByte()}.toByteArray()
    }
}

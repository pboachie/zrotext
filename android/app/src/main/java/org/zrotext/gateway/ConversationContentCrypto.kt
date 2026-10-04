// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import android.os.Build
import java.io.ByteArrayOutputStream
import java.io.DataInputStream
import java.io.DataOutputStream
import java.math.BigInteger
import java.nio.ByteBuffer
import java.nio.CharBuffer
import java.nio.charset.CodingErrorAction
import java.security.KeyPairGenerator
import java.security.MessageDigest
import java.security.SecureRandom
import java.security.Signature
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec
import java.util.UUID
import javax.crypto.Cipher
import javax.crypto.KeyAgreement
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

/** Independently authenticated current state, never supplied by a received envelope. */
internal class ConversationCryptoCurrent(val scope: ConversationCaptureScope,
    val authority: Draft02ManifestAuthority, archiveReaderPoint: ByteArray,
    outboundSignerKeyId: ByteArray, phoneSignerKeyId: ByteArray, val trustedNowMs: Long) {
    private val archive = archiveReaderPoint.copyOf()
    private val outbound = outboundSignerKeyId.copyOf()
    private val phone = phoneSignerKeyId.copyOf()
    val archiveReaderPoint get() = archive.copyOf()
    val outboundSignerKeyId get() = outbound.copyOf()
    val phoneSignerKeyId get() = phone.copyOf()
    init { require(archive.size == 65 && outbound.size == 32 && phone.size == 32) }
    override fun toString() = "ConversationCryptoCurrent(redacted)"
}

/** No key creation, software identity fallback, persistence, transport or radio authority. */
internal class ConversationContentCrypto internal constructor(private val keys: ConversationContentKeyOperations,
    private val current: () -> ConversationCryptoCurrent?) : ConversationSendVerifier {
    constructor(payloadKeys: DevicePayloadKeyStore, signingKeys: DeviceSigningKeyStore,
        current: () -> ConversationCryptoCurrent?) : this(object : ConversationContentKeyOperations {
        override fun recipient() = payloadKeys.existingPublic()
        override fun sign(unsigned:ByteArray,point:ByteArray) = signingKeys.signConversationEnvelope(unsigned,point)
        override fun open(parts:Draft02OutboundEnvelope.Parts) = Draft02PublicJcaKeystoreHpke.openDeviceCek(
            payloadKeys,parts.header,parts.protected,1,parts.keyId,parts.enc,parts.wrap)
    },current)
    private var latestNow = 0L
    private var clockFailed = false
    private val timeLock = Any()
    private fun live(): ConversationCryptoCurrent {
        synchronized(timeLock) { check(!clockFailed) { "Trusted clock requires recovery" } }
        // Authority providers may sample the admission gate. Never invoke them under a
        // crypto monitor: capture already owns admission, while sends verify before admission.
        val value = try { current() } catch (failure: Exception) {
            synchronized(timeLock) { clockFailed = true }; throw failure
        }
        synchronized(timeLock) {
            check(!clockFailed) { "Trusted clock requires recovery" }
            if (value == null || value.trustedNowMs <= 0 || value.trustedNowMs < latestNow) {
                clockFailed = true
                error("Trusted crypto state unavailable")
            }
            latestNow = value.trustedNowMs
        }
        checkNotNull(value)
        check(value.authority.generation == value.scope.trustGeneration)
        check(value.authority.version >= value.scope.activationVersion)
        return value
    }
    private fun stable(initial: ConversationCryptoCurrent): ConversationCryptoCurrent = live().also {
        check(it.scope == initial.scope && it.authority.version == initial.authority.version &&
            same(it.authority.digest, initial.authority.digest) &&
            same(it.archiveReaderPoint, initial.archiveReaderPoint) &&
            same(it.outboundSignerKeyId, initial.outboundSignerKeyId) &&
            same(it.phoneSignerKeyId, initial.phoneSignerKeyId)) { "Crypto authority changed" }
    }
    private fun request(v: ConversationCryptoCurrent, message: String, inbound: Boolean, deviceReader: ByteArray? = null) =
        Draft02ManifestAuthority.Request(if (inbound) Draft02ManifestAuthority.Direction.INBOUND else Draft02ManifestAuthority.Direction.OUTBOUND,
            uuid(v.scope.accountId), uuid(message), uuid(v.scope.deviceId), uuid(v.scope.lineId),
            v.scope.peer.toByteArray(Charsets.US_ASCII), if (inbound) v.phoneSignerKeyId else v.outboundSignerKeyId,
            (if (inbound) emptyList() else listOf(Draft02ManifestAuthority.Reader(1, checkNotNull(deviceReader)))) +
                Draft02ManifestAuthority.Reader(2, unhex(v.scope.readerKeyId)) +
                (if(inbound) v.scope.selectedReaders.map { Draft02ManifestAuthority.Reader(3,unhex(it.keyId)) } else emptyList()))

    /** One immutable capture identity and positive journal sequence; caller admission remains mandatory. */
    fun sealCapture(capture: ConversationCapturedBody, sequence: Long): ByteArray {
        DevicePayloadKeyStore.requireSupportedSdk(Build.VERSION.SDK_INT)
        require(sequence > 0)
        val initial = live()
        check(capture.scope == initial.scope && capture.firstObservedAtMs in 1..initial.trustedNowMs)
        val selected = request(initial, capture.captureId, true)
        val context = initial.authority.context(selected, initial.trustedNowMs)
        check(same(DevicePayloadKeyStore.keyId(initial.archiveReaderPoint), unhex(initial.scope.readerKeyId)))
        val chars = capture.body.toCharArray()
        val content = try { encodeText(chars) } finally { chars.fill('\u0000') }
        val cek = ByteArray(32)
        val nonce = ByteArray(12)
        try {
            val random = SecureRandom()
            random.nextBytes(cek)
            random.nextBytes(nonce)
            val protected = ByteBuffer.allocate(169 + context.peer.size)
                .put(context.accountId).put(context.messageId).put(context.deviceId).put(context.lineId)
                .putLong(context.version).put(context.manifestDigest).put(context.signerKeyId)
                .putLong(capture.firstObservedAtMs).put(uuid(capture.captureId)).putLong(sequence)
                .put(context.peer.size.toByte()).put(context.peer).array()
            val header = byteArrayOf(0x5a,0x54,0x53,0x45,2,2,0,0) + ByteBuffer.allocate(2).putShort(protected.size.toShort()).array()
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(cek, "AES"), GCMParameterSpec(128, nonce))
            cipher.updateAAD(ascii("ZTSE/body/v2\u0000") + header + protected)
            val encrypted = cipher.doFinal(content)
            stable(initial).let { it.authority.context(selected, it.trustedNowMs) }
            val wraps=context.readers.map { reader ->
                val fresh=stable(initial); val checked=fresh.authority.context(selected,fresh.trustedNowMs)
                val point=fresh.authority.readerPoint(checked,reader,fresh.trustedNowMs)
                if(reader.role==2) check(same(point,initial.archiveReaderPoint))
                sealReaderWrap(header,protected,reader.role,reader.keyId,point,cek)
            }.fold(ByteArray(0)) { a,b -> a+b }
            stable(initial).let { it.authority.context(selected, it.trustedNowMs) }
            val unsigned = header + protected + nonce + ByteBuffer.allocate(4).putInt(encrypted.size).array() +
                encrypted + byteArrayOf(context.readers.size.toByte()) + wraps
            checkInboundUnsigned(unsigned, context.signerPoint)
            val signature = keys.sign(unsigned, context.signerPoint)
            check(verifyRaw(signature, context.signerPoint, ascii("ZTSE/sign/v2\u0000") +
                ByteBuffer.allocate(4).putInt(unsigned.size).array() + unsigned)) { "Capture signature" }
            stable(initial).let { it.authority.context(selected, it.trustedNowMs) }
            return unsigned + signature
        } finally { content.fill(0); cek.fill(0); nonce.fill(0) }
    }

    override fun verify(evidence: ByteArray): VerifiedConversationSend {
        DevicePayloadKeyStore.requireSupportedSdk(Build.VERSION.SDK_INT)
        val parts = unpackConfirmedEvidence(evidence)
        val c = Confirmation.decode(parts.confirmation)
        val initial = live()
        val scope = initial.scope
        check(c.account == scope.accountId && c.device == scope.deviceId && c.line == scope.lineId &&
            c.interval == scope.intervalId && c.session == scope.initiatingSessionId && c.generation == scope.bindingGeneration &&
            c.trustGeneration == scope.trustGeneration && c.peer == scope.peer &&
            same(c.reader, unhex(scope.readerKeyId)) && same(c.signer, initial.outboundSignerKeyId) &&
            c.version == initial.authority.version && same(c.manifest, initial.authority.digest) &&
            same(c.envelopeDigest, sha(parts.envelope))) { "Confirmed scope mismatch" }
        fun fresh(): ConversationCryptoCurrent = stable(initial).also {
            check(c.expiresMs > it.trustedNowMs && c.expiresMs - it.trustedNowMs <= 30_000)
        }
        val recipient = keys.recipient()
        check(recipient.security in setOf(PayloadKeySecurity.STRONGBOX, PayloadKeySecurity.TRUSTED_ENVIRONMENT))
        val selected = request(initial, c.message, false, recipient.keyId)
        val proof = Draft02OutboundEnvelope.verify(parts.envelope, initial.authority, selected) { fresh().trustedNowMs }
        val verifiedParts = proof.parts()
        val p = verifiedParts.protected
        val observed = ByteBuffer.wrap(p, 136, 8).long
        check(ByteBuffer.wrap(p, 144, 8).long == c.expiresMs && observed in 1..initial.trustedNowMs &&
            c.expiresMs > observed && c.expiresMs - observed <= 30_000)
        val signer = initial.authority.context(selected, fresh().trustedNowMs).signerPoint
        check(verifyRaw(parts.signature, signer, c.transcript(parts.confirmation))) { "Confirmation signature" }
        fresh()
        val cek = keys.open(verifiedParts)
        var clear: CharArray? = null
        try {
            fresh()
            clear = Draft02Body.open(proof, cek)
            val bytes = encodeText(clear)
            try { check(same(sha(bytes), c.bodyDigest)) { "Confirmed body mismatch" } } finally { bytes.fill(0) }
            val final = fresh()
            proof.checkContext(final.authority, selected, final.trustedNowMs)
            val finalRecipient = keys.recipient()
            check(finalRecipient.security in setOf(PayloadKeySecurity.STRONGBOX, PayloadKeySecurity.TRUSTED_ENVIRONMENT) &&
                same(finalRecipient.keyId, recipient.keyId)) { "Payload custody changed" }
            fresh()
            return VerifiedConversationSend(scope, c.message, c.expiresMs, String(clear))
        } finally { clear?.fill('\u0000'); cek.fill(0) }
    }

    internal class Evidence(val envelope: ByteArray, val confirmation: ByteArray, val signature: ByteArray) {
        override fun toString() = "ConfirmedConversationEvidence(redacted)"
    }
    internal class Confirmation(val account:String,val device:String,val line:String,val interval:String,
        val session:String,val message:String,val generation:Long,val trustGeneration:Long,val version:Long,
        val expiresMs:Long,val peer:String,val signer:ByteArray,val reader:ByteArray,val manifest:ByteArray,
        val envelopeDigest:ByteArray,val bodyDigest:ByteArray) {
        fun transcript(bytes:ByteArray) = ascii("zrotext/conversation/confirm-send/v1\u0000") + ByteBuffer.allocate(4).putInt(bytes.size).array() + bytes
        override fun toString() = "ConversationConfirmation(redacted)"
        companion object {
            fun decode(bytes:ByteArray):Confirmation {
                require(bytes.size in 297..310 && bytes.copyOfRange(0,5).contentEquals(byteArrayOf(0x5a,0x54,0x43,0x53,1)))
                val input=ByteBuffer.wrap(bytes.copyOf());input.position(5)
                fun id()=UUID(input.long,input.long).also { require(it != UUID(0,0)) }.toString()
                fun number()=input.long.also { require(it>0) }
                val ids=List(6){id()}; val nums=List(4){number()}
                val n=input.get().toInt() and 255
                require(n in 3..16 && input.remaining()==n+160)
                val peer=ByteArray(n).also(input::get).toString(Charsets.US_ASCII)
                require(Regex("\\+[1-9][0-9]{1,14}").matches(peer))
                val hashes=List(5){ByteArray(32).also(input::get)}
                return Confirmation(ids[0],ids[1],ids[2],ids[3],ids[4],ids[5],nums[0],nums[1],nums[2],nums[3],peer,
                    hashes[0],hashes[1],hashes[2],hashes[3],hashes[4])
            }
        }
    }
    companion object {
        private val order=BigInteger("FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551",16)
        private fun ascii(value:String)=value.toByteArray(Charsets.US_ASCII)
        private fun sha(bytes:ByteArray)=MessageDigest.getInstance("SHA-256").digest(bytes)
        private fun same(a:ByteArray,b:ByteArray)=MessageDigest.isEqual(a,b)
        private fun uuid(value:String)=UUID.fromString(value).let { require(it.toString()==value && it!=UUID(0,0));ByteBuffer.allocate(16).putLong(it.mostSignificantBits).putLong(it.leastSignificantBits).array() }
        private fun unhex(value:String):ByteArray {require(Regex("[0-9a-f]{64}").matches(value));return value.chunked(2).map{it.toInt(16).toByte()}.toByteArray()}
        private fun encodeText(chars:CharArray):ByteArray {
            val encoded=Charsets.UTF_8.newEncoder().onMalformedInput(CodingErrorAction.REPORT)
                .onUnmappableCharacter(CodingErrorAction.REPORT).encode(CharBuffer.wrap(chars))
            val bytes=ByteArray(encoded.remaining()).also(encoded::get)
            try { Draft02Body.decodeText(bytes).fill('\u0000');return bytes }
            catch(failure:Exception){bytes.fill(0);throw failure}
            finally {if(encoded.hasArray()) encoded.array().fill(0)}
        }
        fun packConfirmedEvidence(envelope:ByteArray,confirmation:ByteArray,signature:ByteArray):ByteArray {
            require(envelope.size in 557..34_213 && confirmation.size in 297..310 && signature.size==64)
            Confirmation.decode(confirmation)
            val out=ByteArrayOutputStream()
            DataOutputStream(out).use {it.write(byteArrayOf(0x5a,0x54,0x43,0x52,1));it.writeInt(envelope.size);it.write(envelope);it.writeShort(confirmation.size);it.write(confirmation);it.write(signature)}
            return out.toByteArray().also {require(it.size<=40*1024)}
        }
        internal fun unpackConfirmedEvidence(evidence:ByteArray):Evidence {
            require(evidence.size in 1..40*1024)
            val input=DataInputStream(evidence.copyOf().inputStream())
            input.use {
                require(ByteArray(5).also(it::readFully).contentEquals(byteArrayOf(0x5a,0x54,0x43,0x52,1)))
                val n=it.readInt();require(n in 557..34_213 && n<=it.available()-2-297-64)
                val envelope=ByteArray(n).also(it::readFully)
                val m=it.readUnsignedShort();require(m in 297..310 && it.available()==m+64)
                val confirmation=ByteArray(m).also(it::readFully);Confirmation.decode(confirmation)
                return Evidence(envelope,confirmation,ByteArray(64).also(it::readFully))
            }
        }
        internal fun checkInboundUnsigned(unsigned:ByteArray,signerPoint:ByteArray) {
            require(unsigned.size in 362..34_018 && unsigned.copyOfRange(0,8).contentEquals(byteArrayOf(0x5a,0x54,0x53,0x45,2,2,0,0)))
            val n=ByteBuffer.wrap(unsigned,8,2).short.toInt() and 65535
            require(n in 172..185)
            val peer=unsigned[178].toInt() and 255;require(peer in 3..16 && n==169+peer)
            val protected=unsigned.copyOfRange(10,10+n)
            require(Regex("\\+[1-9][0-9]{1,14}").matches(protected.copyOfRange(169,n).toString(Charsets.US_ASCII)))
            require((0..3).all{slot->protected.copyOfRange(slot*16,slot*16+16).any{it!=0.toByte()}} &&
                ByteBuffer.wrap(protected,64,8).long>0 && ByteBuffer.wrap(protected,136,8).long>0 &&
                protected.copyOfRange(144,160).any{it!=0.toByte()} && ByteBuffer.wrap(protected,160,8).long>0)
            DevicePayloadKeyStore.decodePoint(signerPoint)
            require(same(sha(ascii("ZTSE/key/v1\u0000")+byteArrayOf(1,1)+signerPoint),protected.copyOfRange(104,136)))
            val body=ByteBuffer.wrap(unsigned,10+n+12,4).int;require(body in 17..32_784)
            val at=10+n+16+body;require(at<unsigned.size)
            val count=unsigned[at].toInt() and 255;require(count in 1..7 && at+1+count*146==unsigned.size)
            var prior:ByteArray?=null
            repeat(count) { i ->
                val start=at+1+i*146; val role=unsigned[start].toInt() and 255
                require(role==if(i==0) 2 else 3)
                val id=unsigned.copyOfRange(start+1,start+33)
                if(i>1) require(compareReaderIds(checkNotNull(prior),id)<0)
                prior=id
                DevicePayloadKeyStore.decodePoint(unsigned.copyOfRange(start+33,start+98))
            }
        }
        private fun compareReaderIds(a:ByteArray,b:ByteArray):Int {
            for(i in a.indices) { val c=(a[i].toInt() and 255).compareTo(b[i].toInt() and 255); if(c!=0)return c }
            return 0
        }
        private fun sealReaderWrap(header:ByteArray,protected:ByteArray,role:Int,id:ByteArray,point:ByteArray,cek:ByteArray):ByteArray {
            val ephemeral=KeyPairGenerator.getInstance("EC").apply{initialize(ECGenParameterSpec("secp256r1"),SecureRandom())}.generateKeyPair()
            val enc=DevicePayloadKeyStore.encodePoint(ephemeral.public as ECPublicKey)
            val dh=KeyAgreement.getInstance("ECDH").run{init(ephemeral.private);doPhase(DevicePayloadKeyStore.decodePoint(point),true);generateSecret()}
            try {
                val secret=Draft02PublicJcaKeystoreHpke.deriveSharedSecret(dh,enc,point)
                try {
                    val material=Draft02PublicJcaKeystoreHpke.deriveKeyMaterial(secret,ascii("ZTSE/wrap/v2\u0000")+header+protected+byteArrayOf(role.toByte())+id)
                    try {val cipher=Cipher.getInstance("AES/GCM/NoPadding");cipher.init(Cipher.ENCRYPT_MODE,SecretKeySpec(material.key,"AES"),GCMParameterSpec(128,material.nonce));return byteArrayOf(role.toByte())+id+enc+cipher.doFinal(cek)}
                    finally{material.clear()}
                } finally{secret.fill(0)}
            } finally{dh.fill(0)}
        }
        internal fun verifyRaw(raw:ByteArray,point:ByteArray,transcript:ByteArray):Boolean {
            if(raw.size!=64)return false
            val r=BigInteger(1,raw.copyOfRange(0,32));val s=BigInteger(1,raw.copyOfRange(32,64))
            if(r.signum()<=0 || r>=order || s.signum()<=0 || s>order.shiftRight(1))return false
            fun scalar(offset:Int):ByteArray {var at=offset;while(at<offset+31 && raw[at]==0.toByte())at++;val value=raw.copyOfRange(at,offset+32);val positive=if(value[0]<0)byteArrayOf(0)+value else value;return byteArrayOf(2,positive.size.toByte())+positive}
            val fields=scalar(0)+scalar(32);val der=byteArrayOf(0x30,fields.size.toByte())+fields
            return Signature.getInstance("SHA256withECDSA").run{initVerify(DevicePayloadKeyStore.decodePoint(point));update(transcript);verify(der)}
        }
    }
}

/** Production constructor supplies only the existing hardware adapters. Test implementations live in src/test. */
internal interface ConversationContentKeyOperations {
    fun recipient():DevicePayloadPublic
    fun sign(unsigned:ByteArray,point:ByteArray):ByteArray
    fun open(parts:Draft02OutboundEnvelope.Parts):ByteArray
}

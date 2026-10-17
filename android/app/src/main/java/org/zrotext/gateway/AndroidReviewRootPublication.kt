// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import java.nio.ByteBuffer
import java.util.UUID

/** Genuine server receipt + exact retained encrypted custody, not session authority.
 * The historical actor session is parsed, never coerced to a current principal.
 */
internal data class AndroidReviewRootPublication(val challenge: UUID, val completedMs: Long) {
    companion object {
        fun verify(receiptBytes: ByteArray, exportBytes: ByteArray,
            independent: AndroidOwnerCustodyKit): AndroidReviewRootPublication {
            val r=AndroidReviewJson.objectValue(receiptBytes)
            val x=AndroidReviewJson.objectValue(exportBytes)
            require(r.keys==setOf("version","request_id","account","actor_owner_user","actor_review_owner_session","root_challenge_id",
                "root_pin_b64","root_fingerprint_b64","completed_ms","server_now_ms"))
            require(x.keys==setOf("version","request_id","account","root_challenge_id","backup_id","generation","root_pin_b64",
                "root_fingerprint_b64","encrypted_backup_b64","public_card_b64","unsigned_enrollment_b64",
                "custody_signature_b64","committed_ms","server_now_ms"))
            fun text(f:Map<String,Any>,key:String)=f[key] as? String?:error("Publication field")
            fun id(f:Map<String,Any>,key:String)=AndroidReviewJson.uuid(text(f,key))
            fun n(f:Map<String,Any>,key:String)=AndroidReviewJson.decimal(text(f,key))
            for(f in listOf(r,x)){
                id(f,"request_id") // exact request correlation is checked by the HTTPS adapter
                require(f["version"]==1 && id(f,"account")==independent.identity.account)
                require(AndroidReviewJson.binary(text(f,"root_pin_b64"),94).contentEquals(independent.pin) &&
                    AndroidReviewJson.binary(text(f,"root_fingerprint_b64"),32).contentEquals(independent.identity.fingerprintBytes()))
            }
            val challenge=id(r,"root_challenge_id")
            require(id(x,"root_challenge_id")==challenge && n(x,"generation")==1L)
            val bundle=ByteBuffer.wrap(independent.bundleId)
            require(id(x,"backup_id")==UUID(bundle.long,bundle.long))
            require(AndroidReviewJson.binary(text(x,"encrypted_backup_b64"),independent.backup().size).contentEquals(independent.backup()) &&
                AndroidReviewJson.binary(text(x,"public_card_b64"),independent.card().size).contentEquals(independent.card()))
            val unsigned=java.util.Base64.getDecoder().decode(text(x,"unsigned_enrollment_b64"))
            require(unsigned.size in 152..663 && java.util.Base64.getEncoder().encodeToString(unsigned)==text(x,"unsigned_enrollment_b64"))
            val parsed=AndroidOwnerCustodyReview.parse(unsigned)
            require(parsed.account==independent.identity.account && parsed.origin==independent.identity.origin &&
                parsed.fingerprint==independent.identity.fingerprint && parsed.challengeId==challenge)
            // Match the ORIGINAL signed actors, never the current session.
            require(id(r,"actor_owner_user")==parsed.user && id(r,"actor_review_owner_session")==parsed.session)
            val transcript="ZTSE/root-custody/v1\u0000".toByteArray(Charsets.US_ASCII) +
                ByteBuffer.allocate(4).putInt(unsigned.size).array() + unsigned +
                AndroidOwnerCustodyKit.hash(independent.backup()) + AndroidOwnerCustodyKit.hash(independent.card()) +
                independent.identity.fingerprintBytes()
            // Reuse the maintained strict raw64/low-S P-256 verifier. This is a
            // historical custody signature, not a new message/grant or time lease.
            require(ConversationContentCrypto.verifyRaw(AndroidReviewJson.binary(text(x,"custody_signature_b64"),64),
                independent.pin.copyOfRange(29,94),transcript))
            val completed=n(r,"completed_ms")
            require(completed==n(x,"committed_ms") && completed<=n(r,"server_now_ms") && completed<=n(x,"server_now_ms"))
            require(completed>=parsed.issuedMs && completed<parsed.expiresMs)
            return AndroidReviewRootPublication(challenge,completed)
        }
    }
}

// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import java.io.File
import java.nio.ByteBuffer
import java.util.Base64
import java.util.UUID
import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

/** Real checked public custody vector, independent of managed fake lifecycle fixtures. */
@RunWith(RobolectricTestRunner::class)
@Config(sdk=[28])
class AndroidReviewRootPublicationTest {
    private fun source(name:String):JSONObject {
        val directory=generateSequence(File(checkNotNull(System.getProperty("user.dir"))).absoluteFile){it.parentFile}
            .take(5).map{File(it,"protocol/v1/vectors")}.first{it.isDirectory}
        return JSONObject(File(directory,name).readText())
    }
    private fun hex(value:String)=value.chunked(2).map{it.toInt(16).toByte()}.toByteArray()
    private fun b64(value:ByteArray)=Base64.getEncoder().encodeToString(value)
    private val backup=source("root-backup-01.json")
    private val custody=source("root-custody-01.json")
    private val kit=AndroidOwnerCustodyKit(hex(backup.getString("ciphertextHex")),hex(source("recovery-kit-01.json").getString("cardHex")))
    private val unsigned=hex(custody.getString("unsignedHex"))
    private val parsed=AndroidOwnerCustodyReview.parse(unsigned)
    private fun receipt()=JSONObject().put("version",1).put("request_id",UUID(0,8)).put("account",kit.identity.account)
        .put("actor_owner_user",parsed.user).put("actor_review_owner_session",parsed.session)
        .put("root_challenge_id",parsed.challengeId).put("root_pin_b64",b64(kit.pin))
        .put("root_fingerprint_b64",b64(kit.identity.fingerprintBytes())).put("completed_ms","1100000").put("server_now_ms","9000000")
    private fun exported():JSONObject {
        val id=ByteBuffer.wrap(kit.bundleId)
        return JSONObject().put("version",1).put("request_id",UUID(0,8)).put("account",kit.identity.account).put("root_challenge_id",parsed.challengeId)
            .put("backup_id",UUID(id.long,id.long)).put("generation","1").put("root_pin_b64",b64(kit.pin))
            .put("root_fingerprint_b64",b64(kit.identity.fingerprintBytes())).put("encrypted_backup_b64",b64(kit.backup()))
            .put("public_card_b64",b64(kit.card())).put("unsigned_enrollment_b64",b64(unsigned))
            .put("custody_signature_b64",b64(hex(custody.getString("signatureHex")))).put("committed_ms","1100000").put("server_now_ms","9000000")
    }
    private fun verify(r:JSONObject=receipt(),x:JSONObject=exported())=AndroidReviewRootPublication.verify(
        r.toString().toByteArray(),x.toString().toByteArray(),kit)
    @Test fun realCustodySignatureAndExactSavedBundleVerifyAsHistoricalPublication() {
        val proof=verify();assertEquals(parsed.challengeId,proof.challenge);assertEquals(1100000,proof.completedMs)
        // No current-session claim: the original challenge expiry has passed.
        assertTrue(parsed.expiresMs<9000000)
        // This verifier accepts no current-session principal at all; actors are
        // historical, but must still match the original signed enrollment.
        for(field in listOf("actor_owner_user","actor_review_owner_session"))
            assertThrows(IllegalArgumentException::class.java){verify(receipt().put(field,UUID(0,777).toString()))}
    }
    @Test fun wrongBundlePinChallengeAndExtraAuthorityFieldsAreRefused() {
        for(x in listOf(exported().put("root_challenge_id",UUID(0,6).toString()),
            exported().put("root_pin_b64",b64(ByteArray(94))),exported().put("encrypted_backup_b64",b64(kit.backup().also{it[it.lastIndex]=(it.last().toInt() xor 1).toByte()})),
            exported().put("public_card_b64",b64(ByteArray(kit.card().size))),exported().put("ordinary_session","forbidden"))){
            assertThrows(IllegalArgumentException::class.java){verify(x=x)}
        }
    }
    @Test fun mutatedSignatureOrDifferentCustodyTranscriptCannotBecomeReceipt() {
        val bad=hex(custody.getString("signatureHex")).also{it[0]=(it[0].toInt() xor 1).toByte()}
        assertThrows(IllegalArgumentException::class.java){verify(x=exported().put("custody_signature_b64",b64(bad)))}
        val other=unsigned.copyOf().also{it[69]=(it[69].toInt() xor 1).toByte()}
        assertThrows(IllegalArgumentException::class.java){verify(x=exported().put("unsigned_enrollment_b64",b64(other)))}
    }
    @Test fun futureInconsistentCompletionOrNoncanonicalBinaryCannotVerify() {
        assertThrows(IllegalArgumentException::class.java){verify(receipt().put("completed_ms","9000001"))}
        for(completed in listOf("1",parsed.expiresMs.toString()))
            assertThrows(IllegalArgumentException::class.java){verify(receipt().put("completed_ms",completed),exported().put("committed_ms",completed))}
        assertThrows(IllegalArgumentException::class.java){verify(x=exported().put("root_fingerprint_b64",b64(kit.identity.fingerprintBytes()).trimEnd('=')))}
    }
}

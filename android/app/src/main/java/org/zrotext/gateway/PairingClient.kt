// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import android.util.Base64
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.Response
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.RequestBody.Companion.toRequestBody
import okhttp3.HttpUrl.Companion.toHttpUrlOrNull
import org.json.JSONObject
import java.io.ByteArrayOutputStream
import java.security.MessageDigest
import java.util.UUID
import java.util.concurrent.TimeUnit

data class VerifiedPairing(
    val comparisonCode: String,
    val fingerprintHex: String,
    val keySecurity: SigningKeySecurity,
    val strongBoxFallbackOnCreation: Boolean?
)

/** Manual M1 claim/proof. Approval remains an explicit authenticated browser action. */
class PairingClient(private val signingKeys: DeviceSigningKeyStore) {
    private val client = OkHttpClient.Builder()
        .followRedirects(false)
        .followSslRedirects(false)
        .callTimeout(20, TimeUnit.SECONDS)
        .build()

    fun claimAndProve(baseOrigin: String, pairingIdText: String, token: String): VerifiedPairing {
        val origin = baseOrigin.trim().toHttpUrlOrNull()
            ?: throw IllegalArgumentException("HTTPS origin required")
        require(origin.scheme == "https" && origin.encodedPath == "/" && origin.username.isEmpty() &&
            origin.password.isEmpty() && origin.query == null && origin.fragment == null) {
            "HTTPS origin required"
        }
        val pairingId = UUID.fromString(pairingIdText.trim())
        require(token.matches(Regex("ztp_[A-Za-z0-9_-]{43}"))) { "Invalid pairing token" }
        val key = signingKeys.getOrCreate()
        val path = origin.newBuilder().addPathSegments("v1/enrollment/pairings")
            .addPathSegment(pairingId.toString())
        val claim = post(path.build().newBuilder().addPathSegment("claim").build().toString(),
            JSONObject().put("token", token).put("public_key_spki", encode(key.spkiDer)))
        val accountId = UUID.fromString(claim.getString("account_id"))
        check(UUID.fromString(claim.getString("pairing_id")) == pairingId) { "Pairing changed" }
        val nonce = decode32(claim.getString("challenge_nonce"))
        val code = claim.getString("comparison_code")
        require(code.matches(Regex("[0-9]{8}"))) { "Invalid comparison code" }
        val fingerprint = claim.getString("key_fingerprint")
        check(MessageDigest.isEqual(fingerprint.toByteArray(), key.fingerprintHex.toByteArray())) {
            "Key fingerprint mismatch"
        }
        val signature = signingKeys.signEnrollmentChallenge(accountId, pairingId, nonce)
        val proof = post(path.build().newBuilder().addPathSegment("prove").build().toString(),
            JSONObject().put("challenge_nonce", encode(nonce)).put("signature_der", encode(signature)))
        check(proof.optBoolean("proof_verified", false)) { "Proof rejected" }
        return VerifiedPairing(code, fingerprint, key.security, key.strongBoxFallbackOnCreation)
    }

    private fun post(url: String, body: JSONObject): JSONObject {
        val request = Request.Builder().url(url)
            .header("Accept", "application/json")
            .header("Cache-Control", "no-store")
            .post(body.toString().toRequestBody("application/json".toMediaType()))
            .build()
        client.newCall(request).execute().use { response ->
            check(response.isSuccessful) { "Pairing request failed (${response.code})" }
            return JSONObject(readBounded(response))
        }
    }

    private fun readBounded(response: Response): String {
        val stream = response.body?.byteStream() ?: error("Empty pairing response")
        val out = ByteArrayOutputStream()
        val buffer = ByteArray(1024)
        while (true) {
            val read = stream.read(buffer)
            if (read < 0) break
            check(out.size() + read <= 4096) { "Pairing response too large" }
            out.write(buffer, 0, read)
        }
        return out.toString(Charsets.UTF_8.name())
    }

    private fun decode32(value: String): ByteArray {
        require(value.matches(Regex("[A-Za-z0-9_-]{43}"))) { "Invalid challenge" }
        val decoded = Base64.decode(value, Base64.URL_SAFE or Base64.NO_WRAP or Base64.NO_PADDING)
        require(decoded.size == 32 && encode(decoded) == value) { "Invalid challenge" }
        return decoded
    }

    private fun encode(value: ByteArray): String =
        Base64.encodeToString(value, Base64.URL_SAFE or Base64.NO_WRAP or Base64.NO_PADDING)
}

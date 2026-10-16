// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import okhttp3.HttpUrl.Companion.toHttpUrl
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import org.json.JSONObject
import java.io.ByteArrayOutputStream
import java.nio.ByteBuffer
import java.util.Base64
import java.util.UUID
import java.util.concurrent.TimeUnit

/** Public locators are navigation hints, never an approved device or permission. */
internal data class PairingLocator(val origin: String, val pairingId: UUID, val fingerprint: String) {
    init {
        AndroidPairingQrPayload.canonicalOrigin(origin)
        require(pairingId != UUID(0, 0) && fingerprint.matches(Regex("[0-9A-F]{64}")))
    }
    val streamEndpoint: String get() = origin.replaceFirst("https://", "wss://") + "/v1/device-stream"
}

internal object PairingBindingProof {
    fun bytes(account: UUID, pairing: UUID, challenge: UUID, fingerprint: ByteArray, nonce: ByteArray): ByteArray {
        require(fingerprint.size == 32 && nonce.size == 32)
        val domain = "ZROTEXT-PAIRING-BINDING-V1\u0000".toByteArray(Charsets.US_ASCII)
        return ByteBuffer.allocate(domain.size + 16 * 3 + 32 * 2).put(domain)
            .putLong(account.mostSignificantBits).putLong(account.leastSignificantBits)
            .putLong(pairing.mostSignificantBits).putLong(pairing.leastSignificantBits)
            .putLong(challenge.mostSignificantBits).putLong(challenge.leastSignificantBits)
            .put(fingerprint).put(nonce).array()
    }
}

internal enum class PairingBindingStatus { PENDING, APPROVED, EXPIRED, CANCELLED, PROOF_REJECTED, AWAITING_PROOF }
internal data class PairingBinding(val status: PairingBindingStatus, val deviceId: UUID?, val comparisonCode: String?)
internal class PairingBindingTerminal(val status: PairingBindingStatus) : IllegalStateException("Original unclaimed pairing is terminal")

/** Only this closed coarse error can retire an unclaimed attempt. 404 and malformed errors stay unknown. */
internal fun pairingBindingTerminal(statusCode: Int, body: String): PairingBindingStatus? = runCatching {
    if (statusCode != 409) return null
    val value = Regex("""\s*\{\s*"code"\s*:\s*"(pairing_expired|pairing_cancelled)"\s*}\s*""").matchEntire(body)
        ?: return null
    when (value.groupValues[1]) {
        "pairing_expired" -> PairingBindingStatus.EXPIRED
        "pairing_cancelled" -> PairingBindingStatus.CANCELLED
        else -> null
    }
}.getOrNull()

/** Status-only possession proof. This transport never claims, approves or starts a connection. */
internal class PairingBindingClient(
    private val existingFingerprint: () -> String,
    private val sign: (UUID, UUID, UUID, ByteArray, ByteArray) -> ByteArray,
    private val elapsed: () -> Long = android.os.SystemClock::elapsedRealtime,
    private val post: (String, JSONObject) -> JSONObject = PairingBindingHttp::post
) {
    constructor(keys: DeviceSigningKeyStore) : this({ keys.existing().fingerprintHex }, keys::signPairingBinding)

    fun read(locator: PairingLocator): PairingBinding {
        val started = elapsed().also { require(it >= 0) }
        fun fresh() { check(Math.subtractExact(elapsed(), started) in 0..60_000L) { "Pairing check expired" } }
        check(existingFingerprint() == locator.fingerprint) { "Original signing identity unavailable" }
        val path = locator.origin.toHttpUrl().newBuilder().addPathSegments("v1/enrollment/pairings")
            .addPathSegment(locator.pairingId.toString()).addPathSegment("binding").build()
        val challenge = try {
            post(path.newBuilder().addPathSegment("challenge").build().toString(),
                JSONObject().put("key_fingerprint", locator.fingerprint))
        } catch (terminal: PairingBindingTerminal) {
            fresh()
            check(existingFingerprint() == locator.fingerprint)
            require(terminal.status in setOf(PairingBindingStatus.EXPIRED, PairingBindingStatus.CANCELLED))
            return PairingBinding(terminal.status, null, null)
        }
        exact(challenge, setOf("schema_version", "account_id", "pairing_id", "challenge_id", "challenge_nonce", "key_fingerprint"))
        require(challenge.get("schema_version") == 1 && string(challenge, "key_fingerprint") == locator.fingerprint)
        val account = uuid(string(challenge, "account_id"))
        require(uuid(string(challenge, "pairing_id")) == locator.pairingId)
        val challengeId = uuid(string(challenge, "challenge_id"))
        val nonceText = string(challenge, "challenge_nonce")
        require(nonceText.matches(Regex("[A-Za-z0-9_-]{43}")))
        val nonce = Base64.getUrlDecoder().decode(nonceText)
        require(nonce.size == 32 && Base64.getUrlEncoder().withoutPadding().encodeToString(nonce) == nonceText)
        val fingerprint = locator.fingerprint.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
        val signature = sign(account, locator.pairingId, challengeId, fingerprint, nonce)
        fresh()
        check(existingFingerprint() == locator.fingerprint) { "Original signing identity changed" }
        val response = post(path.toString(), JSONObject().put("account_id", account.toString())
            .put("challenge_id", challengeId.toString()).put("challenge_nonce", nonceText)
            .put("signature_der", Base64.getUrlEncoder().withoutPadding().encodeToString(signature)))
        fresh()
        exact(response, setOf("schema_version", "status", "account_id", "pairing_id", "device_id", "comparison_code", "key_fingerprint"))
        require(response.get("schema_version") == 1 && uuid(string(response, "account_id")) == account &&
            uuid(string(response, "pairing_id")) == locator.pairingId && string(response, "key_fingerprint") == locator.fingerprint)
        val rawStatus = string(response, "status")
        val status = PairingBindingStatus.valueOf(rawStatus.uppercase(java.util.Locale.ROOT))
        require(rawStatus == status.name.lowercase(java.util.Locale.ROOT))
        val device = if (response.isNull("device_id")) null else uuid(string(response, "device_id"))
        val code = if (response.isNull("comparison_code")) null else string(response, "comparison_code")
        require((status == PairingBindingStatus.APPROVED) == (device != null))
        require(code == null || (code.matches(Regex("[0-9]{8}")) && status in setOf(PairingBindingStatus.PENDING, PairingBindingStatus.APPROVED)))
        require(status != PairingBindingStatus.PENDING || code != null)
        check(existingFingerprint() == locator.fingerprint)
        return PairingBinding(status, device, code)
    }

    private fun string(value: JSONObject, field: String): String = value.get(field) as? String ?: error("Invalid pairing field")
    private fun exact(value: JSONObject, fields: Set<String>) { require(value.keys().asSequence().toSet() == fields) }
    private fun uuid(value: String): UUID = UUID.fromString(value).also { require(it.toString() == value && it != UUID(0, 0)) }
}

private object PairingBindingHttp {
    private val client = OkHttpClient.Builder().followRedirects(false).followSslRedirects(false)
        .callTimeout(20, TimeUnit.SECONDS).build()
    fun post(url: String, body: JSONObject): JSONObject {
        val request = Request.Builder().url(url).header("Accept", "application/json").header("Cache-Control", "no-store")
            .post(body.toString().toRequestBody("application/json".toMediaType())).build()
        client.newCall(request).execute().use { response ->
            val input = checkNotNull(response.body).byteStream()
            val output = ByteArrayOutputStream()
            val buffer = ByteArray(1024)
            while (true) {
                val read = input.read(buffer)
                if (read < 0) break
                check(output.size() + read <= 4096) { "Pairing response too large" }
                output.write(buffer, 0, read)
            }
            val text = output.toString(Charsets.UTF_8.name())
            if (!response.isSuccessful) {
                if (url.endsWith("/binding/challenge")) pairingBindingTerminal(response.code, text)?.let { throw PairingBindingTerminal(it) }
                error("Could not check pairing (${response.code})")
            }
            return JSONObject(text)
        }
    }
}

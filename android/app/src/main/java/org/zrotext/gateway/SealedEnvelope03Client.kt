// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import java.security.MessageDigest
import java.util.concurrent.TimeUnit
import okhttp3.Authenticator
import okhttp3.CookieJar
import okhttp3.HttpUrl.Companion.toHttpUrl
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody

/** Exact public response. Decoding does NOT authenticate current projection or admission receipt. */
internal class Profile03FetchPacket private constructor(
    private val ciphertext: ByteArray, private val review: ByteArray, private val signature: ByteArray,
    val acceptedMs: Long, val intervalStartsMs: Long, val intervalExpiresMs: Long, val selectionEpoch: Long,
    private val projection: ByteArray,
    private val interval: ConversationInterval03Permission,
) {
    fun envelope() = ciphertext.copyOf()
    fun intent() = review.copyOf()
    fun signature() = signature.copyOf()
    fun currentProjection() = projection.copyOf()
    fun intervalPermission() = interval
    override fun toString() = "Profile03FetchPacket(unverified-public-evidence)"
    companion object {
        fun decode(bytes: ByteArray, grant: SealedDispatch03Frames.Grant): Profile03FetchPacket {
            val f = Profile03Json.objectValue(bytes)
            require(f.keys == setOf("v", "envelope", "reviewed_intent", "reviewed_signature", "accepted_ms",
                "interval_starts_ms", "interval_expires_ms", "selection_epoch", "current", "interval_permission") && f["v"] == Profile03Json.Integer(1))
            val envelope = Profile03Json.binary(f, "envelope", 557, 34_213)
            require(MessageDigest.isEqual(MessageDigest.getInstance("SHA-256").digest(envelope), grant.envelopeSha256))
            val intent = Profile03Json.binary(f, "reviewed_intent", 624, 835)
            ReviewedIntent03.decode(intent).requireGrant(grant)
            return Profile03FetchPacket(envelope, intent, Profile03Json.binary(f, "reviewed_signature", 64, 64),
                Profile03Json.decimal(f, "accepted_ms"), Profile03Json.decimal(f, "interval_starts_ms"),
                Profile03Json.decimal(f, "interval_expires_ms"), Profile03Json.decimal(f, "selection_epoch"),
                Profile03Json.render(Profile03Json.nested(f, "current")),
                ConversationInterval03Permission.decode(Profile03Json.nested(f, "interval_permission")).also {
                    it.requireRequest("fetch", grant.attemptId)
                })
        }
    }
}

/** One device-signed03 HTTPS exchange, no cookies, redirects, cache or automatic retries. */
internal class SealedEnvelope03Client(streamUrl: String, client: OkHttpClient,
    private val sign: (SealedDispatch03Frames.Grant) -> ByteArray,
    private val requireCurrent: (SealedDispatch03Frames.Grant) -> Unit,
) {
    private val endpoint = run {
        require(streamUrl.startsWith("wss://"))
        val url = ("https://" + streamUrl.removePrefix("wss://")).toHttpUrl()
        require(url.username.isEmpty() && url.password.isEmpty() && url.query == null && url.fragment == null)
        url.newBuilder().encodedPath("/v1/sealed/dispatch/envelope03").query(null).build()
    }
    private val transport = client.newBuilder().followRedirects(false).followSslRedirects(false)
        .retryOnConnectionFailure(false).authenticator(Authenticator.NONE).proxyAuthenticator(Authenticator.NONE)
        .cookieJar(CookieJar.NO_COOKIES).cache(null).callTimeout(10, TimeUnit.SECONDS).build()

    fun fetch(input: SealedDispatch03Frames.Grant): Profile03FetchPacket? = runCatching {
        val grant = SealedDispatch03Frames.grant(input.json())
        SealedEnvelopeFetch03.transcript(grant)
        requireCurrent(grant)
        val signature = sign(SealedDispatch03Frames.grant(grant.json()))
        val fetch = SealedEnvelopeFetch03.Fetch(grant, signature)
        requireCurrent(grant) // Hardware signing may have waited.
        val request = Request.Builder().url(endpoint).header("Cache-Control", "no-store")
            .post(fetch.json().toRequestBody("application/json".toMediaType())).build()
        val sent = java.util.concurrent.atomic.AtomicBoolean(false)
        val once = transport.newBuilder().addNetworkInterceptor { chain ->
            if (!sent.compareAndSet(false, true)) throw java.io.IOException("Profile03 fetch retry refused")
            chain.proceed(chain.request())
        }.build()
        once.newCall(request).execute().use { response ->
            require(response.code == 200 && response.priorResponse == null && response.cacheResponse == null &&
                response.request.url == request.url && response.request.method == request.method &&
                response.headers.values("Set-Cookie").isEmpty() && response.cacheControl.noStore)
            val body = checkNotNull(response.body)
            val type = checkNotNull(body.contentType())
            require(type.type == "application" && type.subtype == "json" &&
                (type.charset() == null || type.charset() == Charsets.UTF_8) && body.contentLength() <= Profile03Json.MAX_BYTES)
            val bytes = body.byteStream().use { stream ->
                val output = java.io.ByteArrayOutputStream()
                val buffer = ByteArray(4096)
                while (true) {
                    val read = stream.read(buffer, 0, minOf(buffer.size, Profile03Json.MAX_BYTES - output.size() + 1))
                    if (read < 0) break
                    require(read > 0 && output.size() + read <= Profile03Json.MAX_BYTES)
                    output.write(buffer, 0, read)
                }
                output.toByteArray()
            }
            requireCurrent(grant) // No response, parsing or clock from the server renews this request.
            Profile03FetchPacket.decode(bytes, grant).also { requireCurrent(grant) }
        }
    }.getOrNull()
    override fun toString() = "SealedEnvelope03Client(redacted)"
}

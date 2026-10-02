// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import java.security.MessageDigest
import java.util.Base64
import java.util.concurrent.TimeUnit
import okhttp3.HttpUrl.Companion.toHttpUrl
import okhttp3.Authenticator
import okhttp3.CookieJar
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import org.json.JSONObject

/** One bounded, device-signed HTTPS retrieval. Ambiguity never causes an automatic retry. */
internal class SealedEnvelopeClient(streamUrl: String, client: OkHttpClient,
    private val sign: (SealedExecutionGrantValidator.Fields) -> ByteArray,
    private val requireCurrent: (SealedExecutionGrantValidator.Fields) -> Unit) {
    private val endpoint = run {
        require(streamUrl.startsWith("wss://"))
        val origin = ("https://" + streamUrl.removePrefix("wss://")).toHttpUrl()
        require(origin.username.isEmpty() && origin.password.isEmpty() && origin.fragment == null && origin.query == null)
        origin.newBuilder().encodedPath("/v1/sealed/dispatch/envelope").query(null).build()
    }
    private val transport = client.newBuilder().followRedirects(false).followSslRedirects(false)
        .retryOnConnectionFailure(false).authenticator(Authenticator.NONE).proxyAuthenticator(Authenticator.NONE)
        .cookieJar(CookieJar.NO_COOKIES).cache(null).callTimeout(10, TimeUnit.SECONDS).build()

    fun fetch(input: SealedExecutionGrantValidator.Fields): ByteArray? = runCatching {
        val grant = SealedEnvelopeFetch.snapshot(input)
        SealedEnvelopeFetch.transcript(grant)
        requireCurrent(SealedEnvelopeFetch.snapshot(grant))
        val signature = sign(SealedEnvelopeFetch.snapshot(grant))
        require(signature.size in 8..80)
        requireCurrent(SealedEnvelopeFetch.snapshot(grant)) // Keystore acquisition can wait; a stale signer never sends.
        val body = JSONObject().put("grant", SealedEnvelopeFetch.frame(grant))
            .put("signature_der", Base64.getUrlEncoder().withoutPadding().encodeToString(signature)).toString()
        require(body.toByteArray(Charsets.UTF_8).size <= 4096)
        val request = Request.Builder().url(endpoint).header("Cache-Control", "no-store")
            .post(body.toRequestBody("application/json".toMediaType())).build()
        // OkHttp can follow a Retry-After: 0 response independently of its connection retry flag.
        // An operation-scoped network guard permits exactly one wire exchange.
        val sent = java.util.concurrent.atomic.AtomicBoolean(false)
        val once = transport.newBuilder().addNetworkInterceptor { chain ->
            if (!sent.compareAndSet(false, true)) throw java.io.IOException("Sealed fetch retry refused")
            chain.proceed(chain.request())
        }.build()
        once.newCall(request).execute().use { response ->
            require(response.code == 200 && response.header("Content-Type") == "application/vnd.zrotext.sealed.v1")
            val responseBody = checkNotNull(response.body)
            require(responseBody.contentLength() <= MAX_BYTES)
            val bytes = responseBody.byteStream().use { stream ->
                val output = java.io.ByteArrayOutputStream()
                val buffer = ByteArray(4096)
                while (true) {
                    val count = stream.read(buffer)
                    if (count < 0) break
                    require(output.size() + count <= MAX_BYTES)
                    output.write(buffer, 0, count)
                }
                output.toByteArray()
            }
            require(bytes.size in MIN_BYTES..MAX_BYTES &&
                MessageDigest.isEqual(MessageDigest.getInstance("SHA-256").digest(bytes), grant.envelopeDigest))
            requireCurrent(SealedEnvelopeFetch.snapshot(grant)) // Network and response reads may outlive the grant/session.
            bytes
        }
    }.getOrNull()

    override fun toString() = "SealedEnvelopeClient(redacted)"
    companion object { const val MIN_BYTES = 557; const val MAX_BYTES = 34_213 }
}

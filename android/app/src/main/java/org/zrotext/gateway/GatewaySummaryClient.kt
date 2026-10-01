// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import okhttp3.Call
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.Response
import okhttp3.HttpUrl.Companion.toHttpUrlOrNull
import java.io.ByteArrayOutputStream
import java.util.Base64
import java.util.UUID
import java.util.concurrent.TimeUnit

/** Explicit device-scoped read only. This never authenticates a gateway socket. */
internal class GatewaySummaryClient {
    enum class Failure { UNAUTHORIZED, FORBIDDEN, UNAVAILABLE, INVALID_RESPONSE, NETWORK, CANCELLED }
    sealed interface Result {
        data class Success(val snapshot: GatewaySummarySnapshot) : Result
        data class Refused(val reason: Failure) : Result
    }
    private val client = OkHttpClient.Builder().followRedirects(false).followSslRedirects(false)
        .retryOnConnectionFailure(false).callTimeout(20, TimeUnit.SECONDS).build()
    fun newRead(origin: String, readCredential: String, selectedDevice: UUID): Read {
        return Read(client.newCall(request(origin, readCredential, selectedDevice)), selectedDevice)
    }
    class Read internal constructor(private val call: Call, private val device: UUID) {
        fun cancel() { call.cancel() }
        fun execute(): Result = try {
            call.execute().use { response -> decode(response, device) }
        } catch (_: Exception) {
            Result.Refused(if (call.isCanceled()) Failure.CANCELLED else Failure.NETWORK)
        }
    }
    companion object {
        internal fun request(originText: String, credential: String, device: UUID): Request {
            val origin = originText.toHttpUrlOrNull()
            require(origin != null && origin.scheme == "https" && origin.encodedPath == "/" &&
                origin.username.isEmpty() && origin.password.isEmpty() && origin.query == null && origin.fragment == null) { "HTTPS summary origin required" }
            require(device != UUID(0, 0)) { "Invalid summary device" }
            val encoded = credential.removePrefix("ztk_")
            require(credential.startsWith("ztk_") && encoded.matches(Regex("[A-Za-z0-9_-]{43}")) &&
                Base64.getUrlEncoder().withoutPadding().encodeToString(Base64.getUrlDecoder().decode(encoded)) == encoded) { "Separate messages-read API credential required" }
            return Request.Builder().url(origin.newBuilder().addPathSegments("v1/message-summary")
                .addQueryParameter("device_id", device.toString()).build())
                .header("Authorization", "Bearer $credential").header("Accept", "application/json")
                .header("Cache-Control", "no-store").get().build()
        }
        internal fun decode(response: Response, device: UUID): Result {
            if (response.code != 200) return Result.Refused(when (response.code) {
                401 -> Failure.UNAUTHORIZED
                403 -> Failure.FORBIDDEN
                else -> Failure.UNAVAILABLE
            })
            return try {
                val body = response.body ?: return Result.Refused(Failure.INVALID_RESPONSE)
                val type = body.contentType()
                require(type?.type == "application" && type.subtype == "json")
                val out = ByteArrayOutputStream()
                body.byteStream().use { input ->
                    val buffer = ByteArray(1024)
                    while (true) {
                        val count = input.read(buffer)
                        if (count < 0) break
                        require(out.size() + count <= 4096)
                        out.write(buffer, 0, count)
                    }
                }
                Result.Success(GatewaySummaryParser.parse(out.toString(Charsets.UTF_8.name()), device))
            } catch (_: Exception) { Result.Refused(Failure.INVALID_RESPONSE) }
        }
    }
}

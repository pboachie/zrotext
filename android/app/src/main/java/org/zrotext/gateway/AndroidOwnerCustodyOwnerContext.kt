// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import android.webkit.CookieManager
import android.os.SystemClock
import okhttp3.CookieJar
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.Response
import okhttp3.HttpUrl.Companion.toHttpUrl
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.RequestBody.Companion.toRequestBody
import org.json.JSONTokener
import java.io.ByteArrayOutputStream
import java.nio.ByteBuffer
import java.security.MessageDigest
import java.util.Base64
import java.util.UUID
import java.util.concurrent.TimeUnit

/** App-local owner WebView cookie source, never a file, Intent, device bearer or JS callback. */
internal fun interface AndroidOwnerContextCookieSource {
    fun cookies(origin: String): String?
}

internal class AndroidOwnerContextWebViewCookies(
    private val manager: CookieManager = CookieManager.getInstance()
) : AndroidOwnerContextCookieSource {
    override fun cookies(origin: String): String? = manager.getCookie(origin)
}

/** Injectable HTTPS boundary; production keeps platform certificate/hostname validation. */
internal fun interface AndroidOwnerContextHttp {
    fun execute(request: Request): Response
}

internal class AndroidOwnerContextHttps : AndroidOwnerContextHttp {
    private val client = OkHttpClient.Builder().followRedirects(false).followSslRedirects(false)
        .retryOnConnectionFailure(false).cookieJar(CookieJar.NO_COOKIES).cache(null)
        .callTimeout(5, TimeUnit.SECONDS).build()
    override fun execute(request: Request): Response = client.newCall(request).execute()
}

/** Actual current owner-session authority for the same origin-local owner WebView.
 * Public files/challenge metadata are never an authentication or clock input.
 * The server must supply DB-derived server_now_ms in the authenticated session response.
 */
internal class AndroidOwnerCustodyOwnerContext(
    private val cookieSource: AndroidOwnerContextCookieSource = AndroidOwnerContextWebViewCookies(),
    private val elapsed: () -> Long = SystemClock::elapsedRealtime,
    private val http: AndroidOwnerContextHttp = AndroidOwnerContextHttps(),
    private val unavailable: () -> Unit = {}
) : AutoCloseable {
    private class Credentials(val session: String, val csrf: String) {
        fun header() = "__Host-zrotext_session=$session; __Host-zrotext_csrf=$csrf"
        fun digest(): ByteArray = MessageDigest.getInstance("SHA-256")
            .digest((session + "\u0000" + csrf).toByteArray(Charsets.US_ASCII))
        override fun toString() = "OwnerSessionCredentials([REDACTED])"
    }
    private class Sample(val identity: AndroidOwnerCustodyIdentity, val authority: AndroidOwnerCustodyAuthority,
        val credentialDigest: ByteArray, val ticket: Long)
    private val lock = Any()
    private var epoch = 0L
    private var closed = false
    private var inFlight = false
    private var sample: Sample? = null

    /** Worker-thread operation. Failure/logout/session change closes every pending native review. */
    @Synchronized fun refresh(expected: AndroidOwnerCustodyIdentity): AndroidOwnerCustodyAuthority {
        var previous: Sample? = null
        val ticket = synchronized(lock) {
            check(!closed && !inFlight) { "Owner context unavailable" }
            previous = sample
            inFlight = true; sample = null; ++epoch
        }
        try {
            val credentials = credentials(expected.origin)
            val request = request(expected.origin, "/v1/auth/session", "GET", null, credentials)
            val started = elapsed(); require(started >= 0)
            val fields = http.execute(request).use { response -> parseSession(response, request) }
            val received = elapsed()
            val roundtrip = Math.subtractExact(received, started)
            require(roundtrip in 0..MAX_UNCERTAINTY_MS)
            val account = uuid(checkNotNull(fields["account_id"]))
            val user = uuid(checkNotNull(fields["user_id"]))
            val session = uuid(checkNotNull(fields["session_id"]))
            require(fields["role"] == "owner" && account == expected.account)
            val utc = positiveDecimal(checkNotNull(fields["server_now_ms"]))
            Math.addExact(utc, roundtrip)
            val currentCredentials = credentials(expected.origin)
            require(MessageDigest.isEqual(credentials.digest(), currentCredentials.digest()))
            val authority = AndroidOwnerCustodyAuthority(account, user, session, utc, received, roundtrip)
            previous?.let {
                require(it.identity == expected && it.authority.sameSession(authority) &&
                    MessageDigest.isEqual(it.credentialDigest, credentials.digest()))
            }
            synchronized(lock) {
                check(!closed && epoch == ticket)
                sample = Sample(expected, authority, credentials.digest(), ticket)
            }
            return authority
        } catch (_: Exception) {
            invalidate()
            throw IllegalStateException("Authenticated owner context unavailable")
        } finally {
            previous?.credentialDigest?.fill(0)
            synchronized(lock) { inFlight = false }
        }
    }

    /** A short process-only sample; use refresh before review, before sign and after sign.
     * A current cookie alone cannot establish server-side liveness.
     */
    fun currentAuthority(): AndroidOwnerCustodyAuthority? {
        val saved = synchronized(lock) { if (closed || inFlight) null else sample } ?: return null
        val valid = runCatching {
            val age = Math.subtractExact(elapsed(), saved.authority.anchoredElapsedMs)
            require(age in 0..MAX_SAMPLE_AGE_MS)
            require(MessageDigest.isEqual(saved.credentialDigest, credentials(saved.identity.origin).digest()))
            synchronized(lock) { require(!closed && epoch == saved.ticket && sample === saved) }
            saved.authority
        }.getOrNull()
        if (valid == null) invalidate()
        return valid
    }

    /** Existing owner ceremony request under this exact live session. It does not sign.
     * Only fixed relative owner paths are allowed; callers must interpret the actual
     * authenticated issue/bootstrap response rather than promote imported metadata.
     * Any post-action session failure suppresses the result; a mutation may then have
     * an unknown outcome and must be reconciled through its existing ceremony.
     */
    @Synchronized fun exchange(expected: AndroidOwnerCustodyIdentity, path: String, method: String,
        body: ByteArray? = null, maximumResponse: Int = MAX_PUBLIC_RESPONSE_BYTES): ByteArray {
        require(maximumResponse in 1..MAX_PUBLIC_RESPONSE_BYTES)
        try {
            require(body == null || body.size in 1..requestLimit(path))
            val before = refresh(expected)
            val credentials = credentials(expected.origin)
            val request = request(expected.origin, path, method, body, credentials)
            val types = if (path == "/v1/owner/conversation/activation")
                setOf("application/vnd.zrotext.conversation-statement.v1") else setOf("application/json")
            val bytes = http.execute(request).use { response ->
                read(response, request, minOf(maximumResponse, responseLimit(path)), types, method != "GET")
            }
            val after = refresh(expected)
            require(before.sameSession(after))
            return bytes
        } catch (_: Exception) {
            invalidate()
            throw IllegalStateException("Owner ceremony response unavailable; reconcile any attempted mutation")
        }
    }

    /** Bind selected exact public bytes without treating them as owner authentication. */
    fun proposalDigest(proposal: ByteArray): ByteArray {
        require(proposal.size in 1..MAX_PROPOSAL_BYTES)
        check(currentAuthority() != null) { "Authenticated owner context unavailable" }
        return MessageDigest.getInstance("SHA-256").digest(proposal)
    }

    fun invalidate() {
        synchronized(lock) { ++epoch; sample?.credentialDigest?.fill(0); sample = null }
        runCatching(unavailable)
    }

    override fun close() {
        synchronized(lock) { closed = true }
        invalidate()
    }

    private fun credentials(origin: String): Credentials {
        val raw = checkNotNull(cookieSource.cookies(origin))
        require(raw.length in 1..4096 && raw.none { it.code < 32 || it.code > 126 })
        val selected = HashMap<String, String>()
        for (part in raw.split(';')) {
            val pieces = part.trim().split('=', limit = 2)
            require(pieces.size == 2 && pieces[0].isNotEmpty())
            if (pieces[0] !in COOKIE_NAMES) continue
            require(!selected.containsKey(pieces[0]))
            selected[pieces[0]] = pieces[1]
        }
        val session = checkNotNull(selected["__Host-zrotext_session"])
        val csrf = checkNotNull(selected["__Host-zrotext_csrf"])
        token(session, "zts_"); token(csrf, "ztc_")
        return Credentials(session, csrf)
    }

    companion object {
        const val MAX_SAMPLE_AGE_MS = 5_000L
        const val MAX_UNCERTAINTY_MS = 2_000L
        const val MAX_PUBLIC_RESPONSE_BYTES = 65_536
        const val MAX_REQUEST_BYTES = 65_536
        const val MAX_PROPOSAL_BYTES = 20_480
        private val COOKIE_NAMES = setOf("__Host-zrotext_session", "__Host-zrotext_csrf")
        private val SESSION_FIELDS = setOf("account_id", "user_id", "session_id", "role", "server_now_ms")

        private fun token(value: String, prefix: String) {
            require(value.startsWith(prefix))
            val encoded = value.removePrefix(prefix)
            require(encoded.matches(Regex("[A-Za-z0-9_-]{43}")))
            require(Base64.getUrlEncoder().withoutPadding().encodeToString(Base64.getUrlDecoder().decode(encoded)) == encoded)
        }

        private fun uuid(value: String): UUID = UUID.fromString(value).also {
            require(it != UUID(0, 0) && it.toString() == value)
        }

        private fun positiveDecimal(value: String): Long {
            require(value.matches(Regex("[1-9][0-9]{0,18}")))
            return value.toLong().also { require(it > 0) }
        }

        private fun requestLimit(path: String): Int = when {
            path == "/v1/owner/conversation/android-proposal" -> 32_768
            path.startsWith("/v1/auth/") -> 16_384
            path.startsWith("/v1/owner/conversation/sealed-line/") -> 8_192
            path.startsWith("/v1/owner/conversation/") -> 20_480
            else -> error("Unsupported owner ceremony path")
        }

        private fun responseLimit(path: String): Int = when (path) {
            "/v1/auth/session" -> 2_048
            "/v1/auth/sealed-root/challenge" -> 4_096
            "/v1/auth/sealed-root" -> 8_192
            else -> MAX_PUBLIC_RESPONSE_BYTES
        }

        private fun request(origin: String, path: String, method: String, body: ByteArray?, credentials: Credentials): Request {
            AndroidOwnerCustodyIdentity.validateAccountOrigin(UUID(0, 1), origin)
            require(path.matches(Regex("/v1/(?:auth|owner)/[A-Za-z0-9_/-]{1,160}")) &&
                !path.contains("//") && !path.contains("..") && !path.endsWith('/'))
            require(method in setOf("GET", "POST", "DELETE"))
            require((method == "GET") == (body == null))
            val url = (origin + path).toHttpUrl()
            require(url.toString() == origin + path)
            return Request.Builder().url(url).header("Cookie", credentials.header())
                .header("Origin", origin).header("x-zrotext-csrf", credentials.csrf)
                .header("Accept", "application/json").header("Cache-Control", "no-store")
                .method(method, body?.toRequestBody("application/json".toMediaType())).build()
        }

        private fun read(response: Response, request: Request, maximum: Int,
            contentTypes: Set<String> = setOf("application/json"), allowEmpty: Boolean = false): ByteArray {
            require((response.code == 200 || allowEmpty && response.code == 204) &&
                response.request.url == request.url && response.request.method == request.method)
            require(response.priorResponse == null && response.networkResponse?.request?.url?.let { it == request.url } != false)
            require(response.cacheResponse == null && response.cacheControl.noStore)
            if (response.code == 204) {
                require(response.body == null || response.body?.contentLength() == 0L)
                return ByteArray(0)
            }
            val body = checkNotNull(response.body)
            val type = body.contentType()
            require(type != null && "${type.type}/${type.subtype}" in contentTypes &&
                (type.charset() == null || type.charset() == Charsets.UTF_8))
            require(body.contentLength() <= maximum)
            val out = ByteArrayOutputStream()
            body.byteStream().use { input ->
                val buffer = ByteArray(1024)
                while (true) {
                    val count = input.read(buffer, 0, minOf(buffer.size, maximum - out.size() + 1))
                    if (count == -1) break
                    require(count > 0 && out.size() + count <= maximum)
                    out.write(buffer, 0, count)
                }
            }
            require(out.size() > 0)
            return out.toByteArray()
        }

        private fun parseSession(response: Response, request: Request): Map<String, String> {
            val bytes = read(response, request, 2048)
            val text = Charsets.UTF_8.newDecoder().decode(ByteBuffer.wrap(bytes)).toString()
            val input = JSONTokener(text)
            require(input.nextClean() == '{')
            val fields = HashMap<String, String>()
            while (true) {
                require(input.nextClean() == '"'); input.back()
                val key = input.nextValue() as? String ?: error("Invalid session field")
                require(key in SESSION_FIELDS && !fields.containsKey(key) && input.nextClean() == ':')
                require(input.nextClean() == '"'); input.back()
                fields[key] = input.nextValue() as? String ?: error("Invalid session value")
                when (input.nextClean()) {
                    '}' -> break
                    ',' -> Unit
                    else -> error("Invalid session object")
                }
            }
            require(fields.keys == SESSION_FIELDS && input.nextClean() == '\u0000')
            return fields
        }
    }
}

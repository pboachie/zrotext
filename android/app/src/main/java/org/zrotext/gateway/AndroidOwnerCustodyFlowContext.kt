// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import java.util.UUID
import java.nio.ByteBuffer
import java.util.Base64
import org.json.JSONObject
import org.json.JSONTokener

/** Authenticated current server composition, never a JSON file or a JS signing bridge. */
internal fun interface AndroidOwnerCustodyFlowContextProvider {
    fun current(kind: AndroidOwnerCustodyFlowKind, proposal: ByteArray,
        expected: AndroidOwnerCustodyIdentity, selection: AndroidOwnerCustodyFlowSelection): AndroidOwnerCustodyFlowExpected
}

/** The owner enters this scope and checkpoint from separate retained evidence. */
internal data class AndroidOwnerCustodyFlowSelection(val device: UUID, val line: UUID,
    val generation: Long, val peer: String, val pairedFingerprint: String,
    val checkpointVersion: Long, val checkpointDigest: String,
    val phoneExport: ByteArray? = null, val phoneExportFingerprint: String = "") {
    init {
        require(device != UUID(0, 0) && line != UUID(0, 0) && generation > 0)
        require(checkpointVersion >= 0 && checkpointDigest.matches(Regex("[0-9a-f]{64}")))
    }
    fun compare(kind: AndroidOwnerCustodyFlowKind, expected: AndroidOwnerCustodyIdentity, current: AndroidOwnerCustodyAuthority,
        json: JSONObject) {
        val scope = json.getJSONObject("scope")
        fun id(value: UUID) = value.toString().replace("-", "")
        require(scope.getString("account") == id(expected.account) && scope.getString("device") == id(device) && scope.getString("line") == id(line) &&
            scope.getString(if (kind == AndroidOwnerCustodyFlowKind.LINE) "owner_session" else "session") == id(current.session) &&
            scope.getString("origin") == expected.origin)
        if (kind == AndroidOwnerCustodyFlowKind.LINE) {
            require(scope.getString("user") == id(current.user) && scope.getLong("next_generation") == generation &&
                scope.getString("paired_signing_fingerprint") == pairedFingerprint)
        } else {
            require(Regex("\\+[1-9][0-9]{1,14}").matches(peer) && scope.getString("peer") == peer &&
                scope.getString("fingerprint") == expected.fingerprint &&
                scope.getLong(if (kind == AndroidOwnerCustodyFlowKind.GENESIS) "generation" else "line_generation") == generation)
            if (kind == AndroidOwnerCustodyFlowKind.GENESIS) {
                require(checkpointVersion == 0L && checkpointDigest == "00".repeat(32))
                require(scope.getString("device_signing_fingerprint") == pairedFingerprint)
                val export = checkNotNull(phoneExport)
                require(export.size == 223 && export.copyOfRange(0, 5).contentEquals(byteArrayOf(90, 84, 80, 75, 1)))
                require(export.copyOfRange(5, 21).contentEquals(expected.accountBytes()) &&
                    export.copyOfRange(21, 37).contentEquals(current.bytes(device)) && export.copyOfRange(37, 53).contentEquals(current.bytes(line)) &&
                    ByteBuffer.wrap(export, 85, 8).long == generation)
                val reader = export.copyOfRange(93, 158); val signer = export.copyOfRange(158, 223)
                DevicePayloadKeyStore.decodePoint(reader); DevicePayloadKeyStore.decodePoint(signer)
                require(!reader.contentEquals(signer) && AndroidOwnerCustodyKit.hex(AndroidOwnerCustodyKit.hash(signer)) == pairedFingerprint &&
                    export.copyOfRange(53, 85).contentEquals(AndroidOwnerCustodyKit.hash(signer)))
                require(AndroidOwnerCustodyKit.hex(AndroidOwnerCustodyKit.hash("ZTSE/phone-keys/v1\u0000".toByteArray() + export)) == phoneExportFingerprint)
                require(json.getString("phone_reader") == AndroidOwnerCustodyKit.hex(reader) && json.getString("phone_signer") == AndroidOwnerCustodyKit.hex(signer))
            } else require(checkpointVersion > 0 && scope.getLong("predecessor_version") == checkpointVersion &&
                scope.getString("predecessor_digest") == checkpointDigest)
        }
    }
}

/** Same-session public registry contract. A missing, changed or unsupported server route fails
 * closed; it never substitutes imported proposal fields for an authoritative expected scope.
 */
internal class AndroidOwnerCustodyRegisteredFlowContext(private val context: AndroidOwnerCustodyOwnerContext) : AndroidOwnerCustodyFlowContextProvider {
    override fun current(kind: AndroidOwnerCustodyFlowKind, proposal: ByteArray, expected: AndroidOwnerCustodyIdentity,
        selection: AndroidOwnerCustodyFlowSelection): AndroidOwnerCustodyFlowExpected {
        require(kind != AndroidOwnerCustodyFlowKind.ARCHIVE && proposal.size in 1..kind.maximum)
        val before = context.refresh(expected)
        val digest = AndroidOwnerCustodyKit.hex(context.proposalDigest(proposal))
        val line = kind == AndroidOwnerCustodyFlowKind.LINE
        val request = JSONObject().put("expected_session_id", before.session.toString()).apply {
            if (!line) put("kind", kind.nativeKind).put("proposal_sha256_hex", digest)
        }.toString().toByteArray(Charsets.UTF_8)
        val path = if (line) "/v1/owner/conversation/sealed-line/owner-key/${androidOwnerLineChallengeSelector(proposal)}/status"
            else "/v1/owner/conversation/android-proposal/context"
        val bytes = context.exchange(expected, path, "POST", request, 36864)
        val received = readAndroidOwnerStrictPublicObject(Charsets.UTF_8.newDecoder().decode(ByteBuffer.wrap(bytes)).toString(), allowNull = line)
        val json = if (line) {
            require(received.keys().asSequence().toSet() == setOf("receipt", "pending") && received.get("receipt") == JSONObject.NULL &&
                received.get("pending") is JSONObject)
            received.getJSONObject("pending")
        } else received
        val fields = setOf("v", "kind", "account_id", "user_id", "session_id", "origin", "root_fingerprint_hex", "proposal_sha256_hex", "proposal_b64", "expected_context", "server_now_ms", "expires_ms")
        fun integer(name: String): Long { val value = json.get(name); require(value is Int || value is Long); return (value as Number).toLong() }
        require(json.keys().asSequence().toSet() == fields && integer("v") == 1L && integer("kind") == kind.nativeKind.toLong())
        for (field in fields - setOf("v", "kind", "expected_context")) require(json.get(field) is String)
        require(json.get("expected_context") is JSONObject)
        val current = checkNotNull(context.currentAuthority()); require(before.sameSession(current))
        require(json.getString("account_id") == expected.account.toString() && json.getString("user_id") == current.user.toString() &&
            json.getString("session_id") == current.session.toString() && json.getString("origin") == expected.origin &&
            json.getString("root_fingerprint_hex") == expected.fingerprint && json.getString("proposal_sha256_hex") == digest)
        val public = decodeAndroidOwnerPublicProposal(json.getString("proposal_b64"), kind.maximum)
        require(public.contentEquals(proposal))
        fun decimal(name: String): Long { val text = json.getString(name); require(text.matches(Regex("[1-9][0-9]{0,18}"))); return text.toLong() }
        require(decimal("server_now_ms") > 0 && Math.addExact(current.utcMs, current.uncertaintyMs) < decimal("expires_ms"))
        val scoped = json.getJSONObject("expected_context")
        selection.compare(kind, expected, current, scoped)
        return AndroidOwnerCustodyFlowExpected.fromAuthenticatedComposition(scoped.toString().toByteArray(Charsets.UTF_8))
    }
}

/** Untrusted challenge is only a bounded lookup selector. The authenticated status response
 * must independently bind original owner authority and exactly reproduce the full proposal.
 */
internal fun androidOwnerLineChallengeSelector(proposal: ByteArray): UUID {
    val domain = "ZTSE/line/owner-key/register/v1\u0000".toByteArray(Charsets.US_ASCII)
    val offset = domain.size + 5 * 16 + 8
    require(proposal.size in (offset + 16)..1024 && proposal.copyOfRange(0, domain.size).contentEquals(domain))
    val value = ByteBuffer.wrap(proposal, offset, 16)
    return UUID(value.long, value.long).also { require(it != UUID(0, 0)) }
}

/** Bounded protocol parser rejects duplicate names, coercion and unknown primitive syntax.
 * Native independently applies the exact per-kind object/field grammar after this boundary.
 */
internal fun readAndroidOwnerStrictPublicObject(text: String, allowNull: Boolean = false): JSONObject {
    require(text.length in 2..36864)
    val input = JSONTokener(text)
    fun string(): String { require(input.nextClean() == '"'); return input.nextString('"') }
    fun objectAt(depth: Int): JSONObject {
        require(depth <= 4 && input.nextClean() == '{')
        val result = JSONObject(); val names = HashSet<String>()
        val first = input.nextClean(); if (first == '}') return result else input.back()
        while (true) {
            val name = string(); require(names.add(name) && input.nextClean() == ':')
            val start = input.nextClean()
            val value: Any = when (start) {
                '{' -> { input.back(); objectAt(depth + 1) }
                '"' -> input.nextString('"')
                'n' -> { require(allowNull && input.next() == 'u' && input.next() == 'l' && input.next() == 'l'); JSONObject.NULL }
                in '0'..'9' -> {
                    val raw = StringBuilder().append(start)
                    while (true) { val next = input.next(); require(next != '\u0000'); if (next in '0'..'9') raw.append(next) else { input.back(); break } }
                    require(raw.length <= 19 && raw.toString().matches(Regex("0|[1-9][0-9]{0,18}")))
                    raw.toString().toLong()
                }
                else -> error("Strict public JSON primitive required")
            }
            result.put(name, value)
            when (input.nextClean()) { '}' -> return result; ',' -> Unit; else -> error("Strict public JSON object required") }
        }
    }
    val parsed = objectAt(0); require(input.nextClean() == '\u0000'); return parsed
}

internal fun createAndroidOwnerArchiveContext(pin: ByteArray, expected: AndroidOwnerCustodyIdentity,
    authority: AndroidOwnerCustodyAuthority): AndroidOwnerCustodyFlowExpected {
    require(authority.account == expected.account && pin.size == 94 &&
        pin.copyOfRange(5, 21).contentEquals(expected.accountBytes()) &&
        AndroidOwnerCustodyKit.hash("ZTSE/root-pin/v2\u0000".toByteArray() + pin).contentEquals(expected.fingerprintBytes()))
    val issued = Math.subtractExact(authority.utcMs, authority.uncertaintyMs).coerceAtLeast(1)
    val context = JSONObject().put("root_pin", AndroidOwnerCustodyKit.hex(pin))
        .put("operation_id", UUID.randomUUID().toString().replace("-", ""))
        .put("issued_ms", issued).put("expires_ms", Math.addExact(issued, 300000))
    return AndroidOwnerCustodyFlowExpected.fromAuthenticatedComposition(context.toString().toByteArray(Charsets.UTF_8))
}

/** Public-only manual exchange: canonical base64, exact bounds, with no clipboard access. */
internal fun decodeAndroidOwnerPublicProposal(text: String, maximum: Int): ByteArray {
    require(maximum in 1..20480 && text.length in 4..((maximum + 2) / 3 * 4) &&
        text.matches(Regex("[A-Za-z0-9+/]+={0,2}")))
    val bytes = java.util.Base64.getDecoder().decode(text)
    try {
        require(bytes.size in 1..maximum && java.util.Base64.getEncoder().encodeToString(bytes) == text)
        // Private root tokens and raw private archive recovery cannot enter a public-proposal slot.
        require(!bytes.take(6).toByteArray().contentEquals("ZTRK1-".toByteArray()) && bytes.size != 32)
        return bytes
    } catch (failure: Exception) { bytes.fill(0); throw failure }
}

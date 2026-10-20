// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import java.security.MessageDigest
import java.util.UUID

/** Closed current-server-record candidate. The actual source-owned authenticated socket/fetch,
 * pending request, local one-use installed journal and opaque custody remain mandatory.
 * Neither a phase string nor this public verification object can activate an interval.
 */
internal class ConversationInterval03Permission private constructor(val requestKind: String, val requestId: UUID,
    val statement: ConversationInterval03.Statement, private val owner: ByteArray?, private val phone: ByteArray?,
    private val installed: ByteArray?, val requestedMs: Long?, val approvedMs: Long?, val installedMs: Long?,
    val phase: String, val comparedMs: Long, val permissionExpiresMs: Long, private val readers: List<RegistryReader>) {
    class RegistryReader internal constructor(val connector: UUID, val grant: UUID, private val key: ByteArray,
        private val publicPoint: ByteArray, val generation: Long, val registrationExpiresMs: Long,
        val grantExpiresMs: Long, val keyFromMs: Long, val keyUntilMs: Long) {
        fun keyId() = key.copyOf()
        fun point() = publicPoint.copyOf()
        override fun toString() = "ConversationInterval03RegistryCandidate"
    }
    fun ownerSignature() = owner?.copyOf()
    fun phoneSignature() = phone?.copyOf()
    fun installedSignature() = installed?.copyOf()
    fun requireRequest(kind: String, id: UUID) { require(requestKind == kind && requestId == id) }

    /** These checks supplement the authenticated mutable registry source; signed IDs alone
     * never establish current grant authorization. Call only with the ACTUAL source response.
     */
    fun verifyCurrent(selection: Profile03CurrentReader.Selection, hardwareReaderPoint: ByteArray,
        actualOriginDigest: ByteArray, now: Long): Draft03ManifestAuthority.IntervalKeys {
        val c = selection.selected; val s = statement
        require(phase in setOf("requested", "install_pending", "active") && now >= comparedMs && now < permissionExpiresMs &&
            permissionExpiresMs <= s.intervalExpiresMs && permissionExpiresMs <= c.permissionExpiresAtMs && selection.physical.isCurrent())
        require(s.account.toString() == selection.baseBinding.accountId && s.device.toString() == selection.baseBinding.deviceId &&
            s.line.toString() == selection.baseBinding.lineId && s.binding.toString() == selection.installation.newBindingId &&
            s.bindingGeneration == c.bindingGeneration && s.vaultGeneration == c.vaultGeneration && s.manifestVersion == c.manifestVersion &&
            s.selectionEpoch == selection.epoch && same(s.readerKeyId, c.selectedReaderKeyId) && same(s.rootFingerprint, c.rootFingerprint) &&
            same(s.manifestDigest, c.manifestDigest) && same(s.electionCommitment, c.electionCommitment) &&
            same(s.electionBundleSha256, c.electionBundleSha256) && same(s.deviceSessionDigest, selection.deviceSessionDigest()) &&
            same(s.physicalSelectionDigest, selection.physicalDigest()) && same(s.originDigest, actualOriginDigest))
        if (selection.user != null) require(selection.user == s.ownerUser && selection.ownerSession == s.ownerSession)
        if (requestKind == "fetch") require(phase == "active" && comparedMs == c.comparedAtMs)
        if (phase != "active") { s.requireSetupCurrent(now); require(permissionExpiresMs <= s.setupExpiresMs) }
        s.requireIntervalCurrent(now)
        val roles = selection.authority.intervalKeys(s, hardwareReaderPoint, now)
        val ownerProof = checkNotNull(owner)
        require(ConversationContentCrypto.verifyRaw(ownerProof, roles.browserPoint(), ConversationInterval03.requestTranscript(s)))
        phone?.let { require(ConversationContentCrypto.verifyRaw(it, roles.phonePoint(), ConversationInterval03.approvalTranscript(s, ownerProof))) }
        installed?.let { require(ConversationContentCrypto.verifyRaw(it, roles.phonePoint(), ConversationInterval03.installedTranscript(s, ownerProof, checkNotNull(phone)))) }
        for (reader in readers) require(reader.generation == s.vaultGeneration && reader.keyFromMs <= comparedMs &&
            comparedMs < reader.keyUntilMs && permissionExpiresMs <= minOf(reader.registrationExpiresMs, reader.grantExpiresMs, reader.keyUntilMs) &&
            same(reader.point(), roles.integrationPoint(reader.keyId())))
        check(selection.physical.isCurrent())
        return roles
    }
    override fun toString() = "ConversationInterval03Permission(unverified-current-record-projection)"

    companion object {
        fun decode(f: Map<String, Any>): ConversationInterval03Permission {
            require(f.keys == KEYS && f["v"] == Profile03Json.Integer(1) && f["kind"] == "interval_permission03")
            val kind = Profile03Json.text(f, "request_kind").also { require(it in setOf("interval_challenge", "interval_status", "fetch")) }
            val request = id(f, "request_id")
            val statement = ConversationInterval03.Statement.decode(Profile03Json.binary(f, "statement", 695, 1092))
            require(id(f, "interval_id") == statement.interval && same(Profile03Json.binary(f, "statement_sha256", 32, 32), statement.sha256()))
            if (kind == "interval_challenge") require(request == statement.receipt)
            for ((name, expected) in listOf("device_session_digest" to statement.deviceSessionDigest,
                "physical_selection_digest" to statement.physicalSelectionDigest, "owner_session_digest" to statement.ownerSessionDigest))
                require(same(Profile03Json.binary(f, name, 32, 32), expected))
            fun signature(name: String) = if (f[name] === Profile03Json.Null) null else Profile03Json.binary(f, name, 64, 64).also(ConversationInterval03::requireRaw)
            fun time(name: String) = if (f[name] === Profile03Json.Null) null else Profile03Json.decimal(f, name)
            val owner = signature("owner_signature"); val phone = signature("phone_signature"); val installed = signature("installed_signature")
            val requestedAt = time("requested_ms"); val approvedAt = time("approved_ms"); val installedAt = time("installed_ms")
            require((owner == null) == (requestedAt == null) && (phone == null) == (approvedAt == null) &&
                (installed == null) == (installedAt == null) && (phone == null || owner != null) && (installed == null || phone != null))
            val phase = Profile03Json.text(f, "phase").also { require(it in setOf("reserved", "requested", "install_pending", "active", "stopped", "expired")) }
            when (phase) {
                "reserved" -> require(owner == null)
                "requested" -> require(owner != null && phone == null)
                "install_pending" -> require(owner != null && phone != null && installed == null)
                "active" -> require(owner != null && phone != null && installed != null)
            }
            if (kind == "fetch") require(phase == "active")
            val compared = Profile03Json.decimal(f, "compared_ms")
            val expires = Profile03Json.decimal(f, "permission_expires_ms")
            for (at in listOfNotNull(requestedAt, approvedAt, installedAt)) require(at in statement.issuedMs until statement.setupExpiresMs && at <= compared)
            require(approvedAt == null || approvedAt >= checkNotNull(requestedAt))
            require(installedAt == null || installedAt >= checkNotNull(approvedAt))
            val selected = statement.integrations()
            val fields = Profile03Json.intervalReaders(f)
            require(fields.size == selected.size)
            val readers = fields.mapIndexed { index, item ->
                require(item.keys == READER_KEYS && item["read_directions"] == Profile03Json.Integer(12))
                val mapping = selected[index]
                val key = Profile03Json.binary(item, "key_id", 32, 32)
                val point = Profile03Json.binary(item, "key_point", 65, 65)
                DevicePayloadKeyStore.decodePoint(point)
                require(id(item, "connector_id") == mapping.connector && id(item, "read_grant_id") == mapping.readGrant &&
                    same(key, mapping.keyId()) && same(key, sha("ZTSE/key/v1\u0000".toByteArray(Charsets.US_ASCII) + byteArrayOf(0, 16) + point)))
                RegistryReader(mapping.connector, mapping.readGrant, key, point, Profile03Json.decimal(item, "manifest_generation"),
                    Profile03Json.decimal(item, "registration_expires_ms"), Profile03Json.decimal(item, "grant_expires_ms"),
                    Profile03Json.decimal(item, "key_valid_from_ms"), Profile03Json.decimal(item, "key_valid_until_ms"))
                    .also { require(it.keyUntilMs > it.keyFromMs) }
            }
            return ConversationInterval03Permission(kind, request, statement, owner, phone, installed,
                requestedAt, approvedAt, installedAt, phase, compared, expires, readers)
        }
        private val KEYS = setOf("v", "kind", "request_kind", "request_id", "interval_id", "statement_sha256", "statement",
            "owner_signature", "phone_signature", "installed_signature", "requested_ms", "approved_ms", "installed_ms", "phase",
            "device_session_digest", "physical_selection_digest", "owner_session_digest", "compared_ms", "permission_expires_ms", "readers")
        private val READER_KEYS = setOf("connector_id", "read_grant_id", "key_id", "key_point", "manifest_generation", "read_directions",
            "registration_expires_ms", "grant_expires_ms", "key_valid_from_ms", "key_valid_until_ms")
        private fun id(f: Map<String, Any>, name: String) = UUID.fromString(Profile03ClosedUnaccepted.uuid(Profile03Json.text(f, name)))
        private fun sha(bytes: ByteArray) = MessageDigest.getInstance("SHA-256").digest(bytes)
        private fun same(a: ByteArray, b: ByteArray) = MessageDigest.isEqual(a, b)
    }
}

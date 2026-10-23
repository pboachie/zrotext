// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import android.Manifest
import android.content.Context
import android.content.pm.PackageManager
import android.telephony.SubscriptionManager
import java.nio.ByteBuffer
import java.security.MessageDigest
import java.util.UUID

/** Device-authenticated fetch projection composed with independently retained local authority.
 * This reader never creates a root, key, v2 activation, binding allocation or accepted election.
 * Its caller obtains the packet exclusively through the existing device-signed HTTPS client.
 */
internal class Profile03CurrentReader(context: Context, private val origins: Profile03Origins,
    private val db: SmsJournalDatabase, private val trust: Draft02TrustStore,
    private val payloadKeys: DevicePayloadKeyStore, private val signingKeys: DeviceSigningKeyStore,
    private val clock: Profile03SessionTime, private val socketCurrent: () -> Boolean,
    private val requireInterval: (Profile03FetchPacket, SealedDispatch03Frames.Grant, Selection) -> (() -> Unit),
    private val manifests: Profile03ManifestResolver? = null,
) {
    private val application = checkNotNull(context.applicationContext)
    private val origin = origins.protocolOrigin
    private val originDigest = origins.protocolDigest()

    class Selection internal constructor(val election: Draft03PayloadElectionProof, val authority: Draft03ManifestAuthority,
        val selected: Draft03PayloadElectionProof.CurrentAuthority03, val installation: Profile03ElectionRecord,
        val baseBinding: LocalLineBinding, val user: UUID?, val ownerSession: UUID?, val epoch: Long,
        val selectedSubscription: Int, private val activeCards: List<ActiveSimCard>?, val physical: InstalledSelectedLineV2,
        deviceSessionDigest: ByteArray, physicalDigest: ByteArray, val authorityCurrent: () -> Unit = {}) {
        private val sessionIdentity = deviceSessionDigest.copyOf()
        private val physicalIdentity = physicalDigest.copyOf()
        fun deviceSessionDigest() = sessionIdentity.copyOf()
        fun physicalDigest() = physicalIdentity.copyOf()
        fun cards() = activeCards?.toList()
        override fun toString() = "Profile03CurrentSelection(verified-local-evidence)"
    }

    fun read(packet: Profile03FetchPacket, input: SealedDispatch03Frames.Grant) = read(packet, input, false)
    fun readManifest(packet: Profile03FetchPacket, input: SealedDispatch03Frames.Grant) = read(packet, input, true)
    fun readMessageManifest(packet: Profile03FetchPacket, input: SealedDispatch03Frames.Grant) = read(packet, input, true, true)
    private fun read(packet: Profile03FetchPacket, input: SealedDispatch03Frames.Grant, full: Boolean,
        messageFetch: Boolean = false): Draft03OutboundPreparation.Current {
        val grant = SealedDispatch03Frames.grant(input.json())
        // Correlate this actual fetched attempt before Room, framework or hardware waits.
        if (messageFetch) Profile03MessagePermission03.requireFetch(packet.currentProjection(), packet.intervalPermission(), grant)
        val value = selection(packet.currentProjection(), grant.lineId, false, false, full, messageFetch)
        val intervalRamCurrent = requireInterval(packet, grant, value)
        val instant = checkNotNull(clock.nowMs())
        check(instant < grant.expiresAtMs && grant.expiresAtMs <= value.selected.permissionExpiresAtMs)
        val intent = ReviewedIntent03V2.decode(packet.intent())
        intent.requireGrant(grant)
        require(intent.ownerUserId == value.user && intent.ownerSessionId == value.ownerSession && packet.selectionEpoch == value.epoch)
        val compared = value.election.requireCurrent(value.authority, value.selected, instant)
        val request = intent.verifyReceipt(packet.signature(), value.authority, compared, packet.acceptedMs, instant,
            packet.selectionEpoch, originDigest, packet.intervalStartsMs, packet.intervalExpiresMs)
        val context = value.authority.context(request, checkNotNull(clock.nowMs()), intent.expiresMs)
        val hardware = payloadKeys.existingPublic()
        require(same(value.authority.readerPoint(context, Draft03ManifestAuthority.Reader(1, hardware.keyId),
            checkNotNull(clock.nowMs())), hardware.point))
        value.election.requireCurrent(value.authority, value.selected, checkNotNull(clock.nowMs()))
        check(socketCurrent() && value.baseBinding.installedSelectionV2()?.isCurrent() == true)
        return Draft03OutboundPreparation.Current(origins, value.election, value.authority, value.selected, value.installation,
            value.baseBinding, intent, packet.signature(), packet.acceptedMs, packet.selectionEpoch, intent.ownerUserId,
            intent.ownerSessionId, packet.intervalStartsMs, packet.intervalExpiresMs, value.selectedSubscription, value.cards(),
            value.physical, intervalRamCurrent)
    }

    /** Only a nonce-matched authenticated current socket reply or device fetch may call this.
     * A fresh server read cannot create a missing local signed/installed ceremony.
     */
    fun deviceSelection(projection: ByteArray, expectedLine: UUID) = selection(projection, expectedLine, false, true)
    fun manifestDeviceSelection(projection: ByteArray, expectedLine: UUID) = selection(projection, expectedLine, false, true, true)

    /** A nonce-matched accepted reply can finish the SAME previously signed local ceremony.
     * It cannot reserve/sign a new one, accept a retired outcome or renew an installed receipt.
     */
    fun installAccepted(projection: ByteArray, expectedLine: UUID) = selection(projection, expectedLine, true, true)

    private fun selection(projection: ByteArray, expectedLine: UUID, install: Boolean, deviceOnly: Boolean,
        full: Boolean = false, messageFetch: Boolean = false): Selection {
        val f = Profile03Json.objectValue(projection)
        val expected = if (full) { if (deviceOnly) DEVICE_MANIFEST_KEYS else MESSAGE_MANIFEST_KEYS }
            else if (deviceOnly) DEVICE_SELECTION_KEYS else CURRENT_KEYS
        if (messageFetch) {
            require(full && !deviceOnly && !install)
            Profile03MessagePermission03.requireShape(f)
        } else require(f.keys == expected)
        require(f["v"] == Profile03Json.Integer(1) &&
            f["envelope_profile"] == Profile03Json.Integer(3) && f["manifest_profile"] == Profile03Json.Integer(3))
        if (messageFetch) require(f["kind"] == "message_manifest_permission03")
        else if (full) require(f["kind"] == if (deviceOnly) "device_manifest_selection03" else "message_permission03")
        else require(!deviceOnly || f["kind"] == "device_selection03")
        fun number(name: String) = Profile03Json.decimal(f, name)
        fun bytes(name: String) = Profile03Json.binary(f, name, 32, 32)
        fun fieldId(name: String) = id(f, name)
        val observed = checkNotNull(clock.snapshot())
        val identity = observed.first
        val session = identity.session
        origins.requireProtocol(bytes("origin_digest"), session)
        fun now(): Long = checkNotNull(clock.nowMs()).also {
            check(socketCurrent() && clock.snapshot()?.first?.session === session && it > 0)
        }
        now()
        require(fieldId("account_id") == session.accountId && fieldId("device_id") == session.deviceId &&
            fieldId("line_id") == expectedLine && number("connection_epoch") == session.connectionEpoch &&
            number("deployment_epoch") == session.deploymentEpoch &&
            Profile03Json.text(f, "site_id") == identity.site && Profile03Json.text(f, "instance_id") == identity.instance)

        val evidence = Profile03Json.nested(f, "evidence")
        require(evidence.keys == EVIDENCE_KEYS)
        val bundle = Profile03Json.binary(evidence, "bundle", 628, 628)
        val core = bundle.copyOfRange(0, 500)
        val challenge = id(core.copyOfRange(56, 72))
        // Resolve the original local writer record BEFORE an authenticated historical timestamp
        // can be used. A public bundle/projection cannot install a receipt or select a new ID.
        val retained = checkNotNull(db.profile03Elections().find(challenge.toString()))
        retained.requireShape()
        require((retained.state == "installed" || install && retained.state == "signed") &&
            retained.accountId == session.accountId.toString() && retained.deviceId == session.deviceId.toString() &&
            retained.lineId == expectedLine.toString() && retained.originHash == origins.protocolHash &&
            same(Profile03ElectionEncoding.decode(retained.coreB64url, 500), core) &&
            same(Profile03ElectionEncoding.decode(checkNotNull(retained.deviceSignatureB64url), 64), bundle.copyOfRange(500, 564)))
        val old = Profile03Json.binary(evidence, "prior_manifest02", 364, 9751)
        val successor = Profile03Json.binary(evidence, "accepted_manifest03", 366, 9753)
        val acceptedMs = Profile03Json.decimal(evidence, "accepted_ms")
        val accepted = Draft03PayloadElectionProof.AcceptedRecord03(uuid(session.accountId), uuid(session.deviceId),
            uuid(expectedLine), bytes("root_fingerprint"), number("trust_generation"), uuid(fieldId("old_binding_id")),
            number("old_binding_generation"), bytes("old_binding_proof_digest"), uuid(fieldId("binding_id")),
            number("binding_generation"), bytes("reader_key_id"), long(core, 176), core.copyOfRange(184, 216), sha(old),
            long(core, 216), core.copyOfRange(224, 256), sha(successor), sha(core), bytes("election_digest"), sha(bundle), acceptedMs)
        val installation = retained.copy(state = "installed", acceptedEvidenceSha256 = Draft03OutboundPreparation.acceptedIdentity(accepted))
        require((retained.state == "signed" || retained == installation) &&
            installation.oldBindingId == fieldId("old_binding_id").toString() && installation.newBindingId == fieldId("binding_id").toString() &&
            installation.oldGeneration == accepted.oldBindingGeneration && installation.newGeneration == accepted.newBindingGeneration &&
            installation.readerKeyId == hex(accepted.selectedReaderKeyId) &&
            same(bytes("election_bundle_sha256"), accepted.electionBundleSha256))
        now()
        val history = trust.retainedElectionHistory(acceptedMs, ::now)
        history.requireExactEvidence(Profile03Json.binary(evidence, "root_pin", 94, 94), old,
            Profile03Json.decimal(evidence, "prior_accepted_ms"))
        val hardwareReader = payloadKeys.existingPublic()
        require(hardwareReader.security in setOf(PayloadKeySecurity.STRONGBOX, PayloadKeySecurity.TRUSTED_ENVIRONMENT) &&
            same(hardwareReader.keyId, accepted.selectedReaderKeyId))
        val enrolled = signingKeys.existingConversationPublicPoint()
        now() // Existing-key access can block; it never creates a missing key.
        val original = Profile03OriginalBindingProof.verify(
            Profile03Json.binary(evidence, "registration_evidence", 1, 2048),
            Profile03Json.binary(evidence, "activation_evidence", 1, 2048), core, history.pin(), enrolled,
            hardwareReader.keyId, origin)
        require(original.acceptedMs <= long(core, 384) && original.acceptedMs <= acceptedMs)
        require(same(Profile03Json.binary(evidence, "device_signing_point", 65, 65), enrolled) &&
            same(Profile03Json.binary(evidence, "owner_approval_point", 65, 65), original.approvalPoint()) &&
            same(bytes("device_signing_key_id"), signingId(enrolled)) &&
            same(bytes("approval_key_id"), signingId(original.approvalPoint())) &&
            same(bytes("device_session_digest"), identity.deviceSessionDigest(enrolled)))
        history.requireOriginalReader(uuid(session.deviceId), uuid(expectedLine), hardwareReader.keyId, hardwareReader.point)
        val election = Draft03PayloadElectionProof.verifyAccepted(bundle, core, accepted, history.proof,
            successor, enrolled, original.approvalPoint())
        val originalAuthority = history.current03(successor, if (full) acceptedMs else now())
        val installedAuthority = if (full) checkNotNull(manifests).projection(f, evidence, installation, originalAuthority) else null
        val authority = installedAuthority?.authority ?: originalAuthority
        require(authority.version == number("manifest_version") && same(authority.digest, bytes("manifest_digest")))
        val selected = Draft03PayloadElectionProof.CurrentAuthority03(3, 3, accepted.accountId, accepted.deviceId,
            accepted.lineId, accepted.newBindingId, accepted.newBindingGeneration, accepted.selectedReaderKeyId,
            accepted.rootFingerprint, accepted.vaultGeneration, number("manifest_version"), bytes("manifest_digest"),
            accepted.electionCommitment, accepted.electionBundleSha256, number("compared_ms"),
            number(if (deviceOnly) "selection_expires_ms" else "permission_expires_ms"))
        election.requireCurrent(authority, selected, now())
        authority.requireSelectedReader(accepted.deviceId, accepted.lineId, hardwareReader.keyId, hardwareReader.point,
            now(), selected.permissionExpiresAtMs)
        if (!deviceOnly) require(same(bytes("owner_session_digest"), sha(ReviewedIntent03.framed("ZTSE/line/payload-profile/owner-session/v1",
            accepted.accountId + uuid(fieldId("user_id")) + uuid(fieldId("owner_session_id"))))))
        for (permission in listOf(Manifest.permission.SEND_SMS, Manifest.permission.RECEIVE_SMS, Manifest.permission.READ_PHONE_STATE)) {
            check(application.checkSelfPermission(permission) == PackageManager.PERMISSION_GRANTED)
        }
        val line = checkNotNull(db.attempts().currentLineBinding())
        val selectedSubscription = application.getSharedPreferences("gateway_selection", Context.MODE_PRIVATE)
            .getInt("subscription_id", SubscriptionManager.INVALID_SUBSCRIPTION_ID)
        val permit = checkNotNull(line.installedSelectionV2())
        val cards = SimCardContinuity.observe(application)
        check(line.protocolVersion == 2 && line.v2Purpose == "sealed" && line.accountId == installation.accountId &&
            line.deviceId == installation.deviceId && line.lineId == installation.lineId &&
            line.generation == installation.oldGeneration && line.subscriptionId == selectedSubscription &&
            permit.isCurrent() && permit.matches(line) && original.matchesLocal(permit.record) &&
            SimCardContinuity.matches(line.activatedSim(), cards))
        val refreshed = permit.refresh03
        if (refreshed == null) check(!db.selectionRefreshes03().everSigned(installation.newBindingId, hex(bytes("device_session_digest"))))
        if (full && refreshed == null) require(permit.record.proofConnectionEpoch == session.connectionEpoch &&
            installation.connectionEpoch == session.connectionEpoch && installation.deploymentEpoch == session.deploymentEpoch)
        if (deviceOnly || messageFetch) {
            val physical = Profile03Json.nested(f, "physical_selection")
            if (refreshed == null) require(physical.keys == setOf("kind") && physical["kind"] == "original_v2")
            else refreshed.requireProjection(physical, number("selection_epoch"), bytes("device_session_digest"), db)
        } else refreshed?.requireContext(number("selection_epoch"), bytes("device_session_digest"), db)
        if (refreshed != null) require(refreshed.record.electionChallengeId == installation.challengeId &&
            refreshed.record.electionIdentitySha256 == installation.acceptedEvidenceSha256 &&
            refreshed.record.bindingId == installation.newBindingId && refreshed.record.bindingGeneration == installation.newGeneration)
        if (full && refreshed != null) {
            val resolved = checkNotNull(installedAuthority); val c = refreshed.bundle.core
            val acceptedAt = checkNotNull(refreshed.record.acceptedMs); val installedAt = checkNotNull(refreshed.record.installedMs)
            require(acceptedAt in c.issuedMs until c.expiresMs && installedAt in acceptedAt until c.expiresMs && installedAt <= now() &&
                c.account == session.accountId && c.device == session.deviceId && c.line == expectedLine &&
                c.binding.toString() == installation.newBindingId && c.bindingGeneration == installation.newGeneration &&
                c.vaultGeneration == accepted.vaultGeneration && c.selectionEpoch == number("selection_epoch") &&
                same(c.electionDigest, accepted.electionCommitment) && same(c.electionBundleSha256, accepted.electionBundleSha256) &&
                same(c.rootFingerprint, accepted.rootFingerprint) && same(c.readerKeyId, hardwareReader.keyId) &&
                same(c.deviceSessionDigest, bytes("device_session_digest")) && same(c.originDigest, originDigest) &&
                same(c.deviceSigningKeyId, signingId(enrolled)) && same(c.approvalKeyId, signingId(original.approvalPoint())))
            SelectionRefresh03.Bundle.verify(refreshed.bundle.bytes(), c.bytes(), refreshed.bundle.observation(), enrolled, original.approvalPoint())
            resolved.historical(c.manifestVersion, c.manifestDigest, c.issuedMs)
            resolved.historical(c.manifestVersion, c.manifestDigest, acceptedAt).requireSelectedReader(accepted.deviceId, accepted.lineId,
                hardwareReader.keyId, hardwareReader.point, acceptedAt, Math.addExact(installedAt, 1))
            resolved.historical(c.manifestVersion, c.manifestDigest, installedAt)
            resolved.ramCurrent()
        }
        election.requireCurrent(authority, selected, now())
        check(permit.isCurrent())
        if (install) {
            check(db.profile03Elections().install(installation) { actual ->
                check(actual == line && permit.matches(checkNotNull(actual)) && permit.isCurrent())
                election.requireCurrent(authority, selected, now())
            })
        } else check(db.profile03Elections().find(challenge.toString()) == installation)
        election.requireCurrent(authority, selected, now())
        check(permit.isCurrent())
        val physicalDigest = if (refreshed == null) ConversationInterval03.originalPhysicalDigest(session.accountId,
            session.deviceId, expectedLine, id(accepted.newBindingId), accepted.electionCommitment, bytes("device_session_digest"),
            id(accepted.oldBindingId), Profile03Json.binary(evidence, "activation_evidence", 1, 2048))
        else ConversationInterval03.refreshedPhysicalDigest(session.accountId, session.deviceId, expectedLine,
            id(accepted.newBindingId), accepted.electionCommitment, bytes("device_session_digest"), refreshed)
        check(permit.isCurrent())
        installedAuthority?.ramCurrent?.invoke()
        return Selection(election, authority, selected, installation, line,
            if (deviceOnly) null else fieldId("user_id"), if (deviceOnly) null else fieldId("owner_session_id"),
            number("selection_epoch"), selectedSubscription, cards, permit, bytes("device_session_digest"), physicalDigest,
            installedAuthority?.ramCurrent ?: {})
    }
    override fun toString() = "Profile03CurrentReader(local-and-authenticated-device-evidence)"
    companion object {
        private val CURRENT_KEYS = setOf("v", "envelope_profile", "manifest_profile", "account_id", "user_id", "owner_session_id",
            "device_id", "line_id", "selection_epoch", "origin_digest", "owner_session_digest", "device_session_digest", "site_id",
            "instance_id", "connection_epoch", "deployment_epoch", "old_binding_id", "old_binding_generation", "old_binding_proof_digest",
            "binding_id", "binding_generation", "reader_key_id", "device_signing_key_id", "approval_key_id", "root_fingerprint",
            "trust_generation", "manifest_version", "manifest_digest", "election_digest", "election_bundle_sha256", "compared_ms",
            "permission_expires_ms", "evidence")
        private val DEVICE_SELECTION_KEYS = (CURRENT_KEYS - setOf("user_id", "owner_session_id", "owner_session_digest", "permission_expires_ms")) +
            setOf("kind", "selection_expires_ms", "physical_selection")
        private val DEVICE_MANIFEST_KEYS = DEVICE_SELECTION_KEYS + setOf("current_manifest03", "manifest_ancestry_sha256")
        private val MESSAGE_MANIFEST_KEYS = CURRENT_KEYS + setOf("kind", "current_manifest03", "manifest_ancestry_sha256")
        private val EVIDENCE_KEYS = setOf("root_pin", "prior_manifest02", "prior_accepted_ms", "accepted_manifest03", "accepted_ms",
            "bundle", "device_signing_point", "owner_approval_point", "registration_evidence", "activation_evidence")
        private fun id(f: Map<String, Any>, name: String): UUID {
            val raw = Profile03Json.text(f, name)
            return UUID.fromString(raw).also { require(it != UUID(0, 0) && it.toString() == raw) }
        }
        private fun id(bytes: ByteArray) = ByteBuffer.wrap(bytes).let { UUID(it.long, it.long) }
        private fun uuid(id: UUID) = ReviewedIntent03.uuid(id)
        private fun long(bytes: ByteArray, at: Int) = ByteBuffer.wrap(bytes, at, 8).long.also { require(it > 0) }
        private fun sha(bytes: ByteArray) = MessageDigest.getInstance("SHA-256").digest(bytes)
        private fun same(a: ByteArray, b: ByteArray) = MessageDigest.isEqual(a, b)
        private fun hex(bytes: ByteArray) = Draft02OutboundPreparation.hex(bytes)
        private fun signingId(point: ByteArray) = sha("ZTSE/key/v1\u0000".toByteArray(Charsets.US_ASCII) + byteArrayOf(1, 1) + point)
    }
}

// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import android.content.Context
import android.os.SystemClock
import java.nio.ByteBuffer
import java.util.UUID
import java.util.concurrent.Executor
import java.util.concurrent.atomic.AtomicReference

/** Explicit process-only setup. Existing compared-root storage and hardware keys are mandatory.
 * The ordinary service continues to own authentication, negotiation and socket callbacks.
 */
internal class ConversationUserSetupController(
    context: Context, private val lines: SmsAttemptDao, private val payloadAlias: String,
    private val worker: Executor, private val delivery: Executor,
    private val execution: ConversationExecutionComposition,
    private val onReady: (ConversationPresentationPort) -> Unit,
    private val elapsedMillis: () -> Long = SystemClock::elapsedRealtime
) : AutoCloseable {
    internal class Selection(
        val identity: EvidenceIdentity, val intervalId: String, val lineId: String,
        val bindingGeneration: Long, val peer: String,
        val bindings: ConversationConnectionBindings, val site: String, val instance: String,
        phoneReaderId: ByteArray? = null,
        initialManifests: List<ByteArray> = emptyList()
    ) {
        private val reader = phoneReaderId?.copyOf()
        val phoneReaderId get() = reader?.copyOf()
        private val predecessors = initialManifests.also { require(it.size <= ConversationEnrollmentSession.MAX_CHAIN) }
            .map { require(it.size in 364..9751); it.copyOf() }
        val initialManifests get() = predecessors.map { it.copyOf() }
        init { require(reader == null || reader.size == 32 && reader.any { it != 0.toByte() }) }
        override fun toString() = "ConversationUserSelection(redacted)"
    }
    private val application = checkNotNull(context.applicationContext)
    private val gate = Any()
    private var closed = false
    private var installed: AutoCloseable? = null
    private val connection = AtomicReference<ConversationConnectionFactory.Connection?>(null)
    private val negotiation = AtomicReference<ConversationSocketNegotiation?>(null)
    private val executionConnection = AtomicReference<ConversationExecutionComposition.Connection?>(null)
    private val selectedBindings = AtomicReference<ConversationConnectionBindings?>(null)
    private fun requireOpen() = synchronized(gate) { check(!closed) }

    /** Called only for a deliberate selected interval. False opens no journal, key or trust handle. */
    fun begin(selection: Selection, enabled: Boolean = false): Boolean = synchronized(gate) {
        check(!closed)
        if (!enabled || installed != null) return false
        require(selection.bindingGeneration > 0 && selection.bindings.outboundSigner.all { it == 0.toByte() })
        selectedBindings.set(selection.bindings)
        var wire: ConversationAuthenticatedWire? = null
        var expectedSession: ConversationPhoneSession? = null
        var bundle: ConversationActivationBundle? = null
        var prepared: ConversationActivationCodec.Parsed? = null
        var review: ConversationPhoneReview? = null
        var owned: ConversationAndroidConnectionInputs.Owned? = null
        val provider = ConversationAndroidConnectionInputs(application, lines, payloadAlias, delivery,
            { wire?.currentSession() }, object : ConversationSendTransport {
                override fun submit(message: String, attempt: String, scope: ConversationCaptureScope,
                    body: String) = ConversationSubmission.UNKNOWN
            })
        val factory = ConversationConnectionFactory(selection.site, selection.instance, elapsedMillis, worker,
            { session, authenticated ->
                requireOpen(); validateIdentity(selection, session); check(authenticated.currentSession() == session)
                check(expectedSession == null)
                expectedSession = session
                wire = authenticated
                val retrieved = ConversationProposalTransport(authenticated).proposal(selection.intervalId, selection.site, selection.instance)
                requireOpen(); check(authenticated.currentSession() == session)
                val parsed = ConversationActivationCodec.decode(retrieved.statement())
                validateProposalSelection(selection, parsed)
                val clock = ConversationTrustedClock(elapsedMillis, authenticated::currentSession)
                ConversationAuthorityTransport(ConversationSerializedChannel(authenticated), clock,
                    authenticated::currentSession, elapsedMillis).refreshTime()
                requireOpen(); check(authenticated.currentSession() == session)
                val now = checkNotNull(clock.nowMs()); check(now in 1 until parsed.expiresMs)
                val shown = ConversationPhoneReview(UUID.randomUUID().toString(), parsed.scope.intervalId,
                    parsed.scope.lineId, parsed.scope.bindingGeneration, parsed.scope.peer,
                    (if(parsed.scope.selectedReaders.isEmpty()) ConversationActivationCodec.DISCLOSURE else ConversationActivationCodec.READER_DISCLOSURE), "conversation-content-v1", parsed.scope.disclosureDigest,
                    (parsed.expiresMs - now).coerceAtMost(60000), parsed.scope.integrationSelection)
                bundle = retrieved; prepared = parsed; review = shown
                ConversationConnectionProposal(retrieved.statement(), shown)
            }, { session ->
                requireOpen()
                validateIdentity(selection, session); check(session == expectedSession)
                val parsed = checkNotNull(prepared)
                val inputs = provider.openForUserAction(session, parsed.scope, checkNotNull(review), 0) { checkNotNull(selectedBindings.get()) }
                try {
                    requireOpen()
                    val authenticated = checkNotNull(wire)
                    val clock = ConversationTrustedClock(elapsedMillis, authenticated::currentSession)
                    val time = ConversationAuthorityTransport(ConversationSerializedChannel(authenticated), clock,
                        authenticated::currentSession, elapsedMillis)
                    time.refreshTime()
                    fun now(): Long {
                        requireOpen(); check(authenticated.currentSession() == expectedSession && expectedSession == session)
                        return checkNotNull(clock.nowMs()).also { check(it in 1 until parsed.expiresMs) }
                    }
                    val trust = inputs.inputs.trust
                    ConversationManifestBootstrap.install(trust, selection.initialManifests, parsed,
                        inputs.inputs.payloadKeys.existingPublic().keyId, ::now, ::requireOpen)
                    val saved = trust.inspect()
                    check(saved.status == Draft02TrustStore.Status.NEEDS_FRESHNESS)
                    val snapshot = checkNotNull(saved.snapshot)
                    check(snapshot.version > 0) // Never enroll a downloaded root or initial pin here.
                    val manifest = checkNotNull(bundle).manifest()
                    try {
                        check(manifest.size in 364..9751 && manifest.copyOfRange(0, 5).contentEquals(byteArrayOf(90,84,77,65,2)))
                        check(ByteBuffer.wrap(manifest, 21, 8).long == parsed.scope.trustGeneration &&
                            ByteBuffer.wrap(manifest, 29, 8).long == parsed.scope.activationVersion &&
                            Draft02OutboundPreparation.hash(manifest.copyOfRange(0, manifest.size - 64)) == parsed.scope.activationDigest)
                        val prior = trust.currentAuthority(::now)
                        val position = if (prior.version == parsed.scope.activationVersion)
                            Draft02ManifestAuthority.Position.current(prior.version, prior.digest)
                        else Draft02ManifestAuthority.Position.after(prior.version, prior.digest)
                        val candidate = Draft02ManifestAuthority.verify(snapshot.pin, manifest,
                            Draft02ManifestAuthority.Trust(uuid(parsed.scope.accountId),
                                Draft02RootComparison.fingerprint(snapshot.pin), parsed.scope.trustGeneration, position), now())
                        fun contexts(authority: Draft02ManifestAuthority) {
                            val recipient = inputs.inputs.payloadKeys.existingPublic()
                            selection.phoneReaderId?.let { check(it.contentEquals(recipient.keyId)) }
                            check(recipient.security in setOf(PayloadKeySecurity.STRONGBOX, PayloadKeySecurity.TRUSTED_ENVIRONMENT))
                            fun request(inbound: Boolean) = Draft02ManifestAuthority.Request(
                                if (inbound) Draft02ManifestAuthority.Direction.INBOUND else Draft02ManifestAuthority.Direction.OUTBOUND,
                                uuid(parsed.scope.accountId), uuid(parsed.scope.intervalId), uuid(parsed.scope.deviceId),
                                uuid(parsed.scope.lineId), parsed.scope.peer.toByteArray(Charsets.US_ASCII),
                                if (inbound) parsed.signerId else selection.bindings.outboundSigner,
                                (if (inbound) emptyList() else listOf(Draft02ManifestAuthority.Reader(1, recipient.keyId))) +
                                    Draft02ManifestAuthority.Reader(2, hex(parsed.scope.readerKeyId)) +
                                    (if(inbound) parsed.scope.selectedReaders.map { Draft02ManifestAuthority.Reader(3,hex(it.keyId)) } else emptyList()))
                            authority.context(request(true), now())
                            authority.requireDeviceReader(uuid(parsed.scope.accountId), uuid(parsed.scope.deviceId),
                                uuid(parsed.scope.lineId), recipient.keyId, now())
                        }
                        contexts(candidate) // Reject wrong roles/bindings before durable trust CAS.
                        check(trust.acceptManifest(snapshot, manifest, ::now).status == Draft02TrustStore.Status.NEEDS_FRESHNESS)
                        val verified = trust.currentAuthority(::now)
                        check(verified.accountId.contentEquals(uuid(parsed.scope.accountId)) &&
                            verified.version == parsed.scope.activationVersion && verified.generation == parsed.scope.trustGeneration &&
                            Draft02OutboundPreparation.hex(verified.digest) == parsed.scope.activationDigest)
                        contexts(verified)
                        requireOpen(); now(); owned = inputs; inputs.inputs
                    } finally { manifest.fill(0) }
                } catch (error: Exception) { inputs.close(); throw error }
            }, { value ->
                requireOpen()
                val inputs = checkNotNull(owned)
                val presentation = Presentation(value.presentation, inputs.decision, ::requireOpen)
                inputs.decision.observePresentation(value.presentation)
                check(connection.compareAndSet(null, value))
                requireOpen()
                delivery.execute {
                    try { requireOpen(); value.requireLive(); onReady(presentation) }
                    catch (_: Exception) { close() }
                }
            }, dispatchForConnection = { value ->
                requireOpen(); check(executionConnection.compareAndSet(null, value)); execution.dispatch(value)
            })
        installed = ConversationSocketComposition.installOwned({ socket, identity, epoch ->
            requireOpen()
            check(identity == selection.identity)
            val value = factory.create(socket, identity, epoch)
            if (!negotiation.compareAndSet(null, value)) { value.close(); error("Setup already attached") }
            try { requireOpen(); value } catch (error: Exception) { value.close(); throw error }
        }, enabled = true)
        installed != null
    }

    /** Explicit worker action; no reply authority is available before actual phone activation. */
    fun installReplyAuthority(signedSuccessor: ByteArray, signerId: ByteArray,
                              completion: (Boolean) -> Unit = {}) {
        require(signedSuccessor.size in 364..9751 && signerId.size == 32 && signerId.any { it != 0.toByte() })
        val bytes = signedSuccessor.copyOf(); val signer = signerId.copyOf()
        try { worker.execute {
            val accepted = runCatching {
                requireOpen()
                val handle = checkNotNull(connection.get()); handle.requireLive()
                val active = checkNotNull(executionConnection.get())
                val scope = checkNotNull(active.runtime.currentScope())
                val deadline = checkNotNull(active.runtime.executionDeadline(scope))
                fun now(): Long {
                    // Trust storage invokes this while locked: never enter admission/Room here.
                    requireOpen(); handle.requireLive(); active.runtime.requireExecutionOpen()
                    check(active.wire.currentSession() == active.phone)
                    return checkNotNull(active.runtime.trustedNowMs()).also { check(it in 1 until deadline) }
                }
                fun requireActive() {
                    now()
                    check(active.runtime.currentScope() == scope && active.runtime.captureEligible() &&
                        active.inputs.lifecycleLoss() == null)
                    active.inputs.requireAuthority(scope, now())
                    now()
                }
                requireActive()
                val before = active.currentCrypto(scope, now())
                val saved = active.inputs.trust.inspect()
                val snapshot = checkNotNull(saved.snapshot)
                check(saved.status == Draft02TrustStore.Status.NEEDS_FRESHNESS && snapshot.version == before.authority.version)
                val candidate = Draft02ManifestAuthority.verify(snapshot.pin, bytes,
                    Draft02ManifestAuthority.Trust(uuid(scope.accountId), Draft02RootComparison.fingerprint(snapshot.pin),
                        scope.trustGeneration, Draft02ManifestAuthority.Position.after(before.authority.version, before.authority.digest)), now())
                candidate.requireReplySuccessor(before.authority, signer)
                val bindings = checkNotNull(selectedBindings.get())
                fun checkRoles(authority: Draft02ManifestAuthority): (Long) -> Unit {
                    val reader = active.inputs.payloadKeys.existingPublic()
                    check(reader.security in setOf(PayloadKeySecurity.STRONGBOX, PayloadKeySecurity.TRUSTED_ENVIRONMENT))
                    val at = now()
                    authority.requireDeviceReader(uuid(scope.accountId), uuid(scope.deviceId), uuid(scope.lineId), reader.keyId, at)
                    fun request(inbound: Boolean) = Draft02ManifestAuthority.Request(
                        if (inbound) Draft02ManifestAuthority.Direction.INBOUND else Draft02ManifestAuthority.Direction.OUTBOUND,
                        uuid(scope.accountId), uuid(scope.intervalId), uuid(scope.deviceId), uuid(scope.lineId),
                        scope.peer.toByteArray(Charsets.US_ASCII), if (inbound) before.phoneSignerKeyId else signer,
                        (if (inbound) emptyList() else listOf(Draft02ManifestAuthority.Reader(1, reader.keyId))) +
                            Draft02ManifestAuthority.Reader(2, hex(scope.readerKeyId)) +
                            (if(inbound) scope.selectedReaders.map { Draft02ManifestAuthority.Reader(3,hex(it.keyId)) } else emptyList()))
                    val inbound = request(true); val outbound = request(false)
                    val checkAt: (Long) -> Unit = { time ->
                        authority.requireDeviceReader(uuid(scope.accountId), uuid(scope.deviceId), uuid(scope.lineId), reader.keyId, time)
                        authority.context(inbound, time); authority.context(outbound, time)
                    }
                    checkAt(at)
                    return checkAt
                }
                checkRoles(candidate)
                requireActive()
                val current = active.inputs.trust.currentAuthority(::now)
                check(current.version == before.authority.version && current.digest.contentEquals(before.authority.digest))
                check(active.inputs.trust.acceptManifest(snapshot, bytes, ::now).status == Draft02TrustStore.Status.NEEDS_FRESHNESS)
                val installedAuthority = active.inputs.trust.currentAuthority(::now)
                check(installedAuthority.version == candidate.version && installedAuthority.digest.contentEquals(candidate.digest))
                requireActive()
                val finalRoles = checkRoles(installedAuthority)
                active.runtime.withActiveScope(scope) {
                    synchronized(gate) {
                        check(!closed && connection.get() === handle && executionConnection.get() === active)
                        active.runtime.requireExecutionOpen()
                        check(active.wire.currentSession() == active.phone)
                        finalRoles(now())
                        check(selectedBindings.compareAndSet(bindings, ConversationConnectionBindings(bindings.archivePoint, signer)))
                    }
                }
                true
            }.getOrDefault(false)
            bytes.fill(0); signer.fill(0)
            runCatching { delivery.execute { completion(accepted && runCatching { requireOpen() }.isSuccess) } }
        } } catch (_: Exception) {
            bytes.fill(0); signer.fill(0)
            runCatching { delivery.execute { completion(false) } }
        }
    }

    override fun close() {
        val installation = synchronized(gate) {
            if (closed) return
            closed = true
            installed.also { installed = null }
        }
        try { negotiation.getAndSet(null)?.close() }
        finally { try { connection.getAndSet(null)?.close() } finally { installation?.close() } }
    }
    override fun toString() = "ConversationUserSetupController(redacted)"

    /** Same observed domain and Stop outcome; this wrapper manufactures no active/closed state. */
    internal class Presentation(private val delegate: ConversationPresentationPort,
        private val decision: ConversationPhoneDecision, private val requireLive: () -> Unit) : ConversationPresentationPort {
        override fun observe(listener: (ConversationPresentationSnapshot) -> Unit): AutoCloseable {
            requireLive(); return delegate.observe { value -> requireLive(); listener(value) }
        }
        override fun refresh() { requireLive(); delegate.refresh() }
        override fun approvePhoneReview(requestId: String, observedVersion: Long) {
            requireLive(); decision.approve(requestId, observedVersion)
            requireLive(); delegate.approvePhoneReview(requestId, observedVersion)
        }
        override fun declinePhoneReview(requestId: String, observedVersion: Long) {
            requireLive(); delegate.declinePhoneReview(requestId, observedVersion)
        }
        override fun requestStop(intervalId: String, observedVersion: Long) {
            requireLive(); delegate.requestStop(intervalId, observedVersion)
        }
    }
    companion object {
        internal fun validateIdentity(selection: Selection, session: ConversationPhoneSession) {
            check(session.account.toString() == selection.identity.accountId &&
                session.device.toString() == selection.identity.deviceId && session.originHash == selection.identity.originHash)
        }
        internal fun validateProposalSelection(selection: Selection, parsed: ConversationActivationCodec.Parsed) {
            check(parsed.scope.intervalId == selection.intervalId && parsed.scope.lineId == selection.lineId &&
                parsed.scope.bindingGeneration == selection.bindingGeneration && parsed.scope.peer == selection.peer)
            check(DevicePayloadKeyStore.keyId(selection.bindings.archivePoint).contentEquals(hex(parsed.scope.readerKeyId)))
        }
        private fun hex(value: String) = value.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
        private fun uuid(value: String) = UUID.fromString(value).let { ByteBuffer.allocate(16).putLong(it.mostSignificantBits).putLong(it.leastSignificantBits).array() }
    }
}

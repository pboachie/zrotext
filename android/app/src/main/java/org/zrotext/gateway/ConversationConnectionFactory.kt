// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import java.nio.ByteBuffer
import java.util.UUID
import java.util.concurrent.Executor
import java.util.concurrent.atomic.AtomicBoolean
import okhttp3.WebSocket

/** Original proposal supplied deliberately by the feature owner, not discovered from a new endpoint. */
internal class ConversationConnectionProposal(statement: ByteArray, val review: ConversationPhoneReview) {
    private val original = statement.copyOf()
    fun statement() = original.copyOf()
    override fun toString() = "ConversationConnectionProposal(redacted)"
}

/** Independently selected public bindings. The current signed manifest must authorize them at use. */
internal class ConversationConnectionBindings(archivePoint: ByteArray, outboundSigner: ByteArray) {
    private val archive = archivePoint.copyOf()
    private val outbound = outboundSigner.copyOf()
    val archivePoint get() = archive.copyOf()
    val outboundSigner get() = outbound.copyOf()
    init { require(archive.size == 65 && outbound.size == 32) }
    override fun toString() = "ConversationConnectionBindings(redacted)"
}

/** Caller supplies previously enrolled hardware keys and executors. No provisioning defaults.
 * releaseOwnedResources must own only this connection storage, never a successor/shared handle.
 * Factory invokes it once after an accepted lifecycle closure attempt, or before runtime creation.
 */
internal class ConversationConnectionInputs(
    val capture: ConversationCaptureDao, val sends: ConversationSendDao,
    val protection: ConversationJournalProtection, val trust: Draft02TrustStore,
    val payloadKeys: DevicePayloadKeyStore, val signingKeys: DeviceSigningKeyStore,
    val delivery: Executor,
    val bindings: (ConversationCaptureScope, Long) -> ConversationConnectionBindings,
    val requireAuthority: (ConversationCaptureScope, Long) -> Unit,
    val consumePhoneDecision: (ConversationCaptureScope) -> Unit,
    val observedLine: (Int) -> ConversationRuntimeMount.ObservedLine?,
    val lifecycleLoss: () -> ConversationStopReason?,
    val dispatch: ConversationSendTransport,
    private val releaseOwnedResources: () -> Unit = {}
) {
    private val resourcesReleased = AtomicBoolean(false)
    internal fun releaseResources() {
        if (resourcesReleased.compareAndSet(false, true)) releaseOwnedResources()
    }
}

/** Process-only configuration. Neither installation nor negotiation grants phone consent. */
internal class ConversationConnectionFactory(
    private val site: String, private val instance: String,
    private val elapsedMillis: () -> Long, private val worker: Executor,
    private val proposalForSession: (ConversationPhoneSession, ConversationAuthenticatedWire) -> ConversationConnectionProposal,
    private val inputsForSession: (ConversationPhoneSession) -> ConversationConnectionInputs,
    private val publish: (Connection) -> Unit,
    private val mount: ConversationRuntimeMount = ConversationProcessMount.runtime,
    private val dispatchForConnection: ((ConversationExecutionComposition.Connection) -> ConversationSendTransport)? = null
) {
    init { require(listOf(site, instance).all { it.length in 1..64 && it.all { ch -> ch.code in 33..126 } }) }

    fun install(enabled: Boolean = false): Boolean = ConversationSocketComposition.install(::create, enabled)

    internal fun create(socket: WebSocket, identity: EvidenceIdentity, epoch: Long): ConversationSocketNegotiation {
        val gate = Any()
        val lost = AtomicBoolean(false)
        var closed = false
        var owned: Connection? = null
        fun lose() {
            lost.set(true)
            val old = synchronized(gate) { closed = true; owned.also { owned = null } }
            old?.close()
        }
        return ConversationSocketNegotiation(socket, identity, epoch, elapsedMillis, worker, { wire, guard ->
            var candidate: Connection? = null
            var original: ByteArray? = null
            var acquired: ConversationConnectionInputs? = null
            var assembledRuntime: ConversationAuthenticatedRuntime? = null
            try {
                guard()
                val session = checkNotNull(wire.currentSession())
                // Operations can hold the admission gate. Never take negotiation's monitor there:
                // socket loss holds that monitor while synchronously closing admission.
                fun requireSession() { check(!lost.get() && wire.currentSession() == session) }
                val proposal = proposalForSession(session, wire)
                guard()
                original = proposal.statement()
                val parsed = validateProposal(checkNotNull(original), proposal.review, session, site, instance)
                val inputs = inputsForSession(session).also { acquired = it }
                guard()
                check(inputs.lifecycleLoss() == null)
                lateinit var runtime: ConversationAuthenticatedRuntime
                var runtimeBuilt = false
                val activation = ConversationPhoneActivation(checkNotNull(original), inputs.trust, wire,
                    { checkNotNull(runtime.trustedNowMs()) }, inputs.signingKeys::signConversationStatement)
                try {
                    val decisionConsumed = AtomicBoolean(false)
                    val enrolledReader = java.util.concurrent.atomic.AtomicReference<ByteArray?>(null)
                    fun authority(scope: ConversationCaptureScope, now: Long): ConversationCryptoCurrent {
                        requireSession()
                        check(scope == parsed.scope && inputs.lifecycleLoss() == null)
                        inputs.requireAuthority(scope, now)
                        fun trustedNow(): Long = checkNotNull(runtime.trustedNowMs()).also { check(it >= now) }
                        val verified = inputs.trust.currentAuthority(::trustedNow)
                        check(verified.generation == scope.trustGeneration && verified.version >= scope.activationVersion)
                        if (verified.version == scope.activationVersion)
                            check(verified.digest.contentEquals(hex(scope.activationDigest)))
                        val selected = inputs.bindings(scope, now)
                        check(DevicePayloadKeyStore.keyId(selected.archivePoint).contentEquals(hex(scope.readerKeyId)))
                        val recipient = inputs.payloadKeys.existingPublic()
                        check(recipient.security in setOf(PayloadKeySecurity.STRONGBOX, PayloadKeySecurity.TRUSTED_ENVIRONMENT))
                        val deviceReader = recipient.keyId
                        enrolledReader.compareAndSet(null, deviceReader.copyOf())
                        check(checkNotNull(enrolledReader.get()).contentEquals(deviceReader))
                        fun context(inbound: Boolean, at: Long) = verified.context(Draft02ManifestAuthority.Request(
                            if (inbound) Draft02ManifestAuthority.Direction.INBOUND else Draft02ManifestAuthority.Direction.OUTBOUND,
                            uuid(scope.accountId), uuid(scope.intervalId), uuid(scope.deviceId), uuid(scope.lineId),
                            scope.peer.toByteArray(Charsets.US_ASCII), if (inbound) parsed.signerId else selected.outboundSigner,
                            (if (inbound) emptyList() else listOf(Draft02ManifestAuthority.Reader(1,
                                deviceReader))) +
                                Draft02ManifestAuthority.Reader(2, hex(scope.readerKeyId)) +
                            (if(inbound) scope.selectedReaders.map { Draft02ManifestAuthority.Reader(3,hex(it.keyId)) } else emptyList())), at)
                        context(true, now)
                        verified.requireDeviceReader(uuid(scope.accountId), uuid(scope.deviceId), uuid(scope.lineId), deviceReader, now)
                        requireSession()
                        check(inputs.lifecycleLoss() == null)
                        inputs.requireAuthority(scope, trustedNow())
                        val finalAuthority = inputs.trust.currentAuthority(::trustedNow)
                        check(finalAuthority.generation == verified.generation && finalAuthority.version == verified.version &&
                            finalAuthority.digest.contentEquals(verified.digest))
                        inputs.requireAuthority(scope, trustedNow())
                        requireSession()
                        check(inputs.lifecycleLoss() == null)
                        // All potentially blocking storage/key/provider work precedes this sample.
                        // Context checks below use only the verified immutable manifest/key IDs.
                        val completedNow = trustedNow()
                        context(true, completedNow)
                        verified.requireDeviceReader(uuid(scope.accountId), uuid(scope.deviceId), uuid(scope.lineId), deviceReader, completedNow)
                        requireSession()
                        return ConversationCryptoCurrent(scope, verified, selected.archivePoint,
                            selected.outboundSigner, parsed.signerId, completedNow)
                    }
                    runtime = ConversationAuthenticatedRuntime(inputs.capture, inputs.sends, activation,
                        inputs.protection, wire, elapsedMillis, { scope, now -> authority(scope, now) },
                        { scope ->
                            requireSession()
                            check(scope == parsed.scope && decisionConsumed.compareAndSet(false, true))
                            inputs.consumePhoneDecision(scope)
                            requireSession()
                        }, activation::install, worker, inputs.delivery)
                    runtimeBuilt = true
                    assembledRuntime = runtime
                    val crypto = ConversationContentCrypto(inputs.payloadKeys, inputs.signingKeys, {
                        val scope = runtime.currentScope()
                        if (scope == null) null else authority(scope, checkNotNull(runtime.trustedNowMs()))
                    })
                    val dispatch = if (dispatchForConnection == null) inputs.dispatch else
                        checkNotNull(dispatchForConnection.invoke(ConversationExecutionComposition.Connection(
                            runtime, crypto, wire, session, inputs, ::authority)))
                    val content = ConversationContentSession(runtime, crypto, dispatch, mount)
                    candidate = Connection(runtime, content, activation, ::requireSession, inputs::releaseResources)
                    guard()
                    synchronized(gate) {
                        check(!closed)
                        check(content.install(inputs.observedLine, inputs.lifecycleLoss, enabled = true))
                        owned = candidate
                    }
                    // External callbacks never hold the loss lock. Closing during publication still
                    // synchronously fences the published handle and any subsequently queued proposal.
                    checkNotNull(candidate).requireLive()
                    publish(checkNotNull(candidate))
                    checkNotNull(candidate).requireLive()
                    runtime.propose(proposal.review, checkNotNull(original))
                    guard()
                } catch (error: Exception) {
                    if (candidate == null) {
                        try { if (runtimeBuilt) runtime.lifecycleLost(ConversationStopReason.PHONE_SESSION_LOST) }
                        finally { activation.close() }
                    }
                    throw error
                }
            } catch (error: Exception) {
                try { lose() } finally {
                    if (candidate != null) candidate?.close()
                    else acquired?.let { inputs ->
                        val built = assembledRuntime
                        if (built == null) runCatching { inputs.releaseResources() }
                        else built.lifecycleLost(ConversationStopReason.PHONE_SESSION_LOST, inputs::releaseResources)
                    }
                }
                throw error
            } finally { original?.fill(0) }
        }, ::lose)
    }

    internal class Connection internal constructor(
        private val runtime: ConversationAuthenticatedRuntime,
        private val content: ConversationContentSession,
        private val activation: ConversationPhoneActivation,
        private val guard: () -> Unit,
        private val releaseResources: () -> Unit
    ) : AutoCloseable {
        private val closed = AtomicBoolean(false)
        internal fun requireLive() { check(!closed.get()); guard(); check(!closed.get()) }
        val presentation: ConversationPresentationPort get() { requireLive(); return runtime.presentation }
        fun receiveConfirmed(message: String, complete: (Boolean) -> Unit) {
            requireLive(); content.receiveConfirmed(message, complete)
        }
        fun submitConfirmed(message: String): ConversationSubmission {
            requireLive(); return content.submitConfirmed(message)
        }
        @Synchronized override fun close() {
            if (!closed.compareAndSet(false, true)) return
            try { content.close() } finally {
                try { runtime.lifecycleLost(ConversationStopReason.PHONE_SESSION_LOST, releaseResources) }
                finally { activation.close() }
            }
        }
        override fun toString() = "ConversationConnection(redacted)"
    }

    companion object {
        internal fun validateProposal(statement: ByteArray, review: ConversationPhoneReview,
            session: ConversationPhoneSession, site: String, instance: String): ConversationActivationCodec.Parsed {
            val parsed = ConversationActivationCodec.decode(statement)
            val scope = parsed.scope
            require(scope.accountId == session.account.toString() && scope.deviceId == session.device.toString())
            require(parsed.connectionEpoch == session.connectionEpoch && parsed.deploymentEpoch == session.deploymentEpoch)
            require(parsed.site == site && parsed.instance == instance)
            require(review.intervalId == scope.intervalId && review.lineId == scope.lineId &&
                review.lineGeneration == scope.bindingGeneration && review.peer == scope.peer &&
                review.disclosureDigest == scope.disclosureDigest)
            return parsed
        }
        private fun hex(value: String) = value.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
        private fun uuid(value: String): ByteArray = UUID.fromString(value).let {
            ByteBuffer.allocate(16).putLong(it.mostSignificantBits).putLong(it.leastSignificantBits).array()
        }
    }
}

// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import java.util.concurrent.Executor
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicLong
import java.util.concurrent.atomic.AtomicReference

/** Dormant assembly: one authenticated session, clock and admission gate for every operation.
 * Socket custody, canonical activation verification and live permissions/owner/key authority remain
 * mandatory inputs. Construction neither mounts a receiver nor creates persistent credentials.
 * The caller owns the databases and executor lifecycle. A shared serial queue prevents overlap.
 */
internal class ConversationAuthenticatedRuntime(
    journal: ConversationCaptureDao, private val sends: ConversationSendDao,
    private val verifier: ConversationActivationVerifier, private val protection: ConversationJournalProtection,
    private val wire: ConversationAuthenticatedWire, private val elapsedMillis: () -> Long,
    private val requireAuthority: (ConversationCaptureScope, Long) -> Unit,
    consumePhoneDecision: (ConversationCaptureScope) -> Unit,
    exchangeAcceptanceInstall: (ConversationRecoveryRequest) -> ByteArray,
    worker: Executor, private val delivery: Executor
) {
    private val blocked = AtomicBoolean(true)
    private val epoch = AtomicLong(0)
    private val selected = AtomicReference<ConversationPhoneSession?>(null)
    private class TimeWitness(val started: Long, val session: ConversationPhoneSession, val epoch: Long) {
        val deadline = Math.addExact(started, ConversationTrustedClock.MAX_AGE_MS)
        private var lastElapsed = started
        @Synchronized fun beforeDeadline(elapsedMillis: () -> Long): Long {
            val now = try { elapsedMillis() } catch (_: Exception) { throw TimeUnavailable() }
            if (now < 0 || now < lastElapsed || now >= deadline) throw TimeUnavailable()
            lastElapsed = now
            return now
        }
    }
    private class Maintenance(val scope: ConversationCaptureScope, val witness: TimeWitness)
    private class TimeUnavailable : IllegalStateException("Authenticated time unavailable")
    private val timeWitness = AtomicReference<TimeWitness?>(null)
    private val maintenance = AtomicReference<Maintenance?>(null)
    private val bindingLock = Any()
    private val serial = Serial(worker)
    private val clock = ConversationTrustedClock(elapsedMillis, wire::currentSession)
    private val transport = ConversationAuthorityTransport(ConversationSerializedChannel(wire), clock,
        wire::currentSession, elapsedMillis)
    private val contentTransport = ConversationContentTransport(wire)
    private fun freshWitness(session: ConversationPhoneSession, ticket: Long): TimeWitness {
        val start = try { elapsedMillis() } catch (_: Exception) { throw TimeUnavailable() }
        if (start < 0 || start > Long.MAX_VALUE - ConversationTrustedClock.MAX_AGE_MS) throw TimeUnavailable()
        return TimeWitness(start, session, ticket)
    }
    private fun requireWitness(value: TimeWitness) {
        check(timeWitness.get() === value && epoch.get() == value.epoch && selected.get() == value.session)
        value.beforeDeadline(elapsedMillis)
        check(wire.currentSession() == value.session) { "Authenticated session changed" }
    }
    private fun current(scope: ConversationCaptureScope) {
        check(!blocked.get()) { "Admission suspended" }
        val witness = checkNotNull(timeWitness.get())
        requireWitness(witness)
        val session = checkNotNull(selected.get())
        check(wire.currentSession() == session && session.account.toString() == scope.accountId &&
            session.device.toString() == scope.deviceId) { "Authenticated session changed" }
        requireAuthority(scope, checkNotNull(clock.nowMs()) { "Authenticated time unavailable" })
        requireWitness(witness)
        check(!blocked.get() && wire.currentSession() == session)
    }
    private val guarded = object : ConversationActivationVerifier {
        override fun verifiedPreparation(evidence: ByteArray) = verifier.verifiedPreparation(evidence).also(::current)
        override fun verifiedActiveLease(scope: ConversationCaptureScope, challenge: String, evidence: ByteArray): Long {
            current(scope)
            return verifier.verifiedActiveLease(scope, challenge, evidence).also { current(scope) }
        }
    }
    private val admission = ConversationCaptureAdmission(journal, guarded, protection, elapsedMillis, ::current)
    private val recovery = ConversationFreshReviewRecovery(journal, admission, guarded, consumePhoneDecision)
    private val hooks = ConversationLifecycleHooks(admission, sends, clock, recovery, transport::close)
    private val domain = ConversationJournalPresentationDomain(admission, recovery, hooks, guarded,
        elapsedMillis, exchangeAcceptanceInstall)
    private val runtime = ConversationPresentationRuntime(serial, delivery, domain)
    val presentation: ConversationPresentationPort get() = runtime

    /** A proposal grants nothing. An affirmative, current phone decision still completes installation. */
    fun propose(review: ConversationPhoneReview, evidence: ByteArray) {
        val owned = evidence.copyOf()
        val ticket = epoch.get()
        try { serial.execute {
            try {
                val session = checkNotNull(wire.currentSession())
                val candidate = freshWitness(session, ticket)
                transport.refreshTime()
                val scope = verifier.verifiedPreparation(owned.copyOf())
                check(wire.currentSession() == session)
                require(session.account.toString() == scope.accountId && session.device.toString() == scope.deviceId)
                requireAuthority(scope, checkNotNull(clock.nowMs()))
                synchronized(bindingLock) {
                    check(epoch.get() == ticket) { "Proposal cancelled by lifecycle" }
                    candidate.beforeDeadline(elapsedMillis)
                    check(wire.currentSession() == session) { "Authenticated session changed" }
                    selected.set(session); timeWitness.set(candidate); blocked.set(false)
                }
                domain.propose(review, owned)
            } catch (_: Exception) {
                timeWitness.set(null); maintenance.set(null)
                blocked.set(true); admission.disableForLifecycle(); clock.invalidate(); domain.authorityUnavailable()
            } finally { owned.fill(0); runtime.refresh() }
        } } catch (_: Exception) {
            owned.fill(0)
            timeWitness.set(null); maintenance.set(null)
            blocked.set(true); admission.disableForLifecycle(); clock.invalidate()
            runtime.submissionFailed()
        }
    }

    /** Closes eligibility before returning, including while activation is waiting on transport. */
    fun lifecycleLost(reason: ConversationStopReason, afterAttempt: (() -> Unit)? = null) {
        synchronized(bindingLock) {
            blocked.set(true); epoch.incrementAndGet(); timeWitness.set(null); maintenance.set(null)
        }
        admission.disableForLifecycle()
        clock.invalidate()
        runtime.lifecycleStop(reason, afterAttempt)
    }

    /** Point-in-time result only. Refresh never renews admission or retries protected content. */
    internal fun maintainAuthenticatedTime(expectedScope: ConversationCaptureScope, complete: (Boolean) -> Unit) {
        val witness = timeWitness.get()
        if (blocked.get() || witness == null || epoch.get() != witness.epoch) {
            deliverMaintenance(false, complete); return
        }
        val operation = Maintenance(expectedScope, witness)
        if (!maintenance.compareAndSet(null, operation)) { deliverMaintenance(false, complete); return }
        try { serial.execute {
            var candidate: TimeWitness? = null
            var originalLeaseDeadline = 0L
            val result = try {
                check(maintenance.get() === operation)
                check(operation.witness === witness)
                admission.withCurrentScope(operation.scope) { it() }
                // Sample BEFORE remainingMs: any authority wait can only shorten this bound.
                val leaseStarted = witness.beforeDeadline(elapsedMillis)
                val remaining = admission.remainingMs(operation.scope)
                check(remaining > 0)
                originalLeaseDeadline = Math.addExact(leaseStarted, remaining)
                val started = witness.beforeDeadline(elapsedMillis)
                if (started >= originalLeaseDeadline) throw TimeUnavailable()
                val refreshed = freshWitness(witness.session, witness.epoch)
                candidate = refreshed
                check(refreshed.started >= started)
                transport.refreshTime() // No admission/DAO/authority monitor crosses the exchange.
                witness.beforeDeadline(elapsedMillis)
                check(wire.currentSession() == witness.session)
                admission.withCurrentScope(operation.scope) { fresh ->
                    fresh() // Includes genuine authority after blocking work, under original lease.
                    synchronized(bindingLock) {
                        check(!blocked.get() && maintenance.get() === operation)
                        requireWitness(witness)
                        if (witness.beforeDeadline(elapsedMillis) >= originalLeaseDeadline) throw TimeUnavailable()
                        if (refreshed.beforeDeadline(elapsedMillis) >= originalLeaseDeadline) throw TimeUnavailable()
                        check(wire.currentSession() == witness.session) { "Authenticated session changed" }
                        timeWitness.set(refreshed)
                    }
                }
                true
            } catch (error: Throwable) {
                lifecycleLost(if (error is TimeUnavailable) ConversationStopReason.LEASE_EXPIRED
                    else ConversationStopReason.PHONE_SESSION_LOST)
                if (error !is Exception) throw error
                false
            } finally {
                // A discarded, never-started Serial task does NOT run this. Epoch/close retires it.
                maintenance.compareAndSet(operation, null)
            }
            val completedWitness = candidate
            deliverMaintenance(result, complete) {
                !blocked.get() && epoch.get() == witness.epoch && timeWitness.get() === completedWitness &&
                    runCatching {
                        val liveWitness = checkNotNull(completedWitness)
                        requireWitness(liveWitness)
                        check(liveWitness.beforeDeadline(elapsedMillis) < originalLeaseDeadline)
                        check(wire.currentSession() == liveWitness.session) { "Authenticated session changed" }
                    }.isSuccess
            }
        } } catch (_: Exception) {
            maintenance.compareAndSet(operation, null)
            lifecycleLost(ConversationStopReason.WORKER_SHUTDOWN)
            deliverMaintenance(false, complete)
        }
    }
    private fun deliverMaintenance(result: Boolean, complete: (Boolean) -> Unit, stillCurrent: () -> Boolean = { true }) {
        try { delivery.execute {
            val accepted = result && runCatching(stillCurrent).getOrDefault(false)
            if (result && !accepted) lifecycleLost(ConversationStopReason.LEASE_EXPIRED)
            runCatching { complete(accepted) }
        } } catch (_: Exception) { lifecycleLost(ConversationStopReason.WORKER_SHUTDOWN) }
    }


    /** Deliberate closed-only reconciliation; never restores time/admission or retries any send. */
    fun reconcileClosed(deliver: (Boolean) -> Unit) {
        try { serial.execute {
            var original:ByteArray?=null
            val result=runCatching {
                check(blocked.get() || !admission.captureEligible())
                original=admission.originalClosedStatement()
                val scope=ConversationActivationCodec.decode(checkNotNull(original)).scope
                check(sends.closed(scope.intervalId)>0)
                transport.reconcile(scope,checkNotNull(original))
                domain.recordReconciledClosure(scope)
            }.isSuccess
            original?.fill(0);runtime.refresh()
            runCatching { delivery.execute { runCatching { deliver(result) } } }
        } } catch (_:Exception) { runCatching { delivery.execute { runCatching { deliver(false) } } } }
    }

    /** Explicit confirmed-send adapter shares capture/Stop admission and authenticated monotonic time. */
    fun confirmedSender(verifier: ConversationSendVerifier, transport: ConversationSendTransport) =
        ConversationConfirmedSend(sends, admission, verifier, protection, clock::nowMs, transport)

    /** Explicit worker request; receipt retries reuse their durably encrypted packet and counter. */
    fun uploadCapture(token: String, seal: (ConversationCapturedBody, Long) -> ByteArray, complete: (Boolean) -> Unit) {
        try { serial.execute {
            var packet: ByteArray? = null
            val result = runCatching {
                if (admission.captureAcknowledged(token)) return@runCatching
                val (capture, raw) = checkNotNull(admission.sealedCapture(token,seal))
                packet=raw
                admission.withCurrentScope(capture.scope) { it() }
                val ack = contentTransport.upload(capture,raw)
                admission.acknowledgeCapture(token,capture,raw,ack)
            }.isSuccess
            packet?.fill(0)
            runCatching { delivery.execute { runCatching { complete(result) } } }
        } } catch (_:Exception) { runCatching { delivery.execute { complete(false) } } }
    }

    /** Receive exactly an already confirmed packet; this does not submit it to a carrier. */
    fun receiveConfirmed(scope: ConversationCaptureScope, message: String, sender: ConversationConfirmedSend,
                         complete: (Boolean) -> Unit) {
        try { serial.execute {
            var packet: ByteArray?=null
            val result=runCatching {
                admission.withCurrentScope(scope) { it() }
                val raw=contentTransport.confirmed(scope,message); packet=raw
                admission.withCurrentScope(scope) { it() }
                // Sender owns its own admission check. Never invert sender -> admission locks.
                sender.receiveConfirmed(raw,message)
                admission.withCurrentScope(scope) { it() }
            }.isSuccess
            packet?.fill(0)
            runCatching { delivery.execute { runCatching { complete(result) } } }
        } } catch (_:Exception) { runCatching { delivery.execute { complete(false) } } }
    }

    fun captureEligible(): Boolean = admission.captureEligible()
    fun currentScope(): ConversationCaptureScope? = if(blocked.get()) null else admission.activeScope()
    /** Existing admission gate prevents Stop from racing explicit reply-binding publication. */
    internal fun <T> withActiveScope(scope: ConversationCaptureScope, action: () -> T): T =
        admission.withCurrentScope(scope) { fresh ->
            fresh(); check(!blocked.get()); action()
        }
    internal fun requireExecutionOpen() { check(!blocked.get()) }
    internal fun trustedNowMs():Long? = clock.nowMs()
    /** Uses this runtime's actual admission/clock; no second lease or wall-clock authority. */
    internal fun executionDeadline(scope: ConversationCaptureScope): Long? = runCatching {
        val started = checkNotNull(clock.nowMs())
        current(scope)
        val remaining = admission.remainingMs(scope)
        check(remaining > 0)
        // Anchor before providers: their elapsed wait cannot extend the admitted lease.
        val deadline = Math.addExact(started, remaining)
        current(scope)
        check(checkNotNull(clock.nowMs()) < deadline)
        deadline
    }.getOrNull()
    internal fun executionBoundary(authority: () -> ConversationExecutionAuthority?,
        db: SmsJournalDatabase, keys: DevicePayloadKeyStore,
        preparation: (Draft02OutboundPreparation.Grant) -> Draft02OutboundPreparation.Current?) =
        ConversationExecutionBoundary(admission, clock, authority, db, keys, preparation)
    fun firstReceiptBoundary() = admission.firstReceiptBoundary {
        val witness = timeWitness.get()
        if (blocked.get() || witness == null || runCatching { requireWitness(witness) }.isFailure) 0
        else clock.nowMs() ?: 0
    }
    fun observeAtBoundary(boundary: ConversationCaptureAdmission.ReceiptBoundary, token: String,
                          peer: String, line: String, generation: Long, body: String) =
        admission.observeAtBoundary(boundary, token, peer, line, generation, body)

    fun retryCapture(token: String): ConversationCapturedBody? = admission.retry(token)
    fun observeFirstReceipt(token: String, peer: String, line: String, generation: Long,
        body: String): ConversationObservation = admission.observe(token, clock.nowMs() ?: 0, peer, line, generation, body)

    private class Serial(private val executor: Executor) : Executor {
        private val queue = java.util.ArrayDeque<Runnable>()
        private var running = false
        override fun execute(command: Runnable) {
            synchronized(queue) {
            queue.add(command)
            if (running) return
            running = true
            // Resolve delegate admission while locked: concurrent callers cannot be accepted then
            // silently discarded when the delegate rejects the first queue submission.
            try { executor.execute {
                while (true) {
                    val next = synchronized(queue) { if (queue.isEmpty()) { running = false; null } else queue.removeFirst() } ?: break
                    try { next.run() } catch (error: Throwable) {
                        synchronized(queue) { queue.clear(); running = false }; throw error
                    }
                }
            } } catch (error: Exception) { queue.clear(); running = false; throw error }
            }
        }
    }
}

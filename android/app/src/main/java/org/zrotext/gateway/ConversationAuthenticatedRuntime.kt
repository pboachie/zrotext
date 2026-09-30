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
    private val bindingLock = Any()
    private val serial = Serial(worker)
    private val clock = ConversationTrustedClock(elapsedMillis, wire::currentSession)
    private val transport = ConversationAuthorityTransport(ConversationSerializedChannel(wire), clock,
        wire::currentSession, elapsedMillis)
    private fun current(scope: ConversationCaptureScope) {
        check(!blocked.get()) { "Admission suspended" }
        val session = checkNotNull(selected.get())
        check(wire.currentSession() == session && session.account.toString() == scope.accountId &&
            session.device.toString() == scope.deviceId) { "Authenticated session changed" }
        requireAuthority(scope, checkNotNull(clock.nowMs()) { "Authenticated time unavailable" })
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
                transport.refreshTime()
                val scope = verifier.verifiedPreparation(owned.copyOf())
                val session = checkNotNull(wire.currentSession())
                require(session.account.toString() == scope.accountId && session.device.toString() == scope.deviceId)
                requireAuthority(scope, checkNotNull(clock.nowMs()))
                synchronized(bindingLock) {
                    check(epoch.get() == ticket) { "Proposal cancelled by lifecycle" }
                    selected.set(session); blocked.set(false)
                }
                domain.propose(review, owned)
            } catch (_: Exception) {
                blocked.set(true); admission.disableForLifecycle(); clock.invalidate(); domain.authorityUnavailable()
            } finally { owned.fill(0); runtime.refresh() }
        } } catch (_: Exception) {
            owned.fill(0)
            blocked.set(true); admission.disableForLifecycle(); clock.invalidate()
            runtime.submissionFailed()
        }
    }

    /** Closes eligibility before returning, including while activation is waiting on transport. */
    fun lifecycleLost(reason: ConversationStopReason) {
        synchronized(bindingLock) { blocked.set(true); epoch.incrementAndGet() }
        admission.disableForLifecycle()
        clock.invalidate()
        runtime.lifecycleStop(reason)
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

    fun captureEligible(): Boolean = admission.captureEligible()
    internal fun trustedNowMs():Long? = clock.nowMs()
    fun firstReceiptBoundary() = admission.firstReceiptBoundary { if (blocked.get()) 0 else clock.nowMs() ?: 0 }
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

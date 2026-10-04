// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import java.util.concurrent.ScheduledExecutorService
import java.util.concurrent.ScheduledFuture
import java.util.concurrent.TimeUnit

/** Connection-owned scheduling only. Presentation triggers work; the actual runtime verifies it.
 * One missing completion retains one pending identity until close, never a retry/backlog.
 */
internal class ConversationTimeMaintenance(
    presentation: ConversationPresentationPort,
    private val scope: ConversationCaptureScope,
    private val scheduler: ScheduledExecutorService,
    private val failClosed: () -> Unit,
    private val request: (ConversationCaptureScope, (Boolean) -> Unit) -> Unit
) : AutoCloseable {
    private val lock = Any()
    private var closed = false
    private var started = false
    private var timerIdentity: Any? = null
    private var future: ScheduledFuture<*>? = null
    private var pending: Any? = null
    private var observation: AutoCloseable? = null

    init {
        val owned = presentation.observe { value ->
            val active = value.phase == ConversationPresentationPhase.CONFIRMED_ACTIVE &&
                value.intervalId == scope.intervalId && value.lineId == scope.lineId &&
                value.lineGeneration == scope.bindingGeneration
            val begin = synchronized(lock) {
                if (closed) false else if (active && !started) { started = true; true } else false
            }
            if (begin) schedule(0)
            else if (!active && synchronized(lock) { started }) close()
        }
        val retain = synchronized(lock) { if (closed) false else { observation = owned; true } }
        if (!retain) owned.close()
    }

    private fun schedule(delayMs: Long) {
        val identity = Any()
        synchronized(lock) {
            if (closed || timerIdentity != null || pending != null) return
            timerIdentity = identity
        }
        val scheduled = try { scheduler.schedule({ tick(identity) }, delayMs, TimeUnit.MILLISECONDS) }
        catch (_: Exception) { fail(); return }
        val retain = synchronized(lock) {
            if (closed || timerIdentity !== identity) false else { future = scheduled; true }
        }
        if (!retain) scheduled.cancel(false)
    }

    private fun tick(identity: Any) {
        val operation = Any()
        synchronized(lock) {
            if (closed || timerIdentity !== identity) return
            timerIdentity = null; future = null; pending = operation
        }
        // Scheduler only submits runtime work. No Room, authority, key or network callback here.
        try { request(scope) { accepted ->
            val owned = synchronized(lock) {
                if (closed || pending !== operation) false else { pending = null; true }
            }
            if (owned) { if (accepted) schedule(CADENCE_MS) else close() }
        } } catch (_: Exception) { fail() }
    }
    private fun fail() { try { close() } finally { failClosed() } }

    override fun close() {
        val resources = synchronized(lock) {
            if (closed) return
            closed = true; timerIdentity = null; pending = null
            val result = future to observation
            future = null; observation = null
            result
        }
        resources.first?.cancel(false)
        resources.second?.close()
    }
    companion object { const val CADENCE_MS = 10000L }
}

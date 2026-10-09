// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import java.util.Collections
import java.util.UUID

internal enum class ObservedSubscriptionKind { PHYSICAL, EMBEDDED }

/** Public logical-record metadata, never a carrier or durable hardware identity. */
internal data class SubscriptionObservationRow(
    val subscriptionId: Int,
    val kind: ObservedSubscriptionKind,
    val cardId: Int?,
    val portIndex: Int?,
    val slotIndex: Int?
) {
    override fun toString() = "SubscriptionObservationRow(redacted)"
}

/** The eventual platform adapter must supply the complete, unfiltered active list. */
internal data class CompleteSubscriptionRead(
    val apiLevel: Int,
    val ordinaryPermissionGranted: Boolean,
    val readable: Boolean,
    val complete: Boolean,
    val rows: List<SubscriptionObservationRow>
)

internal fun interface CompleteSubscriptionSource {
    fun read(): CompleteSubscriptionRead?
}

internal sealed interface CompleteObservationRegistration

/** Local observation only: no signing, installation, persistence or send authority. */
internal sealed interface CompleteSelectionSnapshot {
    val selected: SubscriptionObservationRow
    val activeRows: List<SubscriptionObservationRow>
}

private class IssuedObservationRegistration : CompleteObservationRegistration

private class IssuedCompleteSelectionSnapshot(
    override val selected: SubscriptionObservationRow,
    override val activeRows: List<SubscriptionObservationRow>,
    val generation: Long,
    val apiLevel: Int
) : CompleteSelectionSnapshot {
    override fun toString() = "CompleteSelectionSnapshot(local observation)"
}

/**
 * Unused API33+ observation foundation. No platform adapter or runtime consumer is registered.
 * Both physical and embedded selections hold the complete set for one observer lifetime.
 * Public port mapping on older APIs is unimplemented; those observations refuse conservatively.
 *
 * Source reads must themselves be coherent. The model brackets two equal complete reads with one
 * registered generation. Callbacks retire at entry, not after a scheduled reread. This is a local
 * continuity signal, not OS-to-radio atomicity, provisioning control or carrier attestation.
 */
internal class CompleteSubscriptionObserver(
    private val source: CompleteSubscriptionSource,
    private val rowBudget: Int = 256
) {
    private val lock = Any()
    private var registration: IssuedObservationRegistration? = null
    private var registrationSucceeded = false
    private var initialCallbackObserved = false
    private var generation = 0L
    private var exhausted = false
    private var selectedSubscriptionId: Int? = null
    private var baseline: List<SubscriptionObservationRow>? = null
    private var issued: IssuedCompleteSelectionSnapshot? = null
    private var baselineApiLevel: Int? = null
    private var monitorLifetime: UUID? = null
    private var privacyProjection: CompleteSetPrivacyProjectionV2? = null

    private class IssuedPrivacyFence(
        val registration: IssuedObservationRegistration,
        val snapshot: IssuedCompleteSelectionSnapshot,
        override val apiLevel: Int,
        override val observerEpoch: Long,
        override val monitorLifetime: UUID?
    ) : CompletePrivacyProjectionFence {
        override val selected get() = snapshot.selected
        override val activeRows get() = snapshot.activeRows
    }

    init { require(rowBudget > 0) }

    fun beginRegistration(): CompleteObservationRegistration = synchronized(lock) {
        retireLocked()
        registrationSucceeded = false
        initialCallbackObserved = false
        selectedSubscriptionId = null
        monitorLifetime = null
        IssuedObservationRegistration().also { registration = it }
    }

    fun registrationSucceeded(token: CompleteObservationRegistration): Boolean = synchronized(lock) {
        if (!ownsRegistrationLocked(token) || exhausted) return@synchronized false
        registrationSucceeded = true
        true
    }

    fun registrationFailed(token: CompleteObservationRegistration): Boolean = synchronized(lock) {
        if (!ownsRegistrationLocked(token)) return@synchronized false
        withdrawLocked()
        true
    }

    /** The first callback is still a retirement event; registration may not have returned yet. */
    fun initialCallback(token: CompleteObservationRegistration): Boolean = subscriptionsChanged(token)

    fun subscriptionsChanged(token: CompleteObservationRegistration): Boolean = synchronized(lock) {
        if (!ownsRegistrationLocked(token)) return@synchronized false
        retireLocked()
        initialCallbackObserved = true
        !exhausted
    }

    /** Regrant requires a new successful registration and initial-callback barrier. */
    fun permissionLost() = synchronized(lock) { withdrawLocked() }

    fun stop() = synchronized(lock) { withdrawLocked() }

    /** Explicit selection only. No peer/default fallback and no installed authority is created. */
    fun observeSelected(subscriptionId: Int): CompleteSelectionSnapshot? {
        val fence = synchronized(lock) {
            if (!readyLocked()) return null
            if (subscriptionId < 0) {
                withdrawLocked()
                return null
            }
            if (selectedSubscriptionId != subscriptionId) {
                retireLocked()
                selectedSubscriptionId = subscriptionId
            }
            if (!readyLocked()) return null
            ReadFence(requireNotNull(registration), generation, subscriptionId)
        }

        // No state lock spans source reads. Permission/error withdrawal cannot be delayed by them.
        val first = readComplete() ?: return withdrawAfterFailedRead(fence)
        if (!fenceCurrent(fence)) return null
        val second = readComplete() ?: return withdrawAfterFailedRead(fence)
        if (first != second) return withdrawAfterFailedRead(fence)
        val selected = first.rows.singleOrNull { it.subscriptionId == subscriptionId }
            ?: return withdrawAfterFailedRead(fence)

        return synchronized(lock) {
            if (!fenceCurrentLocked(fence)) return@synchronized null
            if (baseline != null && (baseline != first.rows || baselineApiLevel != first.apiLevel)) {
                // Even equal-count peer replacement retires the previous observation. A later
                // explicit observation may establish a new candidate, never renewed authority.
                retireLocked()
                return@synchronized null
            }
            baseline = first.rows
            baselineApiLevel = first.apiLevel
            issued?.let { return@synchronized it }
            IssuedCompleteSelectionSnapshot(selected, first.rows, generation, first.apiLevel).also { issued = it }
        }
    }

    /** Memory only. Equal records and snapshots from another lifetime cannot mint currentness. */
    fun isCurrent(snapshot: CompleteSelectionSnapshot): Boolean = synchronized(lock) {
        readyLocked() && snapshot === issued && issued?.generation == generation
    }

    /** Exact issuer identity only. No external snapshot or equal row copy acquires this fence. */
    internal fun capturePrivacyProjection(snapshot: CompleteSelectionSnapshot): CompletePrivacyProjectionFence? =
        synchronized(lock) {
            val actual = issued ?: return@synchronized null
            if (!readyLocked() || snapshot !== actual || actual.generation != generation) return@synchronized null
            IssuedPrivacyFence(requireNotNull(registration), actual, actual.apiLevel,
                generation, monitorLifetime)
        }

    internal fun cachedPrivacyProjection(snapshot: CompleteSelectionSnapshot): CompleteSetPrivacyProjectionV2? =
        synchronized(lock) {
            privacyProjection.takeIf { readyLocked() && snapshot === issued && issued?.generation == generation }
        }

    /** Only pure identity checks and publication occur under this lock; construction is outside. */
    internal fun publishPrivacyProjection(fence: CompletePrivacyProjectionFence,
        candidate: CompleteSetPrivacyProjectionV2): CompleteSetPrivacyProjectionV2? = synchronized(lock) {
        val actual = fence as? IssuedPrivacyFence ?: return@synchronized null
        if (!readyLocked() || actual.registration !== registration || actual.snapshot !== issued ||
            actual.observerEpoch != generation || !candidate.usesFence(this, actual)) return@synchronized null
        privacyProjection?.let { return@synchronized it }
        if (monitorLifetime != null && monitorLifetime != candidate.monitorLifetime) return@synchronized null
        monitorLifetime = candidate.monitorLifetime
        privacyProjection = candidate
        candidate
    }

    internal fun isPrivacyProjectionCurrent(candidate: CompleteSetPrivacyProjectionV2): Boolean =
        synchronized(lock) {
            readyLocked() && privacyProjection === candidate && issued?.generation == generation
        }

    private data class ReadFence(
        val registration: IssuedObservationRegistration,
        val generation: Long,
        val subscriptionId: Int
    )

    private data class CoherentRead(val apiLevel: Int, val rows: List<SubscriptionObservationRow>)

    private fun readComplete(): CoherentRead? {
        return try {
            val result = source.read() ?: return null
            if (result.apiLevel < 33 || !result.ordinaryPermissionGranted || !result.readable ||
                !result.complete || result.rows.isEmpty() || result.rows.size > rowBudget) return null
            val rows = result.rows.toList()
            if (rows.size > rowBudget) return null
            if (rows.any { it.subscriptionId < 0 || it.cardId == null || it.cardId < 0 ||
                    it.portIndex == null || it.portIndex < 0 || it.slotIndex == null || it.slotIndex < 0 }) {
                return null
            }
            if (rows.map { it.subscriptionId }.toSet().size != rows.size) return null
            if (rows.map { it.cardId to it.portIndex }.toSet().size != rows.size) return null
            // Slot need not be unique: two eSIM ports may share the reported logical slot.
            val normalized = Collections.unmodifiableList(ArrayList(rows.sortedBy { it.subscriptionId }))
            CoherentRead(result.apiLevel, normalized)
        } catch (error: Exception) {
            if (error is InterruptedException) Thread.currentThread().interrupt()
            null
        }
    }

    private fun withdrawAfterFailedRead(fence: ReadFence): CompleteSelectionSnapshot? {
        synchronized(lock) {
            // An old read must not withdraw a newer registration or callback generation.
            if (fenceCurrentLocked(fence)) withdrawLocked()
        }
        return null
    }

    private fun fenceCurrent(fence: ReadFence): Boolean = synchronized(lock) {
        fenceCurrentLocked(fence)
    }

    private fun fenceCurrentLocked(fence: ReadFence): Boolean = readyLocked() &&
        registration === fence.registration && generation == fence.generation &&
        selectedSubscriptionId == fence.subscriptionId

    private fun ownsRegistrationLocked(token: CompleteObservationRegistration) =
        registration != null && registration === token

    private fun readyLocked() = !exhausted && registration != null &&
        registrationSucceeded && initialCallbackObserved

    private fun retireLocked() {
        privacyProjection = null
        baselineApiLevel = null
        issued = null
        baseline = null
        if (generation == Long.MAX_VALUE) exhausted = true else generation++
    }

    private fun withdrawLocked() {
        retireLocked()
        registration = null
        monitorLifetime = null
        registrationSucceeded = false
        initialCallbackObserved = false
        selectedSubscriptionId = null
    }
}

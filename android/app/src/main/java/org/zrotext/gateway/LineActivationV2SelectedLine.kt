// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import android.content.Context
import android.content.SharedPreferences
import android.os.Build
import android.os.Handler
import android.os.Looper
import android.telephony.SubscriptionManager
import java.util.concurrent.Executor

/** Only the registered complete-list issuer can create this RAM-only selected lease. */
internal class SelectedLineLeaseV2 private constructor(
    private val owner: LineActivationV2SelectedLineOwner,
    internal val snapshot: CompleteSelectionSnapshot,
    internal val projection: CompleteSetPrivacyProjectionV2
) {
    internal val selected get() = snapshot.selected
    fun observation() = projection.observation()
    fun isCurrent() = owner.isCurrent(this)
    fun recheck() = owner.capture() === this && isCurrent()
    internal fun matches(active: List<ActiveSimCard>?): Boolean = active != null && isCurrent() &&
        projection.matchesCompleteRows(active.map { SubscriptionObservationRow(it.subscriptionId,
            if (it.isEmbedded) ObservedSubscriptionKind.EMBEDDED else ObservedSubscriptionKind.PHYSICAL,
            it.cardId, it.portIndex, it.logicalSlotIndex) }) && isCurrent()
    override fun toString() = "SelectedLineLeaseV2(redacted)"
    internal companion object {
        fun issue(owner: LineActivationV2SelectedLineOwner, snapshot: CompleteSelectionSnapshot,
            projection: CompleteSetPrivacyProjectionV2) = SelectedLineLeaseV2(owner, snapshot, projection)
    }
}

/** A final accepted receipt plus the same live issuer object; saved bytes cannot construct it. */
internal class InstalledSelectedLineV2 private constructor(
    internal val lease: SelectedLineLeaseV2, internal val record: LineActivationV2Record,
    private val owner: LineActivationV2SelectedLineOwner, private val permit: LineActivationV2PublicationPermit
) {
    @Volatile private var retired = false
    internal val selected get() = lease.selected
    internal val refresh03 get() = permit.refresh03
    fun isCurrent(): Boolean = !retired && lease.isCurrent() && owner.isInstalled(this) &&
        permit.installationCurrent() && !retired && lease.isCurrent()
    internal fun matches(binding: LocalLineBinding): Boolean = record.matchesBinding(binding) && isCurrent()
    internal fun retire() { retired = true }
    internal fun activated() = ActivatedSimCard(selected.subscriptionId, checkNotNull(selected.cardId),
        completeSelection = this)
    override fun toString() = "InstalledSelectedLineV2(redacted)"
    internal companion object {
        fun issue(owner: LineActivationV2SelectedLineOwner, permit: LineActivationV2PublicationPermit) =
            InstalledSelectedLineV2(permit.lease, permit.record, owner, permit)
    }
}

/** Service-owned registration; callbacks retire authority before reads or framework cleanup wait. */
internal class LineActivationV2SelectedLineOwner(
    private val api: () -> Int, private val selected: () -> Int,
    source: ProfileObservationSource, main: ((() -> Unit) -> Boolean), reads: Executor
) : AutoCloseable {
    private val lock = Any()
    private var closed = false
    private var lease: SelectedLineLeaseV2? = null
    private var installed: InstalledSelectedLineV2? = null
    private var selection = SubscriptionManager.INVALID_SUBSCRIPTION_ID
    private var cleanup: (() -> Unit)? = null
    private val observations = CompleteSubscriptionObservationAdapter(api, object : ProfileObservationSource {
        override fun permissionGranted() = source.permissionGranted()
        override fun readComplete() = source.readComplete()
        override fun register(callback: () -> Unit) = source.register {
            retireAtEntry()
            callback()
        }
    }, main, reads)

    fun selectCurrent() {
        retireAtEntry()
        observations.stop()
        val id = runCatching(selected).getOrDefault(SubscriptionManager.INVALID_SUBSCRIPTION_ID)
        synchronized(lock) { if (closed) return; selection = id }
        observations.select(id.takeIf { it >= 0 })
    }
    fun capture(): SelectedLineLeaseV2? {
        val id = synchronized(lock) { if (closed) return null; selection }
        if (id < 0 || api() < 33 || selected() != id) { retireAtEntry(); return null }
        val snapshot = observations.observe() ?: run { retireAtEntry(); return null }
        val projection = observations.privacyProjection(snapshot) ?: return null
        if (selected() != id) { retireAtEntry(); return null }
        return synchronized(lock) {
            if (closed || selection != id || !observations.isCurrent(snapshot) || !projection.isCurrent()) null
            else lease?.takeIf { it.snapshot === snapshot && it.projection === projection }
                ?: SelectedLineLeaseV2.issue(this, snapshot, projection).also { lease = it }
        }
    }
    internal fun isCurrent(value: SelectedLineLeaseV2): Boolean = synchronized(lock) {
        !closed && lease === value && observations.isCurrent(value.snapshot) && value.projection.isCurrent()
    }
    internal fun publish(permit: LineActivationV2PublicationPermit): InstalledSelectedLineV2? {
        val value = permit.lease
        val record = permit.record
        if (!record.isInstalled() || !permit.publicationCurrent()) return null
        return synchronized(lock) {
            if (!isCurrent(value) || !permit.publicationCurrent()) null else {
                (installed?.takeIf { it.record == record && it.lease === value && it.isCurrent() }
                    ?: InstalledSelectedLineV2.issue(this, permit).also {
                        installed?.retire(); installed = it
                    }).also { permit.publicationComplete() }
            }
        }
    }
    internal fun lookup(binding: LocalLineBinding): InstalledSelectedLineV2? = synchronized(lock) {
        installed?.takeIf { it.matches(binding) }
    }
    internal fun isInstalled(value: InstalledSelectedLineV2) = synchronized(lock) { !closed && installed === value }
    fun retireAtEntry() = synchronized(lock) { installed?.retire(); installed = null; lease = null }
    fun retireInstalled() = synchronized(lock) { installed?.retire(); installed = null }
    fun stop() { retireAtEntry(); observations.stop() }
    fun permissionLost() { retireAtEntry(); observations.permissionLost() }
    override fun close() {
        synchronized(lock) { closed = true; retireAtEntry() }
        try { observations.close() } finally { cleanup?.invoke(); cleanup = null }
    }
    companion object {
        fun forAndroid(context: Context, reads: Executor): LineActivationV2SelectedLineOwner? {
            if (Build.VERSION.SDK_INT < 33) return null
            val app = checkNotNull(context.applicationContext)
            val preferences = app.getSharedPreferences("gateway_selection", Context.MODE_PRIVATE)
            val main = Handler(Looper.getMainLooper())
            val owner = LineActivationV2SelectedLineOwner({ Build.VERSION.SDK_INT }, {
                preferences.getInt("subscription_id", SubscriptionManager.INVALID_SUBSCRIPTION_ID)
            }, AndroidProfileObservationSource(app), { action ->
                if (Looper.myLooper() == Looper.getMainLooper()) { action(); true } else main.post { action() }
            }, reads)
            val listener = SharedPreferences.OnSharedPreferenceChangeListener { _, key ->
                if (key == "subscription_id") owner.selectCurrent()
            }
            preferences.registerOnSharedPreferenceChangeListener(listener)
            owner.cleanup = { preferences.unregisterOnSharedPreferenceChangeListener(listener) }
            owner.selectCurrent()
            return owner
        }
    }
}

/** Holds the service's real issuer only. No preferences or persisted observation can attach one. */
internal object LineActivationV2SelectedLineMount {
    @Volatile private var owner: LineActivationV2SelectedLineOwner? = null
    @Volatile private var consumer: LineActivationV2Runtime? = null
    fun attach(value: LineActivationV2SelectedLineOwner) { owner = value }
    fun detach(value: LineActivationV2SelectedLineOwner) { synchronized(this) { if (owner === value) owner = null } }
    fun capture() = owner?.capture()
    fun attachConsumer(value: LineActivationV2Runtime) { consumer = value }
    fun detachConsumer(value: LineActivationV2Runtime) { synchronized(this) { if (consumer === value) consumer = null } }
    fun captureForAcceptance(): SelectedLineLeaseV2? {
        val active = consumer?.takeIf { it.isCurrent() } ?: return null
        val lease = capture() ?: return null
        return lease.takeIf { consumer === active && active.isCurrent() && it.isCurrent() }
    }
    fun lookup(binding: LocalLineBinding) = owner?.lookup(binding)
    fun retireAtEntry() { owner?.retireAtEntry() }
    fun retireInstalled() { owner?.retireInstalled() }
    internal fun publishRefresh(permit: LineActivationV2PublicationPermit): InstalledSelectedLineV2? {
        require(permit.refresh03 != null)
        return owner?.publish(permit)
    }
    fun permissionLost() { owner?.permissionLost() }
    fun selectCurrent() { owner?.selectCurrent() }
}

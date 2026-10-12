// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import android.Manifest
import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import android.os.Handler
import android.os.Looper
import android.telephony.SubscriptionManager
import org.json.JSONObject
import java.util.UUID
import java.util.concurrent.Executor

/** Logical Android records, never ICCID, EID, a phone number or carrier ownership evidence. */
internal data class ProfileSubscriptionObservation(
    val subscriptionId: Int, val cardId: Int?, val embedded: Boolean,
    val portIndex: Int?, val logicalSlotIndex: Int?
)

internal data class EsimProfileRecord(
    val subscriptionId: Int, val cardId: Int, val portIndex: Int, val logicalSlotIndex: Int,
    val incarnation: String, val observationEpoch: Long, val leaseId: String
) {
    init {
        require(subscriptionId >= 0 && cardId >= 0 && portIndex >= 0 && logicalSlotIndex >= 0 &&
            observationEpoch > 0 && profileUuid(incarnation) && profileUuid(leaseId))
    }
    override fun toString() = "EsimProfileRecord(redacted)"
}

internal data class ProfileLineAuthority(
    val accountId: String, val deviceId: String, val lineId: String, val bindingGeneration: Long
) {
    init {
        require(listOf(accountId, deviceId, lineId).all(::profileUuid) && bindingGeneration > 0)
    }
    internal fun lineKey() = listOf(accountId, deviceId, lineId).joinToString("|")
    override fun toString() = "ProfileLineAuthority(redacted)"
}

private fun profileUuid(value: String): Boolean = runCatching {
    UUID.fromString(value).let { it != UUID(0, 0) && it.toString() == value }
}.getOrDefault(false)

internal class EsimProfileCandidate private constructor(
    val record: EsimProfileRecord, private val issuer: EsimProfileContinuityTracker
) {
    fun isCurrent(): Boolean = issuer.isCurrent(this)
    internal fun issuedBy(expected: EsimProfileContinuityTracker) = issuer === expected
    override fun toString() = "EsimProfileCandidate(redacted)"
    internal companion object {
        internal fun issue(record: EsimProfileRecord, issuer: EsimProfileContinuityTracker) =
            EsimProfileCandidate(record, issuer)
    }
}

/** Created only after the host validates the exact authenticated ACK and its durable fence. */
internal class ProfileInstallationPermit private constructor(
    val candidate: EsimProfileCandidate, val authority: ProfileLineAuthority, val challengeId: String,
    private val issuer: ProfileChallengeFence
) {
    @Volatile private var retired = false
    internal fun durablyIssued() = !retired && issuer.isIssued(this)
    internal fun stillAccepted() = !retired
    internal fun retire() { retired = true }
    override fun toString() = "ProfileInstallationPermit(redacted)"
    internal companion object {
        internal fun afterDurableAck(candidate: EsimProfileCandidate, authority: ProfileLineAuthority,
                                     challengeId: String, issuer: ProfileChallengeFence) =
            ProfileInstallationPermit(candidate, authority, challengeId, issuer)
    }
}

internal class InstalledEsimProfile private constructor(
    val candidate: EsimProfileCandidate, val authority: ProfileLineAuthority,
    internal val permit: ProfileInstallationPermit, private val issuer: EsimProfileContinuityTracker
) {
    val record get() = candidate.record
    /** Memory only: never reads framework, disk or Keystore after a final clock sample. */
    fun isCurrent(): Boolean = issuer.isCurrent(this)
    override fun toString() = "InstalledEsimProfile(redacted)"
    internal companion object {
        internal fun issue(permit: ProfileInstallationPermit, issuer: EsimProfileContinuityTracker) =
            InstalledEsimProfile(permit.candidate, permit.authority, permit, issuer)
    }
}

/**
 * One registered observer lifetime. No state lock is held across framework, disk or signing calls.
 * A fresh baseline is a new candidate, not renewed owner approval. Persisted records are references
 * only; they never populate installed authority. The platform does not attest database incarnation
 * or atomically couple a snapshot to the radio, so this remains a conservative local signal.
 */
internal class EsimProfileContinuityTracker(
    private val incarnation: String = UUID.randomUUID().toString(),
    private val leaseIds: () -> String = { UUID.randomUUID().toString() }
) {
    private val lock = Any()
    private var registered = false
    private var initialCallback = false
    private var closed = false
    private var epoch = 0L
    private var baseline: List<ProfileSubscriptionObservation>? = null
    private val candidates = mutableMapOf<Int, EsimProfileCandidate>()
    private var installed: InstalledEsimProfile? = null
    private val highestPublished = mutableMapOf<String, Long>()

    init { require(profileUuid(incarnation)) }

    fun registrationSucceeded() = synchronized(lock) {
        if (!closed) registered = true
    }
    fun registrationFailed() = close()

    /** Called directly at callback entry, before queuing any Android reads. */
    fun onSubscriptionsChanged() = synchronized(lock) {
        if (!closed) {
            retireEpoch()
            initialCallback = true
        }
    }
    fun invalidate() = synchronized(lock) { if (!closed) retireEpoch() }
    fun close() = synchronized(lock) {
        if (!closed) {
            retireEpoch()
            closed = true
            registered = false
        }
    }
    private fun retireEpoch() {
        baseline = null
        candidates.clear()
        installed = null
        if (epoch == Long.MAX_VALUE) closed = true else epoch += 1
    }
    fun observationEpoch(): Long? = synchronized(lock) {
        epoch.takeIf { !closed && registered && initialCallback && it > 0 }
    }

    /** Both complete reads and their brackets must belong to the same ready registration epoch. */
    fun acceptSnapshots(before: Long, first: List<ProfileSubscriptionObservation>?,
                        second: List<ProfileSubscriptionObservation>?, after: Long): Boolean = synchronized(lock) {
        if (closed || !registered || !initialCallback || before != epoch || after != epoch) return false
        val one = canonical(first)
        val two = canonical(second)
        if (one == null || two == null || one != two) {
            retireEpoch()
            return false
        }
        val old = baseline
        if (old != null && old != one) {
            // A changed read without an observed callback also retires the old lifetime epoch.
            retireEpoch()
            return false
        }
        if (old == null) {
            try {
                val issued = one.filter { eligible(it, one) }.associate { observation ->
                    val record = EsimProfileRecord(observation.subscriptionId, checkNotNull(observation.cardId),
                        checkNotNull(observation.portIndex), checkNotNull(observation.logicalSlotIndex),
                        incarnation, epoch, leaseIds())
                    observation.subscriptionId to EsimProfileCandidate.issue(record, this)
                }
                if (issued.values.map { it.record.leaseId }.distinct().size != issued.size) {
                    retireEpoch()
                    return false
                }
                candidates.putAll(issued)
                baseline = one
            } catch (_: RuntimeException) {
                retireEpoch()
                return false
            }
        }
        true
    }
    private fun canonical(values: List<ProfileSubscriptionObservation>?): List<ProfileSubscriptionObservation>? {
        if (values == null || values.any { it.subscriptionId < 0 } ||
            values.map { it.subscriptionId }.distinct().size != values.size) return null
        return values.sortedBy { it.subscriptionId }.toList()
    }
    private fun eligible(value: ProfileSubscriptionObservation, all: List<ProfileSubscriptionObservation>): Boolean {
        val card = value.cardId ?: return false
        val port = value.portIndex ?: return false
        val slot = value.logicalSlotIndex ?: return false
        // Android documents logical slot indices as not necessarily unique. Port is scoped to card.
        return value.embedded && card >= 0 && port >= 0 && slot >= 0 &&
            all.none { it !== value && it.cardId == card &&
                (it.portIndex == null || it.portIndex < 0 || it.portIndex == port || !it.embedded) }
    }
    fun candidate(subscriptionId: Int): EsimProfileCandidate? = synchronized(lock) {
        candidates[subscriptionId]?.takeIf { currentCandidate(it) }
    }
    fun isCurrent(candidate: EsimProfileCandidate): Boolean = synchronized(lock) { currentCandidate(candidate) }
    private fun currentCandidate(candidate: EsimProfileCandidate): Boolean =
        !closed && registered && initialCallback && baseline != null && candidate.issuedBy(this) &&
            candidate.record.observationEpoch == epoch &&
            candidates[candidate.record.subscriptionId] === candidate

    /** Only a host-validated, durably fenced final ACK may reach this publication seam. */
    fun publishInstalled(permit: ProfileInstallationPermit, finalReady: () -> Boolean = { true }): InstalledEsimProfile? {
        // Ledger validation can wait. Final proof/selection/time checks run AFTER that wait,
        // outside the tracker lock, and BEFORE any installed authority is inserted.
        if (!permit.durablyIssued() || !runCatching(finalReady).getOrDefault(false)) return null
        return synchronized(lock) {
        if (!currentCandidate(permit.candidate)) return null
        val key = permit.authority.lineKey()
        val old = installed
        if (old != null && old.permit === permit && old.isCurrent()) return old
        if (!permit.stillAccepted() ||
            permit.authority.bindingGeneration <= (highestPublished[key] ?: 0L)) return null
        val result = InstalledEsimProfile.issue(permit, this)
        highestPublished[key] = permit.authority.bindingGeneration
        installed = result
        result
        }
    }
    fun lookupInstalled(record: EsimProfileRecord, authority: ProfileLineAuthority): InstalledEsimProfile? =
        synchronized(lock) {
            installed?.takeIf {
                it.authority == authority && it.record == record && currentInstalled(it)
            }
        }
    fun isCurrent(value: InstalledEsimProfile): Boolean = synchronized(lock) { currentInstalled(value) }
    private fun currentInstalled(value: InstalledEsimProfile): Boolean =
        installed === value && value.permit.stillAccepted() && currentCandidate(value.candidate)
    /** A provisional DAO replacement fences even an old permit not yet inserted. */
    fun retireAuthority(authority: ProfileLineAuthority) = synchronized(lock) {
        val key = authority.lineKey()
        highestPublished[key] = maxOf(highestPublished[key] ?: 0L, authority.bindingGeneration)
        installed?.takeIf { it.authority.lineKey() == key &&
            it.authority.bindingGeneration <= authority.bindingGeneration }?.let {
            it.permit.retire(); installed = null
        }
    }
    /** Obsolete closures cannot revoke a newer accepted installation. */
    fun revoke(value: InstalledEsimProfile) = synchronized(lock) {
        if (installed === value) installed = null
    }
}

internal data class ProfileChallengeKey(val authority: ProfileLineAuthority, val challengeId: String) {
    init { require(profileUuid(challengeId)) }
    override fun toString() = "ProfileChallengeKey(redacted)"
}
internal data class ProfileChallengeLedger(
    val reservations: Set<ProfileChallengeKey> = emptySet(),
    val installedGenerations: Map<String, Long> = emptyMap()
)
internal interface ProfileChallengePersistence {
    val serializationLock: Any get() = this
    /** Null means unreadable/malformed, never an empty replacement ledger. */
    fun read(): ProfileChallengeLedger?
    fun write(ledger: ProfileChallengeLedger): Boolean
}

/**
 * Serialized IO lock is separate from the tracker lock. Disk entries are deny-only; only retained
 * RAM candidate identity permits handshake reuse. No clock eviction. A final authenticated ACK
 * makes old generations obsolete and may prune them; a full ledger fails closed.
 */
internal class ProfileChallengeFence(private val persistence: ProfileChallengePersistence) {
    private val ioLock = persistence.serializationLock
    private val live = mutableMapOf<ProfileChallengeKey, EsimProfileCandidate>()
    private val permits = mutableMapOf<ProfileChallengeKey, ProfileInstallationPermit>()

    fun reserveBeforeSigning(key: ProfileChallengeKey, candidate: EsimProfileCandidate): Boolean =
        synchronized(ioLock) {
            pruneRetired()
            if (!candidate.isCurrent()) return false
            try {
                val ledger = valid(persistence.read()) ?: return false
                if (key.authority.bindingGeneration <=
                    (ledger.installedGenerations[key.authority.lineKey()] ?: 0L)) return false
                if (key in ledger.reservations) return live[key] === candidate && candidate.isCurrent()
                if (ledger.reservations.size >= MAX_ENTRIES) return false
                if (!persistence.write(ledger.copy(reservations = ledger.reservations + key)) ||
                    !candidate.isCurrent()) return false
                live[key] = candidate
                true
            } catch (_: Exception) { false }
        }

    /** Caller must validate the exact server ACK, current authority, proof, selection and clock. */
    fun persistAcceptedAck(key: ProfileChallengeKey, candidate: EsimProfileCandidate): ProfileInstallationPermit? =
        synchronized(ioLock) {
            pruneRetired()
            if (!candidate.isCurrent()) return null
            if (live[key] !== candidate) return null
            try {
                val ledger = valid(persistence.read()) ?: return null
                val cached = permits[key]
                if (cached != null && cached.candidate === candidate &&
                    ledger.installedGenerations[key.authority.lineKey()] == key.authority.bindingGeneration)
                    return cached
                if (key !in ledger.reservations ||
                    key.authority.bindingGeneration <=
                    (ledger.installedGenerations[key.authority.lineKey()] ?: 0L)) return null
                val generations = ledger.installedGenerations + (key.authority.lineKey() to key.authority.bindingGeneration)
                if (generations.size > MAX_ENTRIES) return null
                val remaining = ledger.reservations.filterNot {
                    it.authority.lineKey() == key.authority.lineKey() &&
                        it.authority.bindingGeneration <= key.authority.bindingGeneration
                }.toSet()
                // The new authenticated ACK supersedes older authority across every store facade,
                // even if IO fails. Final radio checks consult only the permanently retired flag.
                synchronized(sharedStateLock) {
                    acceptedByStore[ioLock]?.get(key.authority.lineKey())?.let { prior ->
                        if (prior.authority.bindingGeneration <= key.authority.bindingGeneration) {
                            prior.retire()
                            acceptedByStore[ioLock]?.remove(key.authority.lineKey())
                        }
                    }
                }
                val obsolete = permits.keys.filter {
                    it.authority.lineKey() == key.authority.lineKey() &&
                        it.authority.bindingGeneration <= key.authority.bindingGeneration && it != key
                }
                obsolete.forEach { permits.remove(it)?.retire(); live.remove(it) }
                live.keys.filter {
                    it.authority.lineKey() == key.authority.lineKey() &&
                        it.authority.bindingGeneration <= key.authority.bindingGeneration && it != key
                }.toList().forEach { live.remove(it) }
                if (!persistence.write(ProfileChallengeLedger(remaining, generations)) ||
                    !candidate.isCurrent()) return null
                ProfileInstallationPermit.afterDurableAck(candidate, key.authority, key.challengeId, this).also {
                    permits[key] = it
                    synchronized(sharedStateLock) {
                        acceptedByStore.getOrPut(ioLock) { mutableMapOf() }[key.authority.lineKey()] = it
                    }
                }
            } catch (_: Exception) { null }
        }
    internal fun isIssued(permit: ProfileInstallationPermit): Boolean = synchronized(ioLock) {
        try {
            val ledger = valid(persistence.read()) ?: return false
            permit.stillAccepted() &&
                ledger.installedGenerations[permit.authority.lineKey()] == permit.authority.bindingGeneration &&
                permits[ProfileChallengeKey(permit.authority, permit.challengeId)] === permit &&
                permit.candidate.isCurrent()
        } catch (_: Exception) { false }
    }
    private fun pruneRetired() {
        permits.keys.filter { permits[it]?.stillAccepted() != true }.toList().forEach {
            permits.remove(it); live.remove(it)
        }
    }
    private fun valid(value: ProfileChallengeLedger?): ProfileChallengeLedger? = value?.takeIf {
        it.reservations.size <= MAX_ENTRIES && it.installedGenerations.size <= MAX_ENTRIES &&
            it.installedGenerations.all { (key, generation) ->
                val parts = key.split('|')
                parts.size == 3 && parts.all(::profileUuid) && generation > 0
            }
    }
    companion object {
        internal const val MAX_ENTRIES = 64
        private val sharedStateLock = Any()
        private val acceptedByStore = java.util.WeakHashMap<Any, MutableMap<String, ProfileInstallationPermit>>()
    }
}

internal interface ProfileObservationSource {
    fun permissionGranted(): Boolean
    /** Must be invoked on the app main thread; callback may occur before return or a later throw. */
    fun register(changed: () -> Unit): AutoCloseable
    fun readComplete(): List<ProfileSubscriptionObservation>?
}

/** Adapter is unused until explicit production integration. Tests substitute source and schedulers. */
internal class SimProfileMonitor(
    private val source: ProfileObservationSource,
    private val onMain: ((() -> Unit) -> Unit),
    private val reads: Executor,
    private val trackers: () -> EsimProfileContinuityTracker = { EsimProfileContinuityTracker() }
) {
    private class Registration(val tracker: EsimProfileContinuityTracker) {
        var handle: AutoCloseable? = null
    }
    private val lock = Any()
    private var registration: Registration? = null
    private var requestedStart: Any? = null

    fun start() {
        val request = synchronized(lock) {
            if (registration != null) return
            Any().also { requestedStart = it }
        }
        onMain {
            if (synchronized(lock) { requestedStart !== request }) return@onMain
            if (!runCatching { source.permissionGranted() }.getOrDefault(false)) { stop(); return@onMain }
            val slot = synchronized(lock) {
                if (registration != null || requestedStart !== request) return@onMain
                Registration(trackers()).also { registration = it }
            }
            try {
                val handle = source.register {
                    // Ignore delayed callbacks from a disposed registration. Never adopt their state.
                    val owned = synchronized(lock) { registration === slot }
                    if (owned) {
                        slot.tracker.onSubscriptionsChanged()
                        scheduleRead(slot)
                    }
                }
                val retained = synchronized(lock) {
                    if (registration === slot) { slot.handle = handle; true } else false
                }
                if (!retained) { handle.close(); return@onMain }
                slot.tracker.registrationSucceeded()
                scheduleRead(slot) // The first callback may have arrived before registration returned.
            } catch (_: RuntimeException) {
                retire(slot)
            }
        }
    }
    fun stop() {
        val slot = synchronized(lock) {
            requestedStart = null
            registration.also { registration = null }
        } ?: return
        slot.tracker.close() // Retire before framework cleanup; cleanup failure cannot revive authority.
        runCatching { slot.handle?.close() }
    }
    private fun retire(slot: Registration) {
        val owned = synchronized(lock) {
            if (registration === slot) { registration = null; requestedStart = null; true } else false
        }
        slot.tracker.registrationFailed()
        if (owned) runCatching { slot.handle?.close() }
    }
    private fun scheduleRead(slot: Registration) {
        try { reads.execute { refresh(slot) } } catch (_: RuntimeException) { slot.tracker.invalidate() }
    }
    private fun refresh(slot: Registration): List<ProfileSubscriptionObservation>? {
        if (synchronized(lock) { registration !== slot }) return null
        if (!runCatching { source.permissionGranted() }.getOrDefault(false)) { retire(slot); return null }
        val before = slot.tracker.observationEpoch() ?: return null
        return try {
            val first = source.readComplete()
            val second = source.readComplete()
            val after = slot.tracker.observationEpoch() ?: return null
            if (synchronized(lock) { registration !== slot } ||
                !slot.tracker.acceptSnapshots(before, first, second, after)) null else second?.toList()
        } catch (_: RuntimeException) {
            slot.tracker.invalidate()
            null
        }
    }
    fun observe(): List<ProfileSubscriptionObservation>? {
        val slot = synchronized(lock) { registration } ?: run { start(); return null }
        return refresh(slot)
    }
    fun candidate(subscriptionId: Int): EsimProfileCandidate? =
        synchronized(lock) { registration }?.tracker?.candidate(subscriptionId)
    fun currentTracker(): EsimProfileContinuityTracker? = synchronized(lock) { registration }?.tracker
}

/** Uses ordinary public Android APIs only; no ICCID/EID, default-subscription selection or radio. */
@androidx.annotation.RequiresApi(33)
internal class AndroidProfileObservationSource(context: Context) : ProfileObservationSource {
    private val app = checkNotNull(context.applicationContext)
    override fun permissionGranted() = Build.VERSION.SDK_INT >= 33 &&
        app.checkSelfPermission(Manifest.permission.READ_PHONE_STATE) == PackageManager.PERMISSION_GRANTED
    override fun register(changed: () -> Unit): AutoCloseable {
        check(Looper.myLooper() == Looper.getMainLooper() && permissionGranted())
        val manager = checkNotNull(app.getSystemService(SubscriptionManager::class.java))
        val listener = object : SubscriptionManager.OnSubscriptionsChangedListener() {
            override fun onSubscriptionsChanged() = changed()
        }
        try { manager.addOnSubscriptionsChangedListener(Executor { it.run() }, listener) }
        catch (failure: RuntimeException) {
            runCatching { manager.removeOnSubscriptionsChangedListener(listener) }
            throw failure
        }
        return AutoCloseable { manager.removeOnSubscriptionsChangedListener(listener) }
    }
    override fun readComplete(): List<ProfileSubscriptionObservation>? {
        check(permissionGranted())
        val manager = checkNotNull(app.getSystemService(SubscriptionManager::class.java))
        return manager.completeActiveSubscriptionInfoList?.map {
            ProfileSubscriptionObservation(it.subscriptionId, it.cardId, it.isEmbedded, it.portIndex, it.simSlotIndex)
        }
    }
    companion object {
        fun mainScheduler(): ((() -> Unit) -> Unit) {
            val handler = Handler(Looper.getMainLooper())
            return { action -> if (Looper.myLooper() == Looper.getMainLooper()) action() else handler.post { action() } }
        }
    }
}

/** Public local provenance only. Failed/malformed reads never replace durable denial state. */
internal class PreferenceProfileChallengePersistence(context: Context) : ProfileChallengePersistence {
    private val contextData = checkNotNull(context.applicationContext).applicationInfo.dataDir
    private val preferences = context.getSharedPreferences("sim_profile_challenge_fence", Context.MODE_PRIVATE)
    override val serializationLock: Any get() = diskLock
    override fun read(): ProfileChallengeLedger? = try {
        val text = preferences.getString("ledger_v1", null)
        if (text == null) {
            val file = java.io.File(contextData, "shared_prefs/sim_profile_challenge_fence.xml")
            require(!file.exists() && !java.io.File(file.path + ".bak").exists())
            ProfileChallengeLedger()
        } else {
            require(text.toByteArray(Charsets.UTF_8).size <= 65536)
            val root = JSONObject(text)
            require(root.keys().asSequence().toSet() == setOf("version", "reservations", "installed"))
            require(root.get("version") == 1)
            val entries = root.getJSONArray("reservations")
            val reservations = (0 until entries.length()).map {
                val item = entries.getJSONObject(it)
                require(item.keys().asSequence().toSet() == setOf("account", "device", "line", "generation", "challenge"))
                val authority = ProfileLineAuthority(item.getString("account"), item.getString("device"),
                    item.getString("line"), exactPositiveLong(item.get("generation")))
                ProfileChallengeKey(authority, item.getString("challenge"))
            }
            require(reservations.distinct().size == reservations.size &&
                reservations.size <= ProfileChallengeFence.MAX_ENTRIES)
            val installed = root.getJSONObject("installed")
            val generations = installed.keys().asSequence().associateWith { key ->
                val parts = key.split('|')
                require(parts.size == 3 && parts.all(::profileUuid))
                exactPositiveLong(installed.get(key))
            }
            require(generations.size <= ProfileChallengeFence.MAX_ENTRIES)
            ProfileChallengeLedger(reservations.toSet(), generations)
        }
    } catch (_: Exception) { null }
    override fun write(ledger: ProfileChallengeLedger): Boolean = try {
        val entries = org.json.JSONArray()
        ledger.reservations.sortedBy { it.authority.lineKey() + "|" + it.challengeId }.forEach {
            entries.put(JSONObject().put("account", it.authority.accountId).put("device", it.authority.deviceId)
                .put("line", it.authority.lineId).put("generation", it.authority.bindingGeneration)
                .put("challenge", it.challengeId))
        }
        val generations = JSONObject()
        ledger.installedGenerations.toSortedMap().forEach { (key, value) -> generations.put(key, value) }
        val encoded = JSONObject().put("version", 1).put("reservations", entries).put("installed", generations).toString()
        require(encoded.toByteArray(Charsets.UTF_8).size <= 65536)
        preferences.edit().putString("ledger_v1", encoded).commit() &&
            preferences.getString("ledger_v1", null) == encoded
    } catch (_: Exception) { false }
    companion object { private val diskLock = Any() }
    private fun exactPositiveLong(value: Any): Long {
        require(value is Int || value is Long)
        return (value as Number).toLong().also { require(it > 0) }
    }
}

/** Process-local observer and issuer. Disk state is denial/provenance, never live authority. */
internal object SimProfileContinuity {
    private val lock = Any()
    @Volatile private var monitor: SimProfileMonitor? = null
    @Volatile private var fence: ProfileChallengeFence? = null
    fun initialize(context: Context) {
        if (Build.VERSION.SDK_INT < 33) return
        val existing = synchronized(lock) {
            monitor ?: SimProfileMonitor(AndroidProfileObservationSource(context),
                AndroidProfileObservationSource.mainScheduler(), JournalRuntime.io).also {
                fence = ProfileChallengeFence(PreferenceProfileChallengePersistence(context))
                monitor = it
            }
        }
        existing.start()
    }
    fun observe(context: Context): List<ProfileSubscriptionObservation>? {
        initialize(context)
        return monitor?.observe()
    }
    fun candidate(subscriptionId: Int): EsimProfileCandidate? = monitor?.candidate(subscriptionId)
    fun stop() { monitor?.stop() }
    fun challengeFence(): ProfileChallengeFence? = fence
    /** Internal source-test seam; there is no intent, preference or public activation entrypoint. */
    internal fun replaceForTesting(observer: SimProfileMonitor, issuer: ProfileChallengeFence): AutoCloseable {
        val prior = synchronized(lock) {
            (monitor to fence).also { monitor = observer; fence = issuer }
        }
        return AutoCloseable {
            observer.stop()
            synchronized(lock) { monitor = prior.first; fence = prior.second }
        }
    }
    fun publish(permit: ProfileInstallationPermit, finalReady: () -> Boolean): InstalledEsimProfile? =
        monitor?.currentTracker()?.publishInstalled(permit, finalReady)
    fun lookup(record: EsimProfileRecord, authority: ProfileLineAuthority): InstalledEsimProfile? =
        monitor?.currentTracker()?.lookupInstalled(record, authority)
    fun revoke(installed: InstalledEsimProfile) { monitor?.currentTracker()?.revoke(installed) }
    fun retireAuthority(authority: ProfileLineAuthority) { monitor?.currentTracker()?.retireAuthority(authority) }
}

internal fun ActivatedSimCard.profileChallengeKey(account: String, device: String, line: String,
                                                 generation: Long, challenge: String) =
    ProfileChallengeKey(ProfileLineAuthority(account, device, line, generation), challenge)

/**
 * Unused local preparation metadata, not a signature, installation or radio permission.
 * Neither this interface nor copies of its rows can manufacture a current preparation.
 */
internal sealed interface CompleteSelectionPreparation {
    val selected: SubscriptionObservationRow
    val activeRows: List<SubscriptionObservationRow>
}

/**
 * Disabled bridge over an already held, genuinely issued complete-list observation.
 * Construction, preparation and currentness checks perform no framework reads or registration.
 * The caller owns the adapter and must forward permission/selection/lifecycle withdrawal to it.
 * This does not supply a v2 statement, challenge, key, installed capability or carrier proof.
 */
internal class CompleteSelectionPreparationBridge(
    private val observations: CompleteSubscriptionObservationAdapter
) : AutoCloseable {
    private val lock = Any()
    private var generation = 0L
    private var exhausted = false
    private var closed = false
    private var issued: IssuedPreparation? = null

    private inner class IssuedPreparation(
        val observation: CompleteSelectionSnapshot,
        val preparationGeneration: Long
    ) : CompleteSelectionPreparation {
        override val selected: SubscriptionObservationRow get() = observation.selected
        override val activeRows: List<SubscriptionObservationRow> get() = observation.activeRows
        override fun toString() = "CompleteSelectionPreparation(local observation)"
    }

    /** Explicit selected ID plus exact live issuer object; no peer/default/physical fallback. */
    fun prepareHeld(
        selectedSubscriptionId: Int,
        observation: CompleteSelectionSnapshot
    ): CompleteSelectionPreparation? = synchronized(lock) {
        retireLocked()
        if (closed || exhausted || selectedSubscriptionId < 0 ||
            !observations.isCurrent(observation) ||
            observation.selected.subscriptionId != selectedSubscriptionId) return@synchronized null
        val preparation = IssuedPreparation(observation, generation)
        issued = preparation
        // The underlying observer may retire concurrently. Keep the final memory-only check.
        if (!observations.isCurrent(observation)) {
            issued = null
            return@synchronized null
        }
        preparation
    }

    /** Local observation currentness only. No installed/signing/send consumer accepts this type. */
    fun isCurrent(preparation: CompleteSelectionPreparation): Boolean = synchronized(lock) {
        val current = issued ?: return@synchronized false
        !closed && !exhausted && current === preparation &&
            current.preparationGeneration == generation &&
            observations.isCurrent(current.observation)
    }

    /** Retire this bridge's preparations, leaving the caller-owned observer untouched. */
    fun withdraw() = synchronized(lock) { retireLocked() }

    override fun close() = synchronized(lock) {
        closed = true
        retireLocked()
    }

    private fun retireLocked() {
        issued = null
        if (generation == Long.MAX_VALUE) exhausted = true else generation++
    }
}

/**
 * Caller-owned preparation for one explicitly selected physical or embedded line among peers.
 * Every selection owns a separate adapter: late reads/cleanup cannot affect its replacement.
 * No singleton, signature, installation, saved authority or send consumer accepts this type.
 */
internal class CompleteSelectionPreparationCoordinator(
    private val newObservations: (() -> Unit) -> CompleteSubscriptionObservationAdapter,
    private val reads: Executor
) : AutoCloseable {
    private class Owned(val observations: CompleteSubscriptionObservationAdapter) {
        val bridge = CompleteSelectionPreparationBridge(observations)
        var readTicket: Any? = null
        var preparation: CompleteSelectionPreparation? = null
    }
    private class Selection(val subscriptionId: Int) { var owned: Owned? = null }
    private val lock = Any()
    private var selected: Selection? = null
    private var closed = false

    fun select(subscriptionId: Int?) {
        val next: Selection?
        val old: Owned?
        synchronized(lock) {
            if (closed) return
            val id = subscriptionId?.takeIf { it >= 0 }
            // An explicit refresh/reselection starts a fresh registration, including after a
            // refused whole read. Callback refresh alone keeps this same held registration.
            old = detachLocked()
            next = id?.let(::Selection)
            selected = next
        }
        // The old preparation is already retired, including while platform cleanup blocks.
        old?.observations?.close()
        val intent = next ?: return
        if (!synchronized(lock) { selected === intent && !closed }) return
        val adapter = try { newObservations { refresh(intent) } }
        catch (failure: Exception) { preserveInterrupt(failure); retire(intent); return }
        val owned = Owned(adapter)
        val retained = synchronized(lock) {
            if (selected !== intent || closed || intent.owned != null) false
            else { intent.owned = owned; true }
        }
        if (!retained) { adapter.close(); return }
        // Registration and all platform reads/cleanup occur outside this coordinator's lock.
        adapter.select(intent.subscriptionId)
        refresh(intent) // Also covers an initial callback before register returned its handle.
    }

    /** Actual issuer/bridge currentness in memory; this never reads telephony or signs anything. */
    fun currentPreparation(): CompleteSelectionPreparation? = synchronized(lock) {
        val owned = selected?.owned ?: return@synchronized null
        owned.preparation?.takeIf { !closed && owned.bridge.isCurrent(it) }
    }

    fun isCurrent(preparation: CompleteSelectionPreparation): Boolean = synchronized(lock) {
        val owned = selected?.owned ?: return@synchronized false
        !closed && owned.preparation === preparation && owned.bridge.isCurrent(preparation)
    }

    fun refresh() { synchronized(lock) { selected }?.let(::refresh) }
    fun permissionLost() = withdraw(permanently = false)
    fun stop() = withdraw(permanently = false)
    override fun close() = withdraw(permanently = true)

    private fun refresh(intent: Selection) {
        val owned: Owned
        val ticket = Any()
        synchronized(lock) {
            if (selected !== intent || closed) return
            owned = intent.owned ?: return
            owned.bridge.withdraw()
            owned.preparation = null
            owned.readTicket = ticket
        }
        try {
            reads.execute {
                if (!owns(intent, owned, ticket)) return@execute
                val snapshot = owned.observations.observe()
                synchronized(lock) {
                    if (!ownsLocked(intent, owned, ticket)) return@synchronized
                    owned.preparation = snapshot?.let {
                        owned.bridge.prepareHeld(intent.subscriptionId, it)
                    }
                }
            }
        } catch (failure: Exception) {
            preserveInterrupt(failure)
            // An old rejected submission cannot retire a newer callback/read ticket.
            retire(intent, owned, ticket)
        }
    }

    private fun owns(intent: Selection, owned: Owned, ticket: Any) =
        synchronized(lock) { ownsLocked(intent, owned, ticket) }
    private fun ownsLocked(intent: Selection, owned: Owned, ticket: Any) =
        !closed && selected === intent && intent.owned === owned && owned.readTicket === ticket

    private fun retire(intent: Selection, expected: Owned? = null, ticket: Any? = null) {
        val old = synchronized(lock) {
            if (selected !== intent || (expected != null && intent.owned !== expected) ||
                (ticket != null && intent.owned?.readTicket !== ticket)) null else detachLocked()
        }
        old?.observations?.close()
    }
    private fun withdraw(permanently: Boolean) {
        val old = synchronized(lock) {
            if (permanently) closed = true
            detachLocked()
        }
        old?.observations?.close()
    }
    private fun detachLocked(): Owned? {
        val old = selected?.owned
        selected = null
        old?.let {
            it.readTicket = null
            it.preparation = null
            it.bridge.withdraw()
        }
        return old
    }
    private fun preserveInterrupt(failure: Exception) {
        if (failure is InterruptedException) Thread.currentThread().interrupt()
    }

    companion object {
        /** Inert factory; ordinary permission, registration and coherent reads remain mandatory. */
        fun forAndroid(context: Context, reads: Executor): CompleteSelectionPreparationCoordinator? {
            if (Build.VERSION.SDK_INT < 33) return null
            val app = checkNotNull(context.applicationContext)
            val main = Handler(Looper.getMainLooper())
            return CompleteSelectionPreparationCoordinator({ changed ->
                val ordinary = AndroidProfileObservationSource(app)
                val source = object : ProfileObservationSource {
                    override fun permissionGranted() = ordinary.permissionGranted()
                    override fun readComplete() = ordinary.readComplete()
                    override fun register(callback: () -> Unit) = ordinary.register {
                        callback() // Retirement in the actual adapter precedes refresh scheduling.
                        changed()
                    }
                }
                CompleteSubscriptionObservationAdapter({ Build.VERSION.SDK_INT }, source, { action ->
                    if (Looper.myLooper() == Looper.getMainLooper()) { action(); true }
                    else main.post { action() }
                }, reads)
            }, reads)
        }
    }
}

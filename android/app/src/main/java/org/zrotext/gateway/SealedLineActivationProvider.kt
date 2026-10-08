// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import android.content.Context
import android.os.Build
import android.telephony.SubscriptionManager
import java.util.UUID

/** Session-fenced, explicit line-only acceptance; never mounts a content worker or body consent. */
internal class SealedLineActivationProvider(private val selection: SealedLineAcceptance,
    private val account: UUID, private val deviceId: UUID, private val epoch: Long,
    private val device: SealedLineActivationDevice, private val persistence: SealedLineReceiptPersistence,
    private val install: (PreparedSealedLineActivation) -> Boolean,
    private val installedExactly: (PreparedSealedLineActivation) -> Boolean,
    private val sessionCurrent: () -> Boolean,
    private val acceptedProfile: EsimProfileCandidate? = null,
    private val reserveProfile: (SealedLineChallenge) -> Boolean = { acceptedProfile == null },
    private val publishProfile: (PreparedSealedLineActivation) -> InstalledEsimProfile? = { null },
    private val revokeProfile: (InstalledEsimProfile) -> Unit = SimProfileContinuity::revoke) : AutoCloseable {
    private var closed = false
    private var pending: PreparedSealedLineActivation? = null
    private var proofAccepted = false
    private var installed: SealedLineActivationSnapshot? = null
    private var receiptConfirmed = false
    private var profileInstallation: InstalledEsimProfile? = null
    init { require(epoch > 0 && selection.accountId == account && selection.deviceId == deviceId) }
    private fun current() = !closed && acceptedProfile?.isCurrent() != false &&
        sessionCurrent() && acceptedProfile?.isCurrent() != false
    @Synchronized fun sessionIsCurrent() = current()
    @Synchronized fun accept(input: SealedLineActivationFrames.Incoming): String? {
        if (!current()) return null
        return when (input) {
            is SealedLineActivationFrames.Incoming.Challenge -> challenge(input.value)
            is SealedLineActivationFrames.Incoming.ProofAck -> { proofAck(input.value); null }
            is SealedLineActivationFrames.Incoming.Activated -> activated(input.value)
            is SealedLineActivationFrames.Incoming.InstallAck -> { installAck(input.value); null }
        }
    }
    private fun challenge(c: SealedLineChallenge): String? {
        if (c.connectionEpoch != epoch || !selection.matches(c) ||
            !device.hasSingleActiveSelection(selection.subscriptionId)) return null
        val old = pending
        if (old != null && old.challenge.challengeId == c.challengeId && !same(old.challenge, c)) {
            pending = null; proofAccepted = false; return null
        }
        val retained = old?.takeIf { same(it.challenge, c) && device.validate(it, selection, false) }
        // A repeated retired challenge cannot be prepared against a new observer lease.
        if (retained == null && !reserveProfile(c)) return null
        val proof = retained ?: device.prepare(c, selection) ?: return null
        if (!current() || proof.sim.profile !== acceptedProfile ||
            !device.validate(proof, selection, false)) return null
        if (proof !== old) proofAccepted = false
        pending = proof
        return SealedLineActivationFrames.proof(proof)
    }
    private fun proofAck(a: SealedLineActivationFrames.Ack) {
        if (a.connectionEpoch != epoch || pending?.challenge?.challengeId != a.challengeId) return
        proofAccepted = a.accepted
        if (!a.accepted) pending = null
    }
    private fun activated(a: SealedLineActivationReceipt): String? {
        if (a.connectionEpoch != epoch || a.accountId != account || a.deviceId != deviceId) return null
        val live = pending?.takeIf { proofAccepted && a.matches(it) }
        // A cold start has no implicit acceptance. This path exists only after new explicit
        // selection + authenticated session, and requires exact durable signed provenance.
        val recovered = if (live == null) installed ?: persistence.read() else null
        val proof = live ?: recovered?.takeIf { a.matches(it.proof) && it.receipt.matches(it.proof) }?.proof ?: return null
        if (!a.matches(proof) || !device.validate(proof, selection, true) || !current()) return null
        val locallyInstalled = if (live != null) install(proof) else installedExactly(proof)
        if (!locallyInstalled || !current() || !device.validate(proof, selection, true)) return null
        val snapshot = SealedLineActivationSnapshot(proof, a)
        // DAO installation precedes commit. Crash/failure leaves no send or readiness claim.
        if (!persistence.write(snapshot) || !current() || !installedExactly(proof) ||
            !device.validate(proof, selection, true)) return null
        installed = snapshot
        receiptConfirmed = false
        return SealedLineActivationFrames.installed(a, epoch)
    }
    private fun installAck(a: SealedLineActivationFrames.Ack) {
        val snapshot = installed ?: return
        if (a.connectionEpoch != epoch || snapshot.receipt.challengeId != a.challengeId ||
            !current() || !installedExactly(snapshot.proof) || !device.validate(snapshot.proof, selection, true)) return
        receiptConfirmed = a.accepted
        if (!a.accepted) {
            profileInstallation?.let(revokeProfile); profileInstallation = null
            return
        }
        if (snapshot.proof.sim.profile != null) {
            // Provisional Room/receipt writes above cannot publish execution authority.
            val capability = publishProfile(snapshot.proof)
            var accepted = false
            try {
                accepted = capability != null && capability.isCurrent() && current() &&
                    installedExactly(snapshot.proof) && device.validate(snapshot.proof, selection, true) &&
                    current() && capability.isCurrent()
                if (!accepted) { receiptConfirmed = false; return }
                profileInstallation = capability
            } finally {
                if (!accepted) { capability?.let(revokeProfile); receiptConfirmed = false }
            }
        }
        pending = null; proofAccepted = false
    }
    /** Receipt status only: explicitly incapable of granting body/read/send authority. */
    @Synchronized fun installationReceiptConfirmed(): Boolean {
        val snapshot = installed ?: return false
        return current() && receiptConfirmed && installedExactly(snapshot.proof) &&
            device.validate(snapshot.proof, selection, true)
    }
    @Synchronized override fun close() {
        closed = true; pending = null; proofAccepted = false; installed = null; receiptConfirmed = false
        profileInstallation?.let(revokeProfile); profileInstallation = null
    }
    private fun same(a: SealedLineChallenge, b: SealedLineChallenge) = a.connectionEpoch == b.connectionEpoch &&
        a.challengeId == b.challengeId && a.accountId == b.accountId && a.deviceId == b.deviceId &&
        a.lineId == b.lineId && a.generation == b.generation && a.expiresAtMs == b.expiresAtMs && a.nonce.contentEquals(b.nonce)
}

/** Optional non-UI factory. Only an explicit local phone-line acceptance enables it. */
internal object SealedLineActivationMount {
    private var selection: SealedLineAcceptance? = null
    private var revision = 0L
    private var originalHostCurrent: () -> Boolean = { false }
    private var acceptedProfile: EsimProfileCandidate? = null
    fun enable(value: SealedLineAcceptance, explicitlyAccepted: Boolean = false,
               originCurrent: () -> Boolean = { false }): Boolean =
        enableOwned(value, explicitlyAccepted, originCurrent = originCurrent) != null
    /** Closing an obsolete phone review cannot withdraw a newer explicit acceptance. */
    fun enableOwned(value: SealedLineAcceptance, explicitlyAccepted: Boolean = false,
                    profile: EsimProfileCandidate? = null,
                    originCurrent: () -> Boolean): AutoCloseable? {
        if (!explicitlyAccepted || !runCatching(originCurrent).getOrDefault(false) ||
            profile?.isCurrent() == false) return null
        val owner = synchronized(this) {
            selection = value; originalHostCurrent = originCurrent; acceptedProfile = profile; revision += 1; revision
        }
        return AutoCloseable {
            synchronized(this) { if (revision == owner) disable() }
        }
    }
    @Synchronized fun disable() { selection = null; originalHostCurrent = { false }; acceptedProfile = null; revision += 1 }
    private fun configured(): Triple<SealedLineAcceptance, Long, EsimProfileCandidate?>? = synchronized(this) {
        selection?.let { Triple(it, revision, acceptedProfile) }
    }
    private fun stillSelected(expected: Long): Boolean {
        val guard = synchronized(this) {
            if (selection == null || revision != expected || acceptedProfile?.isCurrent() == false) return false
            originalHostCurrent
        }
        // Never invoke the service/host guard under the global mount monitor.
        if (!runCatching(guard).getOrDefault(false)) return false
        return synchronized(this) { selection != null && revision == expected && originalHostCurrent === guard }
    }
    fun open(context: Context, keys: DeviceSigningKeyStore, account: UUID, deviceId: UUID,
             epoch: Long, sessionCurrent: () -> Boolean): SealedLineActivationProvider? {
        val (accepted, version, profile) = configured() ?: return null // No preferences/DAO/Keystore read while disabled.
        if (accepted.accountId != account || accepted.deviceId != deviceId || epoch <= 0 || Build.VERSION.SDK_INT < 31) return null
        val current = { stillSelected(version) && sessionCurrent() }
        if (!current()) return null
        val application = checkNotNull(context.applicationContext)
        val signer = SealedLineActivationDevice({ Build.VERSION.SDK_INT }, {
            application.getSharedPreferences("gateway_selection", Context.MODE_PRIVATE)
                .getInt("subscription_id", SubscriptionManager.INVALID_SUBSCRIPTION_ID)
        }, {
            val cards = SimCardContinuity.observe(application)
            // Preserve the physical-only observer's prior refusal for an embedded selection.
            // Public card copies contain no opaque profile lease.
            if (profile == null) cards?.map { if (it.isEmbedded) it.copy() else it } else cards
        }, keys::existingConversationPublicPoint,
            acceptedProfileSigner(profile, current, { SimCardContinuity.observe(application) },
                { challenge, sim -> sim.profile?.let { candidate ->
                    SimProfileContinuity.challengeFence()?.reserveBeforeSigning(sim.profileChallengeKey(
                        challenge.accountId.toString(), challenge.deviceId.toString(), challenge.lineId.toString(),
                        challenge.generation, challenge.challengeId.toString()), candidate) == true
                } ?: true }, keys::signSealedLineActivation, System::currentTimeMillis), System::currentTimeMillis)
        val dao = SmsJournalDatabase.get(application).attempts()
        fun matches(proof: PreparedSealedLineActivation): Boolean {
            val c = proof.challenge
            val binding = dao.currentLineBinding() ?: return false
            return binding.slot == 1 && binding.installedAtMs > 0 && binding.accountId == c.accountId.toString() &&
                binding.deviceId == c.deviceId.toString() && binding.lineId == c.lineId.toString() &&
                binding.generation == c.generation && binding.matchesPrepared(proof.sim)
        }
        return SealedLineActivationProvider(accepted, account, deviceId, epoch, signer,
            SealedLineActivationReceiptStore(application), { proof ->
                if (!current() || !signer.validate(proof, accepted, true)) false
                else if (matches(proof)) true // Exact live proof+authenticated ACK, including crash-after-DAO retry.
                else {
                    val c = proof.challenge
                    dao.installVerifiedLineBinding(LocalLineBinding(accountId = c.accountId.toString(),
                        deviceId = c.deviceId.toString(), lineId = c.lineId.toString(), generation = c.generation,
                        subscriptionId = proof.sim.subscriptionId, installedAtMs = signer.now(), cardId = proof.sim.cardId)
                        .withContinuity(proof.sim), SimCardContinuity.observe(application), proof.sim.observedCard())
                }
            }, ::matches, current, profile, { challenge ->
                if (profile == null) true else {
                    val observed = singleActiveLineCandidate(SimCardContinuity.observe(application),
                        accepted.subscriptionId)
                    current() && observed != null && observed.profile === profile &&
                        SimProfileContinuity.challengeFence()?.reserveBeforeSigning(
                            observed.profileChallengeKey(challenge.accountId.toString(), challenge.deviceId.toString(),
                                challenge.lineId.toString(), challenge.generation, challenge.challengeId.toString()), profile) == true &&
                        current()
                }
            }, { proof ->
                val candidate = proof.sim.profile
                if (candidate == null || candidate !== profile || !current() || !matches(proof) ||
                    !signer.validate(proof, accepted, true)) null else {
                    val c = proof.challenge
                    val permit = SimProfileContinuity.challengeFence()?.persistAcceptedAck(
                        proof.sim.profileChallengeKey(c.accountId.toString(), c.deviceId.toString(), c.lineId.toString(),
                            c.generation, c.challengeId.toString()), candidate)
                    if (permit != null && current() && matches(proof) &&
                        signer.validate(proof, accepted, true) && current()) SimProfileContinuity.publish(permit) {
                            current() && matches(proof) && signer.validate(proof, accepted, true) && current()
                        } else null
                }
            })
    }
}

/** Fences the original hardware signer to the immutable local acceptance after provider waits. */
internal fun acceptedProfileSigner(profile: EsimProfileCandidate?, current: () -> Boolean,
    observe: () -> List<ActiveSimCard>?, reserve: (SealedLineChallenge, ActivatedSimCard) -> Boolean,
    sign: (SealedLineChallenge, Int, Int, ByteArray) -> ByteArray,
    now: () -> Long): (SealedLineChallenge, Int, Int, ByteArray) -> ByteArray = { challenge, api, selected, fingerprint ->
    if (profile == null) sign(challenge, api, selected, fingerprint) else {
        val sim = checkNotNull(singleActiveLineCandidate(observe(), selected))
        check(current() && sim.profile === profile)
        check(reserve(challenge, sim))
        check(current() && singleActiveLineCandidate(observe(), selected) == sim)
        val completed = now()
        check(completed > 0 && challenge.expiresAtMs - completed in 1..SealedLineActivationTranscript.CHALLENGE_LIFETIME_MS &&
            profile.isCurrent())
        sign(challenge, api, selected, fingerprint)
    }
}

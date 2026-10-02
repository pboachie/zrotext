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
    private val sessionCurrent: () -> Boolean) : AutoCloseable {
    private var closed = false
    private var pending: PreparedSealedLineActivation? = null
    private var proofAccepted = false
    private var installed: SealedLineActivationSnapshot? = null
    private var receiptConfirmed = false
    init { require(epoch > 0 && selection.accountId == account && selection.deviceId == deviceId) }
    private fun current() = !closed && sessionCurrent()
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
        if (c.connectionEpoch != epoch || !selection.matches(c)) return null
        val old = pending
        if (old != null && old.challenge.challengeId == c.challengeId && !same(old.challenge, c)) {
            pending = null; proofAccepted = false; return null
        }
        val proof = old?.takeIf { same(it.challenge, c) && device.validate(it, selection, false) }
            ?: device.prepare(c, selection) ?: return null
        if (!current() || !device.validate(proof, selection, false)) return null
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
        if (a.accepted) { pending = null; proofAccepted = false }
    }
    /** Receipt status only: explicitly incapable of granting body/read/send authority. */
    @Synchronized fun installationReceiptConfirmed(): Boolean {
        val snapshot = installed ?: return false
        return current() && receiptConfirmed && installedExactly(snapshot.proof) &&
            device.validate(snapshot.proof, selection, true)
    }
    @Synchronized override fun close() {
        closed = true; pending = null; proofAccepted = false; installed = null; receiptConfirmed = false
    }
    private fun same(a: SealedLineChallenge, b: SealedLineChallenge) = a.connectionEpoch == b.connectionEpoch &&
        a.challengeId == b.challengeId && a.accountId == b.accountId && a.deviceId == b.deviceId &&
        a.lineId == b.lineId && a.generation == b.generation && a.expiresAtMs == b.expiresAtMs && a.nonce.contentEquals(b.nonce)
}

/** Optional non-UI factory. Only an explicit local phone-line acceptance enables it. */
internal object SealedLineActivationMount {
    private var selection: SealedLineAcceptance? = null
    private var revision = 0L
    @Synchronized fun enable(value: SealedLineAcceptance, explicitlyAccepted: Boolean = false): Boolean {
        if (!explicitlyAccepted) return false
        selection = value; revision += 1; return true
    }
    @Synchronized fun disable() { selection = null; revision += 1 }
    private fun configured(): Pair<SealedLineAcceptance, Long>? = synchronized(this) {
        selection?.let { it to revision }
    }
    private fun stillSelected(expected: Long) = synchronized(this) { selection != null && revision == expected }
    fun open(context: Context, keys: DeviceSigningKeyStore, account: UUID, deviceId: UUID,
             epoch: Long, sessionCurrent: () -> Boolean): SealedLineActivationProvider? {
        val (accepted, version) = configured() ?: return null // No preferences/DAO/Keystore read while disabled.
        if (accepted.accountId != account || accepted.deviceId != deviceId || epoch <= 0 || Build.VERSION.SDK_INT < 31) return null
        val current = { stillSelected(version) && sessionCurrent() }
        if (!current()) return null
        val application = checkNotNull(context.applicationContext)
        val signer = SealedLineActivationDevice({ Build.VERSION.SDK_INT }, {
            application.getSharedPreferences("gateway_selection", Context.MODE_PRIVATE)
                .getInt("subscription_id", SubscriptionManager.INVALID_SUBSCRIPTION_ID)
        }, { SimCardContinuity.observe(application) }, keys::existingConversationPublicPoint,
            keys::signSealedLineActivation, System::currentTimeMillis)
        val dao = SmsJournalDatabase.get(application).attempts()
        fun matches(proof: PreparedSealedLineActivation): Boolean {
            val c = proof.challenge
            val binding = dao.currentLineBinding() ?: return false
            return binding.slot == 1 && binding.installedAtMs > 0 && binding.accountId == c.accountId.toString() &&
                binding.deviceId == c.deviceId.toString() && binding.lineId == c.lineId.toString() &&
                binding.generation == c.generation && binding.subscriptionId == proof.sim.subscriptionId && binding.cardId == proof.sim.cardId
        }
        return SealedLineActivationProvider(accepted, account, deviceId, epoch, signer,
            SealedLineActivationReceiptStore(application), { proof ->
                if (!current() || !signer.validate(proof, accepted, true)) false
                else if (matches(proof)) true // Exact live proof+authenticated ACK, including crash-after-DAO retry.
                else {
                    val c = proof.challenge
                    dao.installVerifiedLineBinding(LocalLineBinding(accountId = c.accountId.toString(),
                        deviceId = c.deviceId.toString(), lineId = c.lineId.toString(), generation = c.generation,
                        subscriptionId = proof.sim.subscriptionId, installedAtMs = signer.now(), cardId = proof.sim.cardId),
                        SimCardContinuity.observe(application))
                }
            }, ::matches, current)
    }
}

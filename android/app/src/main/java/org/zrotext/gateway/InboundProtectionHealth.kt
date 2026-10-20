// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import android.content.Context
import androidx.room.Entity
import androidx.room.PrimaryKey
import java.security.KeyStore
import java.security.MessageDigest
import javax.crypto.Mac
import javax.crypto.SecretKey

/** Local negative state and an expected identity, never permission for content/radio. This slice
 * has no ready/pin insertion API. Genuine first provisioning and legacy adoption are separate. */
@Entity(tableName = "inbound_protection_state")
data class InboundProtectionRecord(@PrimaryKey val slot: Int = 1, val expectedTag: String?,
    val originId: String?, val blocked: Boolean, val reason: String?, val debtMask: Int,
    val firstObservedMs: Long) {
    internal fun requireShape() {
        require(slot == 1 && debtMask in 0..7 && firstObservedMs > 0)
        expectedTag?.let { require(it.matches(Regex("[0-9a-f]{64}"))) }
        originId?.let(Profile03ClosedUnaccepted::uuid)
        require((expectedTag == null) == (originId == null))
        require(!blocked || reason in setOf("key_unavailable", "identity_changed", "continuity_missing", "storage_unavailable"))
        require(blocked || expectedTag != null && reason == null && debtMask == 0)
    }
    override fun toString() = "InboundProtectionState(no-recipient-or-content)"
}

/** Epochs only move forward. Withdrawal occurs before any Keystore/storage callback. A later
 * successful read cannot restore an old effect lease or clear permanent quarantine. */
internal class InboundProtectionEpochs {
    class Withdrawn : IllegalStateException("Suppression health withdrawn")
    private fun live(value: Boolean) { if (!value) throw Withdrawn() }
    private val lock = Any()
    private var epoch = 0L
    private var held = 0
    private var revoked = false
    inner class Lease internal constructor(private val expected: Long) {
        fun requireCurrent() = synchronized(lock) { live(!revoked && held == 0 && epoch == expected) }
        override fun toString() = "InboundProtectionLease(RAM-only)"
    }
    inner class Receipt internal constructor(private val expected: Long) {
        private var completed = false
        internal var marker: InboundProtectionFiles.Hold? = null
        fun requireReading() = synchronized(lock) { live(!completed && !revoked && epoch >= expected && held > 0) }
        fun completeKnownWithdrawal() {
            synchronized(lock) { live(!completed && !revoked && epoch >= expected && held > 0); completed = true }
            try { marker?.completeKnownWithdrawal() } catch (failure: Exception) { revoke(); throw failure }
            synchronized(lock) { live(!revoked && held > 0); held-- }
        }
    }
    fun beforeProtectionWait(optAction: String?): Receipt? = synchronized(lock) {
        if (optAction !in setOf(OptOutParser.OPT_OUT, OptOutParser.OPT_OUT_REVIEW)) return@synchronized null
        live(!revoked) // Already quarantined: retain aggregate debt, not an unbounded new hold.
        check(epoch < Long.MAX_VALUE && held < Int.MAX_VALUE)
        epoch++; held++; Receipt(epoch)
    }
    fun beforeProtectionWait(context: Context, optAction: String?): Receipt? {
        val ticket = beforeProtectionWait(optAction) ?: return null
        try { ticket.marker = InboundProtectionFaultJournal.begin(context, checkNotNull(optAction)) }
        catch (failure: Exception) { revoke(); runCatching { InboundProtectionFaultJournal.quarantine(context, optAction) }; throw failure }
        return ticket
    }
    fun snapshot(): Long = synchronized(lock) { live(!revoked && held == 0); epoch }
    fun checked(expected: Long): Lease = synchronized(lock) {
        live(!revoked && held == 0 && epoch == expected); Lease(expected)
    }
    fun requireNotRevoked() = synchronized(lock) { live(!revoked && held == 0) }
    fun available(): Boolean = synchronized(lock) { !revoked && held == 0 }
    fun current(expected: Long): Boolean = synchronized(lock) { !revoked && held == 0 && epoch == expected }
    fun revoke() = synchronized(lock) { revoked = true; if (epoch < Long.MAX_VALUE) epoch++ }
}

/** One process owner; constructing an isolated epoch model in tests grants no key/effect. */
internal val InboundProtectionHealth = InboundProtectionEpochs()

/** All actual HMAC reads use the same durable expected identity. Nothing here generates or
 * replaces an alias or pins whichever key happens to be present after history loss. */
internal object InboundProtection {
    class Unavailable internal constructor(val reason: String) : IllegalStateException("Inbound protection requires recovery")
    private fun existing(): SecretKey {
        val store = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        return checkNotNull(store.getKey(ConversationExistingSuppressionTokens.ALIAS, null) as? SecretKey)
            .also { check(it.algorithm.equals("HmacSHA256", true)) }
    }
    private fun tag(key: SecretKey): String = Draft02OutboundPreparation.hex(Mac.getInstance("HmacSHA256").run {
        init(key); doFinal("zrotext-inbound-protection-continuity-v1\u0000".toByteArray(Charsets.US_ASCII))
    })
    /** Cold negative replay only, outside protected storage/Room writers. This deliberately does
     * not require a ready pin/key merely to use authenticated setup/history metadata. */
    fun restoreNegative(context: Context) {
        try {
            InboundProtectionFaultJournal.requireReadable(context, false)
            SmsJournalDatabase.get(context).captures03().protection()?.let {
                it.requireShape(); if (it.blocked) throw Unavailable(checkNotNull(it.reason))
            }
            InboundProtectionHealth.requireNotRevoked()
        } catch (failure: InboundProtectionEpochs.Withdrawn) { throw failure }
        catch (failure: Exception) {
            val reason = (failure as? Unavailable)?.reason ?: "storage_unavailable"
            failed(context, null, System.currentTimeMillis(), reason); throw Unavailable(reason)
        }
    }
    internal fun key(context: Context, receipt: InboundProtectionEpochs.Receipt? = null): SecretKey {
        try {
            InboundProtectionFaultJournal.requireReadable(context, receipt != null)
            return verifiedKey(SmsJournalDatabase.get(context).captures03(), ::existing, current = {
                if (receipt == null) InboundProtectionHealth.requireNotRevoked() else receipt.requireReading()
            })
        } catch (failure: InboundProtectionEpochs.Withdrawn) { throw failure }
        catch (failure: Exception) {
            val reason = (failure as? Unavailable)?.reason ?: "storage_unavailable"
            failed(context, null, System.currentTimeMillis(), reason); throw Unavailable(reason)
        }
    }
    /** Fixture seam supplies actual synthetic keys/storage; production has exactly one provider.
     * current is RAM-only; it does not establish first-ever or initialize a ready identity. */
    internal fun verifiedKey(dao: Capture03Dao, existing: () -> SecretKey, current: () -> Unit,
        withdraw: () -> Unit = InboundProtectionHealth::revoke): SecretKey {
        Capture03IngressGate.requireOutside()
        current()
        try {
            val state = dao.protection()
            state?.requireShape()
            if (state?.blocked == true) throw Unavailable(checkNotNull(state.reason))
            // Absence is never first-ever or legacy-adoption evidence. No production ready/pin
            // insertion exists in this slice; the genuine provisioning dependency stays closed.
            val expected = state?.expectedTag ?: throw Unavailable("continuity_missing")
            if (state.originId == null) throw Unavailable("continuity_missing")
            val key = try { existing() } catch (_: Exception) { throw Unavailable("key_unavailable") }
            val actual = try { tag(key) } catch (_: Exception) { throw Unavailable("key_unavailable") }
            if (!MessageDigest.isEqual(actual.toByteArray(Charsets.US_ASCII), expected.toByteArray(Charsets.US_ASCII)))
                throw Unavailable("identity_changed")
            check(dao.protection() == state)
            current()
            return key
        } catch (failure: Unavailable) {
            withdraw()
            throw failure
        }
    }
    fun lease(context: Context, epoch: Long = InboundProtectionHealth.snapshot()): InboundProtectionEpochs.Lease {
        try {
            InboundProtectionFaultJournal.requireReadable(context, false)
            verifiedKey(SmsJournalDatabase.get(context).captures03(), ::existing,
                current = { InboundProtectionHealth.checked(epoch) })
            return InboundProtectionHealth.checked(epoch)
        } catch (failure: InboundProtectionEpochs.Withdrawn) { throw failure }
        catch (failure: Exception) {
            val reason = (failure as? Unavailable)?.reason ?: "storage_unavailable"
            failed(context, null, System.currentTimeMillis(), reason); throw Unavailable(reason)
        }
    }
    fun failed(context: Context, optAction: String?, at: Long, reason: String) {
        InboundProtectionHealth.revoke() // RAM first, even if Room fails or is unavailable.
        val latch = runCatching { InboundProtectionFaultJournal.quarantine(context, optAction) }
        val mask = when (optAction) { OptOutParser.OPT_OUT -> 1; OptOutParser.OPT_OUT_REVIEW -> 2; OptOutParser.OPT_IN -> 4; else -> 0 }
        try { SmsJournalDatabase.get(context).captures03().quarantineProtection(reason, mask, at.coerceAtLeast(1)) }
        finally { latch.getOrThrow() }
    }
}

/** The actual receiver uses this boundary before Room or HMAC access. A failure retains the
 * already classified negative action; no invented token or successful recipient report escapes. */
internal object InboundProtectionIngress {
    class Prepared<T>(val optAction: String?, val receipt: InboundProtectionEpochs.Receipt?, val value: T)
    fun <T> prepare(body: String, beforeWait: (String?) -> InboundProtectionEpochs.Receipt?,
        tokens: (InboundProtectionEpochs.Receipt?) -> T,
        failed: (String?, Exception) -> Unit): Prepared<T>? {
        val action = OptOutParser.classify(body)
        return try {
            val receipt = beforeWait(action)
            Prepared(action, receipt, tokens(receipt))
        } catch (failure: Exception) { failed(action, failure); null }
    }
}

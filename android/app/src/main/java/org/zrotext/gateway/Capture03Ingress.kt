// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import android.content.Context
import android.database.sqlite.SQLiteDatabase
import java.security.MessageDigest

/** A negative-only witness. Even a fully verified device proof cannot prove acceptance, owner
 * permission, physical continuity or content consent. Missing/partial history blocks content.
 * It must NEVER be passed to the positive capture/sequence path. */
internal object Capture03Exclusion {
    class Candidate(val route: String, val provenance: String?) {
        init { require(route in setOf("legacy", "blocked", "drop03") && (route == "drop03") == (provenance != null)) }
        override fun toString() = "Capture03Exclusion(never-positive-authority)"
    }
    fun decide(rows: List<Profile03ElectionRecord>, retainedMode: Boolean, line: LocalLineBinding?,
        observedSubscription: Int?, compared: () -> Draft02TrustStore.Result, enrolledPoint: () -> ByteArray): Candidate {
        if (rows.isEmpty()) return Candidate(if (retainedMode) "blocked" else "legacy", null)
        return try {
            require(line != null && observedSubscription == line.subscriptionId && line.protocolVersion == 2 && line.v2Purpose == "sealed")
            val selected = rows.filter { it.accountId == line.accountId && it.deviceId == line.deviceId && it.lineId == line.lineId }
            require(selected.isNotEmpty())
            val result = compared()
            require(result.status == Draft02TrustStore.Status.NEEDS_FRESHNESS)
            val pin = Draft02RootComparison.validatePin(checkNotNull(result.snapshot).pin)
            require(pin.copyOfRange(5, 21).contentEquals(ReviewedIntent03.uuid(java.util.UUID.fromString(line.accountId))))
            val point = enrolledPoint()
            val keyId = Profile03RetainedElection.signingId(point)
            val root = Draft02RootComparison.fingerprint(pin)
            // All selected released proofs must agree. No present clock or unsigned accepted
            // flag is substituted for the immutable enrolled signature and compared root.
            for (row in selected) {
                row.requireShape()
                val core = Profile03ElectionEncoding.decode(row.coreB64url, 500)
                val signature = Profile03ElectionEncoding.decode(checkNotNull(row.deviceSignatureB64url), 64)
                require(core.copyOfRange(136, 168).contentEquals(root) && core.copyOfRange(288, 320).contentEquals(keyId))
                require(ConversationContentCrypto.verifyRaw(signature, point,
                    ReviewedIntent03.framed("ZTSE/line/payload-profile/device/v1", core)))
            }
            val original = selected.maxBy { it.newGeneration }
            val bytes = Profile03ElectionEncoding.decode(original.coreB64url, 500) +
                Profile03ElectionEncoding.decode(checkNotNull(original.deviceSignatureB64url), 64)
            Candidate("drop03", Draft02OutboundPreparation.hex(MessageDigest.getInstance("SHA-256").digest(bytes)))
        } catch (_: Exception) { Candidate("blocked", null) }
    }
}

/** Only short storage reservations are serialized. Old receipt reads cannot create a missing
 * journal or initialize a counter. A missing file is NOT evidence usable by positive capture. */
internal object Capture03Ingress {
    class Decision(val row: Capture03Route, val firstLegacy: Boolean) {
        override fun toString() = "Capture03IngressDecision(content-free)"
    }
    /** The actual receiver uses this ordering. Consent withdrawal/reporting are independent of
     * absent/stopped/uncertain content authority; duplicate content is never promoted later. */
    fun deliver(optAction: String?, withdraw: () -> Unit, reserve: () -> Boolean,
        legacyContent: () -> Unit, metadata: (Boolean) -> Unit) {
        if (optAction in setOf(OptOutParser.OPT_OUT, OptOutParser.OPT_OUT_REVIEW)) withdraw()
        val firstLegacy = try { reserve() } catch (_: Exception) { false }
        if (firstLegacy) legacyContent()
        if (firstLegacy || optAction != null) metadata(firstLegacy)
    }
    fun claim(dao: Capture03Dao, token: String, now: Long, candidate: Capture03Exclusion.Candidate,
        unchanged: () -> Unit, legacyEvidence: () -> Boolean): Decision = Capture03IngressGate.reserve {
        unchanged()
        val prior = dao.route(token)
        if (prior != null) return@reserve Decision(prior.also { it.requireShape() }, false)
        // An unreadable preexisting journal is uncertainty, never a false 'no old capture'.
        val old = runCatching(legacyEvidence)
        val chosen = if (old.isFailure) Capture03Exclusion.Candidate("blocked", null) else candidate
        val row = dao.claim(Capture03Route(token, chosen.route, chosen.provenance, null, now),
            null, old.getOrDefault(false), unchanged)
        Decision(row, row.route == "legacy" && !old.getOrDefault(false))
    }
    fun legacyReceipt(context: Context, token: String): Boolean {
        Capture03IngressGate.requireHeld()
        val path = context.getDatabasePath(ConversationJournalStores.CAPTURE_FILE)
        if (!path.exists()) return false // Exclusion read only, NEVER allocator/positive authority.
        check(path.isFile)
        return SQLiteDatabase.openDatabase(path.path, null, SQLiteDatabase.OPEN_READONLY or SQLiteDatabase.NO_LOCALIZED_COLLATORS).use { db ->
            check(db.version in 1..3)
            fun exists(table: String) = db.rawQuery("SELECT 1 FROM $table WHERE token = ? LIMIT 1", arrayOf(token)).use { it.moveToFirst() }
            exists("conversation_receipts") || db.version >= 2 && exists("conversation_wire_captures")
        }
    }
    fun exclude(context: Context, db: SmsJournalDatabase, token: String, now: Long, observedSubscription: Int?): Decision {
        Capture03IngressGate.requireOutside()
        val rows = db.captures03().releasedElections()
        val modes = db.captures03().modes()
        val line = db.attempts().currentLineBinding()
        for (row in rows) Capture03LegacyFence.withdraw(row.accountId, row.deviceId, row.lineId)
        for (row in modes) Capture03LegacyFence.withdraw(row.accountId, row.deviceId, row.lineId)
        val candidate = Capture03Exclusion.decide(rows, modes.isNotEmpty(), line, observedSubscription,
            { Draft02AndroidTrustStorage(context).use { Draft02TrustStore(it).inspect() } },
            { DeviceSigningKeyStore(context).existingConversationPublicPoint() })
        // No provider call inside this callback. Compare the exact storage snapshot after all
        // root/Keystore waits and again in the SAME route transaction before publishing it.
        fun unchanged() {
            check(db.captures03().releasedElections() == rows && db.attempts().currentLineBinding() == line)
            val actual = db.captures03().modes()
            check(actual.size == modes.size && actual.all { a -> modes.any { b -> a.sameIdentity(b) &&
                a.protectedEvidence.contentEquals(b.protectedEvidence) && a.nonce.contentEquals(b.nonce) } })
        }
        return claim(db.captures03(), token, now, candidate, ::unchanged) {
            db.attempts().inboundByDedupe(token) != null || legacyReceipt(context, token)
        }
    }
}

// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import androidx.room.Entity
import java.security.MessageDigest

/** Authenticated server closure provenance only. Unknown refreshes have no invented observation
 * or local signature. The actual current socket/retained election/physical review are separate.
 */
@Entity(tableName = "selection_refresh03_closures", primaryKeys = ["refreshId"])
data class SelectionRefresh03ClosureRecord(val openingId: String, val refreshId: String, val coreB64url: String,
    val closedUnacceptedMs: Long, val supersededByRefreshId: String) {
    internal fun core(): SelectionRefresh03.Core {
        listOf(openingId, refreshId, supersededByRefreshId).forEach { Profile03ClosedUnaccepted.uuid(it) }
        return SelectionRefresh03.Core.decode(Profile03ElectionEncoding.decode(coreB64url, 496)).also {
            require(it.refresh.toString() == refreshId && refreshId != supersededByRefreshId && closedUnacceptedMs >= it.expiresMs)
        }
    }
    override fun toString() = "SelectionRefresh03ClosureRecord(server-history-only)"
}

internal object SelectionRefresh03Closure {
    fun decode(frame: Map<String, Any>): List<SelectionRefresh03ClosureRecord> = Profile03Json.closedUnaccepted(frame).map { f ->
        require(f.keys == setOf("opening_id", "refresh_id", "core", "closed_unaccepted_ms", "superseded_by_refresh_id"))
        SelectionRefresh03ClosureRecord(Profile03Json.text(f, "opening_id"), Profile03Json.text(f, "refresh_id"),
            Profile03ElectionEncoding.encode(Profile03Json.binary(f, "core", 496, 496)),
            Profile03Json.decimal(f, "closed_unaccepted_ms"), Profile03Json.text(f, "superseded_by_refresh_id"))
            .also { it.core() }
    }
    /** Immutable binding/election/keys/manifest/epoch/full device lease/origin. Only refresh UUID,
     * owner-session digest, nonce and the explicit opening window may vary.
     */
    fun sameScope(left: SelectionRefresh03.Core, right: SelectionRefresh03.Core): Boolean {
        val a = left.bytes(); val b = right.bytes()
        return listOf(0 to 56, 72 to 376, 408 to 440).all { (start, end) ->
            MessageDigest.isEqual(a.copyOfRange(start, end), b.copyOfRange(start, end))
        }
    }
    fun requireChain(target: SelectionRefresh03.Core, rows: List<SelectionRefresh03ClosureRecord>, now: Long) {
        require(rows.size <= 16)
        target.requireCurrent(now)
        require(rows.map { it.openingId }.distinct().size == rows.size && rows.map { it.refreshId }.distinct().size == rows.size &&
            rows.none { it.refreshId == target.refresh.toString() })
        for ((index, row) in rows.withIndex()) {
            val old = row.core()
            val next = rows.getOrNull(index + 1)?.core() ?: target
            require(sameScope(old, target) && old.issuedMs < next.issuedMs &&
                row.supersededByRefreshId == next.refresh.toString() && row.closedUnacceptedMs == next.issuedMs &&
                old.expiresMs <= row.closedUnacceptedMs && row.closedUnacceptedMs <= now)
        }
    }
    fun requireFreshDecision(previous: SelectionRefresh03Record, pending: SamePhoneSelectionReview.Pending,
        now: Long) {
        previous.requireShape()
        require(previous.ownerSignatureB64url == null && previous.acceptedMs == null && previous.installedMs == null &&
            previous.state in setOf("reserved", "signed", "retired"))
        val old = SelectionRefresh03.Core.decode(Profile03ElectionEncoding.decode(previous.coreB64url, 496))
        check(now >= old.expiresMs && pending.consentId.toString() != previous.consentId && pending.confirmedMs >= old.expiresMs)
        pending.requireCurrent()
    }
}

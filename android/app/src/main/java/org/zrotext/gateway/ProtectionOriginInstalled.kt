// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import android.content.Context
import javax.crypto.SecretKey

/** Historical installation verification, independent of a network connection. Every actual
 * protected read rechecks BOTH original AES probes, canary, enrolled signer, HMAC identity,
 * exact local proof/receipt and unchanged rows. A downloaded status or ready flag cannot
 * reconstruct any missing half. Framework/Keystore waits stay outside the Room writer. */
internal object ProtectionOriginInstalled {
    fun key(context: Context, current: () -> Unit): SecretKey = verified(context, false, current)
    /** An actual negative-receipt hold may resolve its own sender token. It cannot create a
     * positive lease, clear a cold hold, or bypass the independent original-key checks. */
    fun withdrawalKey(context: Context, receipt: InboundProtectionEpochs.Receipt, current: () -> Unit): SecretKey =
        verified(context, true) { receipt.requireReading(); current() }
    private fun verified(context: Context, withdrawal: Boolean, current: () -> Unit): SecretKey {
        Capture03IngressGate.requireOutside(); current()
        InboundProtectionFaultJournal.requireReadable(context, withdrawal)
        val dao = SmsJournalDatabase.get(context).protectionOrigins()
        val command = checkNotNull(dao.setupCommand()); command.requireShape()
        val row = checkNotNull(dao.installed()) { "Finish original protection setup" }
        val point = SealedDispatch03Frames.decodeCanonical(row.enrolledPointB64url, 65, 65)
        val opening = ProtectionOriginWire.retainedOpening(SealedDispatch03Frames.decodeCanonical(
            checkNotNull(command.openingCandidateB64url), 1, ProtectionOriginJson.MAX_BYTES), command, point)
        val prepared = ProtectionOriginPrepared.fromRetained(command, dao.providers(), opening)
        val attempt = checkNotNull(dao.attempt(row.proofRequestId)).also { it.requireShape() }
        check(attempt.acceptedMs != null && attempt.closedMs == null && attempt.commandId == command.commandId &&
            row.commandId == command.commandId && row.associationB64url == attempt.associationB64url &&
            row.aesProbeB64url == attempt.aesProbeB64url && row.bundleB64url == attempt.bundleB64url &&
            row.installedMs > 0 && Profile03ElectionEncoding.encode(prepared.association.bytes()) == row.associationB64url &&
            Profile03ElectionEncoding.encode(prepared.aesProbe()) == row.aesProbeB64url)
        val bundle = ProtectionOriginProof.Bundle.verify(SealedDispatch03Frames.decodeCanonical(row.bundleB64url, 521, 521),
            prepared.association, point)
        val receipt = ProtectionOriginWire.retainedReceipt(SealedDispatch03Frames.decodeCanonical(row.receiptB64url, 1, 512))
        receipt.requireMatches(bundle); check(receipt.acceptedMs == attempt.acceptedMs)
        val state = checkNotNull(dao.protection()).also { it.requireShape() }
        check(!state.blocked && state.debtMask == 0 && state.expectedTag == row.expectedTag &&
            state.originId == command.openingId && state.firstObservedMs == row.installedMs)
        val keys = ProtectionOriginKeys(context)
        keys.requirePrepared(prepared, opening)
        check(keys.continuityTag() == row.expectedTag)
        val key = keys.suppressionKey()
        prepared.requireSame(dao)
        check(dao.installed() == row && dao.attempt(row.proofRequestId) == attempt && dao.protection() == state)
        InboundProtectionFaultJournal.requireReadable(context, withdrawal)
        current(); return key
    }
}

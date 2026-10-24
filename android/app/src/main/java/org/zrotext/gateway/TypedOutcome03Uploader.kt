// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import java.util.UUID

/** Invoked only by the existing single passive-history worker. No signing, effect clock,
 * legacy pump, new evidence source, platform call or autonomous uncertain retry exists. */
internal object TypedOutcome03Uploader {
    fun report(journal: SmsJournalDatabase, host: TypedHistory03Connections.Host,
        source: TypedHistory03Source, explicitReplay: Boolean): Boolean {
        Capture03IngressGate.requireOutside()
        val row = journal.typedSubmits03().get(source.attemptId) ?: return false
        host.requireOriginal(row)
        val assertion = source.assertionB64url?.let { TypedOutcome03Command.decode(TypedSubmit03Record.unbase(it)) }
            ?: return false
        val upload = TypedOutcome03Upload(UUID.randomUUID().toString(), source.eventId, source.attemptId, source.slot,
            row.commandSha256, checkNotNull(source.assertionB64url), checkNotNull(source.assertionSha256),
            checkNotNull(row.originalOriginSha256), row.originalEnrolledPoint, host.epoch,
            TypedSubmit03Record.base(TypedOutcome03Wire.request(row.command(), assertion, host.epoch)))
        val entry = journal.typedOutcomes03().enter(row, source, upload, explicitReplay) { host.requireOriginal(row) }
            ?: return false
        val ack = host.report(entry)
        // An actual returned receipt may become historical after the socket lifetime ends;
        // appending it grants no clock, quota refund, rearm or platform permission.
        return journal.typedOutcomes03().retainAck(upload, ack.bytes())
    }
}

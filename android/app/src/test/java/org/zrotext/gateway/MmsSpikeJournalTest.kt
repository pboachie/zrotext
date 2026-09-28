// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder

class MmsSpikeJournalTest {
    @get:Rule val folder = TemporaryFolder()

    private val attemptId = "0f0a0b0c-1111-2222-3333-444455556666"

    private fun event(kind: String, atMs: Long = 1700000000000L, detail: String = "") =
        MmsSpikeEvent(attemptId, "txn123", kind, atMs, detail)

    @Test fun appendsAndReplaysEventsDurable() {
        val file = folder.newFile("journal.log")
        MmsSpikeJournal.append(file, event(MmsSpikeJournal.COMPOSED))
        MmsSpikeJournal.append(file, event(MmsSpikeJournal.CALL_RETURNED, detail = "result_0"))
        val replayed = MmsSpikeJournal.replay(file)
        assertEquals(listOf(MmsSpikeJournal.COMPOSED, MmsSpikeJournal.CALL_RETURNED),
            replayed.map { it.kind })
        assertEquals("txn123", replayed[0].transactionId)
        assertEquals("result_0", replayed[1].detail)
    }

    @Test fun replayReturnsOnlyTheValidPrefixAfterACorruptLine() {
        val file = folder.newFile("journal.log")
        MmsSpikeJournal.append(file, event(MmsSpikeJournal.COMPOSED))
        file.appendText("this line is not a journal event\n")
        MmsSpikeJournal.append(file, event(MmsSpikeJournal.SENT_OK))
        val replayed = MmsSpikeJournal.replay(file)
        assertEquals(1, replayed.size)
        assertEquals(MmsSpikeJournal.COMPOSED, replayed[0].kind)
    }

    @Test fun replayOfAMissingFileIsEmpty() {
        assertEquals(emptyList<MmsSpikeEvent>(),
            MmsSpikeJournal.replay(folder.newFolder().resolve("journal.log")))
    }

    @Test fun stateDerivationFollowsEvidenceOnly() {
        assertEquals("none", MmsSpikeJournal.attemptState(emptyList()))
        assertEquals("pending",
            MmsSpikeJournal.attemptState(listOf(event(MmsSpikeJournal.COMPOSED))))
        assertEquals("submitting", MmsSpikeJournal.attemptState(listOf(
            event(MmsSpikeJournal.COMPOSED), event(MmsSpikeJournal.CALL_RETURNED))))
        assertEquals("submitted", MmsSpikeJournal.attemptState(listOf(
            event(MmsSpikeJournal.COMPOSED), event(MmsSpikeJournal.SENT_OK))))
        assertEquals("failed", MmsSpikeJournal.attemptState(listOf(
            event(MmsSpikeJournal.COMPOSED), event(MmsSpikeJournal.SENT_ERROR, detail = "result_2"))))
        assertEquals("unknown", MmsSpikeJournal.attemptState(listOf(
            event(MmsSpikeJournal.COMPOSED), event(MmsSpikeJournal.TIMEOUT_UNKNOWN))))
        assertEquals("unknown", MmsSpikeJournal.attemptState(listOf(
            event(MmsSpikeJournal.COMPOSED), event(MmsSpikeJournal.UNKNOWN_RESULT))))
    }

    @Test fun conflictingTerminalEvidenceBecomesUnknownNotALaterWins() {
        assertEquals("unknown", MmsSpikeJournal.attemptState(listOf(
            event(MmsSpikeJournal.SENT_ERROR), event(MmsSpikeJournal.SENT_OK))))
        assertEquals("unknown", MmsSpikeJournal.attemptState(listOf(
            event(MmsSpikeJournal.SENT_OK), event(MmsSpikeJournal.TIMEOUT_UNKNOWN))))
    }

    @Test fun rejectsEventsThatCouldCorruptTheLineFormat() {
        assertNull(MmsSpikeJournal.validationError(event(MmsSpikeJournal.COMPOSED)))
        assertEquals("unknown event kind", MmsSpikeJournal.validationError(event("deleted")))
        assertEquals("detail must be short printable ASCII",
            MmsSpikeJournal.validationError(event(MmsSpikeJournal.SENT_OK, detail = "a\tb")))
        assertEquals("detail must be short printable ASCII",
            MmsSpikeJournal.validationError(event(MmsSpikeJournal.SENT_OK, detail = "x".repeat(121))))
        assertEquals("timestamp must be positive",
            MmsSpikeJournal.validationError(event(MmsSpikeJournal.COMPOSED, atMs = 0)))
        assertEquals("attempt id must be a UUID",
            MmsSpikeJournal.validationError(event(MmsSpikeJournal.COMPOSED).copy(attemptId = "nope")))
        assertEquals("invalid transaction id",
            MmsSpikeJournal.validationError(event(MmsSpikeJournal.COMPOSED).copy(transactionId = "txn 1")))
    }

    @Test fun appendRefusesAnInvalidEventInsteadOfWritingIt() {
        val file = folder.newFile("journal.log")
        val invalid = event("not_a_kind")
        var thrown = false
        try {
            MmsSpikeJournal.append(file, invalid)
        } catch (_: IllegalStateException) {
            thrown = true
        }
        assertTrue(thrown)
        assertEquals(0, MmsSpikeJournal.replay(file).size)
    }
}

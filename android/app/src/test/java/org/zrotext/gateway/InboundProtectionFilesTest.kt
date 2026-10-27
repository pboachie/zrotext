// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import java.io.File
import java.nio.file.Files
import org.junit.Assert.*
import org.junit.Test

/** Actual temporary files; the Android directory-fsync adapter alone is a fixture seam. */
class InboundProtectionFilesTest {
    @Test fun descriptorMustBeAnActualDirectoryAndIsClosedWhenValidationRefuses() {
        val calls = mutableListOf<String>()
        assertThrows(IllegalStateException::class.java) {
            ProtectionDirectorySync.sync({ calls.add("open"); 7 }, { calls.add("fstat-$it"); false },
                { calls.add("flush-$it") }, { calls.add("close-$it") })
        }
        assertEquals(listOf("open", "fstat-7", "close-7"), calls)
    }
    @Test fun directoryFsyncFailureStillClosesTheOriginalDescriptor() {
        val calls = mutableListOf<String>()
        assertThrows(IllegalStateException::class.java) {
            ProtectionDirectorySync.sync({ 9 }, { calls.add("fstat-$it"); true },
                { calls.add("flush-$it"); error("Synthetic fsync failure") }, { calls.add("close-$it") })
        }
        assertEquals(listOf("fstat-9", "flush-9", "close-9"), calls)
    }
    private fun directory(action: (File) -> Unit) {
        val parent = Files.createTempDirectory("protection-negative-test").toFile()
        try { action(File(parent, "negative")) } finally { check(parent.deleteRecursively()) }
    }
    @Test fun absenceDoesNotCreateAReadyRecordOrAProtectionIdentity() = directory { dir ->
        InboundProtectionFiles {}.requireReadable(dir, false)
        assertFalse(dir.exists())
    }
    @Test fun liveNegativeHoldAllowsOnlyWithdrawalAndColdProcessCannotAdoptIt() = directory { dir ->
        val files = InboundProtectionFiles {}; val hold = files.begin(dir, OptOutParser.OPT_OUT)
        files.requireReadable(dir, true)
        assertThrows(InboundProtectionEpochs.Withdrawn::class.java) { files.requireReadable(dir, false) }
        assertThrows(InboundProtection.Unavailable::class.java) { InboundProtectionFiles {}.requireReadable(dir, true) }
        assertEquals(0L, dir.listFiles()!!.single().length())
        hold.completeKnownWithdrawal(); files.requireReadable(dir, false)
        assertTrue(dir.listFiles()!!.isEmpty())
        assertThrows(IllegalStateException::class.java) { hold.completeKnownWithdrawal() }
    }
    @Test fun permanentQuarantineAndEveryAggregateOptDebtSurviveFreshProcess() = directory { dir ->
        val files = InboundProtectionFiles {}
        for (action in listOf(OptOutParser.OPT_OUT, OptOutParser.OPT_OUT_REVIEW, OptOutParser.OPT_IN))
            files.quarantine(dir, action)
        assertEquals(setOf("quarantined", "opt-out", "opt-review", "opt-in"), dir.listFiles()!!.map { it.name }.toSet())
        assertTrue(dir.listFiles()!!.all { it.length() == 0L })
        assertThrows(InboundProtection.Unavailable::class.java) { InboundProtectionFiles {}.requireReadable(dir, false) }
        assertThrows(InboundProtection.Unavailable::class.java) { files.requireReadable(dir, true) }
    }
    @Test fun partialMarkerCreationCannotBeAdoptedEvenInTheOriginalProcess() = directory { dir ->
        val files = InboundProtectionFiles { if (it == dir) error("Synthetic directory fsync failure") }
        assertThrows(IllegalStateException::class.java) { files.begin(dir, OptOutParser.OPT_OUT_REVIEW) }
        assertEquals(1, dir.listFiles()!!.size)
        assertThrows(InboundProtection.Unavailable::class.java) { files.requireReadable(dir, true) }
        assertThrows(InboundProtection.Unavailable::class.java) { InboundProtectionFiles {}.requireReadable(dir, false) }
    }
    @Test fun failedKnownWithdrawalCleanupPermanentlyWithdrawsRamBeforeAnyLaterEffect() = directory { dir ->
        var fail = false
        val files = InboundProtectionFiles { if (fail) error("Synthetic directory fsync failure") }
        val epochs = InboundProtectionEpochs()
        val receipt = checkNotNull(epochs.beforeProtectionWait(OptOutParser.OPT_OUT))
        receipt.marker = files.begin(dir, OptOutParser.OPT_OUT)
        fail = true
        assertThrows(IllegalStateException::class.java) { receipt.completeKnownWithdrawal() }
        assertFalse(epochs.available())
        assertThrows(InboundProtectionEpochs.Withdrawn::class.java) { epochs.snapshot() }
    }
    @Test fun unknownFileOrDirectoryIsNegativeUncertaintyNeverAnEmptyStateProof() = directory { dir ->
        check(dir.mkdir()); check(File(dir, "unknown").mkdir())
        assertThrows(InboundProtection.Unavailable::class.java) { InboundProtectionFiles {}.requireReadable(dir, true) }
    }
    @Test fun malformedLiveHoldNeverPermitsEvenNegativeIdentityResolution() = directory { dir ->
        val files = InboundProtectionFiles {}; files.begin(dir, OptOutParser.OPT_OUT)
        dir.listFiles()!!.single().writeText("synthetic malformed marker")
        assertThrows(InboundProtection.Unavailable::class.java) { files.requireReadable(dir, true) }
    }
    @Test fun genericMarkerWriteFailureDoesNotLoseAlreadyDurableActionDebt() = directory { dir ->
        var flushes = 0
        val files = InboundProtectionFiles { if (it == dir && ++flushes == 2) error("Synthetic later flush failure") }
        assertThrows(IllegalStateException::class.java) { files.quarantine(dir, OptOutParser.OPT_IN) }
        assertTrue(java.io.File(dir, "opt-in").isFile)
        assertThrows(InboundProtection.Unavailable::class.java) { InboundProtectionFiles {}.requireReadable(dir, true) }
    }
}

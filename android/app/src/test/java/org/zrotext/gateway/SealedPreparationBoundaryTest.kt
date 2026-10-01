// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import androidx.room.Room
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment
import org.robolectric.annotation.Config
import java.util.UUID

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34], application = android.app.Application::class)
class SealedPreparationBoundaryTest {
    private fun db() = Room.inMemoryDatabaseBuilder(RuntimeEnvironment.getApplication(), SmsJournalDatabase::class.java)
        .allowMainThreadQueries().build()
    private fun key() = DevicePayloadKeyStore(RuntimeEnvironment.getApplication(), "zrotext.test.unavailable.${UUID.randomUUID()}")

    @Test fun unavailableOrMismatchedAuthenticatedBindingsCannotReserveOrReachKeyUse() {
        val f = PreparationFixture(); val g = f.grant(); val db = db()
        try {
            assertEquals(Draft02OutboundPreparation.Unavailable,
                Draft02OutboundPreparation.prepare(f.envelope(), g, db, key()) { null })
            val changed = listOf(g.copy(attemptId = UUID.randomUUID().toString()), g.copy(attemptGeneration = 2),
                g.copy(connectionEpoch = 2), g.copy(deploymentEpoch = 2), g.copy(sessionId = UUID.randomUUID().toString()),
                g.copy(originHash = "cd".repeat(32)), g.copy(unsignedDigest = "cd".repeat(32)),
                g.copy(bindingGeneration = 2), g.copy(manifestGeneration = 2), g.copy(manifestVersion = 2),
                g.copy(manifestDigest = "cd".repeat(32)), g.copy(recipientDigest = "cd".repeat(32)),
                g.copy(accountId = UUID.randomUUID().toString()), g.copy(messageId = UUID.randomUUID().toString()),
                g.copy(deviceId = UUID.randomUUID().toString()), g.copy(lineId = UUID.randomUUID().toString()),
                g.copy(subscriptionId = 4), g.copy(cardId = 8), g.copy(expiresAtMs = g.expiresAtMs + 1))
            changed.forEach { actual ->
                assertEquals(Draft02OutboundPreparation.Rejected,
                    Draft02OutboundPreparation.prepare(f.envelope(), actual, db, key()) { f.current(g) })
            }
            for (time in listOf(0L, g.expiresAtMs, f.now - 40_000)) {
                assertEquals(Draft02OutboundPreparation.Rejected,
                    Draft02OutboundPreparation.prepare(f.envelope(), g, db, key()) { f.current(g, time) })
            }
            assertEquals(0, db.sealedPreparations().count())
        } finally { db.close() }
    }

    @Test fun mutableInputIsOwnedBeforeCallbackAndLostKeyCannotEraseTheReservation() {
        val f = PreparationFixture(); val g = f.grant(); val db = db()
        try {
            assertTrue(db.attempts().installVerifiedLineBinding(f.binding(), listOf(ActiveSimCard(3, 7))))
            val bytes = f.envelope()
            assertEquals(Draft02OutboundPreparation.Rejected,
                Draft02OutboundPreparation.prepare(bytes, g, db, key()) { bytes.fill(0); f.current() })
            assertEquals("aborted", db.sealedPreparations().find(g.accountId, g.messageId)?.state)
            assertEquals(1, db.sealedPreparations().count())
            assertEquals(Draft02OutboundPreparation.Rejected,
                Draft02OutboundPreparation.prepare(f.envelope(), g, db, key()) { f.current() })
            assertEquals(1, db.sealedPreparations().count())
        } finally { db.close() }
    }

    @Test fun clockRollbackAndSimContinuityChangesFailBeforeReservation() {
        val f = PreparationFixture(); val g = f.grant(); val db = db()
        try {
            val cards = mutableListOf(ActiveSimCard(3, 7))
            val copied = Draft02OutboundPreparation.Current(g, f.authority(), f.request(), f.now, 3, cards)
            cards.clear()
            assertEquals(listOf(ActiveSimCard(3, 7)), copied.cards())
            for (active in listOf(null, emptyList(), listOf(ActiveSimCard(3, 8)), listOf(ActiveSimCard(3, 7, true)))) {
                assertEquals(Draft02OutboundPreparation.Rejected,
                    Draft02OutboundPreparation.prepare(f.envelope(), g, db, key()) {
                        Draft02OutboundPreparation.Current(g, f.authority(), f.request(), f.now, 3, active)
                    })
            }
            var calls = 0
            assertEquals(Draft02OutboundPreparation.Rejected,
                Draft02OutboundPreparation.prepare(f.envelope(), g, db, key()) {
                    f.current(time = if (++calls < 3) f.now else f.now - 1)
                })
            assertEquals(0, db.sealedPreparations().count())
        } finally { db.close() }
    }

    @Test fun postCommitFreshnessFailureCannotReturnPlaintextAndKeepsNonResumableMetadata() {
        val f = PreparationFixture(); val g = f.grant(); val db = db()
        val chars = "synthetic".toCharArray()
        try {
            val r = SealedPreparationRecord(g.accountId, g.messageId, g.attemptId, g.unsignedDigest, g.identity())
            db.sealedPreparations().reserve(r) {}
            // Exercise the private post-decryption handoff only, never fake hardware admission.
            val finish = Draft02OutboundPreparation.javaClass.declaredMethods.single { it.name == "finish" }
                .apply { isAccessible = true }
            val checkLine: (LocalLineBinding?) -> Unit = { }
            val afterCommit: () -> Unit = {
                check(!db.inTransaction())
                assertEquals("prepared", db.sealedPreparations().find(g.accountId, g.messageId)?.state)
                error("synthetic expired lease after commit")
            }
            assertThrows(Exception::class.java) {
                finish.invoke(Draft02OutboundPreparation, db, r, chars, 1, checkLine, afterCommit)
            }
            assertTrue(chars.all { it == '\u0000' })
            assertEquals("prepared", db.sealedPreparations().find(g.accountId, g.messageId)?.state)
            assertThrows(Exception::class.java) { db.sealedPreparations().reserve(r) {} }
        } finally { chars.fill('\u0000'); db.close() }
    }

    @Test fun privateEphemeralBodyIsRedactedOneUseAndClearedOnFailureOrClose() {
        // Reflection tests ownership only, not a fabricated hardware admission or public factory.
        val type = Class.forName("org.zrotext.gateway.Draft02OutboundPreparation\$OwnedPrepared")
        val constructor = type.declaredConstructors.single().apply { isAccessible = true }
        fun owned(chars: CharArray, check: () -> Unit) =
            constructor.newInstance(chars, 1, check) as Draft02OutboundPreparation.Prepared
        val body = "synthetic".toCharArray(); val handle = owned(body) {}
        assertEquals("PreparedSealedText(redacted)", handle.toString())
        handle.consume { assertEquals("synthetic", String(it)) }
        assertTrue(body.all { it == '\u0000' })
        assertThrows(Exception::class.java) { handle.consume {} }
        val stale = "synthetic".toCharArray(); val denied = owned(stale) { error("synthetic stale lease") }
        assertThrows(Exception::class.java) { denied.consume { fail("Stale plaintext escaped") } }
        assertTrue(stale.all { it == '\u0000' })
        val closed = "synthetic".toCharArray(); owned(closed) {}.close()
        assertTrue(closed.all { it == '\u0000' })
    }
}

// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import org.junit.Assert.*
import org.junit.Test

class ConversationSetupEntrySessionTest {
    private class Handle : ConversationSetupEntrySession.Handle {
        var begins = 0; var closes = 0; var enabled = true; var failedClose = false
        override fun begin(): Boolean { begins++; return enabled }
        override fun close() { closes++; if (failedClose) error("private details") }
    }
    private val port = object : ConversationPresentationPort {
        override fun observe(listener: (ConversationPresentationSnapshot) -> Unit) = AutoCloseable {}
        override fun refresh() = Unit
        override fun approvePhoneReview(requestId: String, observedVersion: Long) = error("No automatic approval")
        override fun declinePhoneReview(requestId: String, observedVersion: Long) = Unit
        override fun requestStop(intervalId: String, observedVersion: Long) = error("No automatic Stop claim")
    }

    @Test fun constructingDoesNotBeginAndDuplicateOpenCannotCreateSecondController() {
        val handle = Handle(); var created = 0
        val session = ConversationSetupEntrySession({ created++; handle }, { _, _ -> })
        assertEquals(0, created); session.open(); session.open()
        assertEquals(1, created); assertEquals(1, handle.begins)
    }
    @Test fun disabledBeginClosesOwnedControllerAndExposesNoPort() {
        val handle = Handle().apply { enabled = false }; var state: ConversationSetupEntrySession.State? = null
        var shown: ConversationPresentationPort? = null
        val session = ConversationSetupEntrySession({ handle }, { next, value -> state = next; shown = value })
        session.open(); assertEquals(ConversationSetupEntrySession.State.UNAVAILABLE, state)
        assertEquals(1, handle.closes); assertNull(shown)
    }
    @Test fun cancelRejectsLateReadyAndReopenOwnsFreshController() {
        val handles = mutableListOf<Handle>(); val callbacks = mutableListOf<(ConversationPresentationPort) -> Unit>()
        var shown: ConversationPresentationPort? = null
        val session = ConversationSetupEntrySession({ callback -> callbacks += callback; Handle().also { handles += it } },
            { _, value -> shown = value })
        session.open(); session.close(); callbacks[0](port); assertNull(shown)
        session.open(); callbacks[0](port); assertNull(shown); callbacks[1](port); assertSame(port, shown)
        assertEquals(1, handles[0].closes); session.close(); session.close(); assertEquals(1, handles[1].closes)
    }
    @Test fun closeFailureNeverClaimsSuccessfulCloseOrReopens() {
        val handle = Handle().apply { failedClose = true }; var created = 0
        var state: ConversationSetupEntrySession.State? = null
        val session = ConversationSetupEntrySession({ created++; handle }, { next, _ -> state = next })
        session.open(); session.close(); assertEquals(ConversationSetupEntrySession.State.CLOSE_FAILED, state)
        session.open(); assertEquals(1, created)
    }
    @Test fun cancellationDuringOpeningNeverCreatesOrBeginsController() {
        var created = 0; lateinit var session: ConversationSetupEntrySession
        session = ConversationSetupEntrySession({ created++; Handle() }, { state, _ ->
            if (state == ConversationSetupEntrySession.State.OPENING) session.close()
        })
        session.open(); assertEquals(0, created)
    }
    @Test fun cancellationInsideFactoryClosesReturnedHandleWithoutBeginning() {
        val handle = Handle(); lateinit var session: ConversationSetupEntrySession
        session = ConversationSetupEntrySession({ ready -> ready(port); session.close(); handle }, { _, _ -> })
        session.open(); assertEquals(0, handle.begins); assertEquals(1, handle.closes)
    }
    @Test fun synchronousReadyIsNotPublishedWhenBeginRefuses() {
        val handle = Handle().apply { enabled = false }; val states = mutableListOf<ConversationSetupEntrySession.State>()
        val session = ConversationSetupEntrySession({ ready -> ready(port); handle }, { state, value ->
            states += state; assertNull(value)
        })
        session.open(); assertFalse(states.contains(ConversationSetupEntrySession.State.READY))
        assertEquals(1, handle.closes)
    }
    @Test fun synchronousReadyCancellationAfterAcceptedBeginClosesExactlyOnce() {
        val handle = Handle(); lateinit var session: ConversationSetupEntrySession
        session = ConversationSetupEntrySession({ ready -> ready(port); handle }, { state, _ ->
            if (state == ConversationSetupEntrySession.State.READY) session.close()
        })
        session.open(); assertEquals(1, handle.begins); assertEquals(1, handle.closes)
    }
}

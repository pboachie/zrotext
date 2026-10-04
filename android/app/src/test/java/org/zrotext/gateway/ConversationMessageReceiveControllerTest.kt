// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import org.junit.Assert.*
import org.junit.Test

class ConversationMessageReceiveControllerTest {
    private val message = "00000000-0000-0000-0000-000000000004"
    private class Fixture {
        var now = 100L
        var calls = 0
        var callback: ((Boolean) -> Unit)? = null
        val connection = Any()
        var snapshot = ConversationPresentationSnapshot(1, ConversationPresentationPhase.CONFIRMED_ACTIVE,
            "00000000-0000-0000-0000-000000000001", "00000000-0000-0000-0000-000000000002", 1, 1000, true)
        var selectedConnection = connection
        var available = true
        var device = "device"
        var observedAt = 100L
        var duringAuthorityRead: (() -> Unit)? = null
        var duringClockRead: (() -> Unit)? = null
        val receiver = ConversationMessageReceiver { _, complete -> calls++; callback = complete }
        val controller = ConversationMessageReceiveController({
            duringAuthorityRead?.invoke()
            if (!available) null else ConversationMessageReceiveController.Current(selectedConnection, "account", device,
                snapshot, observedAt, receiver)
        }, { duringClockRead?.invoke(); now })
    }
    @Test fun explicitReceiveInvokesOnlyPortAndReportsVerifiedCompletion() {
        val f = Fixture()
        assertTrue(f.controller.receive(message))
        assertEquals(1, f.calls)
        assertEquals(ConversationMessageReceiveController.Outcome.RECEIVING, f.controller.outcome)
        f.callback!!(true)
        assertEquals(ConversationMessageReceiveController.Outcome.VERIFIED, f.controller.outcome)
    }
    @Test fun invalidIdsAndUnavailableAuthorityNeverTouchTransport() {
        for (id in listOf("", " $message", message.uppercase().replace("000004", "00000A"), "00000000-0000-0000-0000-000000000000")) {
            val f = Fixture(); assertFalse(f.controller.receive(id)); assertEquals(0, f.calls)
        }
        val f = Fixture(); f.available = false; assertFalse(f.controller.receive(message)); assertEquals(0, f.calls)
    }
    @Test fun oneOutstandingOperationAndDoubleCallbackCannotChangeResult() {
        val f = Fixture(); assertTrue(f.controller.receive(message)); assertFalse(f.controller.receive(message))
        f.callback!!(false); f.callback!!(true)
        assertEquals(1, f.calls); assertEquals(ConversationMessageReceiveController.Outcome.UNKNOWN, f.controller.outcome)
    }
    @Test fun lateResultCannotSurviveStopExpirySimChangeOrConnectionReplacement() {
        val mutations: List<(Fixture) -> Unit> = listOf(
            { it.controller.cancel() }, { it.controller.close() }, { it.now = 1100 }, { it.now = 99 },
            { it.available = false }, { it.selectedConnection = Any() }, { it.device = "other" },
            { it.snapshot = it.snapshot.copy(lineGeneration = 2) },
            { it.snapshot = it.snapshot.copy(lineId = "00000000-0000-0000-0000-000000000003") },
            { it.snapshot = it.snapshot.copy(version = 2) },
            { it.snapshot = ConversationPresentationSnapshot(2, ConversationPresentationPhase.PAUSING) })
        mutations.forEach { change ->
            val f = Fixture(); assertTrue(f.controller.receive(message)); change(f); f.callback!!(true)
            assertEquals(ConversationMessageReceiveController.Outcome.CANCELLED, f.controller.outcome)
        }
    }
    @Test fun refreshedLeaseDoesNotExtendOriginalOperation() {
        val f = Fixture(); assertTrue(f.controller.receive(message))
        f.now = 1100; f.observedAt = 1100; f.callback!!(true)
        assertEquals(ConversationMessageReceiveController.Outcome.CANCELLED, f.controller.outcome)
    }
    @Test fun inactiveExpiredAndFutureClockObservationsRefuseBeforeTransport() {
        val fixtures = listOf(Fixture().apply { now = 1100 }, Fixture().apply { now = 99 },
            Fixture().apply { snapshot = ConversationPresentationSnapshot(1, ConversationPresentationPhase.RECOVERING) })
        fixtures.forEach { f -> assertFalse(f.controller.receive(message)); assertEquals(0, f.calls) }
    }
    @Test fun reentrantCancellationDuringInitialAuthorityOrClockSamplingCannotArmRequest() {
        for (clock in listOf(false, true)) for (close in listOf(false, true)) {
            val f = Fixture()
            val withdraw = { if (close) f.controller.close() else f.controller.cancel() }
            if (clock) f.duringClockRead = withdraw else f.duringAuthorityRead = withdraw
            assertFalse(f.controller.receive(message)); assertEquals(0, f.calls)
            assertEquals(ConversationMessageReceiveController.Outcome.CANCELLED, f.controller.outcome)
        }
    }
    @Test fun reentrantCancellationDuringCompletionCannotPublishVerified() {
        for (clock in listOf(false, true)) for (close in listOf(false, true)) {
            val f = Fixture(); assertTrue(f.controller.receive(message))
            val withdraw = { if (close) f.controller.close() else f.controller.cancel() }
            if (clock) f.duringClockRead = withdraw else f.duringAuthorityRead = withdraw
            f.callback!!(true)
            assertEquals(ConversationMessageReceiveController.Outcome.CANCELLED, f.controller.outcome)
        }
    }
}

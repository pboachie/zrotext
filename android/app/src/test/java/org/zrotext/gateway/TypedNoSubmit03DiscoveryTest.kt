// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

/** Actual metadata controller used by Message details; no Compose/provider acceptance. */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34], application = android.app.Application::class)
class TypedNoSubmit03DiscoveryTest {
    @Test fun stayingInDetailsAcrossActualHostReplacementRefreshesOnlyMetadataUntilANewTap() {
        TypedNoSubmit03Fixture().use { f -> withDatabase { db ->
            val row = f.closed(db); val discovery = TypedNoSubmit03Discovery(f.foreground)
            val initial = discovery.begin(f.host, true)!!
            val old = discovery.publish(initial, row, true)!!; val oldAction = discovery.capture(old)
            val before = TypedHistory03Connections.hostChanges.value; val oldHost = f.host
            val sends = f.sends
            f.reconnect()
            assertNotEquals(before, TypedHistory03Connections.hostChanges.value)
            assertNotSame(oldHost, TypedHistory03Connections.current())
            val actual = discovery.begin(TypedHistory03Connections.current(), true)!!
            val displayed = discovery.publish(actual, db.typedSubmits03().get(row.attemptId), true)!!
            assertSame(f.host, displayed.host); assertEquals(row, displayed.row)
            assertThrows(IllegalStateException::class.java) { oldAction.requireCurrent() }
            val nextAction = discovery.capture(displayed); nextAction.requireCurrent()
            assertEquals(row, nextAction.row); assertEquals(sends, f.sends); assertEquals(0, f.signs)
            assertNull(db.typedNoSubmits03().lineage(row.closingId!!))
        } }
    }
    @Test fun sameHostPauseResumeAbaCannotPublishAnOldLoadOrReviveItsCapturedDecision() {
        TypedNoSubmit03Fixture().use { f -> withDatabase { db ->
            val row = f.closed(db); val discovery = TypedNoSubmit03Discovery(f.foreground)
            val old = discovery.publish(discovery.begin(f.host, true)!!, row, true)!!
            val oldAction = discovery.capture(old); val pending = discovery.begin(f.host, true)!!
            assertNull(discovery.begin(null, false))
            val resumed = discovery.begin(f.host, true)!!
            assertNull(discovery.publish(pending, row, true))
            val next = discovery.publish(resumed, row, true)!!
            assertNull(discovery.refresh(old, row, true)); assertTrue(discovery.isDisplayed(next))
            assertThrows(IllegalStateException::class.java) { discovery.capture(old) }
            assertThrows(IllegalStateException::class.java) { oldAction.requireCurrent() }
            discovery.capture(next).requireCurrent()
            assertEquals(1, f.sends); assertEquals(0, f.signs)
            assertNull(db.typedNoSubmits03().lineage(row.closingId!!))
        } }
    }
    @Test fun delayedOldRoomLoadCompletionCannotOverwriteTheNewConnectionsDisplayedRow() {
        TypedNoSubmit03Fixture().use { f -> withDatabase { db ->
            val row = f.closed(db); val discovery = TypedNoSubmit03Discovery(f.foreground)
            val previous = discovery.publish(discovery.begin(f.host, true)!!, row, true)!!
            val pending = discovery.begin(f.host, true)!!
            val queried = CountDownLatch(1); val release = CountDownLatch(1); val pool = Executors.newSingleThreadExecutor()
            try {
                val late = pool.submit<TypedNoSubmit03Discovery.Display?> {
                    val saved = db.typedNoSubmits03().choices(pending.host.identity.accountId, pending.host.identity.deviceId,
                        pending.host.identity.originHash, TypedSubmit03Record.base(pending.host.point()), "").single()
                    queried.countDown(); check(release.await(5, TimeUnit.SECONDS))
                    discovery.publish(pending, saved, true)
                }
                assertTrue(queried.await(5, TimeUnit.SECONDS)); f.reconnect()
                val current = discovery.publish(discovery.begin(TypedHistory03Connections.current(), true)!!,
                    db.typedSubmits03().get(row.attemptId), true)!!
                release.countDown(); assertNull(late.get(5, TimeUnit.SECONDS))
                assertNull(discovery.refresh(previous, row, true)); assertTrue(discovery.isDisplayed(current))
                assertSame(f.host, discovery.capture(current).host)
                assertEquals(1, f.sends); assertEquals(0, f.signs)
                assertNull(db.typedNoSubmits03().lineage(row.closingId!!))
            } finally { release.countDown(); pool.shutdownNow() }
        } }
    }
}

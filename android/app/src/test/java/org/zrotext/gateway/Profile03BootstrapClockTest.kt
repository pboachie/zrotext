// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import java.util.UUID
import org.junit.Assert.*
import org.junit.Test

class Profile03BootstrapClockTest {
    @Test fun metadataClockIsBoundToTheCurrentOwnerAndNeverSurvivesWithdrawalOrAReplacement() {
        val first = Any(); val second = Any()
        val session = SealedDispatchExecutor.Session(UUID(0, 1), UUID(0, 2), 1, 1, UUID(0, 3), "ab".repeat(32))
        var now: Long? = 100
        try {
            Profile03BootstrapClock.publish(first, session) { now }
            val captured = Profile03BootstrapClock.capture(session.accountId, session.deviceId, session.originHash)
            assertEquals(100L, captured())
            assertThrows(IllegalStateException::class.java) { Profile03BootstrapClock.capture(UUID(0, 9), session.deviceId, session.originHash) }
            assertThrows(IllegalStateException::class.java) { Profile03BootstrapClock.publish(second, session) { now } }
            now = null
            assertThrows(IllegalStateException::class.java) { captured() }
            Profile03BootstrapClock.withdraw(first)
            now = 101
            Profile03BootstrapClock.publish(second, session) { now }
            assertThrows(IllegalStateException::class.java) { captured() }
            assertEquals(101L, Profile03BootstrapClock.capture(session.accountId, session.deviceId, session.originHash)())
            Profile03BootstrapClock.withdraw(first) // A stale owner cannot withdraw its successor.
            assertEquals(101L, Profile03BootstrapClock.capture(session.accountId, session.deviceId, session.originHash)())
        } finally { Profile03BootstrapClock.withdraw(first); Profile03BootstrapClock.withdraw(second) }
    }
}

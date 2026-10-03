// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway
import java.util.UUID
import org.junit.Test
import org.junit.Assert.*
class ConversationTrustedClockTest {
    private var elapsed=100L
    private var live:ConversationPhoneSession?=ConversationPhoneSession(UUID.randomUUID(),UUID.randomUUID(),UUID.randomUUID(),1,1,"11".repeat(32))
    private val clock=ConversationTrustedClock({elapsed},{live})
    private fun install(utc:Long=100000):ConversationTrustedClock.Request {val request=clock.beginRequest();elapsed+=100;clock.installAuthenticatedReply(request.challenge,request.session,utc);return request}
    @Test fun coldStartHasNoWallClockFallback(){assertNull(clock.nowMs())}
    @Test fun trustedUpperBoundIncludesRoundTripAndMonotonicAge(){install();assertEquals(100100L,clock.nowMs());elapsed+=500;assertEquals(100600L,clock.nowMs())}
    @Test fun leaseExpiresWithoutAutomaticRefresh(){install();elapsed+=30000;assertNull(clock.nowMs())}
    @Test fun requestNonceMismatchDiscardsAnchor(){val request=install();val next=clock.beginRequest();assertThrows(IllegalArgumentException::class.java){clock.installAuthenticatedReply(request.challenge,next.session,100100)};assertNull(clock.nowMs())}
    @Test fun replyCannotReplay(){val request=install();assertThrows(IllegalStateException::class.java){clock.installAuthenticatedReply(request.challenge,request.session,100000)}}
    @Test fun excessiveRoundTripNeverInstalls(){val request=clock.beginRequest();elapsed+=2001;assertThrows(IllegalArgumentException::class.java){clock.installAuthenticatedReply(request.challenge,request.session,100000)};assertNull(clock.nowMs())}
    @Test fun differentAuthenticatedSessionNeverInstalls(){val request=clock.beginRequest();live=live!!.copy(session=UUID.randomUUID());assertThrows(IllegalArgumentException::class.java){clock.installAuthenticatedReply(request.challenge,request.session,100000)};assertNull(clock.nowMs())}
    @Test fun sessionRotationClearsTime(){install();live=live!!.copy(connectionEpoch=2);assertNull(clock.nowMs())}
    @Test fun logoutClearsTime(){install();live=null;assertNull(clock.nowMs())}
    @Test fun rebootClockRegressionRequiresNewInstance(){install();elapsed=0;assertNull(clock.nowMs());elapsed=1000;assertThrows(IllegalStateException::class.java){clock.beginRequest()}}
    @Test fun authenticatedUtcCannotMoveBackwardOnRenewal(){install();val request=clock.beginRequest();elapsed+=100;assertThrows(IllegalArgumentException::class.java){clock.installAuthenticatedReply(request.challenge,request.session,99900)};assertNull(clock.nowMs())}
    @Test fun overflowingTimeNeverInstalls(){val request=clock.beginRequest();assertThrows(IllegalArgumentException::class.java){clock.installAuthenticatedReply(request.challenge,request.session,Long.MAX_VALUE)};assertNull(clock.nowMs())}
    @Test fun failedRequestOnLogoutCannotRestoreOldAnchor(){install();val prior=live;live=null;assertThrows(IllegalStateException::class.java){clock.beginRequest()};live=prior;assertNull(clock.nowMs())}
    @Test fun overflowingRenewalFloorCannotBypassRegression(){install();elapsed=Long.MAX_VALUE-1;val request=clock.beginRequest();assertThrows(ArithmeticException::class.java){clock.installAuthenticatedReply(request.challenge,request.session,100100)};assertNull(clock.nowMs())}
    @Test fun explicitInvalidationCannotResumeFromSavedAnchor(){install();clock.invalidate();assertNull(clock.nowMs())}
    @Test fun fasterAuthenticatedRenewalPreservesConservativeTimeWithoutRefusingCurrentSession() {
        install(100000)
        elapsed += 1000
        val request = clock.beginRequest()
        elapsed += 10
        // Server UTC advances correctly; the second sample has a shorter RTT.
        clock.installAuthenticatedReply(request.challenge, request.session, 101010)
        assertEquals(101110L, clock.nowMs())
    }
    @Test fun repeatedFasterRenewalsNeverReduceTheConservativeGrantDeadline() {
        install(100000)
        elapsed += 1000
        val next = clock.beginRequest()
        elapsed += 10
        clock.installAuthenticatedReply(next.challenge, next.session, 101010)
        assertEquals(101110L, clock.nowMs())
        val renewal = clock.beginRequest()
        elapsed += 5
        clock.installAuthenticatedReply(renewal.challenge, renewal.session, 101015)
        assertEquals(101115L, clock.nowMs())
        elapsed += 100
        assertEquals(101215L, clock.nowMs())
        assertTrue(clock.nowMs()!! >= 101200L)
    }
}

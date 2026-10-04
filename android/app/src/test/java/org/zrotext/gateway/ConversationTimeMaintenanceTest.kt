// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import java.util.UUID
import java.util.concurrent.Delayed
import java.util.concurrent.ScheduledFuture
import java.util.concurrent.ScheduledThreadPoolExecutor
import java.util.concurrent.TimeUnit
import org.junit.Assert.*
import org.junit.Test

class ConversationTimeMaintenanceTest {
    private fun id() = UUID.randomUUID().toString()
    private val scope = ConversationCaptureScope(id(),id(),id(),1,"+12",id(),id(),id(),
        "11".repeat(32),"22".repeat(32),1,2,"33".repeat(32),"44".repeat(32))
    private class Port : ConversationPresentationPort {
        val listeners = linkedSetOf<(ConversationPresentationSnapshot) -> Unit>()
        override fun observe(listener: (ConversationPresentationSnapshot) -> Unit): AutoCloseable {
            listeners.add(listener); listener(ConversationPresentationSnapshot(1,ConversationPresentationPhase.UNAVAILABLE))
            return AutoCloseable { listeners.remove(listener) }
        }
        fun publish(value: ConversationPresentationSnapshot) = listeners.toList().forEach { it(value) }
        override fun refresh() = Unit
        override fun approvePhoneReview(requestId: String, observedVersion: Long) = Unit
        override fun declinePhoneReview(requestId: String, observedVersion: Long) = Unit
        override fun requestStop(intervalId: String, observedVersion: Long) = Unit
    }
    private class Timer : ScheduledThreadPoolExecutor(1) {
        class Task(val command: Runnable, val delayMs: Long) : ScheduledFuture<Unit> {
            var cancelled = false
            var done = false
            override fun cancel(mayInterruptIfRunning: Boolean): Boolean { cancelled=true;return true }
            override fun isCancelled() = cancelled
            override fun isDone() = done || cancelled
            override fun get() = Unit
            override fun get(timeout: Long, unit: TimeUnit) = Unit
            override fun getDelay(unit: TimeUnit) = unit.convert(delayMs,TimeUnit.MILLISECONDS)
            override fun compareTo(other: Delayed) = getDelay(TimeUnit.MILLISECONDS).compareTo(other.getDelay(TimeUnit.MILLISECONDS))
        }
        val tasks = mutableListOf<Task>()
        var reject = false
        var immediate = false
        override fun schedule(command: Runnable, delay: Long, unit: TimeUnit): ScheduledFuture<*> {
            check(!reject) { "Synthetic rejected timer" }
            val task=Task(command,unit.toMillis(delay));tasks.add(task)
            if(immediate && delay==0L) { task.done=true;command.run() }
            return task
        }
        fun next(): Task = tasks.first { !it.isDone }.also { it.done=true;it.command.run() }
        fun outstanding() = tasks.count { !it.isDone }
    }
    private fun active() = ConversationPresentationSnapshot(2,ConversationPresentationPhase.CONFIRMED_ACTIVE,
        scope.intervalId,scope.lineId,scope.bindingGeneration,60000,true)
    @Test fun unavailableAndPreparingPresentationCannotScheduleMaintenance() {
        val timer=Timer();val port=Port();var calls=0
        val owner=ConversationTimeMaintenance(port,scope,timer,{}){_,_->calls++}
        try {
            port.publish(ConversationPresentationSnapshot(2,ConversationPresentationPhase.PREPARING))
            assertEquals(0,timer.outstanding());assertEquals(0,calls)
        } finally {owner.close();timer.shutdownNow()}
    }
    @Test fun oneImmediateThenTenSecondTimerWaitsForExactCompletion() {
        val timer=Timer();val port=Port();val replies=mutableListOf<(Boolean)->Unit>()
        val owner=ConversationTimeMaintenance(port,scope,timer,{}){selected,done->assertEquals(scope,selected);replies.add(done)}
        try {
            port.publish(active());port.publish(active());assertEquals(1,timer.outstanding())
            assertEquals(0L,timer.next().delayMs);assertEquals(1,replies.size);assertEquals(0,timer.outstanding())
            port.publish(active());assertEquals(0,timer.outstanding())
            replies[0](true);assertEquals(1,timer.outstanding())
            assertEquals(10000L,timer.next().delayMs);assertEquals(2,replies.size)
            replies[0](true);assertEquals(0,timer.outstanding()) // Duplicate old completion cannot release next work.
        } finally {owner.close();timer.shutdownNow()}
    }
    @Test fun missingDiscardedQueueCompletionRetainsOnePendingWithoutRetries() {
        val timer=Timer();val port=Port();var calls=0
        val owner=ConversationTimeMaintenance(port,scope,timer,{}){_,_->calls++}
        try {
            port.publish(active());timer.next()
            repeat(100){port.publish(active())}
            assertEquals(1,calls);assertEquals(0,timer.outstanding())
            owner.close();assertEquals(0,port.listeners.size)
        } finally {owner.close();timer.shutdownNow()}
    }
    @Test fun closeCancelsOnlyOwnedFutureAndDoesNotShutdownSharedScheduler() {
        val timer=Timer();val port=Port();var foreign=0;var calls=0
        val other=timer.schedule(Runnable {foreign++},1,TimeUnit.SECONDS)
        val owner=ConversationTimeMaintenance(port,scope,timer,{}){_,_->calls++}
        try {
            port.publish(active());val late=timer.tasks.last().command;owner.close();late.run()
            assertFalse(timer.isShutdown);assertFalse(other.isCancelled);assertEquals(0,calls)
            timer.next();assertEquals(1,foreign);assertEquals(0,port.listeners.size)
        } finally {owner.close();timer.shutdownNow()}
    }
    @Test fun stopClosesOwnerAndLatePositiveCannotRestartScheduling() {
        val timer=Timer();val port=Port();var reply:((Boolean)->Unit)?=null
        val owner=ConversationTimeMaintenance(port,scope,timer,{}){_,done->reply=done}
        try {
            port.publish(active());timer.next()
            port.publish(ConversationPresentationSnapshot(3,ConversationPresentationPhase.PAUSING))
            checkNotNull(reply)(true);port.publish(active())
            assertEquals(0,timer.outstanding());assertEquals(0,port.listeners.size)
        } finally {owner.close();timer.shutdownNow()}
    }
    @Test fun failedMaintenanceClosesSchedulingWithoutAutomaticRetry() {
        val timer=Timer();val port=Port()
        val owner=ConversationTimeMaintenance(port,scope,timer,{}){_,done->done(false)}
        try {port.publish(active());timer.next();port.publish(active());assertEquals(0,timer.outstanding());assertEquals(0,port.listeners.size)}
        finally {owner.close();timer.shutdownNow()}
    }
    @Test fun rejectedTimerRetiresObservationAndCannotAffectSharedExecutor() {
        val timer=Timer();val port=Port();timer.reject=true;var stops=0
        val owner=ConversationTimeMaintenance(port,scope,timer,{stops++}){_,_->error("Rejected timer must not request")}
        try {port.publish(active());assertEquals(0,port.listeners.size);assertFalse(timer.isShutdown);assertEquals(1,stops)}
        finally {owner.close();timer.shutdownNow()}
    }
    @Test fun inlineImmediateDispatchCannotOverwriteNextOwnedFuture() {
        val timer=Timer();val port=Port();timer.immediate=true
        val owner=ConversationTimeMaintenance(port,scope,timer,{}){_,done->done(true)}
        try {port.publish(active());assertEquals(1,timer.outstanding());owner.close();assertEquals(0,timer.outstanding())}
        finally {owner.close();timer.shutdownNow()}
    }
    @Test fun requestSubmissionFailureInvokesOwnedStopAndDoesNotScheduleRetry() {
        val timer=Timer();val port=Port();var stops=0
        val owner=ConversationTimeMaintenance(port,scope,timer,{stops++}){_,_->error("Synthetic submission failure")}
        try {port.publish(active());timer.next();assertEquals(1,stops);assertEquals(0,timer.outstanding());assertEquals(0,port.listeners.size)}
        finally {owner.close();timer.shutdownNow()}
    }
    @Test fun anotherIntervalPresentationCannotStartFrozenScopeMaintenance() {
        val timer=Timer();val port=Port()
        val owner=ConversationTimeMaintenance(port,scope,timer,{}){_,_->error("Wrong interval must not request")}
        try {port.publish(active().copy(intervalId=id()));assertEquals(0,timer.outstanding())}
        finally {owner.close();timer.shutdownNow()}
    }
}

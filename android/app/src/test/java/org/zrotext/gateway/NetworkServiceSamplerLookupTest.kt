// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import android.content.Context
import android.os.Looper
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment
import org.robolectric.Shadows.shadowOf
import org.robolectric.annotation.Config
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger

/** One subscription-list lookup per status sample, off the main looper. */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [28])
class NetworkServiceSamplerLookupTest {
    private class CountingLookup(val result: List<Int>?) {
        val lookups = AtomicInteger(0)
        val sawMainThread = booleanArrayOf(false)
        val resolve: (Int) -> List<Int>? = { _ ->
            lookups.incrementAndGet()
            sawMainThread[0] = Looper.myLooper() == Looper.getMainLooper()
            result
        }
    }

    /**
     * Drains the paused main looper until [delivered] fires or five seconds pass.
     *
     * The lookup runs on the sampler's executor and only then posts its continuation
     * to the main looper, so a single idle() can run before that post lands (the
     * lookup counter is bumped before the post). Idling repeatedly until the
     * delivery latch fires waits for the post itself, not for a proxy of it.
     */
    private fun idleMainLooperUntil(delivered: CountDownLatch): Boolean {
        val mainLooper = shadowOf(Looper.getMainLooper())
        val deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(5)
        while (true) {
            mainLooper.idle()
            if (delivered.count == 0L) return true
            if (System.nanoTime() >= deadline) return false
            Thread.sleep(5)
        }
    }

    private fun awaitSample(sampler: NetworkServiceSampler) {
        val samplerDone = CountDownLatch(1)
        sampler.sample({ true }) { _, _ -> samplerDone.countDown() }
        assertTrue(idleMainLooperUntil(samplerDone))
    }

    @Test fun oneSampleMakesExactlyOneLookupOffTheMainLooperAndDeliversIt() {
        val app = RuntimeEnvironment.getApplication()
        app.getSharedPreferences("gateway_selection", Context.MODE_PRIVATE)
            .edit().putInt("subscription_id", 7).commit()
        val lookup = CountingLookup(listOf(7, 9))
        val sampler = NetworkServiceSampler(app, selectedId = { 7 },
            activeSubscriptionIds = lookup.resolve)
        val delivered = arrayOfNulls<List<Int>?>(1)
        val deliveredDone = CountDownLatch(1)
        sampler.sample({ true }) { _, resolved ->
            delivered[0] = resolved
            deliveredDone.countDown()
        }
        assertTrue(idleMainLooperUntil(deliveredDone))
        assertEquals(1, lookup.lookups.get())
        assertEquals(listOf(7, 9), delivered[0])
        assertFalse(lookup.sawMainThread[0])
        // A second sample resolves once more; nothing resolves between samples.
        awaitSample(sampler)
        assertEquals(2, lookup.lookups.get())
        assertFalse(lookup.sawMainThread[0])
        sampler.shutdown()
    }

    @Test fun lookupOnlyResolvesOnceWithoutACapture() {
        val app = RuntimeEnvironment.getApplication()
        val lookup = CountingLookup(null)
        val sampler = NetworkServiceSampler(app, selectedId = { -1 },
            activeSubscriptionIds = lookup.resolve)
        val done = CountDownLatch(1)
        val active = arrayOfNulls<List<Int>?>(1)
        sampler.lookupOnly { resolved ->
            active[0] = resolved
            done.countDown()
        }
        assertTrue(done.await(5, TimeUnit.SECONDS))
        assertEquals(1, lookup.lookups.get())
        assertNull(active[0])
        sampler.shutdown()
    }
}

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

    private fun awaitSample(sampler: NetworkServiceSampler, lookup: CountingLookup) {
        val before = lookup.lookups.get()
        val samplerDone = CountDownLatch(1)
        sampler.sample({ true }) { _, _ -> samplerDone.countDown() }
        // Wait for the lookup executor's counter, then drain the main looper for the
        // posted continuation.
        val deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(5)
        while (lookup.lookups.get() == before && System.nanoTime() < deadline) Thread.sleep(5)
        shadowOf(Looper.getMainLooper()).idle()
        assertTrue(samplerDone.await(5, TimeUnit.SECONDS))
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
        val deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(5)
        while (lookup.lookups.get() == 0 && System.nanoTime() < deadline) Thread.sleep(5)
        shadowOf(Looper.getMainLooper()).idle()
        assertTrue(deliveredDone.await(5, TimeUnit.SECONDS))
        assertEquals(1, lookup.lookups.get())
        assertEquals(listOf(7, 9), delivered[0])
        assertFalse(lookup.sawMainThread[0])
        // A second sample resolves once more; nothing resolves between samples.
        awaitSample(sampler, lookup)
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

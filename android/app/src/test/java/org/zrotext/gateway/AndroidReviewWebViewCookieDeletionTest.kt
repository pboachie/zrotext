// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import android.os.Looper
import android.webkit.CookieManager
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicReference
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.Shadows.shadowOf
import org.robolectric.annotation.Config
import org.robolectric.annotation.LooperMode

/** Actual queued UI adapter and CookieManager, with synthetic cookie values only. */
@RunWith(RobolectricTestRunner::class)
@Config(sdk=[28])
@LooperMode(LooperMode.Mode.PAUSED)
class AndroidReviewWebViewCookieDeletionTest {
    private val origin="https://review.example.test"
    private val name="__Host-ztrw-l-00000000000000000000000000000001"
    private val original=name+"=retained"
    private val deletion=name+"=; Path=/; Secure; SameSite=Strict; Max-Age=0; HttpOnly"
    private val manager=CookieManager.getInstance()
    private val adapter=AndroidReviewWebViewCookieDeletion()
    private fun arrange(){
        manager.removeAllCookies(null)
        manager.setCookie(origin,original+"; Path=/; Secure; HttpOnly; SameSite=Strict")
        manager.setCookie(origin,"__Host-ztrw-owner=unrelated; Path=/; Secure; HttpOnly; SameSite=Strict")
        shadowOf(Looper.getMainLooper()).idle()
        assertTrue(manager.getCookie(origin).contains(original))
    }
    private fun start(active:AtomicBoolean=AtomicBoolean(true)):Pair<Thread,AtomicReference<Boolean?>> {
        val result=AtomicReference<Boolean?>()
        val worker=Thread{result.set(adapter.apply(origin,deletion,original){active.get()})}
        worker.start()
        val until=System.nanoTime()+1_000_000_000
        while(shadowOf(Looper.getMainLooper()).isIdle && worker.isAlive && System.nanoTime()<until)Thread.sleep(1)
        assertTrue("UI operation must actually be queued",worker.isAlive)
        assertFalse(shadowOf(Looper.getMainLooper()).isIdle)
        return worker to result
    }
    private fun finish(pair:Pair<Thread,AtomicReference<Boolean?>>,expected:Boolean){
        pair.first.join(3000);assertFalse("Bounded cookie callback must settle",pair.first.isAlive)
        assertEquals(expected,pair.second.get())
        assertTrue(manager.getCookie(origin).contains("__Host-ztrw-owner=unrelated"))
    }
    @Test fun successfulUiCallbackTargetsOnlyMatchingSelector() {
        arrange();val pending=start();shadowOf(Looper.getMainLooper()).idle();finish(pending,true)
        // RoboCookieManager models Expires, not Chromium Max-Age removal.
        // Prove the exact-name empty-value dispatch here. The real transport
        // independently requires ACTUAL absence before reporting success.
        val held=manager.getCookie(origin).split(';').map{it.trim()}.filter{it.substringBefore('=')==name}
        assertTrue(held.isEmpty() || held.single()==name+"=")
        assertFalse(adapter.apply(origin,deletion,original){true}) // never block the UI thread
    }
    @Test fun timeoutWithdrawsQueuedDeletionBeforeLooperLaterRuns() {
        arrange();val pending=start();finish(pending,false)
        shadowOf(Looper.getMainLooper()).idle()
        assertTrue(manager.getCookie(origin).contains(original))
    }
    @Test fun lifecycleCancellationBeforeActualDispatchPreservesSelector() {
        arrange();val active=AtomicBoolean(true);val pending=start(active);active.set(false)
        shadowOf(Looper.getMainLooper()).idle();finish(pending,false)
        assertTrue(manager.getCookie(origin).contains(original))
    }
    @Test fun changedSameNamedCookieCannotBeDeletedByOldQueuedOperation() {
        arrange();val pending=start()
        manager.setCookie(origin,name+"=newer; Path=/; Secure; HttpOnly; SameSite=Strict")
        shadowOf(Looper.getMainLooper()).idle();finish(pending,false)
        assertTrue(manager.getCookie(origin).contains(name+"=newer"))
    }
}

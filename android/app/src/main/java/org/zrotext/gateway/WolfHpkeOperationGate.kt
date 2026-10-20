// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

/** One process's pinned SINGLE_THREADED wolfSSL entry gate. Admission is RAM-only,
 * never Room, root/alias lookup or framework inspection. Receiver retains key→gate order;
 * sender never acquires an alias/storage lock while holding this gate. Callers own pending
 * secret output and must clear it when post-operation admission refuses. */
internal object WolfHpkeOperationGate {
    private val lock = Any()
    fun <T> operation(current: () -> Unit, run: () -> T): T {
        current()
        return synchronized(lock) { current(); run().also { current() } }
    }
}

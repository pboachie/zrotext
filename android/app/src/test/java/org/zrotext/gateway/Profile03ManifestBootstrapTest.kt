// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

/** Real synthetic root/manifest signatures; public key descriptors do not prove device custody. */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34], application = android.app.Application::class)
class Profile03ManifestBootstrapTest {
    private class Memory : Draft02TrustStore.Storage, Draft02TrustStore.Session {
        var key = Draft02TrustStore.KeyState.ABSENT
        var bytes: ByteArray? = null
        var writes = 0
        var beforeCommit: () -> Unit = {}
        @Synchronized override fun <T> locked(action: Draft02TrustStore.Session.() -> T) = action(this)
        override fun keyState() = key
        override fun read() = bytes?.copyOf()
        override fun createKey() { check(key == Draft02TrustStore.KeyState.ABSENT); key = Draft02TrustStore.KeyState.READY }
        override fun seal(plaintext: ByteArray) = plaintext.copyOf()
        override fun open(ciphertext: ByteArray) = ciphertext.copyOf()
        override fun write(ciphertext: ByteArray, preCommit: () -> Unit) {
            beforeCommit(); preCommit(); bytes = ciphertext.copyOf(); writes++
        }
    }
    private fun compared(f: Profile03ExecutionFixture, memory: Memory): Draft02TrustStore {
        val store = Draft02TrustStore(memory)
        val comparison = Draft02RootComparison()
        val display = comparison.begin(f.pin, f.account)
        check(store.enroll(comparison.confirm(display.fingerprintHex, true)).status == Draft02TrustStore.Status.NEEDS_FRESHNESS)
        return store
    }
    private fun reader(f: Profile03ExecutionFixture) = DevicePayloadPublic(Profile03ExecutionFixture.point(f.reader),
        Profile03ExecutionFixture.keyId(f.reader, false), PayloadKeySecurity.TRUSTED_ENVIRONMENT)

    @Test fun genuineInitialChainCommitsOnceAndExactReplayNeverRenewsAcceptance() = Profile03ExecutionFixture().use { f ->
        val memory = Memory(); val store = compared(f, memory)
        val chain = listOf(f.old, f.successor02())
        assertEquals(2L, Profile03ManifestBootstrap.install(store, chain, f.binding, reader(f),
            Profile03ExecutionFixture.point(f.enrollment), { f.now }, {}))
        assertEquals(2, memory.writes) // Compared-root write plus one old-or-final chain write.
        val accepted = checkNotNull(store.inspect().snapshot).bytes()
        assertEquals(2L, Profile03ManifestBootstrap.install(store, chain, f.binding, reader(f),
            Profile03ExecutionFixture.point(f.enrollment), { f.now + 1 }, {}))
        assertArrayEquals(accepted, checkNotNull(store.inspect().snapshot).bytes())
        assertEquals(2, memory.writes)
    }
    @Test fun missingComparisonWrongReaderWrongEnrollmentAndNonGenesisOrderNeverPublishAPrefix() = Profile03ExecutionFixture().use { f ->
        val empty = Memory()
        assertTrue(runCatching { Profile03ManifestBootstrap.install(Draft02TrustStore(empty), listOf(f.old), f.binding,
            reader(f), Profile03ExecutionFixture.point(f.enrollment), { f.now }, {}) }.isFailure)
        assertEquals(0, empty.writes)
        for (test in 0..2) {
            val memory = Memory(); val store = compared(f, memory)
            val before = checkNotNull(memory.bytes).copyOf()
            val wrongReader = DevicePayloadPublic(Profile03ExecutionFixture.point(f.archive),
                Profile03ExecutionFixture.keyId(f.archive, false), PayloadKeySecurity.TRUSTED_ENVIRONMENT)
            assertTrue(runCatching { Profile03ManifestBootstrap.install(store,
                if (test == 2) listOf(f.successor02(), f.old) else listOf(f.old, f.successor02()), f.binding,
                if (test == 0) wrongReader else reader(f),
                Profile03ExecutionFixture.point(if (test == 1) f.approval else f.enrollment), { f.now }, {}) }.isFailure)
            assertArrayEquals(before, memory.bytes)
            assertEquals(1, memory.writes)
        }
    }
    @Test fun interruptedAtomicWriteRetainsComparedRootAndCanResumeTheSameCompleteChain() = Profile03ExecutionFixture().use { f ->
        val memory = Memory(); val store = compared(f, memory)
        val original = checkNotNull(memory.bytes).copyOf()
        var current = true
        memory.beforeCommit = { current = false }
        fun now(): Long { check(current); return f.now }
        val chain = listOf(f.old, f.successor02())
        assertTrue(runCatching { Profile03ManifestBootstrap.install(store, chain, f.binding, reader(f),
            Profile03ExecutionFixture.point(f.enrollment), ::now, {}) }.isFailure)
        assertArrayEquals(original, memory.bytes)
        assertEquals(0L, store.inspect().snapshot!!.version)
        current = true; memory.beforeCommit = {}
        assertEquals(2L, Profile03ManifestBootstrap.install(store, chain, f.binding, reader(f),
            Profile03ExecutionFixture.point(f.enrollment), ::now, {}))
        assertEquals(2, memory.writes)
    }
}

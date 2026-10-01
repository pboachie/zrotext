// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import java.nio.ByteBuffer
import java.util.Base64
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import javax.crypto.KeyGenerator

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34])
class Draft02TrustStoreTest {
    private val fixture = JSONObject(javaClass.classLoader!!.getResourceAsStream("draft02-genesis.json")!!
        .bufferedReader().use { it.readText() })
    private val pin get() = Base64.getDecoder().decode(fixture.getString("root_pin_b64"))
    private val manifest get() = Base64.getDecoder().decode(fixture.getString("manifest_b64"))
    private val now get() = fixture.getLong("now_ms")
    private fun receipt(controller: Draft02RootComparison = Draft02RootComparison()): Draft02RootComparison.Receipt {
        val display = controller.begin(pin, pin.copyOfRange(5, 21))
        return controller.confirm(display.fingerprintHex, true)
    }
    private fun denied(action: () -> Unit) {
        try { action(); fail("Expected rejection") } catch (_: IllegalArgumentException) { } catch (_: IllegalStateException) { }
    }

    @Test fun existingKeyCipherAuthenticatesVersionContextNoncePayloadAndKey() {
        fun key() = KeyGenerator.getInstance("AES").apply { init(256) }.generateKey()
        val key = key()
        val aad = "synthetic-root-store-context".toByteArray()
        val plaintext = pin
        val encoded = Draft02RootStateCipher.seal(key, aad, plaintext)
        assertArrayEquals(plaintext, Draft02RootStateCipher.open(key, aad, encoded))
        assertFalse(encoded.contentEquals(Draft02RootStateCipher.seal(key, aad, plaintext)))
        fun corrupt(action: () -> Unit) {
            try { action(); fail("Expected authentication failure") }
            catch (failure: Draft02TrustStore.Failure) { assertEquals(Draft02TrustStore.Status.CORRUPT, failure.status) }
        }
        corrupt { Draft02RootStateCipher.open(key(), aad, encoded) }
        corrupt { Draft02RootStateCipher.open(key, aad + byteArrayOf(0), encoded) }
        for (offset in listOf(0, 4, 5, 16, 17, encoded.lastIndex)) {
            corrupt { Draft02RootStateCipher.open(key, aad, encoded.copyOf().apply { this[offset] = (this[offset].toInt() xor 1).toByte() }) }
        }
        for (bad in listOf(ByteArray(0), encoded.copyOf(32), encoded + byteArrayOf(0), ByteArray(16385))) {
            corrupt { Draft02RootStateCipher.open(key, aad, bad) }
        }
        denied { Draft02RootStateCipher.seal(key, aad, ByteArray(16384)) }
    }

    @Test fun currentAuthorityRequiresExistingAcceptedStateAndFreshAuthenticatedTime() {
        val memory=Memory();val store=Draft02TrustStore(memory)
        denied {store.currentAuthority {now}};assertEquals(0,memory.creations)
        val enrolled=store.enroll(receipt());denied {store.currentAuthority {now}}
        store.acceptManifest(enrolled.snapshot!!,manifest){now}
        val revision=store.inspect().snapshot!!.revision
        assertEquals(1L,store.currentAuthority {now}.version)
        assertEquals(revision,store.inspect().snapshot!!.revision);assertEquals(1,memory.creations)
        denied {store.currentAuthority {now-1}}
        var calls=0;denied {store.currentAuthority {if(calls++==0)now else now-1}}
        memory.key=Draft02TrustStore.KeyState.ABSENT;denied {store.currentAuthority {now}}
        assertEquals(1,memory.creations)
    }

    @Test fun fullDeliberateAccountBoundComparisonIsRequiredAndOneUse() {
        val controller = Draft02RootComparison()
        denied { controller.begin(pin, ByteArray(16)) }
        for (fingerprint in listOf("", "0".repeat(64), "g".repeat(64))) {
            controller.begin(pin, pin.copyOfRange(5, 21))
            denied { controller.confirm(fingerprint, true) }
        }
        val display = controller.begin(pin, pin.copyOfRange(5, 21))
        denied { controller.confirm(display.fingerprintHex, false) }
        val receipt = receipt(controller)
        val store = Draft02TrustStore(Memory())
        assertEquals(Draft02TrustStore.Status.NEEDS_FRESHNESS, store.enroll(receipt).status)
        assertEquals(Draft02TrustStore.Status.REJECTED, store.enroll(receipt).status)
    }

    @Test fun cancellationAndCandidateChangeInvalidateOutstandingComparison() {
        val controller = Draft02RootComparison()
        val cancelled = receipt(controller)
        controller.cancel()
        assertEquals(Draft02TrustStore.Status.REJECTED, Draft02TrustStore(Memory()).enroll(cancelled).status)
        val replaced = receipt(controller)
        controller.begin(pin, pin.copyOfRange(5, 21))
        assertEquals(Draft02TrustStore.Status.REJECTED, Draft02TrustStore(Memory()).enroll(replaced).status)
    }

    @Test fun cancellationDuringWriteCannotCommitAndRequiresRecovery() {
        val memory = Memory()
        val controller = Draft02RootComparison()
        val receipt = receipt(controller)
        memory.beforeCommit = { controller.cancel() }
        val store = Draft02TrustStore(memory)
        assertEquals(Draft02TrustStore.Status.REJECTED, store.enroll(receipt).status)
        assertNull(memory.data)
        assertEquals(Draft02TrustStore.Status.RECOVERY_REQUIRED, store.inspect().status)
    }

    @Test fun pinAndManifestCommitTogetherAndColdLoadNeverConfersFreshAuthority() {
        val memory = Memory()
        val store = Draft02TrustStore(memory)
        val genesis = store.enroll(receipt()).snapshot!!
        assertEquals(0, genesis.version)
        val accepted = store.acceptManifest(genesis, manifest) { now }
        assertEquals(Draft02TrustStore.Status.NEEDS_FRESHNESS, accepted.status)
        assertEquals(1, accepted.snapshot!!.version)
        val cold = Draft02TrustStore(memory).inspect()
        assertEquals(Draft02TrustStore.Status.NEEDS_FRESHNESS, cold.status)
        assertArrayEquals(pin, cold.snapshot!!.pin)
        assertEquals(now, cold.snapshot.verifiedAtMs)
        assertEquals(Draft02TrustStore.Status.CONFLICT, store.enroll(receipt()).status)
    }

    @Test fun snapshotsAndCallerArraysCannotAlterStoredRootOrExpectedRevision() {
        val memory = Memory()
        val store = Draft02TrustStore(memory)
        val snapshot = store.enroll(receipt()).snapshot!!
        snapshot.pin.fill(0)
        snapshot.bytes().fill(0)
        assertArrayEquals(pin, snapshot.pin)
        val bytes = snapshot.bytes()
        val copy = Draft02TrustStore.Snapshot(bytes)
        bytes.fill(0)
        assertArrayEquals(snapshot.bytes(), copy.bytes())
        val candidate = manifest
        memory.beforeCommit = { candidate.fill(0) }
        assertEquals(Draft02TrustStore.Status.NEEDS_FRESHNESS, store.acceptManifest(snapshot, candidate) { now }.status)
        assertEquals(Draft02TrustStore.Status.NEEDS_FRESHNESS, store.inspect().status)
    }

    @Test fun twoControllersCannotBothCommitAgainstTheSameRevision() {
        val memory = Memory()
        val first = Draft02TrustStore(memory)
        val snapshot = first.enroll(receipt()).snapshot!!
        val start = CountDownLatch(1)
        val pool = Executors.newFixedThreadPool(2)
        try {
            val results = (1..2).map { pool.submit<Draft02TrustStore.Status> {
                check(start.await(5, TimeUnit.SECONDS))
                Draft02TrustStore(memory).acceptManifest(snapshot, manifest) { now }.status
            } }
            start.countDown()
            assertEquals(setOf(Draft02TrustStore.Status.NEEDS_FRESHNESS, Draft02TrustStore.Status.STALE),
                results.map { it.get(10, TimeUnit.SECONDS) }.toSet())
        } finally { pool.shutdownNow() }
    }

    @Test fun rejectedManifestAndInterruptedWritesPreserveOldWholeState() {
        val memory = Memory()
        val store = Draft02TrustStore(memory)
        val snapshot = store.enroll(receipt()).snapshot!!
        val original = memory.data!!.copyOf()
        val bad = manifest.apply { this[lastIndex] = (this[lastIndex].toInt() xor 1).toByte() }
        assertEquals(Draft02TrustStore.Status.REJECTED, store.acceptManifest(snapshot, bad) { now }.status)
        memory.beforeCommit = { throw Draft02TrustStore.Failure(Draft02TrustStore.Status.IO_FAILURE) }
        assertEquals(Draft02TrustStore.Status.IO_FAILURE, store.acceptManifest(snapshot, manifest) { now }.status)
        assertArrayEquals(original, memory.data)
    }

    @Test fun trustedClockRegressionAndExpiryDuringWriteRollBack() {
        val memory = Memory()
        val store = Draft02TrustStore(memory)
        var snapshot = store.enroll(receipt()).snapshot!!
        snapshot = store.acceptManifest(snapshot, manifest) { now }.snapshot!!
        val original = memory.data!!.copyOf()
        assertEquals(Draft02TrustStore.Status.REJECTED, store.acceptManifest(snapshot, manifest) { now - 1 }.status)
        for (finalTime in listOf(now - 1, ByteBuffer.wrap(manifest, 45, 8).long + 1)) {
            var clock = now
            memory.beforeCommit = { clock = finalTime }
            assertEquals(Draft02TrustStore.Status.REJECTED, store.acceptManifest(snapshot, manifest) { clock }.status)
            assertArrayEquals(original, memory.data)
        }
    }

    @Test fun missingKeyAndPartialEnrollmentNeverCreateReplacementKeys() {
        val memory = Memory()
        val store = Draft02TrustStore(memory)
        assertEquals(Draft02TrustStore.Status.UNENROLLED_NEEDS_COMPARISON, store.inspect().status)
        assertEquals(0, memory.creations)
        store.enroll(receipt())
        memory.key = Draft02TrustStore.KeyState.ABSENT
        assertEquals(Draft02TrustStore.Status.KEY_LOST, store.inspect().status)
        assertEquals(Draft02TrustStore.Status.KEY_LOST, store.enroll(receipt()).status)
        assertEquals(1, memory.creations)
        memory.key = Draft02TrustStore.KeyState.READY
        memory.data = null
        assertEquals(Draft02TrustStore.Status.RECOVERY_REQUIRED, store.inspect().status)
        memory.key = Draft02TrustStore.KeyState.UNSUPPORTED
        assertEquals(Draft02TrustStore.Status.UNSUPPORTED, store.inspect().status)
    }

    @Test fun malformedAndTamperedStoredRecordsAreCorruptNotUnenrolled() {
        val memory = Memory()
        val store = Draft02TrustStore(memory)
        store.enroll(receipt())
        val valid = memory.data!!.copyOf()
        for (bad in listOf(ByteArray(0), ByteArray(16385), valid + byteArrayOf(0),
            valid.copyOf().apply { this[4] = 2 }, valid.copyOf().apply { ByteBuffer.wrap(this).putLong(5, 0) },
            valid.copyOf().apply { ByteBuffer.wrap(this).putLong(13, 1) },
            valid.copyOf().apply { ByteBuffer.wrap(this).putLong(50, 2) })) {
            memory.data = bad
            assertEquals(Draft02TrustStore.Status.CORRUPT, store.inspect().status)
        }
        memory.data = valid
        memory.openFailure = true
        assertEquals(Draft02TrustStore.Status.CORRUPT, store.inspect().status)
        memory.openFailure = false
        val snapshot = store.inspect().snapshot!!
        store.acceptManifest(snapshot, manifest) { now }
        val accepted = memory.data!!.copyOf()
        memory.data = accepted.copyOf().apply { this[lastIndex] = (this[lastIndex].toInt() xor 1).toByte() }
        assertEquals(Draft02TrustStore.Status.CORRUPT, store.inspect().status)
        memory.data = accepted.copyOf().apply { ByteBuffer.wrap(this).putLong(13, 2) }
        assertEquals(Draft02TrustStore.Status.CORRUPT, store.inspect().status)
    }

    @Test fun validOldSnapshotRestorationStillNeedsExternalFreshnessRatherThanClaimingRollbackResistance() {
        val memory = Memory()
        val store = Draft02TrustStore(memory)
        val snapshot = store.enroll(receipt()).snapshot!!
        val old = memory.data!!.copyOf()
        store.acceptManifest(snapshot, manifest) { now }
        memory.data = old // Model an attacker restoring an authentic older file.
        val restored = Draft02TrustStore(memory).inspect()
        assertEquals(Draft02TrustStore.Status.NEEDS_FRESHNESS, restored.status)
        assertEquals(0, restored.snapshot!!.version)
    }

    /** Deterministic transaction fault fixture; identity encoding is not a production crypto provider. */
    private class Memory : Draft02TrustStore.Storage, Draft02TrustStore.Session {
        var key = Draft02TrustStore.KeyState.ABSENT
        var data: ByteArray? = null
        var creations = 0
        var beforeCommit: () -> Unit = {}
        var openFailure = false
        @Synchronized override fun <T> locked(action: Draft02TrustStore.Session.() -> T) = action(this)
        override fun keyState() = key
        override fun createKey() { creations++; check(key == Draft02TrustStore.KeyState.ABSENT); key = Draft02TrustStore.KeyState.READY }
        override fun read() = data?.copyOf()
        override fun seal(plaintext: ByteArray) = plaintext.copyOf()
        override fun open(ciphertext: ByteArray): ByteArray {
            if (openFailure) throw Draft02TrustStore.Failure(Draft02TrustStore.Status.CORRUPT)
            return ciphertext.copyOf()
        }
        override fun write(ciphertext: ByteArray, preCommit: () -> Unit) {
            beforeCommit(); preCommit(); data = ciphertext.copyOf()
        }
    }
}

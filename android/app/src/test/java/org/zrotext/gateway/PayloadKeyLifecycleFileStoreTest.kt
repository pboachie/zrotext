// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment
import org.robolectric.annotation.Config
import java.util.UUID

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34], application = android.app.Application::class)
class PayloadKeyLifecycleFileStoreTest {
    private val context get() = RuntimeEnvironment.getApplication()
    private fun withStore(block: (String) -> Unit) {
        val alias = "zrotext.test.lifecycle.${UUID.randomUUID()}"
        try { block(alias) } finally {
            val file = PayloadKeyLifecycleFileStore.recordFile(context, alias)
            for (suffix in listOf("", ".new", ".bak", ".lock")) java.io.File(file.path + suffix).delete()
        }
    }

    @Test fun persistentBoundAndRevokedRecordsReloadWithoutAKeyReplacement() = withStore { alias ->
        val id = ByteArray(32) { 8 }; var created = 0; var present = false
        fun lifecycle() = PayloadKeyLifecycle(PayloadKeyLifecycleFileStore(context, alias))
        fun enroll() = lifecycle().enroll({ present }, { created++; present = true },
            { check(present); id.copyOf() }) { it }
        assertArrayEquals(id, enroll())
        assertArrayEquals(id, enroll())
        assertEquals(1, created)
        val bytes = PayloadKeyLifecycleFileStore.recordFile(context, alias).readBytes()
        assertEquals(38, bytes.size)
        id[0] = 9
        assertThrows(IllegalStateException::class.java) { enroll() }
        id[0] = 8
        lifecycle().revoke(id)
        present = false
        assertThrows(IllegalStateException::class.java) { enroll() }
        assertEquals(1, created)
    }

    @Test fun corruptedOversizedOrDeletedMetadataCannotAdoptAnExistingAlias() = withStore { alias ->
        val store = PayloadKeyLifecycleFileStore(context, alias)
        store.locked { it.write(PayloadKeyRecord.Bound(ByteArray(32) { 2 })) }
        val file = PayloadKeyLifecycleFileStore.recordFile(context, alias)
        for (bad in listOf(byteArrayOf(), ByteArray(39), ByteArray(38),
            PayloadKeyLifecycleFileStore.encode(PayloadKeyRecord.Bound(ByteArray(32) { 2 })) + 1)) {
            file.writeBytes(bad)
            assertThrows(Exception::class.java) { store.locked { it.read() } }
        }
        assertTrue(file.delete())
        var creates = 0
        assertThrows(IllegalStateException::class.java) {
            PayloadKeyLifecycle(store).enroll<ByteArray>({ true }, { creates++ }, { ByteArray(32) { 2 } }) { it }
        }
        assertEquals(0, creates)
    }

    @Test fun interruptedRevocationReplacementRefusesUseOfThePreviouslyBoundKey() = withStore { alias ->
        val id = ByteArray(32) { 7 }
        val store = PayloadKeyLifecycleFileStore(context, alias)
        store.locked { it.write(PayloadKeyRecord.Bound(id)) }
        val file = PayloadKeyLifecycleFileStore.recordFile(context, alias)
        // Process death after syncing the replacement but before atomic publication.
        java.io.File(file.path + ".new").writeBytes(PayloadKeyLifecycleFileStore.encode(PayloadKeyRecord.Revoked(id)))
        var operations = 0
        assertThrows(IllegalStateException::class.java) {
            PayloadKeyLifecycle(PayloadKeyLifecycleFileStore(context, alias))
                .existing(id, { id.copyOf() }, { it }) { operations++ }
        }
        assertEquals(0, operations)
        var created = 0
        assertThrows(IllegalStateException::class.java) {
            PayloadKeyLifecycle(PayloadKeyLifecycleFileStore(context, alias))
                .enroll<ByteArray>({ true }, { created++ }, { id.copyOf() }) { it }
        }
        assertEquals(0, created)
    }

    @Test fun metadataCodecRejectsUnknownStateVersionWidthAndEmptyIdentity() {
        val valid = PayloadKeyLifecycleFileStore.encode(PayloadKeyRecord.Bound(ByteArray(32) { 3 }))
        val altered = listOf(valid.copyOf(37), valid + 1,
            valid.copyOf().apply { this[4] = 2 }, valid.copyOf().apply { this[5] = 4 },
            valid.copyOf().apply { fill(0, 6, size) })
        for (bytes in altered) assertThrows(Exception::class.java) { PayloadKeyLifecycleFileStore.decode(bytes) }
        assertTrue(PayloadKeyLifecycleFileStore.decode(
            PayloadKeyLifecycleFileStore.encode(PayloadKeyRecord.Pending)) is PayloadKeyRecord.Pending)
    }

    @Test fun interruptedFirstCommitRefusesGenerationAndCommittedPendingRefusesRetry() = withStore { alias ->
        val file = PayloadKeyLifecycleFileStore.recordFile(context, alias)
        assertTrue(file.parentFile!!.isDirectory || file.parentFile!!.mkdirs())
        java.io.File(file.path + ".new").writeBytes(PayloadKeyLifecycleFileStore.encode(PayloadKeyRecord.Pending))
        var creates = 0
        fun enroll() = PayloadKeyLifecycle(PayloadKeyLifecycleFileStore(context, alias))
            .enroll({ false }, { creates++ }, { ByteArray(32) { 2 } }) { it }
        assertThrows(IllegalStateException::class.java) { enroll() }
        assertEquals(0, creates)
        assertTrue(java.io.File(file.path + ".new").delete())
        PayloadKeyLifecycleFileStore(context, alias).locked { it.write(PayloadKeyRecord.Pending) }
        assertThrows(IllegalStateException::class.java) { enroll() }
        assertEquals(0, creates)
    }
}

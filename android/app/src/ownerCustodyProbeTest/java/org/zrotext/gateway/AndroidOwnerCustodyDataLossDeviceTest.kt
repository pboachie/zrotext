// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import android.content.Context
import android.os.SystemClock
import android.os.ParcelFileDescriptor
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.DataInputStream
import java.io.DataOutputStream
import java.io.File
import java.io.FileOutputStream
import java.nio.ByteBuffer
import java.security.KeyStore
import java.util.UUID
import java.util.Base64
import javax.crypto.KeyGenerator
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith

/** Fixture-only synthetic retention. Never use these helpers with production owner material.
 * Run Preparation, terminate instrumentation, clear ONLY the isolated target package, then
 * run Recovery without reinstalling or clearing its separate test package.
 */
private object SyntheticOwnerDataLoss {
    const val targetPackage = "org.zrotext.gateway.ownercustodyfixture"
    const val testPackage = "$targetPackage.test"
    const val wrappingAlias = "synthetic-owner-data-loss-wrapper"
    const val marker = "synthetic-owner-data-loss-marker"
    const val preferences = "synthetic-owner-data-loss-preferences"
    private const val retainedDirectory = "synthetic-owner-data-loss-retained"

    fun contexts(): Pair<Context, Context> {
        val instrumentation = InstrumentationRegistry.getInstrumentation()
        val target = instrumentation.targetContext
        val retained = instrumentation.context
        assertEquals(targetPackage, target.packageName)
        assertEquals(testPackage, retained.packageName)
        assertNotEquals(target.applicationInfo.dataDir, retained.applicationInfo.dataDir)
        return Pair(target, retained)
    }

    private fun retainedPath(relative: String): String {
        check(relative in listOf("kit/backup.ztrb", "kit/card.ztrc", "separate-token/recovery.ztrk", "independent-identity/expected.bin"))
        return "no_backup/$retainedDirectory/$relative"
    }

    /** Instrumentation runs as target UID. A constant package-scoped shell pipe places
     * synthetic bytes in the DIFFERENT test UID's private directory, never external storage
     * or shell output. The target transfer file is transient and cannot survive pm clear.
     */
    fun retain(target: Context, retained: Context, relative: String, bytes: ByteArray) {
        check(target.packageName == targetPackage && retained.packageName == testPackage)
        val destination = retainedPath(relative)
        val transfer = File(target.noBackupFilesDir, "synthetic-owner-data-loss-transfer")
        try {
            write(transfer, bytes)
            shellTransfer("run-as $targetPackage cat no_backup/${transfer.name} | " +
                "run-as $testPackage sh -c 'umask 077; mkdir -p ${destination.substringBeforeLast('/')}; " +
                "cat > $destination; test -s $destination && printf TRANSFER_OK'")
            val readback = readRetained(target, retained, relative, bytes.size)
            try { assertTrue("Retained synthetic material readback must match", readback.contentEquals(bytes)) }
            finally { readback.fill(0) }
        } finally { transfer.delete() }
    }

    fun readRetained(target: Context, retained: Context, relative: String, maximum: Int): ByteArray {
        check(target.packageName == targetPackage && retained.packageName == testPackage)
        val source = retainedPath(relative)
        val transfer = File(target.noBackupFilesDir, "synthetic-owner-data-loss-transfer")
        try {
            shellTransfer("run-as $testPackage cat $source | " +
                "run-as $targetPackage sh -c 'umask 077; mkdir -p no_backup; " +
                "cat > no_backup/${transfer.name}; test -s no_backup/${transfer.name} && printf TRANSFER_OK'")
            return read(transfer, maximum)
        } finally { transfer.delete() }
    }

    private fun shellTransfer(command: String) {
        // executeShellCommand tokenizes a process command rather than shell syntax.
        // Its sh -c argument contains no whitespace; base64 encodes ONLY the constant
        // package/path plumbing above, never any retained owner bytes.
        val plumbing = Base64.getEncoder().encodeToString(command.toByteArray(Charsets.US_ASCII))
        val shell = "sh -c echo${'$'}{IFS}$plumbing|base64${'$'}{IFS}-d|sh"
        val descriptor = InstrumentationRegistry.getInstrumentation().uiAutomation.executeShellCommand(shell)
        val status = ParcelFileDescriptor.AutoCloseInputStream(descriptor).use {
            readAndroidOwnerCustodyFile(it, 32)
        }
        assertEquals("TRANSFER_OK", String(status, Charsets.US_ASCII))
    }

    fun write(file: File, bytes: ByteArray) {
        check(file.parentFile!!.isDirectory || file.parentFile!!.mkdirs())
        FileOutputStream(file).use { output -> output.write(bytes); output.flush(); output.fd.sync() }
    }

    fun read(file: File, maximum: Int): ByteArray = file.inputStream().use {
        readAndroidOwnerCustodyFile(it, maximum)
    }

    fun identityBytes(identity: AndroidOwnerCustodyIdentity): ByteArray = ByteArrayOutputStream().also { bytes ->
        DataOutputStream(bytes).use { output ->
            output.writeInt(1)
            output.write(identity.accountBytes())
            output.writeUTF(identity.origin)
            output.write(identity.fingerprintBytes())
        }
    }.toByteArray()

    fun identity(bytes: ByteArray): AndroidOwnerCustodyIdentity = DataInputStream(ByteArrayInputStream(bytes)).use { input ->
        check(input.readInt() == 1)
        val account = ByteArray(16).also { input.readFully(it) }
        val origin = input.readUTF()
        val fingerprint = ByteArray(32).also { input.readFully(it) }
        check(input.read() == -1)
        val uuid = ByteBuffer.wrap(account)
        AndroidOwnerCustodyIdentity(UUID(uuid.long, uuid.long), origin, AndroidOwnerCustodyKit.hex(fingerprint))
    }

    fun localKitFile(context: Context, identity: AndroidOwnerCustodyIdentity): File = File(
        File(context.noBackupFilesDir, "android-owner-custody-v1"),
        AndroidOwnerCustodyKit.hex(AndroidOwnerCustodyKit.hash(identity.accountBytes() + identity.origin.toByteArray(Charsets.UTF_8)))
    )

    fun keyStore(): KeyStore = KeyStore.getInstance("AndroidKeyStore").also { it.load(null) }

    fun assertNoSignatureAuthority(controller: AndroidOwnerCustodyController, expected: AndroidOwnerCustodyIdentity) {
        val origin = expected.origin.toByteArray(Charsets.UTF_8)
        fun uuid() = ByteBuffer.allocate(16).putLong(UUID.randomUUID().mostSignificantBits).putLong(1).array()
        val proposal = ByteBuffer.allocate(151 + origin.size).put(byteArrayOf(90, 84, 82, 69, 1))
            .put(expected.accountBytes()).put(uuid()).put(uuid()).put(uuid()).put(ByteArray(32) { 7 })
            .put(expected.fingerprintBytes()).putLong(1000).putLong(61000).putShort(origin.size.toShort()).put(origin).array()
        assertThrows(IllegalStateException::class.java) { controller.review(proposal, expected) }
        assertNull(controller.snapshot().review)
        assertNull(controller.snapshot().publicSignatures)
        assertFalse(controller.snapshot().recoveryVerified)
    }
}

@RunWith(AndroidJUnit4::class)
class AndroidOwnerCustodyDataLossPreparationTest {
    @Test fun retainSyntheticNativeKitOutsideTargetBeforeAppDataLoss() {
        val (target, retained) = SyntheticOwnerDataLoss.contexts()
        assertTrue(AndroidOwnerCustodyNativeBridge.available)
        val account = UUID.randomUUID()
        val accountBytes = ByteBuffer.allocate(16).putLong(account.mostSignificantBits).putLong(account.leastSignificantBits).array()
        val created = checkNotNull(AndroidOwnerCustodyNativeBridge.nativeCreate(accountBytes, "https://owner.example"))
        try {
            assertEquals(5, created.size)
            val expected = AndroidOwnerCustodyIdentity(account, "https://owner.example", AndroidOwnerCustodyKit.hex(created[3]))
            val kit = AndroidOwnerCustodyKit(created[0], created[1])
            assertEquals(expected, kit.identity)
            AndroidOwnerCustodyStore.create(target).put(kit) { true }
            assertTrue(AndroidOwnerCustodyKit.decode(SyntheticOwnerDataLoss.read(
                SyntheticOwnerDataLoss.localKitFile(target, expected), AndroidOwnerCustodyKit.MAX_RECORD)).matches(kit))

            // These deliberately separate private test-package records represent retained
            // external copies. No target-app file or wrapping key participates in Recovery.
            SyntheticOwnerDataLoss.retain(target, retained, "kit/backup.ztrb", created[0])
            SyntheticOwnerDataLoss.retain(target, retained, "kit/card.ztrc", created[1])
            SyntheticOwnerDataLoss.retain(target, retained, "separate-token/recovery.ztrk", created[2])
            SyntheticOwnerDataLoss.retain(target, retained, "independent-identity/expected.bin",
                SyntheticOwnerDataLoss.identityBytes(expected))
            SyntheticOwnerDataLoss.write(File(target.filesDir, SyntheticOwnerDataLoss.marker), byteArrayOf(1))
            assertTrue(target.getSharedPreferences(SyntheticOwnerDataLoss.preferences, Context.MODE_PRIVATE)
                .edit().putBoolean("prepared", true).commit())
            KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore").apply {
                init(KeyGenParameterSpec.Builder(SyntheticOwnerDataLoss.wrappingAlias,
                    KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
                    .setBlockModes(KeyProperties.BLOCK_MODE_GCM).setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                    .setKeySize(256).build())
                generateKey()
            }
            assertTrue(SyntheticOwnerDataLoss.keyStore().containsAlias(SyntheticOwnerDataLoss.wrappingAlias))
        } finally {
            created.getOrNull(2)?.fill(0)
            AndroidOwnerCustodyNativeBridge.nativeCloseAll()
        }
    }
}

@RunWith(AndroidJUnit4::class)
class AndroidOwnerCustodyDataLossRecoveryTest {
    @Test fun retainedCopiesRestoreAfterActualTargetDataAndWrappingKeyLossWithoutAuthority() {
        val (target, retained) = SyntheticOwnerDataLoss.contexts()
        assertTrue(AndroidOwnerCustodyNativeBridge.available)
        assertFalse("Run only after clearing the isolated target app", File(target.filesDir, SyntheticOwnerDataLoss.marker).exists())
        assertTrue(target.getSharedPreferences(SyntheticOwnerDataLoss.preferences, Context.MODE_PRIVATE).all.isEmpty())
        assertFalse("The target UID's synthetic local wrapping key must also be gone",
            SyntheticOwnerDataLoss.keyStore().containsAlias(SyntheticOwnerDataLoss.wrappingAlias))
        assertFalse(File(target.noBackupFilesDir, "android-owner-custody-v1").exists())
        val backup = SyntheticOwnerDataLoss.readRetained(target, retained, "kit/backup.ztrb", 748)
        val card = SyntheticOwnerDataLoss.readRetained(target, retained, "kit/card.ztrc", 645)
        val token = SyntheticOwnerDataLoss.readRetained(target, retained, "separate-token/recovery.ztrk", 79)
        val expected = SyntheticOwnerDataLoss.identity(SyntheticOwnerDataLoss.readRetained(
            target, retained, "independent-identity/expected.bin", 566))
        assertFalse(SyntheticOwnerDataLoss.localKitFile(target, expected).exists())
        assertFalse(File(target.noBackupFilesDir, "android-owner-custody-v1").exists())
        assertEquals(79, token.size)
        try {
            val wrongIdentities = listOf(expected.copy(account = UUID.randomUUID()),
                expected.copy(origin = "https://other.example"),
                expected.copy(fingerprint = if (expected.fingerprint == "00".repeat(32)) "11".repeat(32) else "00".repeat(32)))
            for (wrong in wrongIdentities) {
                val attempt = token.copyOf()
                assertThrows(IllegalStateException::class.java) {
                    AndroidOwnerCustodyNativeBridge.nativeRecoveryCheck(backup, card, attempt,
                        wrong.accountBytes(), wrong.origin, wrong.fingerprintBytes())
                }
                assertTrue(attempt.all { it == 0.toByte() })
            }
            // Recompute the card's public backup digest: this reaches AEAD rejection instead
            // of merely testing the cheap public digest check.
            val corrupted = backup.copyOf().also { it[it.lastIndex] = (it.last().toInt() xor 1).toByte() }
            val matchingCard = card.copyOf().also { AndroidOwnerCustodyKit.hash(corrupted).copyInto(it, it.size - 32) }
            val attempt = token.copyOf()
            assertThrows(IllegalStateException::class.java) {
                AndroidOwnerCustodyNativeBridge.nativeRecoveryCheck(corrupted, matchingCard, attempt,
                    expected.accountBytes(), expected.origin, expected.fingerprintBytes())
            }
            assertTrue(attempt.all { it == 0.toByte() })
            assertFalse(SyntheticOwnerDataLoss.localKitFile(target, expected).exists())

            val controller = AndroidOwnerCustodyController(AndroidOwnerCustodyNative(), AndroidOwnerCustodyStore.create(target),
                { SystemClock.elapsedRealtime() }) // No owner session is fabricated by recovery.
            try {
                assertFalse(controller.snapshot().recoveryVerified)
                val freshToken = token.copyOf()
                controller.recover(backup, card, freshToken, expected, separatelyRetained = true)
                assertTrue(freshToken.all { it == 0.toByte() })
                assertTrue(controller.snapshot().recoveryVerified)
                assertEquals(expected, controller.snapshot().identity)
                assertFalse(controller.snapshot().canReveal)
                assertNull(controller.snapshot().review)
                assertNull(controller.snapshot().publicSignatures)
                val restored = SyntheticOwnerDataLoss.read(SyntheticOwnerDataLoss.localKitFile(target, expected), AndroidOwnerCustodyKit.MAX_RECORD)
                assertTrue(AndroidOwnerCustodyKit.decode(restored).matches(AndroidOwnerCustodyKit(backup, card)))
                assertFalse(String(restored, Charsets.US_ASCII).contains("ZTRK1-"))
                SyntheticOwnerDataLoss.assertNoSignatureAuthority(controller, expected)
            } finally { controller.close() }
        } finally {
            token.fill(0)
            AndroidOwnerCustodyNativeBridge.nativeCloseAll()
        }
    }
}

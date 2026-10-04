// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import android.os.Build
import android.os.Bundle
import android.provider.Settings
import androidx.room.Room
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith
import java.security.KeyStore
import java.security.KeyPairGenerator
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec
import java.util.UUID
import javax.crypto.KeyAgreement

/** Separate app identity; fresh owned aliases and in-memory Room. Never samples a SIM or sends SMS. */
@RunWith(AndroidJUnit4::class)
class PreparationProbeDeviceTest {
    private fun isolated() {
        val instrumentation = InstrumentationRegistry.getInstrumentation()
        check(InstrumentationRegistry.getArguments().getString("isolatedPreparationProbe") == "true")
        check(Build.VERSION.SDK_INT >= 31)
        check(instrumentation.targetContext.packageName == PreparationProbeRunner.APP)
        check(instrumentation.context.packageName == PreparationProbeRunner.APP + ".test")
        check(instrumentation.targetContext.applicationContext.javaClass == android.app.Application::class.java)
        val info = instrumentation.targetContext.packageManager.getPackageInfo(PreparationProbeRunner.APP,
            android.content.pm.PackageManager.GET_PERMISSIONS)
        check(info.requestedPermissions.isNullOrEmpty())
    }
    private fun withKey(block: (DevicePayloadKeyStore, DevicePayloadPublic, () -> Unit) -> Unit) {
        isolated()
        val alias = "zrotext.probe.preparation.${UUID.randomUUID()}"
        val store = KeyStore.getInstance("AndroidKeyStore").apply { load(null, null) }
        check(!store.containsAlias(alias))
        try {
            val key = DevicePayloadKeyStore(InstrumentationRegistry.getInstrumentation().targetContext, alias)
            block(key, key.getOrCreateForEnrollment()) { store.deleteEntry(alias) }
        } finally {
            if (store.containsAlias(alias)) store.deleteEntry(alias)
            val file = PayloadKeyLifecycleFileStore.recordFile(InstrumentationRegistry.getInstrumentation().targetContext, alias)
            for (suffix in listOf("", ".new", ".bak", ".lock")) java.io.File(file.path + suffix).delete()
        }
        check(!store.containsAlias(alias))
    }

    /** Default round-trip runs in CI; explicit stages retain only an owned synthetic alias.
     * BOOT_COUNT is an observation, never trusted UTC, attestation or rollback protection. */
    @Test fun payloadCustodyReloadNeverRecreatesLostOrRevokedIdentity() {
        isolated()
        val args = InstrumentationRegistry.getArguments()
        val stage = args.getString("custodyStage") ?: "roundtrip"
        require(stage in setOf("roundtrip", "enroll", "reload", "lose", "revoke", "cleanup"))
        // Automatic cleanup belongs only to the default freshly allocated round-trip.
        require(stage != "roundtrip" || !args.containsKey("custodySession"))
        val session = args.getString("custodySession") ?: UUID.randomUUID().toString().replace("-", "")
        require(Regex("[0-9a-f]{32}").matches(session))
        val alias = "zrotext.probe.custody.$session"
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        val store = KeyStore.getInstance("AndroidKeyStore").apply { load(null, null) }
        fun key() = DevicePayloadKeyStore(context, alias)
        fun bootCount() = Settings.Global.getInt(context.contentResolver, Settings.Global.BOOT_COUNT, -1)
        fun cleanup() {
            if (store.containsAlias(alias)) store.deleteEntry(alias)
            val file = PayloadKeyLifecycleFileStore.recordFile(context, alias)
            for (suffix in listOf("", ".new", ".bak", ".lock")) java.io.File(file.path + suffix).delete()
        }
        fun enroll(): DevicePayloadPublic {
            check(!store.containsAlias(alias))
            check(!PayloadKeyLifecycleFileStore.recordFile(context, alias).exists())
            return key().getOrCreateForEnrollment()
        }
        fun reload(id: ByteArray, security: String): DevicePayloadPublic {
            val public = key().existingPublic()
            assertArrayEquals(id, public.keyId)
            assertEquals(security, public.security.name)
            assertNull(store.getKey(alias, null)?.encoded)
            val sender = KeyPairGenerator.getInstance("EC").run {
                initialize(ECGenParameterSpec("secp256r1")); generateKeyPair()
            }
            val expected = KeyAgreement.getInstance("ECDH").run {
                init(sender.private); doPhase(DevicePayloadKeyStore.decodePoint(public.point), true); generateSecret()
            }
            val actual = key().agreeExisting(DevicePayloadKeyStore.encodePoint(sender.public as ECPublicKey), id)
            try { assertArrayEquals(expected, actual) } finally { expected.fill(0); actual.fill(0) }
            return public
        }
        fun ownedRecord(id: ByteArray) {
            val record = PayloadKeyLifecycleFileStore(context, alias).locked { it.read() }
            val stored = when (record) {
                is PayloadKeyRecord.Bound -> record.keyId()
                is PayloadKeyRecord.Revoked -> record.keyId()
                else -> error("Owned custody fixture unavailable")
            }
            assertArrayEquals(id, stored)
        }
        fun lose(id: ByteArray, security: String) {
            reload(id, security)
            store.deleteEntry(alias)
            assertThrows(IllegalStateException::class.java) { key().getOrCreateForEnrollment() }
            assertThrows(IllegalStateException::class.java) { key().existingPublic() }
            assertFalse(store.containsAlias(alias))
            ownedRecord(id)
        }
        fun revoke(id: ByteArray) {
            ownedRecord(id)
            key().revokeExisting(id)
            assertThrows(IllegalStateException::class.java) { key().existingPublic() }
            store.deleteEntry(alias)
            assertThrows(IllegalStateException::class.java) { key().getOrCreateForEnrollment() }
            assertThrows(IllegalStateException::class.java) { key().existingPublic() }
            assertFalse(store.containsAlias(alias))
        }
        fun pin(): ByteArray {
            val value = requireNotNull(args.getString("custodyKeyId"))
            require(Regex("[0-9a-f]{64}").matches(value))
            return ByteArray(32) { value.substring(it * 2, it * 2 + 2).toInt(16).toByte() }
        }
        fun expectedSecurity(): String = requireNotNull(args.getString("custodySecurity")).also {
            require(it in PayloadKeySecurity.entries.map { level -> level.name })
        }
        when (stage) {
            "roundtrip" -> try {
                val public = enroll()
                assertThrows(AssertionError::class.java) { reload(ByteArray(32), public.security.name) }
                assertThrows(AssertionError::class.java) { reload(public.keyId, "SYNTHETIC_WRONG_LEVEL") }
                reload(public.keyId, public.security.name)
                lose(public.keyId, public.security.name)
                revoke(public.keyId)
            } finally { cleanup() }
            "enroll" -> {
                val public = enroll()
                val count = bootCount(); check(count >= 0)
                InstrumentationRegistry.getInstrumentation().addResults(Bundle().apply {
                    putString("custodyKeyId", public.keyId.joinToString("") { "%02x".format(it.toInt() and 255) })
                    putString("custodySecurity", public.security.name)
                    putString("custodyBootCount", count.toString())
                })
            }
            "reload" -> {
                val previous = requireNotNull(args.getString("custodyBootCount")).toInt()
                require(previous >= 0)
                val reboot = args.getString("custodyRequireReboot") ?: "false"
                require(reboot in setOf("true", "false"))
                val current = bootCount()
                if (reboot == "true") check(current > previous) else check(current == previous)
                reload(pin(), expectedSecurity())
            }
            "lose" -> lose(pin(), expectedSecurity())
            "revoke" -> revoke(pin())
            "cleanup" -> {
                // Never let cleanup arguments remove an unpinned fixture identity.
                ownedRecord(pin())
                cleanup()
            }
        }
    }

    @Test fun independentTinkWrapOpensThroughExistingKeystoreAndLostKeyCannotBeRecreated() = withKey { key, public, lose ->
        val sample = SealedPreparationDeviceSample(public)
        val parts = sample.proof.parts()
        fun open() = Draft02PublicJcaKeystoreHpke.openDeviceCek(key, parts.header, parts.protected,
            1, parts.keyId, parts.enc, parts.wrap)
        val cek = open()
        val chars = Draft02Body.open(sample.proof, cek)
        try { assertEquals("Synthetic device preparation", String(chars)); assertTrue(cek.all { it == 0.toByte() }) }
        finally { chars.fill('\u0000') }
        assertThrows(Exception::class.java) {
            Draft02PublicJcaKeystoreHpke.openDeviceCek(key, parts.header, parts.protected.copyOf().apply { this[0] = 9 },
                1, parts.keyId, parts.enc, parts.wrap)
        }
        lose()
        assertThrows(Exception::class.java) { open() }
        assertThrows(Exception::class.java) { key.existingPublic() }
        assertThrows(Exception::class.java) { key.getOrCreateForEnrollment() }
    }

    @Test fun preparationRequiresActualReportedHardwareAndNeverProducesAlphaState() = withKey { key, public, _ ->
        val sample = SealedPreparationDeviceSample(public)
        val instrumentation = InstrumentationRegistry.getInstrumentation()
        val db = Room.inMemoryDatabaseBuilder(instrumentation.targetContext, SmsJournalDatabase::class.java)
            .allowMainThreadQueries().build()
        try {
            assertTrue(db.attempts().installVerifiedLineBinding(sample.fixture.binding(), listOf(ActiveSimCard(3, 7))))
            val result = Draft02OutboundPreparation.prepare(sample.envelope, sample.grant, db, key) { sample.current() }
            val hardware = public.security in setOf(PayloadKeySecurity.STRONGBOX, PayloadKeySecurity.TRUSTED_ENVIRONMENT)
            val report = if (hardware) "platform-reported-hardware" else "unsupported"
            instrumentation.addResults(Bundle().apply { putString("preparationCustody", report) })
            if (hardware) {
                assertTrue(result is Draft02OutboundPreparation.Prepared)
                (result as Draft02OutboundPreparation.Prepared).consume { assertEquals("Synthetic device preparation", String(it)) }
                assertThrows(Exception::class.java) { result.consume {} }
            } else {
                assertEquals(Draft02OutboundPreparation.Unsupported, result)
                assertEquals("aborted", db.sealedPreparations().find(sample.grant.accountId, sample.grant.messageId)?.state)
            }
            assertNull(db.attempts().getAttempt(sample.grant.attemptId))
            assertEquals(0, db.openHelper.readableDatabase.query("SELECT COUNT(*) FROM alpha_radio_events").use { it.moveToFirst(); it.getInt(0) })
            assertEquals(Draft02OutboundPreparation.Rejected,
                Draft02OutboundPreparation.prepare(sample.envelope, sample.grant, db, key) { sample.current() })
        } finally { db.close() }
    }
}

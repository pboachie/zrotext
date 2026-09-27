// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import android.os.Build
import android.os.Bundle
import androidx.room.Room
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith
import java.security.KeyStore
import java.util.UUID

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
            val key = DevicePayloadKeyStore(alias)
            block(key, key.getOrCreateForEnrollment()) { store.deleteEntry(alias) }
        } finally { if (store.containsAlias(alias)) store.deleteEntry(alias) }
        check(!store.containsAlias(alias))
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

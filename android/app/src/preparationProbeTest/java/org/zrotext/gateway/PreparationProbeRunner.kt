// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import android.app.Application
import android.content.Context
import android.os.Bundle
import androidx.test.runner.AndroidJUnitRunner

/** No discovery or caller-selected tests; this APK can execute only its synthetic probe. */
class PreparationProbeRunner : AndroidJUnitRunner() {
    private var rejectSelector = false
    override fun onCreate(arguments: Bundle) {
        val custody = arguments.getString("class") == CUSTODY_TEST
        val allowed = if (custody) setOf("class", "isolatedPreparationProbe", "custodyStage", "custodySession",
            "custodyKeyId", "custodySecurity", "custodyBootCount", "custodyRequireReboot")
            else setOf("class", "isolatedPreparationProbe")
        rejectSelector = arguments.keySet().any { it !in allowed } ||
            arguments.getString("isolatedPreparationProbe") != "true" ||
            arguments.getString("class") !in setOf(null, TEST, HPKE_TEST, CUSTODY_TEST) ||
            custody && (arguments.getString("custodyStage") !in setOf("enroll", "reload", "lose", "revoke", "cleanup") ||
                !Regex("[0-9a-f]{32}").matches(arguments.getString("custodySession").orEmpty()))
        super.onCreate(Bundle(arguments).apply {
            putString("class", when {
                custody -> CUSTODY_TEST
                arguments.getString("class") == HPKE_TEST -> HPKE_TEST
                else -> TEST
            })
            putString("isolatedPreparationProbe", "true")
        })
    }

    override fun onStart() {
        if (rejectSelector) {
            finish(0, Bundle().apply { putString("probeRejected", "selector") })
            return
        }
        super.onStart()
    }

    override fun newApplication(cl: ClassLoader, className: String, context: Context): Application {
        check(context.packageName == APP && className == "android.app.Application")
        return super.newApplication(cl, className, context)
    }

    companion object {
        const val APP = "org.zrotext.gateway.preparationprobe"
        const val TEST = "org.zrotext.gateway.PreparationProbeDeviceTest"
        const val HPKE_TEST = "org.zrotext.gateway.WolfHpkeKeystoreBridgeDeviceTest"
        const val CUSTODY_TEST = TEST + "#payloadCustodyReloadNeverRecreatesLostOrRevokedIdentity"
    }
}

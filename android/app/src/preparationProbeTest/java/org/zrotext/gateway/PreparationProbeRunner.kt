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
        rejectSelector = arguments.keySet().any { it !in setOf("class", "isolatedPreparationProbe") } ||
            arguments.getString("isolatedPreparationProbe") != "true" ||
            arguments.getString("class") !in setOf(null, TEST)
        super.onCreate(Bundle().apply { putString("class", TEST); putString("isolatedPreparationProbe", "true") })
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
    }
}

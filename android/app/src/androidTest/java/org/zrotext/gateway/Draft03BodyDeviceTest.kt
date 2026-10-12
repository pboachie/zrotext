// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.runner.RunWith

/** Synthetic body authentication only: no custody, HPKE receiver, application startup or radio. */
@RunWith(AndroidJUnit4::class)
class Draft03BodyDeviceTest : Draft03BodyCorpus()

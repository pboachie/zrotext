// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.runner.RunWith

/** Pure public evidence only; does not acquire device keys or execute fetch/preparation/radio. */
@RunWith(AndroidJUnit4::class)
class Draft03DispatchWireDeviceTest : Draft03DispatchWireCorpus()

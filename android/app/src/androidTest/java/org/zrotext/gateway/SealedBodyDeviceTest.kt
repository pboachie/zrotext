// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway
import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.runner.RunWith
/** Crypto and divideMessage only: no SmsManager.send methods, subscriptions, permissions or app UI. */
@RunWith(AndroidJUnit4::class)
class SealedBodyDeviceTest : SealedBodyCorpus()

// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.runner.RunWith

/** Public cryptographic verification only; no app startup, custody, permissions or radio. */
@RunWith(AndroidJUnit4::class)
class Draft03AuthorityEnvelopeDeviceTest : Draft03AuthorityEnvelopeCorpus()

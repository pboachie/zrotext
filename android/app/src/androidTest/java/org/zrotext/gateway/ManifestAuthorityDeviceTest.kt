// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.runner.RunWith

/** Cryptography only: no app launch, persistent state, permissions or radio operations. */
@RunWith(AndroidJUnit4::class)
class ManifestAuthorityDeviceTest : ManifestAuthorityCorpus()

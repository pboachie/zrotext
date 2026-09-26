// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34])
class ManifestIdentityCorpusTest : ManifestIdentityCorpus()

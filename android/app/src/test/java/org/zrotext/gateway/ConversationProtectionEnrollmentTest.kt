// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import org.junit.Assert.*
import org.junit.Test

class ConversationProtectionEnrollmentTest {
    @Test fun missingKeysWithRetainedContentOrSuppressionNeverCreateReplacements() {
        var creations = 0; var verifications = 0
        assertThrows(IllegalStateException::class.java) {
            ConversationProtectionEnrollment.prepare({ false }, { true }, { creations++ }, { verifications++ }, {})
        }
        assertEquals(0, creations); assertEquals(0, verifications)
    }
    @Test fun existingUnusableKeysNeverFallBackToCreation() {
        var creations = 0
        assertThrows(IllegalStateException::class.java) {
            ConversationProtectionEnrollment.prepare({ true }, { error("Existing key needs no state fallback") },
                { creations++ }, { error("Existing key unavailable") }, {})
        }
        assertEquals(0, creations)
    }
    @Test fun explicitEmptyStateEnrollmentCreatesOnceAndVerifiesExistingKeys() {
        var present = false; var creations = 0; var verifications = 0
        fun enroll() = ConversationProtectionEnrollment.prepare({ present }, { false },
            { creations++; present = true }, { check(present); verifications++ }, {})
        enroll(); enroll()
        assertEquals(1, creations); assertEquals(2, verifications)
    }
    @Test fun foregroundLossAfterInventoryReadCannotCreateKeys() {
        var live = true; var creations = 0
        assertThrows(IllegalStateException::class.java) {
            ConversationProtectionEnrollment.prepare({ false }, { live = false; false },
                { creations++ }, {}, { check(live) })
        }
        assertEquals(0, creations)
    }
}

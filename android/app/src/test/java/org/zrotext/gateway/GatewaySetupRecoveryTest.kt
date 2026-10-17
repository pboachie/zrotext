// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import org.junit.Assert.*
import org.junit.Test
import java.security.ProviderException
import java.util.UUID

class GatewaySetupRecoveryTest {
    private val fingerprint = "AB".repeat(32)
    private val locator = PairingLocator("https://gateway.example.test",
        UUID.fromString("11111111-1111-4111-8111-111111111111"), fingerprint)

    @Test fun transientKeyReadRetainsUnknownOutcomeAndLaterReadsTheOriginalBinding() {
        var ready = false
        var bindingReads = 0
        val identity = { ExistingSigningIdentity.observe({ true }) {
            if (!ready) throw ProviderException("Temporarily unavailable")
            fingerprint
        } }
        val read = { observePairingRecovery(locator, identity) {
            bindingReads++
            PairingBinding(PairingBindingStatus.PENDING, null, "12345678")
        } }
        assertEquals(PairingRecoveryObservation(GatewaySetupRecovery.UNAVAILABLE), read())
        assertEquals(0, bindingReads)
        ready = true
        val recovered = read()
        assertEquals(GatewaySetupRecovery.COMPARE, recovered.recovery)
        assertEquals("12345678", recovered.binding?.comparisonCode)
        assertEquals(1, bindingReads)
    }

    @Test fun aliasLookupFailureIsUnavailableAndNeverChecksNetwork() {
        val identity = ExistingSigningIdentity.observe({ throw ProviderException("Unavailable") }) {
            fail("An unavailable alias lookup cannot read a fingerprint"); fingerprint
        }
        assertEquals(ExistingSigningIdentity.Unavailable, identity)
        assertEquals(PairingRecoveryObservation(GatewaySetupRecovery.UNAVAILABLE),
            observePairingRecovery(locator, { identity }) { error("Must not contact server") })
    }

    @Test fun confirmedAbsentAliasDoesNotReadOrCreateAKeyOrContactServer() {
        val identity = ExistingSigningIdentity.observe({ false }) {
            fail("An absent alias cannot read or create a key"); fingerprint
        }
        assertEquals(ExistingSigningIdentity.Missing, identity)
        assertEquals(PairingRecoveryObservation(GatewaySetupRecovery.KEYS_LOST),
            observePairingRecovery(locator, { identity }) { error("Must not contact server") })
    }

    @Test fun confirmedDifferentFingerprintRequiresExplicitReplacementWithoutNetwork() {
        val identity = ExistingSigningIdentity.observe({ true }) { "CD".repeat(32) }
        assertEquals(PairingRecoveryObservation(GatewaySetupRecovery.KEYS_LOST),
            observePairingRecovery(locator, { identity }) { error("Must not contact server") })
    }
}

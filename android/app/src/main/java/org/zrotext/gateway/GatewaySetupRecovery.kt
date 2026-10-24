// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import android.content.Context
import java.util.UUID

/** Persists public navigation only. A fresh existing-key status proof is required on every resume. */
internal object PairingLocatorStore {
    private const val PREFS = "pairing-locator"
    fun read(context: Context): PairingLocator? = runCatching {
        val prefs = context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
        PairingLocator(checkNotNull(prefs.getString("origin", null)),
            UUID.fromString(checkNotNull(prefs.getString("pairing_id", null))),
            checkNotNull(prefs.getString("fingerprint", null)))
    }.getOrNull()

    fun save(context: Context, locator: PairingLocator): Boolean = context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
        .edit().clear().putString("origin", locator.origin).putString("pairing_id", locator.pairingId.toString())
        .putString("fingerprint", locator.fingerprint).commit()

    fun clear(context: Context): Boolean = context.getSharedPreferences(PREFS, Context.MODE_PRIVATE).edit().clear().commit()
}

internal data class PairingRecoveryObservation(val recovery: GatewaySetupRecovery, val binding: PairingBinding? = null)

/** This boundary can read only the existing identity and binding, never create or claim one. */
internal fun observePairingRecovery(locator: PairingLocator, identity: () -> ExistingSigningIdentity,
    readBinding: () -> PairingBinding): PairingRecoveryObservation {
    when (val key = runCatching(identity).getOrDefault(ExistingSigningIdentity.Unavailable)) {
        ExistingSigningIdentity.Missing -> return PairingRecoveryObservation(GatewaySetupRecovery.KEYS_LOST)
        ExistingSigningIdentity.Unavailable -> return PairingRecoveryObservation(GatewaySetupRecovery.UNAVAILABLE)
        is ExistingSigningIdentity.Present -> if (key.fingerprint != locator.fingerprint)
            return PairingRecoveryObservation(GatewaySetupRecovery.KEYS_LOST)
    }
    val binding = runCatching(readBinding).getOrNull()
        ?: return PairingRecoveryObservation(GatewaySetupRecovery.UNAVAILABLE)
    return PairingRecoveryObservation(GatewaySetupRecovery.from(binding.status), binding)
}

internal enum class GatewaySetupRecovery(val title: String, val detail: String) {
    NEW("Connect this phone", "Keep the owner dashboard open. Select the service you trust, then scan its pairing QR."),
    CHECKING("Checking your last pairing", "Your progress is saved. This checks the original phone key; it does not repeat an approval or start a connection."),
    COMPARE("Compare on both screens", "Compare both complete values with your owner dashboard, then approve there. The result updates automatically."),
    APPROVED("Phone approval confirmed", "Connect and finish phone protection before enabling SMS receiving. Then choose the active SIM and review access. Account and billing steps stay on the website."),
    EXPIRED("Replace the expired pairing", "Your account and subscription are unchanged. Replace only this pairing in the owner dashboard, then scan the new QR."),
    CANCELLED("Pairing was cancelled", "Your account and subscription are unchanged. Create a new pairing in the owner dashboard when you are ready."),
    PROOF_REQUIRED("Pairing needs a new QR", "The original key proof did not finish. Cancel this pairing in the owner dashboard and replace only this step; no claim is retried automatically."),
    KEYS_LOST("Original phone key is unavailable", "Your account and subscription remain on the website. Revoke the old phone there and create a new pairing. Recovery never replaces a key automatically."),
    UNAVAILABLE("Could not confirm pairing yet", "Keep your saved setup. Check the internet connection and original ticket in the owner dashboard. Status checks are safe to retry; approvals and connection starts are not repeated.");

    companion object {
        fun from(status: PairingBindingStatus): GatewaySetupRecovery = when (status) {
            PairingBindingStatus.PENDING -> COMPARE
            PairingBindingStatus.APPROVED -> APPROVED
            PairingBindingStatus.EXPIRED -> EXPIRED
            PairingBindingStatus.CANCELLED -> CANCELLED
            PairingBindingStatus.PROOF_REJECTED, PairingBindingStatus.AWAITING_PROOF -> PROOF_REQUIRED
        }
    }
}

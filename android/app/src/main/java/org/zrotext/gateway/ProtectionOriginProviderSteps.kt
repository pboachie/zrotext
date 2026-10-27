// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import java.util.UUID

/** Provider calls live outside Room, ingress and protected-storage locks. The production
 * implementation is AndroidKeyStore; the test seam cannot manufacture an installed origin. */
internal interface ProtectionOriginProviderPort {
    fun aliasesMatchRetained(rows: List<ProtectionSetupProvider>)
    fun generate(kind: String, probeContext: ByteArray): ByteArray
    fun requireResult(kind: String, expected: ByteArray, probeContext: ByteArray)
}

internal class ProtectionOriginProviderSteps(private val dao: ProtectionSetupDao,
    private val provider: ProtectionOriginProviderPort, private val at: () -> Long) {
    fun complete(command: ProtectionSetupCommand, opening: ProtectionOriginWire.Opening,
        current: () -> Unit): List<ProtectionSetupProvider> {
        current(); check(dao.command() == command)
        val context = ProtectionOriginProof.probeContext(command, opening)
        provider.aliasesMatchRetained(dao.providers())
        current()
        for (kind in ProtectionSetupProvider.KINDS) {
            current(); check(dao.command() == command)
            val prior = dao.provider(kind)
            if (prior != null) {
                prior.requireShape()
                val result = checkNotNull(prior.evidenceB64url) { "Original provider result needs recovery" }
                provider.requireResult(kind, SealedDispatch03Frames.decodeCanonical(result, 1, 512), context)
                current(); check(dao.provider(kind) == prior)
                continue
            }
            val operation = ProtectionSetupProvider(kind, command.commandId, UUID.randomUUID().toString(), at())
            check(dao.reserveProviderEntry(command, operation, current))
            current()
            val returned = provider.generate(kind, context.copyOf()).copyOf()
            // Preserve only the actual result of the exact already-burned call. A pause,
            // reconnect or Stop during provider work prevents progression, not history.
            dao.retainProviderEvidence(operation, Profile03ElectionEncoding.encode(returned),
                Draft02OutboundPreparation.hex(ProtectionOriginProof.sha(returned))) {
                check(dao.command() == command && dao.provider(kind)?.operationId == operation.operationId)
            }
            current()
            provider.requireResult(kind, returned, context)
            current()
        }
        return dao.providers().also { current(); check(it.size == 4 && it.all { row -> row.evidenceB64url != null }) }
    }
}

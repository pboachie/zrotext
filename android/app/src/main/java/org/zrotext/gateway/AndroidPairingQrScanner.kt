// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

/** Permissionless scanner boundary. No transport, key creation or automatic retry. */
internal fun interface AndroidPairingQrScanSource {
    fun start(callback: (AndroidPairingQrScanResult) -> Unit)
}

internal sealed interface AndroidPairingQrScanResult {
    class Scanned(val raw: String) : AndroidPairingQrScanResult {
        override fun toString() = "Scanned(redacted)"
    }
    data object Canceled : AndroidPairingQrScanResult
    data object Unavailable : AndroidPairingQrScanResult
}

internal sealed interface AndroidPairingQrClaimOutcome {
    class Verified(val pairing: VerifiedPairing) : AndroidPairingQrClaimOutcome
    data object Unknown : AndroidPairingQrClaimOutcome
}

/** A scan transports existing claim inputs; explicit browser comparison/approval still follows. */
internal class AndroidPairingQrScanner(
    private val source: AndroidPairingQrScanSource,
    private val knownOrigin: () -> String,
    private val elapsed: () -> Long,
    private val claim: (AndroidPairingQrClaimInputs, (AndroidPairingQrClaimOutcome) -> Unit) -> Unit,
    private val verified: (VerifiedPairing, Long, String) -> Unit = { _, _, _ -> },
    private val changed: () -> Unit = {}
) : AutoCloseable {
    enum class Phase { IDLE, SCANNING, REVIEW, CLAIMING, VERIFIED, UNKNOWN, CLOSED }
    data class Snapshot(val generation: Long, val phase: Phase, val expectedOrigin: String?, val scannedOrigin: String?,
        val canScan: Boolean, val canConfirm: Boolean, val canUseManual: Boolean, val status: String)

    private val gate = Any()
    private var generation = 0L
    private var phase = Phase.IDLE
    private var resumed = true
    private var scanFlight: Long? = null
    private var selectedOrigin: String? = null
    private var scannedOrigin: String? = null
    private var started = 0L
    private var payload: AndroidPairingQrPayload? = null
    private var claimInputs: AndroidPairingQrClaimInputs? = null
    private var status = "Scan the current pairing QR, or use the existing manual pairing fields."

    fun snapshot(): Snapshot = synchronized(gate) {
        expireLocked()
        Snapshot(generation, phase, selectedOrigin, scannedOrigin,
            resumed && phase == Phase.IDLE && scanFlight == null,
            resumed && phase == Phase.REVIEW && payload != null,
            resumed && phase == Phase.IDLE && scanFlight == null, status)
    }

    /** Call only from the scan button. A canceled platform scan remains in flight until it settles. */
    fun scan(): Boolean {
        val ticket = synchronized(gate) {
            expireLocked()
            if (!resumed || phase != Phase.IDLE || scanFlight != null) return false
            val independentlyKnown = try { AndroidPairingQrPayload.canonicalOrigin(knownOrigin()) }
                catch (_: Exception) { status = "Enter the HTTPS server origin you know before scanning."; changed(); return false }
            val at = try { elapsed().also { require(it >= 0) } }
                catch (_: Exception) { status = "Scanner unavailable. Use the existing manual pairing fields."; changed(); return false }
            generation++; selectedOrigin = independentlyKnown; scannedOrigin = null
            started = at; phase = Phase.SCANNING; scanFlight = generation
            status = "Scanner open. No pairing request has been sent."
            generation
        }
        changed()
        try { source.start { receive(ticket, it) } }
        catch (_: Exception) { receive(ticket, AndroidPairingQrScanResult.Unavailable) }
        return true
    }

    private fun receive(ticket: Long, result: AndroidPairingQrScanResult) {
        synchronized(gate) {
            if (scanFlight == ticket) scanFlight = null
            if (ticket != generation || phase != Phase.SCANNING) return
            expireLocked()
            if (ticket != generation || phase != Phase.SCANNING) return
            if (result !is AndroidPairingQrScanResult.Scanned) {
                revokeLocked(Phase.IDLE, "Scanner canceled or unavailable. Use manual pairing, or deliberately scan again.")
            } else {
                val candidate = try { AndroidPairingQrPayload.parse(result.raw) }
                    catch (_: Exception) { null }
                if (candidate == null) revokeLocked(Phase.IDLE, "QR refused. Use the current pairing QR or manual fields.")
                else if (!sameOriginLocked() || candidate.origin != selectedOrigin) {
                    candidate.close(); revokeLocked(Phase.IDLE, "Scanned server does not match your independently selected HTTPS server. No request sent.")
                } else {
                    payload = candidate; scannedOrigin = candidate.origin; phase = Phase.REVIEW
                    status = "Confirm this HTTPS server before sending the one-use pairing claim. Browser comparison and approval remain separate."
                }
            }
        }
        changed()
    }

    /** Only explicit confirmation can call the existing claim/proof transport. */
    fun confirmOrigin(confirmed: Boolean): Boolean {
        val operation = synchronized(gate) {
            expireLocked()
            if (!confirmed || !resumed || phase != Phase.REVIEW) return false
            if (!sameOriginLocked()) { revokeLocked(Phase.IDLE, "Server selection changed. Scan a fresh ticket."); changed(); return false }
            val ticket = generation
            val inputs = checkNotNull(payload).takeClaimInputs { synchronized(gate) {
                ticket == generation && phase == Phase.CLAIMING && resumed &&
                    sameOriginLocked() && withinLifetimeLocked()
            } }; payload?.close(); payload = null
            claimInputs = inputs; phase = Phase.CLAIMING
            status = "Pairing claim/proof in progress. Do not retry an unknown outcome."
            generation to inputs
        }
        changed()
        if (!synchronized(gate) { operation.first == generation && phase == Phase.CLAIMING && resumed }) {
            operation.second.close(); return false
        }
        try { claim(operation.second) { complete(operation.first, it) } }
        catch (_: Exception) { complete(operation.first, AndroidPairingQrClaimOutcome.Unknown) }
        return true
    }

    /** The existing manual claim button is explicit consent and shares this same one-shot state. */
    fun claimManual(origin: String, pairingId: String, token: String, confirmed: Boolean): Boolean {
        synchronized(gate) {
            expireLocked()
            if (!confirmed || !resumed || phase != Phase.IDLE || scanFlight != null) return false
            val candidate = try {
                val value = AndroidPairingQrPayload.manual(origin, pairingId, token)
                if (value.origin != AndroidPairingQrPayload.canonicalOrigin(knownOrigin())) { value.close(); error("Manual pairing input refused") }
                value
            } catch (_: Exception) { status = "Manual pairing input refused. Check the independently known HTTPS server and current ticket."; changed(); return false }
            val at = try { elapsed().also { require(it >= 0) } }
                catch (_: Exception) { candidate.close(); status = "Pairing unavailable. No request sent."; changed(); return false }
            generation++; selectedOrigin = candidate.origin; scannedOrigin = candidate.origin
            started = at; payload = candidate; phase = Phase.REVIEW
        }
        return confirmOrigin(true)
    }

    private fun complete(ticket: Long, outcome: AndroidPairingQrClaimOutcome) {
        synchronized(gate) {
            if (ticket != generation || phase != Phase.CLAIMING) return
            claimInputs?.close(); claimInputs = null
            if (!resumed || !sameOriginLocked() || !withinLifetimeLocked() || outcome !is AndroidPairingQrClaimOutcome.Verified)
                revokeLocked(Phase.UNKNOWN, "Pairing outcome unknown. Reconcile the original ticket in the browser; do not retry.")
            else {
                val origin = checkNotNull(selectedOrigin)
                generation++; phase = Phase.VERIFIED
                status = "Phone proof verified. Compare the exact code and fingerprint in the browser and explicitly approve there."
                // Callback only schedules public UI output. It must resample this generation when delivered.
                verified(outcome.pairing, generation, origin)
            }
        }
        changed()
    }

    fun cancel() { synchronized(gate) {
        if (phase == Phase.CLOSED) return
        revokeLocked(if (phase == Phase.CLAIMING || phase == Phase.UNKNOWN) Phase.UNKNOWN else Phase.IDLE,
            if (phase == Phase.CLAIMING || phase == Phase.UNKNOWN) "Pairing outcome unknown. Reconcile the original browser ticket before any retry."
            else "Pairing scan cleared. Existing manual fields remain available.")
    }; changed() }

    /** The delegated scanner opens another Activity; no claim is permitted during that excursion. */
    fun pause() { synchronized(gate) {
        resumed = false
        if (phase != Phase.SCANNING && phase != Phase.CLOSED)
            revokeLocked(if (phase == Phase.CLAIMING || phase == Phase.UNKNOWN) Phase.UNKNOWN else Phase.IDLE,
                if (phase == Phase.CLAIMING || phase == Phase.UNKNOWN) "Pairing outcome unknown. Check the original ticket in the browser."
                else "Pairing input cleared while away from this screen.")
    }; changed() }

    fun resume() { synchronized(gate) { resumed = true; expireLocked() }; changed() }
    override fun close() { synchronized(gate) { resumed = false; revokeLocked(Phase.CLOSED, "Pairing scanner closed.") }; changed() }

    private fun sameOriginLocked() = runCatching { AndroidPairingQrPayload.canonicalOrigin(knownOrigin()) == selectedOrigin }.getOrDefault(false)
    private fun withinLifetimeLocked() = runCatching { Math.subtractExact(elapsed(), started) in 0 until 300_000L }.getOrDefault(false)
    private fun expireLocked() {
        if (phase in setOf(Phase.SCANNING, Phase.REVIEW, Phase.CLAIMING, Phase.VERIFIED) && (!withinLifetimeLocked() || !sameOriginLocked()))
            revokeLocked(if (phase == Phase.CLAIMING) Phase.UNKNOWN else Phase.IDLE,
                if (phase == Phase.CLAIMING) "Pairing outcome unknown. Reconcile the original browser ticket before retry."
                else "Pairing input expired or server changed. Scan a fresh current ticket.")
    }
    private fun revokeLocked(next: Phase, text: String) {
        generation++; payload?.close(); payload = null; claimInputs?.close(); claimInputs = null
        selectedOrigin = null; scannedOrigin = null; phase = next; status = text
    }
}

// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import java.util.Locale

/** Only the phone sees SMS plaintext. The relay receives a signed action code. */
internal object OptOutParser {
    const val OPT_OUT = "opt_out"
    const val OPT_OUT_REVIEW = "opt_out_review"
    const val OPT_IN = "opt_in"

    private val stopWords = setOf("STOP", "STOPALL", "UNSUBSCRIBE", "CANCEL", "END",
        "QUIT", "REVOKE", "OPTOUT")
    private val reviewPhrases = listOf("PLEASE STOP", "STOP SENDING", "STOP SMS",
        "STOP TEXTING", "STOP MESSAGING", "UNSUBSCRIBE ME", "DON'T TEXT",
        "DO NOT TEXT", "DON'T MESSAGE", "DO NOT MESSAGE", "REMOVE ME",
        "TAKE ME OFF", "OPT ME OUT", "NO MORE TEXTS", "NO MORE MESSAGES",
        "I DO NOT WANT TEXTS", "I WITHDRAW CONSENT", "I REVOKE CONSENT")

    fun classify(body: String): String? {
        val normalized = body.trim().uppercase(Locale.ROOT)
        if (normalized == "START" || normalized == "UNSTOP") return OPT_IN
        if (normalized.trimEnd('.', '!', ',', ';') in stopWords) return OPT_OUT
        val spaced = normalized.replace(Regex("[^A-Z0-9']+"), " ").trim()
        if (reviewPhrases.any { spaced.contains(it) }) return OPT_OUT_REVIEW
        return null
    }
}

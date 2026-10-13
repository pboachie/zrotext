// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.HexFormat;
import java.util.regex.Pattern;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/** Verifies the exact raw request bytes before parsing or processing an event. */
public final class Webhook {
    private static final Pattern TIMESTAMP = Pattern.compile("(?:0|[1-9][0-9]{0,15})");
    private static final Pattern SIGNATURE = Pattern.compile("v1=[0-9a-f]{64}");
    private Webhook() {}

    public static void verify(byte[] signingKey, String timestamp, String signature, byte[] body) {
        verify(signingKey, timestamp, signature, body, Instant.now().getEpochSecond());
    }

    /** nowSeconds is explicit for deterministic tests; the window is inclusive, +/-300 seconds. */
    public static void verify(byte[] signingKey, String timestamp, String signature,
                              byte[] body, long nowSeconds) {
        if (timestamp == null || !TIMESTAMP.matcher(timestamp).matches()) {
            throw new VerificationException("bad_timestamp");
        }
        long seconds = Long.parseLong(timestamp);
        // Comparing bounded timestamp endpoints avoids overflow from attacker-chosen clocks.
        if (nowSeconds < seconds - 300 || nowSeconds > seconds + 300) {
            throw new VerificationException("timestamp_out_of_window");
        }
        if (signature == null || !SIGNATURE.matcher(signature).matches()) {
            throw new VerificationException("bad_signature_format");
        }
        if (signingKey == null || signingKey.length != 32) {
            throw new IllegalArgumentException("signingKey must contain 32 decoded bytes");
        }
        if (body == null) throw new IllegalArgumentException("body must contain raw bytes");
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(signingKey, "HmacSHA256"));
            mac.update((timestamp + ".").getBytes(StandardCharsets.US_ASCII));
            byte[] expected = mac.doFinal(body);
            if (!MessageDigest.isEqual(expected, HexFormat.of().parseHex(signature.substring(3)))) {
                throw new VerificationException("signature_mismatch");
            }
        } catch (GeneralSecurityException failure) {
            throw new IllegalStateException("HMAC-SHA256 unavailable", failure);
        }
    }

    public static final class VerificationException extends IllegalArgumentException {
        private static final long serialVersionUID = 1L;
        public final String reason;
        private VerificationException(String reason) {
            super("webhook verification failed: " + reason);
            this.reason = reason;
        }
    }
}

// SPDX-License-Identifier: AGPL-3.0-only
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HexFormat;
import org.zrotext.Webhook;

public final class WebhookTest {
    public static void main(String[] args) throws Exception {
        byte[] key = "0123456789abcdef0123456789abcdef".getBytes(StandardCharsets.US_ASCII);
        int count = 0;
        var lines = Files.readAllLines(Path.of(args[0]));
        for (String line : lines.subList(1, lines.size())) {
            String[] row = line.split("\t", -1);
            String actual = "ok";
            try {
                Webhook.verify(key, row[1], row[2], HexFormat.of().parseHex(row[3]), Long.parseLong(row[4]));
            } catch (Webhook.VerificationException failure) {
                actual = failure.reason;
            }
            if (!actual.equals(row[5])) throw new AssertionError(row[0] + ": " + actual);
            count++;
        }
        String signature = "v1=036f0ddc8ddd72da03802b4a2b49547d6516ad1a6a5347527a093387536cb405";
        byte[] body = "{\"event\":\"test\"}".getBytes(StandardCharsets.UTF_8);
        for (String timestamp : new String[] {"", "1700000000\n", " 1700000000", "1e9"}) {
            rejects(key, timestamp, signature, body, "bad_timestamp");
        }
        rejects(key, "1700000000", signature + "\n", body, "bad_signature_format");
        rejects(new byte[32], "1700000000", signature, body, "signature_mismatch");
        System.out.println("Java: " + count + " shared vectors and 6 rejection checks passed");
    }

    private static void rejects(byte[] key, String timestamp, String signature, byte[] body, String reason) {
        try {
            Webhook.verify(key, timestamp, signature, body, 1700000000);
        } catch (Webhook.VerificationException failure) {
            if (failure.reason.equals(reason)) return;
            throw failure;
        }
        throw new AssertionError("Expected " + reason);
    }
}

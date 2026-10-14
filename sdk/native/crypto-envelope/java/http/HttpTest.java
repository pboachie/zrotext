package org.zrotext.candidate;
import com.google.gson.*;
import java.nio.charset.StandardCharsets;

/** Synthetic subprocess adapter; stdin and trust roots are test-owned. */
public final class HttpTest {
    private HttpTest() { }
    public static void main(String[] args) throws Exception {
        JsonObject p = JsonParser.parseString(new String(System.in.readAllBytes(), StandardCharsets.UTF_8)).getAsJsonObject();
        String state = "unavailable"; long start = System.nanoTime();
        try {
            OriginalHttp client = new OriginalHttp(p.get("Origin").getAsString(), p.get("Timeout").getAsLong(), p.get("Roots").getAsString());
            String method = p.get("Method").getAsString(), invalid = p.get("Invalid").getAsString();
            String id = new java.util.UUID(1, 2).toString();
            var request = new OriginalHttp.Request(method, invalid.equals("version") ? 0 : 1,
                method.equals("read") || method.equals("consume") ? (invalid.equals("uuid") ? "invalid" : id) : null,
                method.equals("status") ? id : null, method.equals("page") ? 2 : null, null,
                method.equals("consume") ? id : null, null);
            start = System.nanoTime();
            OriginalHttp.Wire wire = client.exchange(p.get("Grant").getAsString(), request);
            if (!JsonParser.parseString(wire.untrustedJson()).getAsJsonObject().get("untrusted").getAsBoolean()) throw new IllegalStateException();
            state = "untrusted";
        } catch (OriginalHttp.Failure error) { state = error.unknown ? "unknown" : "unavailable";
            JsonObject detail = new JsonObject(); detail.addProperty("state", state);
            if (error.getMessage() != null) detail.addProperty("reason", error.getMessage());
            detail.addProperty("elapsed", (System.nanoTime() - start) / 1e9);
            System.out.println(detail); return; }
        JsonObject result = new JsonObject(); result.addProperty("state", state); result.addProperty("elapsed", (System.nanoTime() - start) / 1e9);
        System.out.println(result);
    }
}

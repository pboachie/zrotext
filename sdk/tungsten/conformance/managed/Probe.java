import io.github.pboachie.zrotext.ZrotextClient;
import io.github.pboachie.tungsten.runtime.*;
import java.time.Duration;
import java.util.Map;

/** Synthetic test process: input and output are one JSON object each. */
public final class Probe {
    private Probe() {}
    public static void main(String[] ignored) throws Exception {
        var input = (JsonObject) Json.parse(new String(System.in.readAllBytes(), java.nio.charset.StandardCharsets.UTF_8));
        var options = ClientOptions.builder().baseUrl((String) input.get("base"))
            .timeout(Duration.ofMillis(1500)).validateResponses(ClientOptions.ValidateResponses.STRICT);
        if (Boolean.TRUE.equals(input.get("auth"))) {
            options.auth("ownerSession", AuthCredential.parts(Map.of(
                "__Host-zrotext_session", "synthetic-session", "__Host-zrotext_csrf", "synthetic-csrf", "origin", "https://example.test")))
                .auth("bearerAuth", AuthCredential.secret("synthetic-bearer"))
                .auth("workflowCredential", AuthCredential.secret("ztw_synthetic"));
        }
        var client = new ZrotextClient(options.build());
        var call = CallOptions.builder().idempotencyKey((String) input.get("key")).build();
        if (Boolean.TRUE.equals(input.get("confirm"))) {
            var preview = client.dispatch().previewOperation((String) input.get("operation"), input.get("args"), call);
            if (!preview.isOk()) { System.out.println(Json.write(preview.error().toJson())); return; }
            call = call.toBuilder().confirm(Confirm.token(preview.unwrap().confirmationToken())).build();
        }
        var result = client.dispatch().invoke((String) input.get("operation"), input.get("args"), call);
        System.out.println(Json.write(result.isOk() ? JsonObject.of("ok", true) : result.error().toJson()));
    }
}

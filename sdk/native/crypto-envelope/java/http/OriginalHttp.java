package org.zrotext.candidate;

import com.google.gson.*;
import com.google.gson.stream.*;
import java.io.*;
import java.net.*;
import java.net.http.*;
import java.nio.*;
import java.nio.charset.*;
import java.security.*;
import java.security.cert.*;
import java.time.Duration;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicBoolean;
import javax.net.ssl.*;

/** Candidate transport only. Returned wire JSON is untrusted, including proofs. */
public final class OriginalHttp {
    public static final class Failure extends Exception {
        private static final long serialVersionUID = 1L;
        public final boolean unknown;
        public Failure(boolean unknown) { super(unknown ? "original reply outcome unknown" : "original reply unavailable"); this.unknown = unknown; }
    }
    public record Wire(String untrustedJson) {}
    public record Cursor(String eventId, long acceptedAtMs) {}
    public record Request(String method, long acceptedManifestVersion, String eventId,
                          String consumptionId, Integer limit, Cursor cursor,
                          String requestId, String activeRequestId) {}
    private static final long SAFE = 9007199254740991L;
    private static final int MAX = 524288;
    private final HttpClient client;
    private final URI endpoint;
    private final long timeoutMs;

    /** Additional roots must be independently trusted application CA configuration. */
    public OriginalHttp(String origin, long timeoutMs, String additionalRootsPem) throws Failure {
        try {
            if (timeoutMs < 1 || timeoutMs > 10000 || !origin.startsWith("https://") || origin.chars().anyMatch(c -> c <= 32 || c >= 127 || "\\?#".indexOf(c) >= 0)) throw new Failure(false);
            URI uri = new URI(origin);
            if (uri.getHost() == null || uri.getRawUserInfo() != null || !(uri.getRawPath().isEmpty() || uri.getRawPath().equals("/"))) throw new Failure(false);
            this.endpoint = new URI(origin.replaceFirst("/$", "") + "/v1/reply-events");
            this.timeoutMs = timeoutMs;
            // Refuse application-wide settings that can opt POST into replay.
            if (Boolean.getBoolean("jdk.httpclient.enableAllMethodRetry")) throw new Failure(false);
            SSLContext ssl = SSLContext.getInstance("TLS");
            TrustManagerFactory platform = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            platform.init((KeyStore)null);
            X509TrustManager system = trust(platform);
            X509TrustManager extra = null;
            if (!additionalRootsPem.isEmpty()) {
                KeyStore store = KeyStore.getInstance(KeyStore.getDefaultType()); store.load(null, null);
                var certificates = CertificateFactory.getInstance("X.509").generateCertificates(new ByteArrayInputStream(additionalRootsPem.getBytes(StandardCharsets.US_ASCII)));
                if (certificates.isEmpty()) throw new Failure(false);
                int i = 0; for (var certificate : certificates) store.setCertificateEntry("additional-" + i++, certificate);
                TrustManagerFactory configured = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm()); configured.init(store); extra = trust(configured);
            }
            final X509TrustManager added = extra;
            ssl.init(null, new TrustManager[] { new X509TrustManager() {
                public X509Certificate[] getAcceptedIssuers() { return system.getAcceptedIssuers(); }
                public void checkClientTrusted(X509Certificate[] c, String a) throws CertificateException { system.checkClientTrusted(c, a); }
                public void checkServerTrusted(X509Certificate[] c, String a) throws CertificateException {
                    try { system.checkServerTrusted(c, a); }
                    catch (CertificateException error) { if (added == null) throw error; added.checkServerTrusted(c, a); }
                }
            }}, null);
            SSLParameters params = new SSLParameters(); params.setEndpointIdentificationAlgorithm("HTTPS"); params.setProtocols(new String[] {"TLSv1.3", "TLSv1.2"});
            client = HttpClient.newBuilder().sslContext(ssl).sslParameters(params).version(HttpClient.Version.HTTP_1_1)
                .followRedirects(HttpClient.Redirect.NEVER).connectTimeout(Duration.ofMillis(timeoutMs))
                .proxy(new ProxySelector() {
                    public List<Proxy> select(URI u) { return List.of(Proxy.NO_PROXY); }
                    public void connectFailed(URI u, SocketAddress address, IOException error) { }
                }).build();
        } catch (Exception error) { throw new Failure(false); }
    }
    private static X509TrustManager trust(TrustManagerFactory f) throws GeneralSecurityException {
        for (TrustManager t : f.getTrustManagers()) if (t instanceof X509TrustManager x) return x;
        throw new GeneralSecurityException();
    }
    private static String uuid(String s) throws Failure {
        if (s == null || !s.matches("[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}") || s.replace("-", "").equals("0".repeat(32))) throw new Failure(false);
        return s;
    }
    private static byte[] body(Request r) throws Failure {
        if (r.acceptedManifestVersion < 1 || r.acceptedManifestVersion > SAFE) throw new Failure(false);
        JsonObject b = new JsonObject(); b.addProperty("v", 1); b.addProperty("method", r.method); b.addProperty("accepted_manifest_version", r.acceptedManifestVersion);
        switch (r.method) {
            case "current" -> { }
            case "read" -> b.addProperty("event_id", uuid(r.eventId));
            case "status" -> b.addProperty("consumption_id", uuid(r.consumptionId));
            case "page" -> {
                if (r.limit == null || r.limit < 1 || r.limit > 32) throw new Failure(false);
                b.addProperty("limit", r.limit); b.add("cursor", JsonNull.INSTANCE);
                if (r.cursor != null) {
                    if (r.cursor.acceptedAtMs < 1 || r.cursor.acceptedAtMs > SAFE) throw new Failure(false);
                    JsonObject cursor = new JsonObject(); cursor.addProperty("event_id", uuid(r.cursor.eventId)); cursor.addProperty("accepted_at_ms", r.cursor.acceptedAtMs); b.add("cursor", cursor);
                }
            }
            case "consume" -> {
                JsonObject params = new JsonObject(); params.addProperty("event_id", uuid(r.eventId)); params.addProperty("request_id", uuid(r.requestId));
                params.addProperty("active_request_id", r.activeRequestId == null ? null : uuid(r.activeRequestId)); params.add("descriptor", JsonNull.INSTANCE); b.add("params", params);
            }
            default -> throw new Failure(false);
        }
        if ((!r.method.equals("read") && !r.method.equals("consume") && r.eventId != null) || (!r.method.equals("status") && r.consumptionId != null) || (!r.method.equals("page") && (r.limit != null || r.cursor != null)) || (!r.method.equals("consume") && (r.requestId != null || r.activeRequestId != null))) throw new Failure(false);
        return b.toString().getBytes(StandardCharsets.UTF_8);
    }
    private static final class Once implements HttpRequest.BodyPublisher {
        private final HttpRequest.BodyPublisher inner;
        private final AtomicBoolean used = new AtomicBoolean();
        Once(byte[] bytes) { inner = HttpRequest.BodyPublishers.ofByteArray(bytes); }
        public long contentLength() { return inner.contentLength(); }
        public void subscribe(Flow.Subscriber<? super ByteBuffer> s) {
            if (!used.compareAndSet(false, true)) {
                s.onSubscribe(new Flow.Subscription() { public void request(long n) {} public void cancel() {} });
                s.onError(new IOException("request replay refused"));
            } else inner.subscribe(s);
        }
    }
    private static final class Bounded implements HttpResponse.BodySubscriber<byte[]> {
        private final CompletableFuture<byte[]> result = new CompletableFuture<>();
        private final ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        private Flow.Subscription subscription;
        public CompletionStage<byte[]> getBody() { return result; }
        public void onSubscribe(Flow.Subscription s) { subscription = s; s.request(1); }
        public void onNext(List<ByteBuffer> chunks) {
            for (ByteBuffer chunk : chunks) {
                if (chunk.remaining() > MAX - bytes.size()) { subscription.cancel(); result.completeExceptionally(new IOException("response limit")); return; }
                byte[] part = new byte[chunk.remaining()]; chunk.get(part); bytes.writeBytes(part);
            }
            subscription.request(1);
        }
        public void onError(Throwable t) { result.completeExceptionally(t); }
        public void onComplete() { result.complete(bytes.toByteArray()); }
    }
    public Wire exchange(String credential, Request request) throws Failure {
        boolean attempted = false;
        CompletableFuture<HttpResponse<byte[]>> pending = null;
        try {
            if (!credential.matches("ztr_[A-Za-z0-9_-]{43}")) throw new Failure(false);
            byte[] key = Base64.getUrlDecoder().decode(credential.substring(4));
            if (key.length != 32 || !Base64.getUrlEncoder().withoutPadding().encodeToString(key).equals(credential.substring(4))) throw new Failure(false);
            byte[] body = body(request);
            if (Thread.currentThread().isInterrupted()) throw new Failure(false);
            HttpRequest message = HttpRequest.newBuilder(endpoint).timeout(Duration.ofMillis(timeoutMs))
                .header("Authorization", "Bearer " + credential).header("Content-Type", "application/json")
                .header("Cache-Control", "no-store").POST(new Once(body)).build();
            long start = System.nanoTime();
            attempted = true;
            pending = client.sendAsync(message, info -> new Bounded());
            HttpResponse<byte[]> response = pending.get(timeoutMs, TimeUnit.MILLISECONDS);
            if (response.statusCode() < 200 || response.statusCode() >= 300 || !response.headers().firstValue("Content-Type").orElse("").split(";", 2)[0].trim().equalsIgnoreCase("application/json")) throw new Failure(false);
            String text = StandardCharsets.UTF_8.newDecoder().onMalformedInput(CodingErrorAction.REPORT).onUnmappableCharacter(CodingErrorAction.REPORT).decode(ByteBuffer.wrap(response.body())).toString();
            JsonReader reader = new JsonReader(new StringReader(text)); reader.setStrictness(Strictness.STRICT); reader.setNestingLimit(64);
            Set<String> seen = new HashSet<>(); JsonElement kind = null, result = null;
            reader.beginObject();
            while (reader.hasNext()) {
                String name = reader.nextName(); if (!seen.add(name)) throw new Failure(false);
                JsonElement value = JsonParser.parseReader(reader);
                if (name.equals("kind")) kind = value; else if (name.equals("result")) result = value; else throw new Failure(false);
            }
            reader.endObject();
            if (reader.peek() != JsonToken.END_DOCUMENT || seen.size() != 2 || kind == null || !kind.isJsonPrimitive() || !kind.getAsJsonPrimitive().isString() || !kind.getAsString().equals(request.method) || result == null || System.nanoTime() - start >= TimeUnit.MILLISECONDS.toNanos(timeoutMs)) throw new Failure(false);
            return new Wire(result.toString());
        } catch (Exception error) {
            if (pending != null) pending.cancel(true);
            if (error instanceof InterruptedException) Thread.currentThread().interrupt();
            throw new Failure(attempted && request != null && "consume".equals(request.method));
        }
    }
}

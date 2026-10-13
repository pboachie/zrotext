using System.Net;
using System.Net.Http;
using System.Net.Security;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace Zrotext.Candidate;

// Candidate transport. A successful wire result is NOT authenticated authority.
public sealed class OriginalHttp : IDisposable
{
    public sealed class Failure : Exception
    {
        public bool Unknown { get; }
        public Failure(bool unknown = false) : base(unknown ? "original reply outcome unknown" : "original reply unavailable") { Unknown = unknown; }
    }
    public sealed record Wire(string UntrustedJson);
    public sealed record Cursor(string EventId, long AcceptedAtMs);
    public sealed record Request(string Method, long AcceptedManifestVersion,
        string? EventId = null, string? ConsumptionId = null, int? Limit = null,
        Cursor? PageCursor = null, string? RequestId = null, string? ActiveRequestId = null);
    private const long Safe = 9007199254740991;
    private const int Maximum = 524288;
    private readonly HttpClient client;
    private readonly Uri endpoint;
    private readonly TimeSpan timeout;
    private readonly X509Certificate2Collection additional = new();
    private sealed class OnceContent(byte[] bytes) : HttpContent
    {
        private int used;
        protected override bool TryComputeLength(out long length) { length = bytes.Length; return true; }
        protected override Task SerializeToStreamAsync(Stream stream, TransportContext? context)
        {
            if (Interlocked.Exchange(ref used, 1) != 0) throw new IOException("request replay refused");
            return stream.WriteAsync(bytes, 0, bytes.Length);
        }
    }

    public OriginalHttp(string origin, int timeoutMs, string additionalRootsPem = "")
    {
        try
        {
            if (timeoutMs < 1 || timeoutMs > 10000 || origin.Any(c => c <= 32 || c >= 127 || "\\?#".Contains(c))) throw new Failure();
            // Inspect the raw suffix before Uri's dot-segment normalization.
            if (!origin.StartsWith("https://", StringComparison.Ordinal)) throw new Failure();
            string authority = origin[8..];
            if (authority.Contains('@')) throw new Failure();
            int slash = authority.IndexOf('/');
            if (slash >= 0 && authority[slash..] != "/") throw new Failure();
            if (!Uri.TryCreate(origin, UriKind.Absolute, out var uri) || uri.Scheme != "https" || uri.Host.Length == 0 || uri.UserInfo.Length != 0) throw new Failure();
            endpoint = new Uri(origin.TrimEnd('/') + "/v1/reply-events");
            timeout = TimeSpan.FromMilliseconds(timeoutMs);
            if (additionalRootsPem.Length != 0)
            {
                additional.ImportFromPem(additionalRootsPem);
                if (additional.Count == 0) throw new Failure();
            }
            var handler = new SocketsHttpHandler
            {
                AllowAutoRedirect = false, UseProxy = false, UseCookies = false,
                AutomaticDecompression = DecompressionMethods.None,
                ConnectTimeout = timeout, PooledConnectionLifetime = TimeSpan.Zero,
                SslOptions = new SslClientAuthenticationOptions
                {
                    EnabledSslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13,
                    RemoteCertificateValidationCallback = VerifyCertificate
                }
            };
            client = new HttpClient(handler) { Timeout = Timeout.InfiniteTimeSpan };
        }
        catch { foreach (var cert in additional) cert.Dispose(); throw new Failure(); }
    }
    private bool VerifyCertificate(object _, X509Certificate? certificate, X509Chain? supplied, SslPolicyErrors errors)
    {
        if (errors == SslPolicyErrors.None) return true;
        if (errors != SslPolicyErrors.RemoteCertificateChainErrors || certificate is null || additional.Count == 0) return false;
        using var chain = new X509Chain();
        chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
        chain.ChainPolicy.CustomTrustStore.AddRange(additional);
        chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
        chain.ChainPolicy.VerificationFlags = X509VerificationFlags.NoFlag;
        chain.ChainPolicy.ApplicationPolicy.Add(new System.Security.Cryptography.Oid("1.3.6.1.5.5.7.3.1"));
        if (supplied is not null)
            foreach (var element in supplied.ChainElements) chain.ChainPolicy.ExtraStore.Add(element.Certificate);
        using var leaf = new X509Certificate2(certificate);
        return chain.Build(leaf);
    }
    private static string Uuid(string? s)
    {
        if (s is null || !Regex.IsMatch(s, "\\A[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\\z") || s.Replace("-", "") == new string('0', 32)) throw new Failure();
        return s;
    }
    private static byte[] Body(Request r)
    {
        if (r.AcceptedManifestVersion < 1 || r.AcceptedManifestVersion > Safe) throw new Failure();
        var fields = new Dictionary<string, object?> { ["v"] = 1, ["method"] = r.Method, ["accepted_manifest_version"] = r.AcceptedManifestVersion };
        switch (r.Method)
        {
            case "current": break;
            case "read": fields["event_id"] = Uuid(r.EventId); break;
            case "status": fields["consumption_id"] = Uuid(r.ConsumptionId); break;
            case "page":
                if (r.Limit is null or < 1 or > 32) throw new Failure();
                fields["limit"] = r.Limit;
                fields["cursor"] = null;
                if (r.PageCursor is { } cursor)
                {
                    if (cursor.AcceptedAtMs < 1 || cursor.AcceptedAtMs > Safe) throw new Failure();
                    fields["cursor"] = new { event_id = Uuid(cursor.EventId), accepted_at_ms = cursor.AcceptedAtMs };
                }
                break;
            case "consume":
                fields["params"] = new Dictionary<string, object?>
                {
                    ["event_id"] = Uuid(r.EventId), ["request_id"] = Uuid(r.RequestId),
                    ["active_request_id"] = r.ActiveRequestId is null ? null : Uuid(r.ActiveRequestId), ["descriptor"] = null
                };
                break;
            default: throw new Failure();
        }
        if ((r.Method != "read" && r.Method != "consume" && r.EventId is not null) ||
            (r.Method != "status" && r.ConsumptionId is not null) ||
            (r.Method != "page" && (r.Limit is not null || r.PageCursor is not null)) ||
            (r.Method != "consume" && (r.RequestId is not null || r.ActiveRequestId is not null))) throw new Failure();
        return JsonSerializer.SerializeToUtf8Bytes(fields);
    }
    public async Task<Wire> ExchangeAsync(string credential, Request request, CancellationToken cancellation = default)
    {
        bool attempted = false;
        try
        {
            if (!Regex.IsMatch(credential, "\\Aztr_[A-Za-z0-9_-]{43}\\z")) throw new Failure();
            var raw = Convert.FromBase64String(credential[4..].Replace('-', '+').Replace('_', '/') + "=");
            if (raw.Length != 32 || Convert.ToBase64String(raw).TrimEnd('=').Replace('+', '-').Replace('/', '_') != credential[4..]) throw new Failure();
            byte[] body = Body(request);
            cancellation.ThrowIfCancellationRequested();
            using var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellation);
            deadline.CancelAfter(timeout);
            using var message = new HttpRequestMessage(HttpMethod.Post, endpoint)
            { Version = HttpVersion.Version11, VersionPolicy = HttpVersionPolicy.RequestVersionExact, Content = new OnceContent(body) };
            message.Headers.TryAddWithoutValidation("Authorization", "Bearer " + credential);
            message.Headers.TryAddWithoutValidation("Cache-Control", "no-store");
            message.Headers.ConnectionClose = true;
            message.Content.Headers.ContentType = new("application/json");
            attempted = true;
            using var response = await client.SendAsync(message, HttpCompletionOption.ResponseHeadersRead, deadline.Token).ConfigureAwait(false);
            if (!response.IsSuccessStatusCode || response.Content.Headers.ContentType?.MediaType != "application/json" || response.Content.Headers.ContentLength > Maximum) throw new Failure();
            await using var stream = await response.Content.ReadAsStreamAsync(deadline.Token).ConfigureAwait(false);
            using var output = new MemoryStream();
            byte[] buffer = new byte[8192];
            int count;
            while ((count = await stream.ReadAsync(buffer, deadline.Token).ConfigureAwait(false)) != 0)
            {
                if (output.Length + count > Maximum) throw new Failure();
                output.Write(buffer, 0, count);
            }
            string text = new UTF8Encoding(false, true).GetString(output.ToArray());
            using var json = JsonDocument.Parse(text, new JsonDocumentOptions { MaxDepth = 64 });
            if (json.RootElement.ValueKind != JsonValueKind.Object) throw new Failure();
            var seen = new HashSet<string>();
            foreach (var field in json.RootElement.EnumerateObject()) if (!seen.Add(field.Name)) throw new Failure();
            if (!seen.SetEquals(new[] { "kind", "result" }) || json.RootElement.GetProperty("kind").GetString() != request.Method) throw new Failure();
            var result = new Wire(json.RootElement.GetProperty("result").GetRawText());
            deadline.Token.ThrowIfCancellationRequested();
            return result;
        }
        catch { throw new Failure(attempted && request?.Method == "consume"); }
    }
    public void Dispose() { client.Dispose(); foreach (var cert in additional) cert.Dispose(); }
}

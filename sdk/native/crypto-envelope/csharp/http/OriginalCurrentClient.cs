using System.Security.Cryptography;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace Zrotext.Candidate;

// Authenticated snapshot after durable advancement, not perpetual authorization.
public sealed class OriginalCurrentClient
{
    private static readonly object Permit = new();
    public sealed class Verified
    {
        public OriginalReplyReader.Authority Authority { get; }
        internal Verified(object permit, OriginalReplyReader.Authority authority) { Need(ReferenceEquals(permit, Permit)); Authority = authority; }
    }
    private const long Safe = 9007199254740991;
    private static readonly string[] Fields = ["account_id", "interval_id", "device_id", "line_id", "connector_id", "read_grant_id", "reader_id", "root_generation", "authority_revision", "expires_at_ms", "observed_at_ms", "current_manifest_version", "current_manifest_digest", "manifest_chain"];
    private readonly OriginalHttp transport;
    private readonly OriginalReplyCheckpoint checkpoint;
    private readonly OriginalReplyReader.Scope scope;
    private readonly ManifestChain.RootPin root;
    private readonly SemaphoreSlim gate = new(1, 1);
    private long revision, last;
    private bool failed;
    private static void Need(bool value) { if (!value) throw new OriginalHttp.Failure(); }
    private static long Positive(long value) { Need(value > 0 && value <= Safe); return value; }
    private static long Integer(JsonElement value) { Need(value.ValueKind == JsonValueKind.Number && value.TryGetInt64(out _)); return Positive(value.GetInt64()); }
    private static string Text(JsonElement value) { Need(value.ValueKind == JsonValueKind.String); return value.GetString()!; }
    private static JsonElement Exact(JsonElement value, params string[] fields)
    {
        Need(value.ValueKind == JsonValueKind.Object); var seen = new HashSet<string>();
        foreach (var field in value.EnumerateObject()) Need(seen.Add(field.Name));
        Need(seen.SetEquals(fields)); return value;
    }
    private static bool Same(byte[] a, byte[] b) => CryptographicOperations.FixedTimeEquals(a, b);
    private static void Uuid(JsonElement value, byte[] expected)
    {
        string text = Text(value);
        Need(Regex.IsMatch(text, "\\A[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\\z") && Same(Convert.FromHexString(text.Replace("-", "")), expected));
    }
    private ManifestChain.Verified At(byte[] bytes, ManifestChain.Verified? previous, long time) => ManifestChain.OriginalAccepted02(bytes, root, previous, time);
    public OriginalCurrentClient(OriginalHttp transport, OriginalReplyCheckpoint checkpoint, byte[] pin, byte[] fingerprint, OriginalReplyReader.Scope scope, long now)
    {
        try
        {
            Positive(now); this.transport = transport; this.checkpoint = checkpoint; this.scope = scope; root = ManifestChain.RootPin.Enroll(pin, fingerprint);
            var saved = checkpoint.ReadSnapshot(scope, now); var first = saved.History[0]; At(first.Bytes(), null, first.ComparisonMs);
            revision = saved.Revision; last = now;
        }
        catch { throw new OriginalHttp.Failure(); }
    }
    private long Sample(Func<long> clock) { long now = Positive(clock()); Need(now >= last); last = now; return now; }
    private static void Fresh(long now, long observed, long expires) => Need(now < expires && now <= observed + 30000 && observed <= now + 30000);
    public async Task<Verified> CurrentAsync(string credential, Func<long> clock, CancellationToken cancellation = default)
    {
        bool acquired = false;
        try
        {
            Need(clock is not null && gate.Wait(0)); acquired = true; Need(!failed); long now = Sample(clock!);
            var saved = checkpoint.ReadSnapshot(scope, now);
            if (saved.Revision != revision) { failed = true; Need(false); }
            var latest = saved.History[^1];
            var wire = await transport.ExchangeAsync(credential, new OriginalHttp.Request("current", latest.Version), cancellation).ConfigureAwait(false);
            using var json = JsonDocument.Parse(wire.UntrustedJson, new JsonDocumentOptions { MaxDepth = 64 });
            var p = Exact(json.RootElement, Fields); now = Sample(clock!);
            long observed = Integer(p.GetProperty("observed_at_ms")), expires = Integer(p.GetProperty("expires_at_ms")); Fresh(now, observed, expires);
            string[] names = ["account_id", "device_id", "line_id", "interval_id", "connector_id", "read_grant_id"];
            byte[][] expected = [scope.Account, scope.Device, scope.Line, scope.Interval, scope.Connector, scope.Grant];
            for (int i = 0; i < names.Length; i++) Uuid(p.GetProperty(names[i]), expected[i]);
            Need(Text(p.GetProperty("reader_id")) == Convert.ToHexString(scope.Reader).ToLowerInvariant() && Integer(p.GetProperty("authority_revision")) == 1);
            var chain = p.GetProperty("manifest_chain"); Need(chain.ValueKind == JsonValueKind.Array && chain.GetArrayLength() is >= 1 and <= 32);
            var history = saved.History.ToList(); var previous = latest; int index = 0;
            foreach (var row in chain.EnumerateArray())
            {
                var entry = Exact(row, "version", "accepted_at_ms", "manifest_b64"); long version = Integer(entry.GetProperty("version")), accepted = Integer(entry.GetProperty("accepted_at_ms"));
                Need(accepted <= now + 30000 && version == (index == 0 ? latest.Version : previous.Version + 1));
                string encoded = Text(entry.GetProperty("manifest_b64")); Need(encoded.Length <= 13004);
                byte[] bytes = Convert.FromBase64String(encoded); Need(bytes.Length <= 9751 && Convert.ToBase64String(bytes) == encoded);
                var current = At(bytes, previous, accepted); Need(current.Version == version && current.Generation == latest.Generation && Same(current.RootPoint(), latest.RootPoint()));
                if (index == 0) Need(Same(current.Digest(), latest.Digest())); else history.Add(current);
                previous = current; index++;
            }
            Need(Integer(p.GetProperty("current_manifest_version")) == previous.Version && Integer(p.GetProperty("root_generation")) == latest.Generation && Text(p.GetProperty("current_manifest_digest")) == Convert.ToHexString(previous.Digest()).ToLowerInvariant() && history.Count <= 64);
            now = Sample(clock!); Fresh(now, observed, expires); At(previous.Bytes(), previous, now);
            long Fence(ManifestChain.Verified manifest, long floor)
            {
                cancellation.ThrowIfCancellationRequested(); long time = Sample(clock!); Need(time >= floor); Fresh(time, observed, expires); At(manifest.Bytes(), manifest, time); return time;
            }
            failed = true; var committed = checkpoint.Accept(scope, history, revision, now, Fence);
            cancellation.ThrowIfCancellationRequested(); long after = Sample(clock!); Need(after >= committed.ComparisonMs); Fresh(after, observed, expires);
            var final = committed.History[^1]; At(final.Bytes(), final, after);
            if (after > committed.ComparisonMs) committed = checkpoint.Accept(scope, committed.History, committed.Revision, after, Fence);
            revision = committed.Revision; last = committed.ComparisonMs; failed = false;
            return new Verified(Permit, new OriginalReplyReader.Authority(scope, "1", last, expires, committed.History[^1]));
        }
        catch { throw new OriginalHttp.Failure(); }
        finally { if (acquired) gate.Release(); }
    }
}

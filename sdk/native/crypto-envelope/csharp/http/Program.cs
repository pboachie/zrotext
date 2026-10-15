using System.Diagnostics;
using System.Text.Json;
using Zrotext.Candidate;

using var input = JsonDocument.Parse(Console.In.ReadToEnd());
var p = input.RootElement;
string state = "unavailable";
var elapsed = Stopwatch.StartNew();
try
{
    using var client = new OriginalHttp(p.GetProperty("Origin").GetString()!, p.GetProperty("Timeout").GetInt32(), p.GetProperty("Roots").GetString()!);
    string method = p.GetProperty("Method").GetString()!, invalid = p.GetProperty("Invalid").GetString()!;
    string id = new Guid(1, 2, 3, new byte[8]).ToString();
    var request = new OriginalHttp.Request(method, invalid == "version" ? 0 : 1,
        method is "read" or "consume" ? (invalid == "uuid" ? "invalid" : id) : null,
        method == "status" ? id : null, method == "page" ? 2 : null, null,
        method == "consume" ? id : null);
    elapsed.Restart();
    var wire = await client.ExchangeAsync(p.GetProperty("Grant").GetString()!, request);
    using var json = JsonDocument.Parse(wire.UntrustedJson);
    if (!json.RootElement.GetProperty("untrusted").GetBoolean()) throw new Exception("invalid test result");
    state = "untrusted";
}
catch (OriginalHttp.Failure error) { state = error.Unknown ? "unknown" : "unavailable"; }
Console.WriteLine(JsonSerializer.Serialize(new { state, elapsed = elapsed.Elapsed.TotalSeconds }));

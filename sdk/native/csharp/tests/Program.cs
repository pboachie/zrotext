// SPDX-License-Identifier: AGPL-3.0-only
using System.Text;
using Zrotext;

byte[] key = Encoding.ASCII.GetBytes("0123456789abcdef0123456789abcdef");
int count = 0;
foreach (string line in File.ReadLines(args[0]).Skip(1))
{
    string[] row = line.Split('\t');
    string actual = "ok";
    try { Webhook.Verify(key, row[1], row[2], Convert.FromHexString(row[3]), long.Parse(row[4])); }
    catch (VerificationException failure) { actual = failure.Reason; }
    if (actual != row[5]) throw new Exception(row[0] + ": " + actual);
    count++;
}
string signature = "v1=036f0ddc8ddd72da03802b4a2b49547d6516ad1a6a5347527a093387536cb405";
byte[] body = Encoding.UTF8.GetBytes("{\"event\":\"test\"}");
foreach (string timestamp in new[] { "", "1700000000\n", " 1700000000", "1e9" })
    Rejects(key, timestamp, signature, body, "bad_timestamp");
Rejects(key, "1700000000", signature + "\n", body, "bad_signature_format");
Rejects(new byte[32], "1700000000", signature, body, "signature_mismatch");
Console.WriteLine($"C#: {count} shared vectors and 6 rejection checks passed");

static void Rejects(byte[] key, string timestamp, string signature, byte[] body, string reason)
{
    try { Webhook.Verify(key, timestamp, signature, body, 1700000000); }
    catch (VerificationException failure) { if (failure.Reason == reason) return; throw; }
    throw new Exception("Expected " + reason);
}

// SPDX-License-Identifier: AGPL-3.0-only
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;

namespace Zrotext;

public static class Webhook
{
    private static readonly Regex Timestamp = new(@"\A(?:0|[1-9][0-9]{0,15})\z", RegexOptions.CultureInvariant);
    private static readonly Regex Signature = new(@"\Av1=[0-9a-f]{64}\z", RegexOptions.CultureInvariant);

    public static void Verify(byte[] signingKey, string timestamp, string signature, byte[] body) =>
        Verify(signingKey, timestamp, signature, body, DateTimeOffset.UtcNow.ToUnixTimeSeconds());

    // Authenticate the bytes received, before any JSON decoding or reserialization.
    public static void Verify(byte[] signingKey, string timestamp, string signature, byte[] body, long nowSeconds)
    {
        if (timestamp is null || !Timestamp.IsMatch(timestamp)) throw new VerificationException("bad_timestamp");
        long seconds = long.Parse(timestamp, System.Globalization.CultureInfo.InvariantCulture);
        if (nowSeconds < seconds - 300 || nowSeconds > seconds + 300)
            throw new VerificationException("timestamp_out_of_window");
        if (signature is null || !Signature.IsMatch(signature)) throw new VerificationException("bad_signature_format");
        if (signingKey is null || signingKey.Length != 32)
            throw new ArgumentException("signingKey must contain 32 decoded bytes", nameof(signingKey));
        ArgumentNullException.ThrowIfNull(body);
        using var mac = IncrementalHash.CreateHMAC(HashAlgorithmName.SHA256, signingKey);
        mac.AppendData(Encoding.ASCII.GetBytes(timestamp + "."));
        mac.AppendData(body);
        if (!CryptographicOperations.FixedTimeEquals(mac.GetHashAndReset(), Convert.FromHexString(signature[3..])))
            throw new VerificationException("signature_mismatch");
    }
}

public sealed class VerificationException(string reason) : ArgumentException("webhook verification failed: " + reason)
{
    public string Reason { get; } = reason;
}

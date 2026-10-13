// SPDX-License-Identifier: AGPL-3.0-only
using System.Security.Cryptography;
using System.Text;

namespace Zrotext.Candidate;

// Symmetric candidate primitive only; callers must separately verify signer, routing, manifest and replay authority.
public static class CandidateBody
{
    public static string Open(byte[] contentKey, byte[] nonce, byte[] verifiedAad, byte[] ciphertext)
    {
        if (contentKey is null || contentKey.Length != 32 || nonce is null || nonce.Length != 12 ||
            verifiedAad is null || verifiedAad.Length is < 1 or > 36864 ||
            ciphertext is null || ciphertext.Length is < 17 or > 32784)
            throw new BodyException("shape");
        byte[] plaintext = new byte[ciphertext.Length - 16];
        try
        {
            using var cipher = new AesGcm(contentKey, 16);
            cipher.Decrypt(nonce, ciphertext.AsSpan(0, plaintext.Length), ciphertext.AsSpan(plaintext.Length), plaintext, verifiedAad);
            return Decode(plaintext);
        }
        catch (CryptographicException) { throw new BodyException("authentication"); }
        finally { CryptographicOperations.ZeroMemory(plaintext); }
    }

    public static string Decode(byte[] bytes)
    {
        if (bytes is null || bytes.Length is < 1 or > 32768) throw new BodyException("length");
        if (Array.IndexOf(bytes, (byte)0) >= 0) throw new BodyException("nul");
        if (bytes.Length >= 3 && bytes[0] == 0xef && bytes[1] == 0xbb && bytes[2] == 0xbf) throw new BodyException("bom");
        try { return new UTF8Encoding(false, true).GetString(bytes); }
        catch (DecoderFallbackException) { throw new BodyException("utf8"); }
    }
}

public sealed class BodyException(string reason) : ArgumentException("candidate body: " + reason)
{
    public string Reason { get; } = reason;
}

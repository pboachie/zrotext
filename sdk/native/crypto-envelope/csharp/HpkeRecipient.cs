using System;
using System.Numerics;
using System.Security.Cryptography;
using System.Text;

namespace Zrotext.Candidate;

/// <summary>Candidate-only RFC9180 base-mode, sequence-zero CEK unwrap. No manifest authority.</summary>
public static class HpkeRecipient
{
    private static readonly byte[] Kem = {75,69,77,0,16};
    private static readonly byte[] Suite = {72,80,75,69,0,16,0,1,0,1};
    private static readonly byte[] Version = Encoding.ASCII.GetBytes("HPKE-v1");
    private static byte[] Join(params byte[][] values) {
        int size = 0; foreach (var value in values) size += value.Length;
        var result = new byte[size]; int at = 0;
        foreach (var value in values) { value.CopyTo(result, at); at += value.Length; }
        return result;
    }
    private static byte[] Extract(byte[] suite, byte[] salt, string label, byte[] input) =>
        HMACSHA256.HashData(salt, Join(Version, suite, Encoding.ASCII.GetBytes(label), input));
    private static byte[] Expand(byte[] suite, byte[] key, string label, byte[] info, int size) {
        var block = HMACSHA256.HashData(key, Join(new byte[] {0, (byte)size}, Version, suite, Encoding.ASCII.GetBytes(label), info, new byte[] {1}));
        try { return block.AsSpan(0, size).ToArray(); } finally { CryptographicOperations.ZeroMemory(block); }
    }
    private static ECDiffieHellman Point(byte[] bytes) {
        if (bytes.Length != 65 || bytes[0] != 4) throw new CryptographicException("P256 point encoding");
        var x = new BigInteger(bytes.AsSpan(1,32), isUnsigned:true, isBigEndian:true);
        var y = new BigInteger(bytes.AsSpan(33,32), isUnsigned:true, isBigEndian:true);
        var p = new BigInteger(Convert.FromHexString("FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF"), true, true);
        var b = new BigInteger(Convert.FromHexString("5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B"), true, true);
        if (x>=p || y>=p || (y*y-(x*x*x-3*x+b))%p != 0) throw new CryptographicException("P256 point not on curve");
        return ECDiffieHellman.Create(new ECParameters { Curve = ECCurve.NamedCurves.nistP256,
            Q = new ECPoint { X = bytes.AsSpan(1, 32).ToArray(), Y = bytes.AsSpan(33, 32).ToArray() } });
    }
    /// <summary>Caller supplies an authorized native key handle. Exportability is not attested here.</summary>
    public static byte[] Open(ECDiffieHellman recipient, byte[] publicPoint, byte[] encapsulated,
                              byte[] info, byte[] aad, byte[] ciphertext) {
        if (info.Length > 36864 || aad.Length > 36864 || ciphertext.Length != 48)
            throw new CryptographicException("Candidate wrap bounds");
        var pk = (byte[])publicPoint.Clone(); var enc = (byte[])encapsulated.Clone();
        var contextInfo = (byte[])info.Clone(); var authenticated = (byte[])aad.Clone(); var encrypted = (byte[])ciphertext.Clone();
        using var publicKey = Point(pk); using var ephemeral = Point(enc);
        var actual = recipient.ExportParameters(false);
        if (actual.Curve.Oid.Value != ECCurve.NamedCurves.nistP256.Oid.Value || actual.Q.X is null || actual.Q.Y is null ||
            !CryptographicOperations.FixedTimeEquals(actual.Q.X, pk.AsSpan(1,32)) ||
            !CryptographicOperations.FixedTimeEquals(actual.Q.Y, pk.AsSpan(33,32)))
            throw new CryptographicException("Recipient key binding");
        var secrets = new byte[6][];
        var plaintext = new byte[32]; bool success = false;
        try {
            secrets[0] = recipient.DeriveRawSecretAgreement(ephemeral.PublicKey);
            if (secrets[0].Length != 32) throw new CryptographicException("P256 shared secret width");
            secrets[1] = Extract(Kem, Array.Empty<byte>(), "eae_prk", secrets[0]);
            secrets[2] = Expand(Kem, secrets[1], "shared_secret", Join(enc, pk), 32);
            var context = Join(new byte[] {0}, Extract(Suite, Array.Empty<byte>(), "psk_id_hash", Array.Empty<byte>()), Extract(Suite, Array.Empty<byte>(), "info_hash", contextInfo));
            secrets[3] = Extract(Suite, secrets[2], "secret", Array.Empty<byte>());
            secrets[4] = Expand(Suite, secrets[3], "key", context, 16);
            secrets[5] = Expand(Suite, secrets[3], "base_nonce", context, 12);
            using var cipher = new AesGcm(secrets[4], 16);
            cipher.Decrypt(secrets[5], encrypted.AsSpan(0,32), encrypted.AsSpan(32,16), plaintext, authenticated);
            success = true; return plaintext;
        } finally {
            foreach (var secret in secrets) if (secret is not null) CryptographicOperations.ZeroMemory(secret);
            if (!success) CryptographicOperations.ZeroMemory(plaintext);
        }
    }
}

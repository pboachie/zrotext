using System;
using System.Numerics;
using System.Security.Cryptography;
using System.Text;

namespace Zrotext.Candidate;

/// <summary>Candidate-only RFC9180 base-mode, sequence-zero CEK unwrap. No manifest authority.</summary>
public static class HpkeRecipient
{
    /// <summary>Trusted application content adapter. This interface alone makes no custody claim.</summary>
    public interface IContentRecipient { byte[] OpenContent(byte[] publicPoint,byte[] enc,byte[] info,byte[] aad,byte[] ciphertext); }
    private sealed class SoftwareContentAdapter : IContentRecipient {
        private readonly ECDiffieHellman key;internal SoftwareContentAdapter(ECDiffieHellman key){this.key=key;}
        public byte[] OpenContent(byte[] pk,byte[] enc,byte[] info,byte[] aad,byte[] ct)=>HpkeRecipient.OpenContent(key,pk,enc,info,aad,ct);
    }
    public static IContentRecipient SoftwareContent(ECDiffieHellman key)=>new SoftwareContentAdapter(key);
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
    internal static ECDiffieHellman Point(byte[] bytes) {
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
        if(ciphertext.Length!=48)throw new CryptographicException("Candidate wrap bounds");
        return OpenContent(recipient,publicPoint,encapsulated,info,aad,ciphertext);
    }
    internal static byte[] OpenContent(ECDiffieHellman recipient,byte[] publicPoint,byte[] encapsulated,byte[] info,byte[] aad,byte[] ciphertext) {
        if (info.Length > 36864 || aad.Length > 36864 || (ciphertext.Length<17 || ciphertext.Length>32784))
            throw new CryptographicException("Candidate wrap bounds");
        var pk = (byte[])publicPoint.Clone(); var enc = (byte[])encapsulated.Clone();
        var contextInfo = (byte[])info.Clone(); var authenticated = (byte[])aad.Clone(); var encrypted = (byte[])ciphertext.Clone();
        using var publicKey = Point(pk); using var ephemeral = Point(enc);
        var actual = recipient.ExportParameters(false);
        if (actual.Curve.Oid.Value != ECCurve.NamedCurves.nistP256.Oid.Value || actual.Q.X is null || actual.Q.Y is null ||
            !CryptographicOperations.FixedTimeEquals(actual.Q.X, pk.AsSpan(1,32)) ||
            !CryptographicOperations.FixedTimeEquals(actual.Q.Y, pk.AsSpan(33,32)))
            throw new CryptographicException("Recipient key binding");
        var shared=recipient.DeriveRawSecretAgreement(ephemeral.PublicKey);
        try{return CryptContent(shared,pk,enc,contextInfo,authenticated,encrypted,false);}finally{CryptographicOperations.ZeroMemory(shared);}
    }
    internal static byte[] SealContent(byte[] pk,byte[] info,byte[] aad,byte[] plain) {
        if(plain.Length<1 || plain.Length>32768)throw new CryptographicException("Candidate content bounds");
        using var peer=Point(pk);using var ephemeral=ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);var q=ephemeral.ExportParameters(false).Q;var enc=Join(new byte[]{4},q.X!,q.Y!);var shared=ephemeral.DeriveRawSecretAgreement(peer.PublicKey);
        try{return Join(enc,CryptContent(shared,pk,enc,info,aad,plain,true));}finally{CryptographicOperations.ZeroMemory(shared);}
    }
    private static byte[] CryptContent(byte[] shared,byte[] pk,byte[] enc,byte[] contextInfo,byte[] authenticated,byte[] encrypted,bool seal) {
        if(shared.Length!=32 || contextInfo.Length>36864 || authenticated.Length>36864 || (seal?(encrypted.Length<1 || encrypted.Length>32768):(encrypted.Length<17 || encrypted.Length>32784)))throw new CryptographicException("Candidate content bounds");
        var secrets = new byte[6][];
        var plaintext = new byte[seal?encrypted.Length+16:encrypted.Length-16]; bool success = false;
        try {
            secrets[0] = (byte[])shared.Clone();
            if (secrets[0].Length != 32) throw new CryptographicException("P256 shared secret width");
            secrets[1] = Extract(Kem, Array.Empty<byte>(), "eae_prk", secrets[0]);
            secrets[2] = Expand(Kem, secrets[1], "shared_secret", Join(enc, pk), 32);
            var context = Join(new byte[] {0}, Extract(Suite, Array.Empty<byte>(), "psk_id_hash", Array.Empty<byte>()), Extract(Suite, Array.Empty<byte>(), "info_hash", contextInfo));
            secrets[3] = Extract(Suite, secrets[2], "secret", Array.Empty<byte>());
            secrets[4] = Expand(Suite, secrets[3], "key", context, 16);
            secrets[5] = Expand(Suite, secrets[3], "base_nonce", context, 12);
            using var cipher = new AesGcm(secrets[4], 16);
            if(seal)cipher.Encrypt(secrets[5],encrypted,plaintext.AsSpan(0,encrypted.Length),plaintext.AsSpan(encrypted.Length,16),authenticated);
            else cipher.Decrypt(secrets[5], encrypted.AsSpan(0,encrypted.Length-16), encrypted.AsSpan(encrypted.Length-16,16), plaintext, authenticated);
            success = true; return plaintext;
        } finally {
            foreach (var secret in secrets) if (secret is not null) CryptographicOperations.ZeroMemory(secret);
            if (!success) CryptographicOperations.ZeroMemory(plaintext);
        }
    }
}

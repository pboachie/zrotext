using System;
using System.Numerics;
using System.Security.Cryptography;
using Zrotext.Candidate;

int checks = 0, vectors = 0;
void Rejects(Action action) {
    try { action(); } catch (Exception error) when (error is CryptographicException or ArgumentException) { checks++; return; }
    throw new Exception("Invalid wrap accepted");
}
byte[] Mutate(byte[] value) {
    if (value.Length == 0) return new byte[] {1};
    var result = (byte[])value.Clone(); result[^1] ^= 1; return result;
}
for (string? line; (line = Console.ReadLine()) is not null;) {
    var fields = line.Split('\t');
    if (fields.Length != 9) throw new Exception("Fixture fields");
    var data = new byte[7][];
    for (int i=0;i<7;i++) data[i] = Convert.FromHexString(fields[i+2]);
    // Private scalar import is intentionally confined to the test adapter.
    using var key = ECDiffieHellman.Create(new ECParameters { Curve=ECCurve.NamedCurves.nistP256, D=data[0],
        Q=new ECPoint { X=data[1].AsSpan(1,32).ToArray(), Y=data[1].AsSpan(33,32).ToArray() } });
    var plaintext = HpkeRecipient.Open(key,data[1],data[2],data[3],data[4],data[5]);
    if (!CryptographicOperations.FixedTimeEquals(plaintext,data[6])) throw new Exception("Cross-client plaintext mismatch");
    CryptographicOperations.ZeroMemory(plaintext); checks++; vectors++;
    var negated = (byte[])data[1].Clone();
    var prime = new BigInteger(Convert.FromHexString("FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF"),true,true);
    var opposite = (prime-new BigInteger(negated.AsSpan(33,32),true,true)).ToByteArray(true,true);
    negated.AsSpan(33,32).Clear(); opposite.CopyTo(negated,65-opposite.Length);
    try { HpkeRecipient.Open(key,negated,data[2],data[3],data[4],new byte[48]); throw new Exception("Unbound recipient"); }
    catch (CryptographicException error) when (error.Message == "Recipient key binding") { checks++; }
    for (int i=1;i<=5;i++) {
        var changed = (byte[][])data.Clone(); changed[i] = Mutate(changed[i]);
        Rejects(() => HpkeRecipient.Open(key,changed[1],changed[2],changed[3],changed[4],changed[5]));
    }
    Rejects(() => HpkeRecipient.Open(key,data[1],new byte[65],data[3],data[4],data[5]));
    var offCurve = new byte[65]; offCurve[0]=4;
    Rejects(() => HpkeRecipient.Open(key,data[1],offCurve,data[3],data[4],data[5]));
    Rejects(() => HpkeRecipient.Open(key,data[1],new byte[33],data[3],data[4],data[5]));
    Rejects(() => HpkeRecipient.Open(key,data[1],data[2],new byte[36865],data[4],data[5]));
    Rejects(() => HpkeRecipient.Open(key,data[1],data[2],data[3],new byte[36865],data[5]));
    Rejects(() => HpkeRecipient.Open(key,data[1],data[2],data[3],data[4],new byte[47]));
}
if (vectors<2) throw new Exception("Missing profile component vectors");
Console.WriteLine($"C# HPKE: {checks} checks on {vectors} vectors passed");

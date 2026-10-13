using System;
using System.Numerics;
using System.Security.Cryptography;
using Zrotext.Candidate;
int checks=0,rows=0;
void Reject(Action attempt) {
    try{attempt();}catch(CryptographicException){checks++;return;}
    throw new Exception("Invalid envelope accepted");
}
for(string? line;(line=Console.ReadLine()) is not null;) {
    var f=line.Split('\t');if(f.Length!=9)throw new Exception("Fixture fields");
    int profile=int.Parse(f[1]),role=int.Parse(f[5]);
    var bytes=Convert.FromHexString(f[2]);var signer=Convert.FromHexString(f[3]);var bodyAad=Convert.FromHexString(f[4]);var id=Convert.FromHexString(f[6]);
    var signed=SignedEnvelope.Verify(bytes,profile,signer);
    if(!signed.BodyAad().AsSpan().SequenceEqual(bodyAad) || !signed.WrapInfo(role,id).AsSpan().SequenceEqual(Convert.FromHexString(f[7])) || !signed.WrapAad(role,id).AsSpan().SequenceEqual(Convert.FromHexString(f[8])))throw new Exception("Transcript mismatch");
    checks+=3;rows++;
    var copied=signed.Bytes();Array.Clear(copied);if(!signed.Bytes().AsSpan().SequenceEqual(bytes))throw new Exception("Mutable snapshot");checks++;
    foreach(int at in new[]{0,4,5,6,7,8,9,10,74,114,146,154,162,bytes.Length-65,bytes.Length-1}) {
        var changed=(byte[])bytes.Clone();changed[at]^=1;Reject(()=>SignedEnvelope.Verify(changed,profile,signer));
    }
    Reject(()=>SignedEnvelope.Verify(bytes,profile==2?3:2,signer));
    Reject(()=>SignedEnvelope.Verify(bytes.AsSpan(0,bytes.Length-1).ToArray(),profile,signer));
    var trailing=new byte[bytes.Length+1];bytes.CopyTo(trailing,0);Reject(()=>SignedEnvelope.Verify(trailing,profile,signer));
    Reject(()=>signed.WrapInfo(role,new byte[32]));
    var order=new BigInteger(Convert.FromHexString("FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551"),true,true);
    var high=(byte[])bytes.Clone();var scalar=(order-new BigInteger(bytes.AsSpan(bytes.Length-32,32),true,true)).ToByteArray(true,true);
    high.AsSpan(high.Length-32,32).Clear();scalar.CopyTo(high,high.Length-scalar.Length);Reject(()=>SignedEnvelope.Verify(high,profile,signer));
    Array.Clear(bytes);if(!signed.BodyAad().AsSpan().SequenceEqual(bodyAad))throw new Exception("Caller mutation changed verified bytes");checks++;
}
if(rows<3)throw new Exception("Missing fixture coverage");
Console.WriteLine($"C# envelope: {checks} checks on {rows} rows passed");

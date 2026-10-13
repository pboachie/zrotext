using System;
using System.Buffers.Binary;
using System.Numerics;
using System.Security.Cryptography;
using System.Text;

namespace Zrotext.Candidate;

/// <summary>Immutable signature-verified component, not manifest or current authority.</summary>
public sealed class SignedEnvelope {
    private readonly byte[] bytes;
    private readonly int profile, kind, prefixEnd, bodyEnd, count;
    private static readonly BigInteger Order = new(Convert.FromHexString("FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551"),true,true);
    private SignedEnvelope(byte[] bytes,int profile,int kind,int prefixEnd,int bodyEnd,int count) {
        this.bytes=bytes; this.profile=profile; this.kind=kind; this.prefixEnd=prefixEnd; this.bodyEnd=bodyEnd; this.count=count;
    }
    private static void Require(bool condition) { if(!condition) throw new CryptographicException("Invalid candidate envelope"); }
    private static byte[] Domain(string label) => Encoding.ASCII.GetBytes(label+"\0");
    private static byte[] Join(params byte[][] parts) {
        int size=0; foreach(var part in parts) size+=part.Length;
        var output=new byte[size]; int at=0;
        foreach(var part in parts) {part.CopyTo(output,at);at+=part.Length;} return output;
    }
    private static long U64(byte[] input,int at) {long value=BinaryPrimitives.ReadInt64BigEndian(input.AsSpan(at,8));Require(value>=0);return value;}
    public static SignedEnvelope Verify(byte[] input,int expectedProfile,byte[] trustedSigner) {
        Require(expectedProfile is 2 or 3); Require(input.Length>=426 && input.Length<=36864);
        var b=(byte[])input.Clone();var signer=(byte[])trustedSigner.Clone();
        Require(b[0]==90 && b[1]==84 && b[2]==83 && b[3]==69 && b[4]==expectedProfile && b[6]==0 && b[7]==0);
        int kind=b[5];Require(kind is 1 or 2);Require(expectedProfile!=3 || kind==1);
        if(expectedProfile==3 && b.AsSpan(26,16).SequenceEqual(new byte[16]))
            throw new CryptographicException("Profile03 message identity");
        Require(b.Length<=(kind==1?34213:34082));
        int size=BinaryPrimitives.ReadUInt16BigEndian(b.AsSpan(8,2));
        Require(size>=(kind==1?157:172) && size<=(kind==1?170:185));
        int end=10+size,peerAt=10+(kind==1?153:168),peerLength=b[peerAt];
        Require(peerLength>=3 && peerLength<=16 && size==(kind==1?154:169)+peerLength);
        Require(b[peerAt+1]==43 && b[peerAt+2]>=49 && b[peerAt+2]<=57);
        for(int i=peerAt+3;i<end;i++) Require(b[i]>=48 && b[i]<=57);
        U64(b,74);long observed=U64(b,146);
        if(kind==1) {long expires=U64(b,154);Require(b[162]==1 && expires>observed && expires-observed<=900000);}
        else {Require(b.AsSpan(26,16).SequenceEqual(b.AsSpan(154,16)));Require(U64(b,170)>0);}
        uint length=BinaryPrimitives.ReadUInt32BigEndian(b.AsSpan(end+12,4));Require(length>=17 && length<=32784);
        int bodyEnd=end+16+(int)length;Require(bodyEnd<b.Length);
        int count=b[bodyEnd];Require(count>=(kind==1?2:1) && count<=(kind==1?8:7));
        int unsignedEnd=bodyEnd+1+146*count;Require(unsignedEnd+64==b.Length);
        int devices=0,archives=0;byte[]? previous=null;
        for(int i=0;i<count;i++) {
            int at=bodyEnd+1+146*i,role=b[at];Require(role>=1 && role<=3);
            var ordering=b.AsSpan(at,33).ToArray();Require(previous is null || previous.AsSpan().SequenceCompareTo(ordering)<0);previous=ordering;
            using var point=HpkeRecipient.Point(b.AsSpan(at+33,65).ToArray());
            if(role==1)devices++;if(role==2)archives++;
        }
        Require(devices==(kind==1?1:0) && archives==1);
        var raw=b.AsSpan(unsignedEnd,64).ToArray();
        var r=new BigInteger(raw.AsSpan(0,32),true,true);var s=new BigInteger(raw.AsSpan(32,32),true,true);
        Require(r>0 && r<Order && s>0 && s<=Order/2);
        using var signerPoint=HpkeRecipient.Point(signer);
        var identity=SHA256.HashData(Join(Domain("ZTSE/key/v1"),new byte[]{1,1},signer));
        Require(CryptographicOperations.FixedTimeEquals(identity,b.AsSpan(114,32)));
        var lengthBytes=new byte[4];BinaryPrimitives.WriteInt32BigEndian(lengthBytes,unsignedEnd);
        var transcript=Join(Domain("ZTSE/sign/v"+expectedProfile),lengthBytes,b.AsSpan(0,unsignedEnd).ToArray());
        using var verifier=ECDsa.Create(signerPoint.ExportParameters(false));
        Require(verifier.VerifyData(transcript,raw,HashAlgorithmName.SHA256,DSASignatureFormat.IeeeP1363FixedFieldConcatenation));
        return new SignedEnvelope(b,expectedProfile,kind,end,bodyEnd,count);
    }
    public int Profile => profile;
    public int Kind => kind;
    public byte[] Bytes() => (byte[])bytes.Clone();
    public byte[] ProtectedBytes() => bytes.AsSpan(10,prefixEnd-10).ToArray();
    public byte[] Nonce() => bytes.AsSpan(prefixEnd,12).ToArray();
    public byte[] BodyCiphertext() => bytes.AsSpan(prefixEnd+16,bodyEnd-prefixEnd-16).ToArray();
    public byte[] BodyAad() => Join(Domain("ZTSE/body/v"+profile),bytes.AsSpan(0,prefixEnd).ToArray());
    private int Wrap(int role,byte[] identity) {
        Require(identity.Length==32);
        for(int i=0;i<count;i++) {int at=bodyEnd+1+146*i;if(bytes[at]==role && CryptographicOperations.FixedTimeEquals(identity,bytes.AsSpan(at+1,32)))return at;}
        throw new CryptographicException("Recipient wrap missing");
    }
    private byte[] Suffix(int role,byte[] identity) {int at=Wrap(role,identity);return Join(bytes.AsSpan(0,prefixEnd).ToArray(),bytes.AsSpan(at,33).ToArray());}
    public byte[] WrapInfo(int role,byte[] identity) => Join(Domain("ZTSE/wrap/v"+profile),Suffix(role,identity));
    public byte[] WrapAad(int role,byte[] identity) {var suffix=Suffix(role,identity);return profile==2?Array.Empty<byte>():Join(Domain("ZTSE/wrap-aad/v3"),suffix);}
    public byte[] Encapsulated(int role,byte[] identity) {int at=Wrap(role,identity);return bytes.AsSpan(at+33,65).ToArray();}
    public byte[] WrappedKey(int role,byte[] identity) {int at=Wrap(role,identity);return bytes.AsSpan(at+98,48).ToArray();}
}

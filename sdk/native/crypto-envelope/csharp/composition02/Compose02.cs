using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
namespace Zrotext.Candidate;

/// <summary>Fresh profile02 candidate bytes, never live transport permission.</summary>
public static class Compose02 {
    public sealed record Recipient(int Role,byte[] Id);
    public sealed record Request(ManifestChain.Verified Manifest,long NowMs,byte[] Message,byte[] Device,byte[] Line,
        long ObservedMs,long ExpiresMs,string Peer,string Content,ProtectedSigner Signer,IReadOnlyList<Recipient> Recipients);
    private static void Need(bool value){if(!value)throw new CryptographicException("Candidate composition refused");}
    private static byte[] Join(params byte[][] values){var result=new byte[values.Sum(b=>b.Length)];int at=0;foreach(var b in values){b.CopyTo(result,at);at+=b.Length;}return result;}
    private static byte[] Label(string value)=>Encoding.ASCII.GetBytes(value+"\0");
    private static byte[] Part(byte[] b,int at,int length)=>b.AsSpan(at,length).ToArray();
    private static bool Same(byte[] a,byte[] b)=>CryptographicOperations.FixedTimeEquals(a,b);
    private static byte[] U64(long n){var b=new byte[8];BinaryPrimitives.WriteInt64BigEndian(b,n);return b;}
    private static long Num(byte[] b,int at)=>BinaryPrimitives.ReadInt64BigEndian(b.AsSpan(at,8));
    private static byte[] Id(byte[] point)=>SHA256.HashData(Join(Label("ZTSE/key/v1"),new byte[]{1,1},point));
    private static byte[] Extract(byte[] suite,byte[] salt,string label,byte[] data)=>HMACSHA256.HashData(salt,Join(Encoding.ASCII.GetBytes("HPKE-v1"),suite,Encoding.ASCII.GetBytes(label),data));
    private static byte[] Expand(byte[] suite,byte[] key,string label,byte[] info,int size){byte[] block=HMACSHA256.HashData(key,Join(new byte[]{0,(byte)size},Encoding.ASCII.GetBytes("HPKE-v1"),suite,Encoding.ASCII.GetBytes(label),info,new byte[]{1}));try{return Part(block,0,size);}finally{CryptographicOperations.ZeroMemory(block);}}
    private static byte[] Encrypt(byte[] key,byte[] nonce,byte[] text,byte[] aad){var cipher=new byte[text.Length];var tag=new byte[16];using var aes=new AesGcm(key,16);aes.Encrypt(nonce,text,cipher,tag,aad);return Join(cipher,tag);}
    private static byte[] Wrap(byte[] point,byte[] cek,byte[] info,byte[] aad){
        using var ephemeral=ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);using var recipient=HpkeRecipient.Point(point);var q=ephemeral.ExportParameters(false).Q;byte[] enc=Join(new byte[]{4},q.X!,q.Y!);
        byte[] kem={75,69,77,0,16},suite={72,80,75,69,0,16,0,1,0,1};var material=new List<byte[]>();
        byte[] Keep(byte[] value){material.Add(value);return value;}
        try{
            byte[] dh=Keep(ephemeral.DeriveRawSecretAgreement(recipient.PublicKey));Need(dh.Length==32);
            byte[] prk=Keep(Extract(kem,Array.Empty<byte>(),"eae_prk",dh)),shared=Keep(Expand(kem,prk,"shared_secret",Join(enc,point),32));
            byte[] context=Join(new byte[]{0},Extract(suite,Array.Empty<byte>(),"psk_id_hash",Array.Empty<byte>()),Extract(suite,Array.Empty<byte>(),"info_hash",info));
            byte[] schedule=Keep(Extract(suite,shared,"secret",Array.Empty<byte>())),key=Keep(Expand(suite,schedule,"key",context,16)),nonce=Keep(Expand(suite,schedule,"base_nonce",context,12));
            return Join(enc,Encrypt(key,nonce,cek,aad));
        }finally{foreach(var value in material)CryptographicOperations.ZeroMemory(value);}
    }
    public static byte[] Fresh(Request input){
        Need(input.Message.Length==16 && input.Device.Length==16 && input.Line.Length==16 && input.Recipients.Count is >=2 and <=8 && input.Recipients.All(v=>v.Role is >=1 and <=3 && v.Id.Length==32));
        var r=input with{Message=(byte[])input.Message.Clone(),Device=(byte[])input.Device.Clone(),Line=(byte[])input.Line.Clone(),Recipients=input.Recipients.Select(v=>new Recipient(v.Role,(byte[])v.Id.Clone())).ToArray()};
        Need(r.Manifest.Profile==2 && r.NowMs>=0 && r.ObservedMs>=0 && r.ExpiresMs>r.ObservedMs && r.ExpiresMs-r.ObservedMs<=900000);
        var current=ManifestChain.ContinueChain(r.Manifest.Bytes(),r.Manifest,2,r.NowMs);
        Need(r.Peer.Length is >=3 and <=16 && r.Peer[0]=='+' && r.Peer[1] is >= '1' and <= '9' && r.Peer.AsSpan(2).ToArray().All(c=>c is >= '0' and <= '9'));
        Need(r.Content.Length is >=1 and <=32768);byte[] text=new UTF8Encoding(false,true).GetBytes(r.Content);byte[]? cek=null;
        try{
            Need(text.Length is >=1 and <=32768 && !text.Contains((byte)0) && !text.AsSpan().StartsWith(new byte[]{239,187,191}));
            byte[] publicPoint=r.Signer.PublicPoint(),signerId=Id(publicPoint);var keys=current.KeyRecords();byte[] signer=keys.Single(k=>k[0]==5 && Same(Part(k,1,32),signerId));
            Need(signer[148]==1 && Num(signer,132)<=r.NowMs && r.NowMs<Num(signer,140) && BinaryPrimitives.ReadUInt16BigEndian(signer.AsSpan(130))==1 && Same(Part(signer,114,16),r.Line) && Same(Part(signer,33,65),publicPoint));
            var sorted=r.Recipients.OrderBy(v=>v.Role).ThenBy(v=>Convert.ToHexString(v.Id),StringComparer.Ordinal).ToArray();Need(sorted.Count(v=>v.Role==1)==1 && sorted.Count(v=>v.Role==2)==1 && sorted.Select(v=>v.Role+":"+Convert.ToHexString(v.Id)).Distinct().Count()==sorted.Length);
            var targets=new List<(int Role,byte[] Id,byte[] Point)>();foreach(var v in sorted){byte[] key=keys.Single(k=>k[0]==v.Role && Same(Part(k,1,32),v.Id));Need(key[148]==1 && Num(key,132)<=r.NowMs && r.NowMs<Num(key,140) && (BinaryPrimitives.ReadUInt16BigEndian(key.AsSpan(130))&4)!=0);if(v.Role==1)Need(Same(Part(key,98,16),r.Device) && Same(Part(key,114,16),r.Line));targets.Add((v.Role,v.Id,Part(key,33,65)));}
            byte[] fields=Join(current.Account(),r.Message,r.Device,r.Line,U64(current.Version),current.Digest(),signerId,U64(r.ObservedMs),U64(r.ExpiresMs),new byte[]{1,(byte)r.Peer.Length},Encoding.ASCII.GetBytes(r.Peer)),size=new byte[2];BinaryPrimitives.WriteUInt16BigEndian(size,checked((ushort)fields.Length));byte[] prefix=Join(new byte[]{90,84,83,69,2,1,0,0},size,fields);
            cek=RandomNumberGenerator.GetBytes(32);byte[] nonce=RandomNumberGenerator.GetBytes(12),body=Encrypt(cek,nonce,text,Join(Label("ZTSE/body/v2"),prefix));var wraps=new List<byte[]>();foreach(var v in targets)wraps.Add(Join(new byte[]{(byte)v.Role},v.Id,Wrap(v.Point,cek,Join(Label("ZTSE/wrap/v2"),prefix,new byte[]{(byte)v.Role},v.Id),Array.Empty<byte>())));
            byte[] length=new byte[4];BinaryPrimitives.WriteInt32BigEndian(length,body.Length);byte[] unsigned=Join(prefix,nonce,length,body,new byte[]{(byte)wraps.Count},Join(wraps.ToArray())),envelope=Join(unsigned,r.Signer.SignEnvelope02(unsigned));SignedEnvelope.Verify(envelope,2,publicPoint);return envelope;
        }finally{CryptographicOperations.ZeroMemory(text);if(cek is not null)CryptographicOperations.ZeroMemory(cek);}
    }
}

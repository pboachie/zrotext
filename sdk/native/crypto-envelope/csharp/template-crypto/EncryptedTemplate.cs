using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
namespace Zrotext.Candidate;

/// <summary>Candidate ZTWT01 client encryption. No network, save or dispatch authority.</summary>
public static class EncryptedTemplate
{
    private static readonly byte[] Domain=Encoding.ASCII.GetBytes("ZT/workflow-template/hpke/v1\0");
    private static void Need(bool b){if(!b)throw new CryptographicException("Encrypted template refused");}
    private static long Number(byte[] b,int at)=>BinaryPrimitives.ReadInt64BigEndian(b.AsSpan(at,8));
    private static bool Same(byte[] a,byte[] b)=>CryptographicOperations.FixedTimeEquals(a,b);
    private static byte[] Join(params byte[][] pieces){int length=pieces.Sum(p=>p.Length);var result=new byte[length];int at=0;foreach(var p in pieces){p.CopyTo(result,at);at+=p.Length;}return result;}
    /// <summary>Independently expected context. Never derive it from untrusted ciphertext.</summary>
    public sealed class Scope
    {
        private readonly byte[] aad;
        public Scope(byte[] expectedAad){Need(expectedAad.Length==222);var b=(byte[])expectedAad.Clone();Need(b[..6].SequenceEqual(new byte[]{90,84,87,84,1,1}));foreach(int at in new[]{6,22,38,54,70})Need(b.AsSpan(at,16).ContainsAnyExcept((byte)0));foreach(int at in new[]{86,94,102,110,118})Need(Number(b,at)>0);Need(Number(b,94)<=128);foreach(int at in new[]{126,158,190})Need(b.AsSpan(at,32).ContainsAnyExcept((byte)0));aad=b;}
        public static Scope Capture(byte[] account,byte[] device,byte[] line,byte[] interval,byte[] template,long binding,long revision,long expires,long trust,long version,byte[] peerDigest,byte[] reader,byte[] manifestDigest){foreach(var b in new[]{account,device,line,interval,template})Need(b.Length==16);foreach(var b in new[]{peerDigest,reader,manifestDigest})Need(b.Length==32);var numbers=new byte[40];int at=0;foreach(long n in new[]{binding,revision,expires,trust,version}){BinaryPrimitives.WriteInt64BigEndian(numbers.AsSpan(at,8),n);at+=8;}return new Scope(Join(new byte[]{90,84,87,84,1,1},account,device,line,interval,template,numbers,peerDigest,reader,manifestDigest));}
        public byte[] Aad()=>(byte[])aad.Clone();
    }
    public sealed record Authority(ManifestChain.Verified Manifest,long NowMs);
    private static bool Active(byte[] k,long now,int permission)=>k[148]==1 && Number(k,132)<=now && now<Number(k,140) && (BinaryPrimitives.ReadUInt16BigEndian(k.AsSpan(130,2))&permission)!=0;
    private static byte[] Authorize(Authority a,byte[] aad){
        Need(a is not null && a.Manifest is not null && a.NowMs>0 && a.Manifest.Profile==2);var m=ManifestChain.ContinueChain(a!.Manifest!.Bytes(),a.Manifest,2,a.NowMs);long expires=Number(aad,102);
        Need(expires>a.NowMs && expires-a.NowMs<=(30L*86400000) && Same(m.Account(),aad[6..22]) && m.Generation==Number(aad,110) && m.Version==Number(aad,118) && Same(m.Digest(),aad[190..222]));byte[]? reader=null;bool signer=false;
        foreach(var key in m.KeyRecords()){if(key[0]==2 && Same(key[1..33],aad[158..190]) && Active(key,a.NowMs,8))reader=key[33..98];if(key[0]==4 && Same(key[98..114],aad[22..38]) && Same(key[114..130],aad[38..54]) && Active(key,a.NowMs,2) && BinaryPrimitives.ReadUInt16BigEndian(key.AsSpan(130,2))==2)signer=true;}
        Need(reader is not null && signer);return reader!;
    }
    private static void FinalCheck(Authority before,byte[] point,byte[] aad,Func<Authority> source){var after=source();var current=Authorize(after,aad);Need(after.NowMs>=before.NowMs && Same(point,current) && Same(before.Manifest.RootPoint(),after.Manifest.RootPoint()) && Same(before.Manifest.EnrolledRootPoint(),after.Manifest.EnrolledRootPoint()));}
    /// <summary>Source must consult current permission/selection; signed history alone is insufficient.</summary>
    public static byte[] Seal(Scope scope,TemplateContent content,Func<Authority> source){byte[]? plain=null;try{var aad=scope.Aad();plain=content.Canonical();Need(plain.Length>=1 && plain.Length<=32768);var before=source();var point=Authorize(before,aad);var wrapped=HpkeRecipient.SealContent(point,Join(Domain,aad),aad,plain);Need(wrapped.Length==65+plain.Length+16);var length=new byte[4];BinaryPrimitives.WriteInt32BigEndian(length,wrapped.Length-65);var output=Join(aad,wrapped[..65],length,wrapped[65..]);FinalCheck(before,point,aad,source);return output;}finally{if(plain is not null)CryptographicOperations.ZeroMemory(plain);}}
    public static TemplateContent Open(Scope scope,byte[] envelope,HpkeRecipient.IContentRecipient recipient,Func<Authority> source){byte[]? plain=null;try{Need(envelope.Length>=308 && envelope.Length<=33075);var wire=(byte[])envelope.Clone();var aad=scope.Aad();Need(Same(wire[..222],aad) && BinaryPrimitives.ReadInt32BigEndian(wire.AsSpan(287,4))==wire.Length-291);var before=source();var point=Authorize(before,aad);plain=recipient.OpenContent(point,wire[222..287],Join(Domain,aad),aad,wire[291..]);Need(plain.Length>=1 && plain.Length<=32768);FinalCheck(before,point,aad,source);return TemplateContent.Parse(plain);}finally{if(plain is not null)CryptographicOperations.ZeroMemory(plain);}}
    /// <summary>Digest of transport bytes only, not plaintext or authority.</summary>
    public static byte[] Digest(byte[] envelope){Need(envelope.Length>=308 && envelope.Length<=33075);return SHA256.HashData((byte[])envelope.Clone());}
}

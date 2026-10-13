using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.Numerics;
using System.Security.Cryptography;
using System.Text;

namespace Zrotext.Candidate;

/// <summary>Selected role-3 opening with independently authenticated callback authority.</summary>
public static class OriginalReplyReader {
    private static readonly object Permit=new();
    private static readonly BigInteger Order=new(Convert.FromHexString("FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551"),true,true);
    private const string Disclosure="With your approval, ZROtext transfers encrypted SMS content for this selected phone line and conversation to your paired browser and the explicitly listed customer-controlled readers. Stop closes new capture and transfer; retained encrypted content is deleted separately.";
    private static void Need(bool ok){if(!ok)throw new CryptographicException("Original reply refused");}
    private static byte[] Part(byte[] b,int at,int size)=>b.AsSpan(at,size).ToArray();
    private static bool Same(byte[] a,byte[] b)=>CryptographicOperations.FixedTimeEquals(a,b);
    private static bool Zero(byte[] b){foreach(byte v in b)if(v!=0)return false;return true;}
    private static long Number(byte[] b,int at)=>BinaryPrimitives.ReadInt64BigEndian(b.AsSpan(at,8));
    private static byte[] Fixed(byte[] b,int size){Need(b.Length==size && !Zero(b));return (byte[])b.Clone();}
    public sealed class Scope {
        private readonly byte[] account,device,line,interval,connector,grant,reader;
        public string Peer{get;}
        public Scope(byte[] account,byte[] device,byte[] line,byte[] interval,byte[] connector,byte[] grant,byte[] reader,string peer){
            this.account=Fixed(account,16);this.device=Fixed(device,16);this.line=Fixed(line,16);this.interval=Fixed(interval,16);this.connector=Fixed(connector,16);this.grant=Fixed(grant,16);this.reader=Fixed(reader,32);
            Need(System.Text.RegularExpressions.Regex.IsMatch(peer,@"\A\+[1-9][0-9]{1,14}\z"));Peer=peer;
        }
        internal byte[] Account=>(byte[])account.Clone();internal byte[] Device=>(byte[])device.Clone();internal byte[] Line=>(byte[])line.Clone();internal byte[] Interval=>(byte[])interval.Clone();internal byte[] Connector=>(byte[])connector.Clone();internal byte[] Grant=>(byte[])grant.Clone();internal byte[] Reader=>(byte[])reader.Clone();
        internal bool Matches(Scope? other)=>other is not null && Same(account,other.account) && Same(device,other.device) && Same(line,other.line) && Same(interval,other.interval) && Same(connector,other.connector) && Same(grant,other.grant) && Same(reader,other.reader) && Peer==other.Peer;
    }
    /// <summary>Dual-phone evidence, not a live grant or durable history receipt.</summary>
    public sealed class Selection {
        private readonly byte[] archive;private readonly byte[][] readers;
        internal Scope Scope{get;}internal ManifestChain.Verified Activation{get;}
        internal byte[] Archive=>(byte[])archive.Clone();internal int Count=>readers.Length;internal byte[] Reader(int i)=>(byte[])readers[i].Clone();
        internal Selection(object permit,Scope scope,byte[] archive,List<byte[]> readers,ManifestChain.Verified activation){Need(ReferenceEquals(permit,Permit));Scope=scope;this.archive=(byte[])archive.Clone();this.readers=new byte[readers.Count][];for(int i=0;i<readers.Count;i++)this.readers[i]=(byte[])readers[i].Clone();Activation=activation;}
    }
    public sealed record Authority(Scope Scope,string Revision,long NowMs,long ExpiresMs,ManifestChain.Verified Manifest);
    private sealed class Cursor {
        private readonly byte[] b;internal int At{get;private set;}
        internal Cursor(byte[] b){this.b=b;}
        internal byte[] Take(int count){Need(count>=0 && count<=b.Length-At);var output=Part(b,At,count);At+=count;return output;}
        internal byte[] Id(int count)=>Fixed(Take(count),count);
        internal long Positive(){long n=Number(Take(8),0);Need(n>0);return n;}
        internal int Octet()=>Take(1)[0];
        internal string Text(){var value=Take(Octet());foreach(byte v in value)Need(v>=33 && v<=126);return Encoding.ASCII.GetString(value);}
    }
    private static byte[] Key(ManifestChain.Verified manifest,int role,byte[] id){foreach(var k in manifest.KeyRecords())if(k[0]==role && Same(Part(k,1,32),id))return k;throw new CryptographicException("Selected key absent");}
    private static void Active(byte[] k,long now,int scope)=>Need(k[148]==1 && now>=Number(k,132) && now<Number(k,140) && (BinaryPrimitives.ReadUInt16BigEndian(k.AsSpan(130,2))&scope)!=0);
    private static void Signature(byte[] point,byte[] input,string domain,byte[] body){
        Need(input.Length==64);var sig=(byte[])input.Clone();var r=new BigInteger(sig.AsSpan(0,32),true,true);var s=new BigInteger(sig.AsSpan(32,32),true,true);Need(r>0 && r<Order && s>0 && s<=Order/2);
        using var publicPoint=HpkeRecipient.Point(point);using var verifier=ECDsa.Create(publicPoint.ExportParameters(false));var prefix=Encoding.ASCII.GetBytes(domain+"\0");var transcript=new byte[prefix.Length+4+body.Length];prefix.CopyTo(transcript,0);BinaryPrimitives.WriteInt32BigEndian(transcript.AsSpan(prefix.Length,4),body.Length);body.CopyTo(transcript,prefix.Length+4);Need(verifier.VerifyData(transcript,sig,HashAlgorithmName.SHA256,DSASignatureFormat.IeeeP1363FixedFieldConcatenation));
    }
    public static Selection VerifySelection(byte[] input,byte[] approval,byte[] installation,ManifestChain.Verified activation,long acceptedMs,Scope scope){
        Need(input.Length>=380 && input.Length<=1536 && activation.Profile==2);var raw=(byte[])input.Clone();var p=new Cursor(raw);Need(Same(p.Take(5),new byte[]{90,84,67,65,2}));var account=p.Id(16);var device=p.Id(16);var line=p.Id(16);p.Positive();var interval=p.Id(16);p.Id(16);p.Id(16);p.Id(32);
        long expires=p.Positive();string peer=p.Text(),content=p.Text();var disclosure=p.Take(32);var archive=p.Id(32);var signer=p.Id(32);long generation=p.Positive(),previous=p.Positive();p.Id(32);long version=p.Positive();var digest=p.Id(32);p.Positive();p.Positive();string site=p.Text(),instance=p.Text();
        int count=p.Octet();Need(count>=1 && count<=6);var readers=new List<byte[]>();var connectors=new List<byte[]>();var grants=new List<byte[]>();bool chosen=false;
        for(int i=0;i<count;i++){var connector=p.Id(16);var grant=p.Id(16);var reader=p.Id(32);Need(i==0 || readers[i-1].AsSpan().SequenceCompareTo(reader)<0);for(int j=0;j<i;j++)Need(!Same(connectors[j],connector) && !Same(grants[j],grant));chosen|=Same(connector,scope.Connector) && Same(grant,scope.Grant) && Same(reader,scope.Reader);connectors.Add(connector);grants.Add(grant);readers.Add(reader);}
        Need(p.At==raw.Length && chosen && content=="conversation-content-v1" && Same(disclosure,SHA256.HashData(Encoding.UTF8.GetBytes(Disclosure))) && site.Length>=1 && site.Length<=64 && instance.Length>=1 && instance.Length<=64 && previous<long.MaxValue && version==previous+1 && acceptedMs>0 && acceptedMs<expires && peer==scope.Peer && Same(account,scope.Account) && Same(device,scope.Device) && Same(line,scope.Line) && Same(interval,scope.Interval));
        var verified=ManifestChain.ContinueChain(activation.Bytes(),activation,2,acceptedMs);Need(verified.Generation==generation && verified.Version==version && Same(verified.Digest(),digest) && Same(verified.Account(),scope.Account));var signing=Key(verified,4,signer);Active(signing,acceptedMs,2);Need(Same(Part(signing,98,16),scope.Device) && Same(Part(signing,114,16),scope.Line));
        Signature(Part(signing,33,65),approval,"zrotext/conversation/approve/v2",raw);Signature(Part(signing,33,65),installation,"zrotext/conversation/install/v2",raw);return new Selection(Permit,scope,archive,readers,verified);
    }
    private static Authority Current(Authority value,Scope scope){
        Need(value is not null && scope.Matches(value.Scope) && !string.IsNullOrEmpty(value.Revision) && value.Revision.Length<=128 && value.NowMs>0 && value.NowMs<value.ExpiresMs && value.Manifest.Profile==2);
        return value! with {Manifest=ManifestChain.ContinueChain(value!.Manifest.Bytes(),value.Manifest,2,value.NowMs)};
    }
    public static string OpenSoftware(byte[] input,byte[] expectedEvent,ManifestChain.Verified historical,Selection selection,Scope scope,ECDiffieHellman recipient,Func<Authority> source){
        Need(input.Length>=426 && input.Length<=34082 && historical.Profile==2 && selection.Scope.Matches(scope));var b=(byte[])input.Clone();var message=Fixed(expectedEvent,16);Need(b[4]==2 && b[5]==2 && Same(Part(b,26,16),message));var initial=Current(source(),scope);var current=initial.Manifest;
        Need(Same(historical.Account(),scope.Account) && Same(current.Account(),scope.Account) && historical.Generation==current.Generation && current.Generation==selection.Activation.Generation && Same(historical.EnrolledRootPoint(),current.EnrolledRootPoint()) && Same(current.EnrolledRootPoint(),selection.Activation.EnrolledRootPoint()) && historical.DescendsFrom(selection.Activation) && current.DescendsFrom(historical));
        long observed=Number(b,146);Need(observed>0 && observed<=initial.NowMs && observed<historical.ExpiresMs && (historical.IssuedMs<=observed || historical.IssuedMs-observed<=300000) && Same(Part(b,10,16),scope.Account) && Same(Part(b,42,16),scope.Device) && Same(Part(b,58,16),scope.Line) && Number(b,74)==historical.Version && Same(Part(b,82,32),historical.Digest()));
        var signer=Key(historical,4,Part(b,114,32));Active(signer,observed,2);Need(Same(Part(signer,98,16),scope.Device) && Same(Part(signer,114,16),scope.Line));var envelope=SignedEnvelope.Verify(b,2,Part(signer,33,65));int prefix=10+BinaryPrimitives.ReadUInt16BigEndian(b.AsSpan(8,2)),end=prefix+16+BinaryPrimitives.ReadInt32BigEndian(b.AsSpan(prefix+12,4));Need(Encoding.ASCII.GetString(b,179,prefix-179)==scope.Peer && b[end]==1+selection.Count);
        for(int i=0;i<b[end];i++){int at=end+1+146*i,role=i==0?2:3;var id=i==0?selection.Archive:selection.Reader(i-1);Need(b[at]==role && Same(Part(b,at+1,32),id));Active(Key(historical,role,id),observed,8);}
        var selected=Key(current,3,scope.Reader);Active(selected,initial.NowMs,8);byte[]? cek=null;
        try{
            cek=HpkeRecipient.Open(recipient,Part(selected,33,65),envelope.Encapsulated(3,scope.Reader),envelope.WrapInfo(3,scope.Reader),envelope.WrapAad(3,scope.Reader),envelope.WrappedKey(3,scope.Reader));string plain=CandidateBody.Open(cek,envelope.Nonce(),envelope.BodyAad(),envelope.BodyCiphertext());var after=Current(source(),scope);
            Need(after.Revision==initial.Revision && after.NowMs>=initial.NowMs && after.NowMs<initial.ExpiresMs && after.NowMs<Number(selected,140) && after.Manifest.Generation==current.Generation && after.Manifest.Version==current.Version && Same(after.Manifest.RootPoint(),current.RootPoint()) && Same(after.Manifest.EnrolledRootPoint(),current.EnrolledRootPoint()) && Same(after.Manifest.Digest(),current.Digest()));return plain;
        }finally{if(cek is not null)CryptographicOperations.ZeroMemory(cek);}
    }
}

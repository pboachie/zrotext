using System;
using System.Buffers.Binary;
using System.Numerics;
using System.Security.Cryptography;
using System.Text;
using System.Diagnostics;
using System.Threading;
using System.Threading.Tasks;
namespace Zrotext.Candidate;
/// <summary>Historical integrity only; never current permission, installed access or custody.</summary>
public static class ContactField {
    private static readonly object Permit=new();
    private static readonly SemaphoreSlim Admission=new(4,4);
    private static readonly BigInteger Order=new(Convert.FromHexString("FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551"),true,true);
    internal static void Need(bool value){if(!value)throw new CryptographicException("Contact historical integrity refused");}
    private static byte[] Part(byte[] b,int at,int n)=>b.AsSpan(at,n).ToArray();
    private static bool Same(byte[] a,byte[] b)=>CryptographicOperations.FixedTimeEquals(a,b);
    private static bool Zero(byte[] b){foreach(byte v in b)if(v!=0)return false;return true;}
    private static byte[] Fixed(byte[] b,int n){Need(b is not null && b.Length==n && !Zero(b));return (byte[])b!.Clone();}
    private static long Number(byte[] b,int at){long n=BinaryPrimitives.ReadInt64BigEndian(b.AsSpan(at,8));Need(n>0);return n;}
    private static byte[] Domain(string s)=>Encoding.ASCII.GetBytes(s+"\0");
    private static byte[] Join(params byte[][] values){int size=0;foreach(var b in values)size+=b.Length;byte[] result=new byte[size];int at=0;foreach(var b in values){b.CopyTo(result,at);at+=b.Length;}return result;}
    private static void Signature(byte[] point,byte[] raw,string label,byte[] unsigned){
        Need(raw.Length==64);var r=new BigInteger(raw.AsSpan(0,32),true,true);var s=new BigInteger(raw.AsSpan(32,32),true,true);Need(r>0 && r<Order && s>0 && s<=Order/2);
        using var key=HpkeRecipient.Point(point);using var verifier=ECDsa.Create(key.ExportParameters(false));var length=new byte[4];BinaryPrimitives.WriteInt32BigEndian(length,unsigned.Length);
        Need(verifier.VerifyData(Join(Domain(label),length,unsigned),raw,HashAlgorithmName.SHA256,DSASignatureFormat.IeeeP1363FixedFieldConcatenation));
    }
    public sealed class Statement {
        private readonly byte[] raw,account,fingerprint,manifest,reader,point,root,writer,digest;
        internal byte[] Account=>(byte[])account.Clone();internal byte[] Manifest=>(byte[])manifest.Clone();internal byte[] Reader=>(byte[])reader.Clone();internal byte[] Root=>(byte[])root.Clone();internal byte[] Writer=>(byte[])writer.Clone();
        internal long Version{get;}internal long ReaderGeneration{get;}
        internal Statement(object permit,byte[] b,byte[] account,byte[] fp,byte[] md,byte[] reader,byte[] point,byte[] root,byte[] writer,string origin,long version,long generation){
            Need(ReferenceEquals(permit,Permit));raw=(byte[])b.Clone();this.account=(byte[])account.Clone();fingerprint=(byte[])fp.Clone();manifest=(byte[])md.Clone();this.reader=(byte[])reader.Clone();this.point=(byte[])point.Clone();this.root=(byte[])root.Clone();this.writer=(byte[])writer.Clone();Origin=origin;Version=version;ReaderGeneration=generation;digest=SHA256.HashData(b);
        }
        internal string Origin{get;}internal byte[] Fingerprint=>(byte[])fingerprint.Clone();
        public byte[] Bytes()=>(byte[])raw.Clone();public byte[] Digest()=>(byte[])digest.Clone();
    }
    public static Statement VerifyStatement(byte[] input,ManifestChain.Verified accepted,byte[] expectedAccount,string expectedOrigin,byte[] expectedFingerprint,ContactOrigin parser){
        Need(input is not null && input.Length>=314 && input.Length<=817 && accepted is not null && accepted.Profile==2 && accepted.Generation==1);
        byte[] b=(byte[])input!.Clone(),account=Fixed(expectedAccount,16),fp=Fixed(expectedFingerprint,32);Need(parser is not null && parser.Accepts(expectedOrigin));
        Need(Same(Part(b,0,6),new byte[]{90,84,75,65,1,3}));int n=BinaryPrimitives.ReadUInt16BigEndian(b.AsSpan(38,2));Need(n>=9 && n<=512 && b.Length==305+n);
        string origin=Encoding.ASCII.GetString(b,40,n);Need(parser!.Accepts(origin) && Same(Encoding.ASCII.GetBytes(origin),Part(b,40,n)) && origin==expectedOrigin);
        int at=40+n;Need(Number(b,at)==1);long version=Number(b,at+8),generation=Number(b,at+16);at+=24;
        byte[] fingerprint=Fixed(Part(b,at,32),32),md=Fixed(Part(b,at+32,32),32),reader=Fixed(Part(b,at+64,32),32),point=Fixed(Part(b,at+96,65),65);at+=161;
        long issued=Number(b,at),until=Number(b,at+8);Need(until>issued && until-issued<=86400000);Fixed(Part(b,6,16),16);Fixed(Part(b,22,16),16);using var publicPoint=HpkeRecipient.Point(point);
        Need(Same(reader,SHA256.HashData(Join(Domain("ZTSE/key/v1"),new byte[]{0,16},point))) && Same(Part(b,22,16),account) && Same(accepted!.Account(),account) && version==accepted.Version && Same(md,accepted.Digest()) && issued>=accepted.IssuedMs && until<=accepted.ExpiresMs);
        byte[]? selected=null,rootRecord=null;foreach(byte[] k in accepted!.KeyRecords())if(k[148]==1 && BinaryPrimitives.ReadInt64BigEndian(k.AsSpan(132,8))<=issued && issued<BinaryPrimitives.ReadInt64BigEndian(k.AsSpan(140,8))){if(k[0]==2 && Same(Part(k,1,32),reader))selected=k;if(k[0]==6)rootRecord=k;}
        Need(selected is not null && rootRecord is not null);Need(BinaryPrimitives.ReadUInt16BigEndian(selected!.AsSpan(130,2))==12 && BinaryPrimitives.ReadUInt16BigEndian(rootRecord!.AsSpan(130,2))==0 && Same(Part(selected!,33,65),point) && until<=BinaryPrimitives.ReadInt64BigEndian(selected.AsSpan(140,8)) && until<=BinaryPrimitives.ReadInt64BigEndian(rootRecord.AsSpan(140,8)));
        byte[] root=Part(rootRecord!,33,65),one=new byte[8];BinaryPrimitives.WriteInt64BigEndian(one,1);byte[] pin=Join(new byte[]{90,84,82,80,2},account,one,root);
        Need(Same(fingerprint,fp) && Same(fp,SHA256.HashData(Join(Domain("ZTSE/root-pin/v2"),pin))));Signature(root,Part(b,b.Length-64,64),"ZT/contact-reader/authorization/v1",Part(b,0,b.Length-64));
        return new Statement(Permit,b,account,fp,md,reader,point,root,Part(rootRecord!,1,32),origin,version,generation);
    }
    public sealed class Verified {
        private readonly byte[] bytes,digest;
        internal Verified(object permit,byte[] b){Need(ReferenceEquals(permit,Permit));bytes=(byte[])b.Clone();digest=SHA256.HashData(b);}
        public byte[] Bytes()=>(byte[])bytes.Clone();public byte[] Digest()=>(byte[])digest.Clone();
    }
    public sealed class Expected {
        private readonly byte[] account,fingerprint,contact,routing;
        internal byte[] Account=>(byte[])account.Clone();internal byte[] Fingerprint=>(byte[])fingerprint.Clone();internal byte[] Contact=>(byte[])contact.Clone();internal byte[] Routing=>(byte[])routing.Clone();internal string Origin{get;}
        public Expected(byte[] account,string origin,byte[] fingerprint,byte[] contact,byte[] routing,ContactOrigin parser){this.account=Fixed(account,16);this.fingerprint=Fixed(fingerprint,32);this.contact=Fixed(contact,16);this.routing=Fixed(routing,32);Need(parser is not null && parser.Accepts(origin));Origin=origin;}
    }
    private static void Bound(byte[] u,Statement s,Expected e){
        Need(s is not null && e is not null && Same(s.Account,e.Account) && Same(s.Fingerprint,e.Fingerprint) && s.Origin==e.Origin);
        Need(Same(Part(u,6,16),s!.Account) && Same(Part(u,22,16),e!.Contact) && Same(Part(u,166,32),e.Routing) && Number(u,54)==s.Version && Number(u,62)==s.ReaderGeneration && Same(Part(u,70,32),s.Reader) && Same(Part(u,102,32),s.Manifest) && Same(Part(u,134,32),s.Digest()) && Same(Part(u,214,32),s.Writer));
    }
    public static Verified ProduceSoftware(ECDsa key,Statement statement,Expected expected,byte[] input,CancellationToken cancelled=default){
        ArgumentNullException.ThrowIfNull(key);return Produce(statement,expected,input,cancelled,(u,live)=>{var publicParameters=key.ExportParameters(false);Need(publicParameters.Curve.Oid.Value=="1.2.840.10045.3.1.7" && publicParameters.Q.X is not null && publicParameters.Q.Y is not null && Same(Join(new byte[]{4},publicParameters.Q.X,publicParameters.Q.Y),statement.Root));byte[] challenge=Domain("ZROtext/software-contact-key-binding/v1");live();byte[] binding=key.SignData(challenge,HashAlgorithmName.SHA256,DSASignatureFormat.IeeeP1363FixedFieldConcatenation);using var expectedPoint=HpkeRecipient.Point(statement.Root);using var proof=ECDsa.Create(expectedPoint.ExportParameters(false));Need(proof.VerifyData(challenge,binding,HashAlgorithmName.SHA256,DSASignatureFormat.IeeeP1363FixedFieldConcatenation));byte[] length=new byte[4];BinaryPrimitives.WriteInt32BigEndian(length,u.Length);byte[] transcript=Join(Domain("ZT/contact-field/commitment/v1"),length,u);try{live();byte[] raw=key.SignData(transcript,HashAlgorithmName.SHA256,DSASignatureFormat.IeeeP1363FixedFieldConcatenation);Need(raw.Length==64);var s=new BigInteger(raw.AsSpan(32,32),true,true);if(s>Order/2){byte[] low=(Order-s).ToByteArray(true,true);Array.Clear(raw,32,32);low.CopyTo(raw,64-low.Length);}return raw;}finally{CryptographicOperations.ZeroMemory(transcript);}});
    }
    public static Verified ProduceProtected(ProtectedContactSigner key,Statement statement,Expected expected,byte[] input,CancellationToken cancelled=default){
        Need(key is not null && statement is not null);return Produce(statement!,expected,input,cancelled,(u,live)=>{Need(Same(key!.PublicPoint(),statement!.Root));live();return key.SignField(u,live);});
    }
    private static Verified Produce(Statement statement,Expected expected,byte[] input,CancellationToken cancelled,Func<byte[],Action,byte[]> signer){
        byte[] captured=Unsigned(input);bool transferred=false;
        try{Bound(captured,statement,expected);Need(!cancelled.IsCancellationRequested && Admission.Wait(0));long start=Stopwatch.GetTimestamp();
            bool Live()=>!cancelled.IsCancellationRequested && Stopwatch.GetElapsedTime(start)<TimeSpan.FromSeconds(10);
            Task<Verified> pending;
            try{pending=Task.Run(()=>{byte[]? signature=null,signed=null;try{Need(Live());signature=signer(captured,()=>Need(Live()));Need(Live());signed=Join(captured,signature);var verified=Verify(signed,statement,expected.Contact,expected.Routing);Need(Live());return verified;}finally{CryptographicOperations.ZeroMemory(captured);if(signature is not null)CryptographicOperations.ZeroMemory(signature);if(signed is not null)CryptographicOperations.ZeroMemory(signed);Admission.Release();}});transferred=true;}
            catch{Admission.Release();throw;}
            _=pending.ContinueWith(task=>{_=task.Exception;},CancellationToken.None,TaskContinuationOptions.OnlyOnFaulted|TaskContinuationOptions.ExecuteSynchronously,TaskScheduler.Default);
            while(!pending.IsCompleted){Need(Live());Thread.Sleep(10);}Need(Live());var result=pending.GetAwaiter().GetResult();Need(Live());return result;
        }finally{if(!transferred)CryptographicOperations.ZeroMemory(captured);}
    }
    internal static byte[] Unsigned(byte[] input){
        Need(input is not null && input.Length>=332 && input.Length<=2379);byte[] b=(byte[])input!.Clone();Need(Same(Part(b,0,5),new byte[]{90,84,67,79,1}) && (b[5]==1 || b[5]==2));
        foreach(int at in new[]{6,22,198})Fixed(Part(b,at,16),16);foreach(int at in new[]{70,102,134,166,214})Fixed(Part(b,at,32),32);foreach(int at in new[]{38,46,54,62})Number(b,at);Need(Number(b,46)==1);
        using var point=HpkeRecipient.Point(Part(b,246,65));int n=BinaryPrimitives.ReadInt32BigEndian(b.AsSpan(311,4));Need(n>=17 && n<=(b[5]==1?272:2064) && b.Length==315+n);return b;
    }
    public static Verified Verify(byte[] input,Statement statement,byte[] expectedContact,byte[] expectedRouting){
        Need(input is not null && input.Length>=396 && input.Length<=2443 && statement is not null);byte[] b=(byte[])input!.Clone(),u=Unsigned(Part(b,0,b.Length-64)),contact=Fixed(expectedContact,16),routing=Fixed(expectedRouting,32);
        Need(Same(Part(u,6,16),statement!.Account) && Same(Part(u,22,16),contact) && Same(Part(u,166,32),routing) && Number(u,54)==statement.Version && Number(u,62)==statement.ReaderGeneration && Same(Part(u,70,32),statement.Reader) && Same(Part(u,102,32),statement.Manifest) && Same(Part(u,134,32),statement.Digest()) && Same(Part(u,214,32),statement.Writer));
        Signature(statement.Root,Part(b,b.Length-64,64),"ZT/contact-field/commitment/v1",u);return new Verified(Permit,b);
    }
}

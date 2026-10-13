using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
namespace Zrotext.Candidate;

/// <summary>Candidate protected composition; never an SMS grant or dispatch operation.</summary>
public static class Compose03 {
    public sealed record Recipient(int Role,byte[] Id);
    public sealed record Request(ManifestChain.Verified Manifest,Election03.Proof Proof,ElectedReader03.IAuthoritySource Authority,
        byte[] Message,long ObservedMs,long ExpiresMs,string Peer,string Content,ProtectedSigner Signer,IReadOnlyList<Recipient> Recipients);
    private sealed record Plan(byte[] Prefix,byte[] Text,(int Role,byte[] Id,byte[] Point)[] Recipients,byte[] Public,byte[] Intent,long Now);
    private static void Need(bool value){if(!value)throw new CryptographicException("Candidate composition refused");}
    private static byte[] Join(params byte[][] values){var result=new byte[values.Sum(b=>b.Length)];int at=0;foreach(var b in values){b.CopyTo(result,at);at+=b.Length;}return result;}
    private static byte[] Label(string value)=>Encoding.ASCII.GetBytes(value+"\0");
    private static byte[] Part(byte[] b,int at,int length)=>b.AsSpan(at,length).ToArray();
    private static bool Same(byte[] a,byte[] b)=>CryptographicOperations.FixedTimeEquals(a,b);
    private static byte[] U64(long n){var b=new byte[8];BinaryPrimitives.WriteInt64BigEndian(b,n);return b;}
    private static long Num(byte[] b,int at)=>BinaryPrimitives.ReadInt64BigEndian(b.AsSpan(at,8));
    private static byte[] Id(byte[] point)=>SHA256.HashData(Join(Label("ZTSE/key/v1"),new byte[]{1,1},point));
    private static Request Capture(Request r){Need(r.Message.Length==16 && r.Recipients.Count is >=2 and <=8 && r.Recipients.All(v=>v.Id.Length==32));return r with {Message=(byte[])r.Message.Clone(),Recipients=r.Recipients.Select(v=>new Recipient(v.Role,(byte[])v.Id.Clone())).ToArray()};}
    private static Plan Authorize(Request r){
        var snapshot=r.Authority.Read();long now=snapshot.NowMs;var bound=Election03.RequireCurrent(r.Proof,r.Manifest,snapshot.AuthenticatedRecord,now);
        Need(r.Message.Length==16 && r.Message.Any(v=>v!=0) && r.ObservedMs>0 && r.ObservedMs<=now && now<r.ExpiresMs && r.ExpiresMs-r.ObservedMs<=900000);
        Need(r.Peer.Length is >=3 and <=16 && r.Peer[0]=='+' && r.Peer[1] is >= '1' and <= '9' && r.Peer.AsSpan(2).ToArray().All(c=>c is >= '0' and <= '9'));
        Need(r.Content.Length is >=1 and <=32768);
        byte[] text=new UTF8Encoding(false,true).GetBytes(r.Content);bool transferred=false;
        try{
        Need(text.Length is >=1 and <=32768 && !text.Contains((byte)0) && !text.AsSpan().StartsWith(new byte[]{239,187,191}));
        byte[] point=r.Signer.PublicPoint(),signerId=Id(point);var keys=r.Manifest.KeyRecords();
        byte[] signer=keys.Single(k=>k[0]==5 && Same(Part(k,1,32),signerId));
        Need(signer[148]==1 && Num(signer,132)<=r.ObservedMs && now<Num(signer,140) && BinaryPrimitives.ReadUInt16BigEndian(signer.AsSpan(130))==1 && Same(Part(signer,114,16),bound.Field("lineId")) && Same(Part(signer,33,65),point));
        Need(r.Recipients.Count is >=2 and <=8 && r.Recipients.All(k=>k.Role is >=1 and <=3 && k.Id.Length==32) && r.Recipients.Count(k=>k.Role==1)==1 && r.Recipients.Count(k=>k.Role==2)==1);
        var sorted=r.Recipients.OrderBy(k=>k.Role).ThenBy(k=>Convert.ToHexString(k.Id),StringComparer.Ordinal).ToArray();
        Need(sorted.Select(k=>k.Role+":"+Convert.ToHexString(k.Id)).Distinct().Count()==sorted.Length);
        long deadline=Math.Min(r.Manifest.ExpiresMs,Math.Min(Num(signer,140),bound.Number("permissionExpiresAtMs")));
        var recipients=new List<(int Role,byte[] Id,byte[] Point)>();
        foreach(var requested in sorted){
            byte[] key=keys.Single(k=>k[0]==requested.Role && Same(Part(k,1,32),requested.Id));
            Need(key[148]==1 && Num(key,132)<=r.ObservedMs && now<Num(key,140) && (BinaryPrimitives.ReadUInt16BigEndian(key.AsSpan(130))&4)!=0);
            if(requested.Role==1)Need(Same(requested.Id,bound.Field("selectedReaderKeyId")) && Same(Part(key,98,16),bound.Field("deviceId")) && Same(Part(key,114,16),bound.Field("lineId")));
            deadline=Math.Min(deadline,Num(key,140));recipients.Add((requested.Role,(byte[])requested.Id.Clone(),Part(key,33,65)));
        }
        Need(r.ExpiresMs<=deadline);
        byte[] fields=Join(bound.Field("accountId"),r.Message,bound.Field("deviceId"),bound.Field("lineId"),U64(bound.Number("manifestVersion")),bound.Field("manifestDigest"),signerId,U64(r.ObservedMs),U64(r.ExpiresMs),new byte[]{1,(byte)r.Peer.Length},Encoding.ASCII.GetBytes(r.Peer));
        byte[] size=new byte[2];BinaryPrimitives.WriteUInt16BigEndian(size,checked((ushort)fields.Length));var prefix=Join(new byte[]{90,84,83,69,3,1,0,0},size,fields);
        byte[] intent=SHA256.HashData(Join(Label("ZTSE/native-outbound-intent/v1"),prefix,SHA256.HashData(text),Join(recipients.Select(k=>Join(new byte[]{(byte)k.Role},k.Id,k.Point)).ToArray()),bound.Field("bindingId"),U64(bound.Number("bindingGeneration")),bound.Field("electionCommitment"),bound.Field("electionBundleSha256")));
        var result=new Plan(prefix,text,recipients.ToArray(),point,intent,now);transferred=true;return result;
        }finally{if(!transferred)CryptographicOperations.ZeroMemory(text);}
    }
    private static long Recheck(Request r,Plan plan,long floor){var fresh=Authorize(r);try{Need(fresh.Now>=floor && Same(fresh.Intent,plan.Intent));return fresh.Now;}finally{CryptographicOperations.ZeroMemory(fresh.Text);}}
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
    private static (byte[] Envelope,long Now) Compose(Request r,Plan plan,long floor){
        byte[] cek=RandomNumberGenerator.GetBytes(32);
        try{
            byte[] nonce=RandomNumberGenerator.GetBytes(12),body=Encrypt(cek,nonce,plan.Text,Join(Label("ZTSE/body/v3"),plan.Prefix));var wraps=new List<byte[]>();
            foreach(var recipient in plan.Recipients){byte[] suffix=Join(plan.Prefix,new byte[]{(byte)recipient.Role},recipient.Id);wraps.Add(Join(new byte[]{(byte)recipient.Role},recipient.Id,Wrap(recipient.Point,cek,Join(Label("ZTSE/wrap/v3"),suffix),Join(Label("ZTSE/wrap-aad/v3"),suffix))));}
            byte[] size=new byte[4];BinaryPrimitives.WriteInt32BigEndian(size,body.Length);byte[] unsigned=Join(plan.Prefix,nonce,size,body,new byte[]{(byte)wraps.Count},Join(wraps.ToArray()));
            byte[] envelope=Join(unsigned,r.Signer.SignEnvelope03(unsigned));SignedEnvelope.Verify(envelope,3,plan.Public);return (envelope,Recheck(r,plan,floor));
        }finally{CryptographicOperations.ZeroMemory(cek);}
    }
    public static byte[] Fresh(Request request){var r=Capture(request);var plan=Authorize(r);try{return Compose(r,plan,plan.Now).Envelope;}finally{CryptographicOperations.ZeroMemory(plan.Text);}}

    /// <summary>Trusted private application path. Persist exact ciphertext before exposure; never reset after uncertain outcomes.</summary>
    public static byte[] ComposeOrReplay(string path,byte[] rootPin,byte[] comparedFingerprint,Request request){
        byte[] pin=(byte[])rootPin.Clone(),fingerprint=(byte[])comparedFingerprint.Clone();var trust=ManifestChain.RootPin.Enroll(pin,fingerprint);
        var r=Capture(request);var plan=Authorize(r);
        try{
            Need(Same(trust.Account,r.Manifest.Account()) && Same(trust.Point,r.Manifest.Root));
            byte[] header=Join(new byte[]{90,84,74,52},pin,fingerprint),identity=Part(plan.Prefix,10,64);
            string full=Path.GetFullPath(path);Need(!Directory.Exists(full));
            if(File.Exists(full))Need((File.GetAttributes(full)&FileAttributes.ReparsePoint)==0);
            FileStream? stream=null;bool fresh=false;
            for(int attempt=0;attempt<100 && stream is null;attempt++){
                try{stream=new FileStream(full,FileMode.CreateNew,FileAccess.ReadWrite,FileShare.None,4096,FileOptions.WriteThrough);fresh=true;}
                catch(IOException){
                    try{stream=new FileStream(full,FileMode.Open,FileAccess.ReadWrite,FileShare.None,4096,FileOptions.WriteThrough);}
                    catch(IOException)when(attempt<99){Thread.Sleep(50);}
                }
            }
            Need(stream is not null);using var file=stream!;
            if(fresh){byte[] initial=U64(plan.Now);file.Write(Join(header,initial,SHA256.HashData(Join(header,initial))));file.Flush(true);}
            Need(file.Length>=header.Length+40 && file.Length<=10000000);file.Position=0;
            byte[] actual=new byte[header.Length];file.ReadExactly(actual);Need(Same(actual,header));
            byte[] clock=new byte[8],clockHash=new byte[32];file.ReadExactly(clock);file.ReadExactly(clockHash);Need(Same(clockHash,SHA256.HashData(Join(header,clock))));long floor=Num(clock,0);Need(floor>0);
            void Advance(long now){Need(now>=floor);if(now>floor){long position=file.Position;byte[] next=U64(now);file.Position=header.Length;file.Write(Join(next,SHA256.HashData(Join(header,next))));file.Flush(true);file.Position=position;floor=now;}}
            Advance(plan.Now);
            byte[]? stored=null;int count=0;
            while(file.Position<file.Length){
                Need(++count<=256 && file.Length-file.Position>=132);byte[] leading=new byte[100];file.ReadExactly(leading);int size=BinaryPrimitives.ReadInt32BigEndian(leading.AsSpan(96));
                Need(size is >=557 and <=34213 && file.Length-file.Position>=size+32);byte[] envelope=new byte[size],checksum=new byte[32];file.ReadExactly(envelope);file.ReadExactly(checksum);Need(Same(checksum,SHA256.HashData(Join(leading,envelope))));
                if(Same(Part(leading,0,64),identity)){
                    Need(stored is null && Same(Part(leading,64,32),plan.Intent));SignedEnvelope.Verify(envelope,3,plan.Public);
                    Need(envelope.AsSpan(0,plan.Prefix.Length).SequenceEqual(plan.Prefix));int end=plan.Prefix.Length+16+BinaryPrimitives.ReadInt32BigEndian(envelope.AsSpan(plan.Prefix.Length+12));
                    Need(envelope[end]==plan.Recipients.Length);
                    for(int i=0;i<plan.Recipients.Length;i++)Need(envelope[end+1+146*i]==plan.Recipients[i].Role && Same(Part(envelope,end+2+146*i,32),plan.Recipients[i].Id));
                    stored=envelope;
                }
            }
            Advance(Recheck(r,plan,floor));
            if(stored is not null)return stored;
            Need(count<256);var composed=Compose(r,plan,floor);Advance(composed.Now);byte[] created=composed.Envelope,length=new byte[4];BinaryPrimitives.WriteInt32BigEndian(length,created.Length);byte[] record=Join(identity,plan.Intent,length,created);
            file.Write(record);file.Write(SHA256.HashData(record));file.Flush(true);Advance(Recheck(r,plan,floor));return created;
        }finally{CryptographicOperations.ZeroMemory(plan.Text);}
    }
}

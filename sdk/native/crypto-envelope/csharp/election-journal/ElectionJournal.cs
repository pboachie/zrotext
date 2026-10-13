using System.Buffers.Binary;
using System.Security.Cryptography;
namespace Zrotext.Candidate;
/// <summary>Bounded trusted-path signed history, not hostile-filesystem rollback resistance.</summary>
public sealed class ElectionJournal {
    public sealed record Snapshot(long Revision,ManifestChain.Verified? Manifest,Election03.Proof? Proof);
    private sealed record Selection(ManifestChain.Verified Manifest,Election03.Proof? Proof);
    public sealed class Expectations {
        private readonly byte[] core,device,owner,digest;private readonly IReadOnlyDictionary<string,object> accepted;
        internal byte[] Core=>(byte[])core.Clone();internal byte[] Device=>(byte[])device.Clone();internal byte[] Owner=>(byte[])owner.Clone();internal byte[] Digest=>(byte[])digest.Clone();
        internal IReadOnlyDictionary<string,object> Accepted=>accepted.ToDictionary(v=>v.Key,v=>v.Value is byte[] b?(object)b.Clone():v.Value);
        public Expectations(byte[] expectedCore,IReadOnlyDictionary<string,object> acceptedRecord,byte[] devicePoint,byte[] ownerPoint){
            Need(expectedCore.Length==500 && devicePoint.Length==65 && ownerPoint.Length==65 && acceptedRecord.Count<=32);core=(byte[])expectedCore.Clone();device=(byte[])devicePoint.Clone();owner=(byte[])ownerPoint.Clone();using var dp=HpkeRecipient.Point(device);using var op=HpkeRecipient.Point(owner);
            var values=new Dictionary<string,object>();var encoded=new List<byte[]>();foreach(var pair in acceptedRecord){Need(System.Text.RegularExpressions.Regex.IsMatch(pair.Key,"\\A[A-Za-z][A-Za-z0-9]{0,63}\\z"));byte[] name=System.Text.Encoding.ASCII.GetBytes(pair.Key),value;
                if(pair.Value is byte[] bytes){Need(bytes.Length is 16 or 32);byte[] captured=(byte[])bytes.Clone();values.Add(pair.Key,captured);value=Join(new byte[]{0,(byte)captured.Length},captured);}
                else{Need(pair.Value is long or int);long n=Convert.ToInt64(pair.Value);Need(n>0);values.Add(pair.Key,n);byte[] number=new byte[8];BinaryPrimitives.WriteInt64BigEndian(number,n);value=Join(new byte[]{1},number);}
                encoded.Add(Join(new byte[]{(byte)name.Length},name,value));
            }
            accepted=values;var ordered=encoded.OrderBy(v=>Convert.ToHexString(v),StringComparer.Ordinal).ToArray();digest=SHA256.HashData(Join(core,device,owner,Join(ordered)));
        }
    }
    private readonly string path;private readonly byte[] header;private readonly ManifestChain.RootPin trust;private readonly Expectations? expected;
    public ElectionJournal(string path,byte[] pin,byte[] fingerprint,Expectations? expectations){this.path=Path.GetFullPath(path);byte[] captured=(byte[])pin.Clone(),compared=(byte[])fingerprint.Clone();trust=ManifestChain.RootPin.Enroll(captured,compared);header=Join(new byte[]{90,84,69,51},captured,compared);expected=expectations;}
    private static void Need(bool v){if(!v)throw new CryptographicException("Election journal refused");}
    private static byte[] Join(params byte[][] values){byte[] output=new byte[values.Sum(v=>v.Length)];int at=0;foreach(var v in values){v.CopyTo(output,at);at+=v.Length;}return output;}
    private static bool Same(byte[] a,byte[] b)=>CryptographicOperations.FixedTimeEquals(a,b);
    private static byte[] Read(FileStream f,int size){byte[] v=new byte[size];f.ReadExactly(v);return v;}
    private Selection Step(byte[] raw,byte[]? election,Selection? current,long now){
        Need(raw.Length is >=364 and <=9753 && raw[4] is 2 or 3);if(current is null){Need(election is null && raw[4]==2);return new(ManifestChain.Genesis02(raw,trust,now),null);}
        if(election is not null){Need(election.Length==660 && expected is not null && current.Manifest.Profile==2 && raw[4]==3 && current.Proof is null && Same(election.AsSpan(628,32).ToArray(),expected.Digest));var accepted=expected!.Accepted;Need(accepted.TryGetValue("acceptedAtMs",out var time) && time is long value && value==now);
            var proof=Election03.Verify(election.AsSpan(0,628).ToArray(),expected.Core,accepted,current.Manifest,current.Manifest.Bytes(),raw,expected.Device,expected.Owner);return new(proof.AcceptedManifest,proof);
        }
        Need(raw[4]==current.Manifest.Profile);var next=ManifestChain.ContinueChain(raw,current.Manifest,raw[4],now);Need(current.Manifest.Version<long.MaxValue && next.Version==current.Manifest.Version+1);return new(next,current.Proof);
    }
    private sealed class Clock {
        private readonly FileStream file;private readonly byte[] header;public long Floor{get;private set;}
        public Clock(FileStream file,byte[] header,long now){this.file=file;this.header=header;byte[] value=Read(file,8);Need(Same(Read(file,32),SHA256.HashData(Join(header,value))));Floor=BinaryPrimitives.ReadInt64BigEndian(value);Need(Floor>=0 && Floor<=now);}
        public void Advance(long now){Need(now>=Floor);if(now>Floor){long at=file.Position;byte[] value=new byte[8];BinaryPrimitives.WriteInt64BigEndian(value,now);file.Position=header.Length;file.Write(Join(value,SHA256.HashData(Join(header,value))));file.Flush(true);file.Position=at;Floor=now;}}
    }
    private Snapshot Access(long now,Func<FileStream,long,Selection?,Clock,Snapshot> action){
        Need(now>0 && !Directory.Exists(path));if(File.Exists(path))Need((File.GetAttributes(path)&FileAttributes.ReparsePoint)==0);
        FileStream? stream=null;bool created=false;for(int attempt=0;attempt<100 && stream is null;attempt++){
            try{stream=new FileStream(path,FileMode.CreateNew,FileAccess.ReadWrite,FileShare.None,4096,FileOptions.WriteThrough);created=true;}
            catch(IOException){try{stream=new FileStream(path,FileMode.Open,FileAccess.ReadWrite,FileShare.None,4096,FileOptions.WriteThrough);}catch(IOException)when(attempt<99){Thread.Sleep(50);}}
        }
        Need(stream is not null);using var file=stream!;if(created){byte[] initial=new byte[8];file.Write(Join(header,initial,SHA256.HashData(Join(header,initial))));file.Flush(true);}
        Need(file.Length>=header.Length+40 && file.Length<=3000000);file.Position=0;Need(Same(Read(file,header.Length),header));var clock=new Clock(file,header,now);Selection? current=null;long revision=0,comparison=0;
        while(file.Position<file.Length){
            Need(revision<256 && file.Length-file.Position>=56);byte[] prefix=Read(file,24);long next=BinaryPrimitives.ReadInt64BigEndian(prefix),time=BinaryPrimitives.ReadInt64BigEndian(prefix.AsSpan(8));int transitionSize=BinaryPrimitives.ReadInt32BigEndian(prefix.AsSpan(16)),size=BinaryPrimitives.ReadInt32BigEndian(prefix.AsSpan(20));
            Need(next==revision+1 && time>=comparison && time<=clock.Floor && transitionSize is 0 or 660 && size is >=364 and <=9753 && file.Length-file.Position>=transitionSize+size+32);
            byte[] transition=Read(file,transitionSize),raw=Read(file,size);Need(Same(Read(file,32),SHA256.HashData(Join(prefix,transition,raw))));current=Step(raw,transitionSize==0?null:transition,current,time);revision=next;comparison=time;
        }
        return action(file,revision,current,clock);
    }
    public Snapshot Accept(byte[] manifest,byte[]? bundle,long expectedRevision,long now){byte[] raw=(byte[])manifest.Clone();byte[]? change=bundle is null?null:(byte[])bundle.Clone();return Access(now,(file,revision,current,clock)=>{
        Need(expectedRevision==revision && revision<256);Need(change is null || change.Length==628 && expected is not null);byte[] entry=change is null?Array.Empty<byte>():Join(change,expected!.Digest);var value=Step(raw,change is null?null:entry,current,now);byte[] prefix=new byte[24];BinaryPrimitives.WriteInt64BigEndian(prefix,revision+1);BinaryPrimitives.WriteInt64BigEndian(prefix.AsSpan(8),now);BinaryPrimitives.WriteInt32BigEndian(prefix.AsSpan(16),entry.Length);BinaryPrimitives.WriteInt32BigEndian(prefix.AsSpan(20),raw.Length);byte[] record=Join(prefix,entry,raw);clock.Advance(now);file.Write(Join(record,SHA256.HashData(record)));file.Flush(true);return new Snapshot(revision+1,value.Manifest,value.Proof);
    });}
    public Snapshot ReadSnapshot(long now)=>Access(now,(file,revision,current,clock)=>{var value=current is null?null:ManifestChain.ContinueChain(current.Manifest.Bytes(),current.Manifest,current.Manifest.Profile,now);clock.Advance(now);return new Snapshot(revision,value,current?.Proof);});
}

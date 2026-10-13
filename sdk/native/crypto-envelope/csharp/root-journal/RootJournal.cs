using System.Buffers.Binary;
using System.Security.Cryptography;
namespace Zrotext.Candidate;
/// <summary>Bounded trusted-path signed history, not hostile-filesystem rollback resistance.</summary>
public sealed class RootJournal {
    public sealed record Snapshot(long Revision,ManifestChain.Verified? Manifest);
    private readonly string path;private readonly byte[] header;private readonly ManifestChain.RootPin trust;private readonly Dictionary<long,byte[]> approvals=new();
    public RootJournal(string path,byte[] pin,byte[] fingerprint,IReadOnlyDictionary<long,byte[]> approvedRoots){
        Need(approvedRoots.Count<=256);this.path=Path.GetFullPath(path);byte[] captured=(byte[])pin.Clone(),compared=(byte[])fingerprint.Clone();trust=ManifestChain.RootPin.Enroll(captured,compared);header=Join(new byte[]{90,84,67,50},captured,compared);
        foreach(var pair in approvedRoots){Need(pair.Key>1 && pair.Value.Length==65);byte[] point=(byte[])pair.Value.Clone();using var checkedPoint=HpkeRecipient.Point(point);approvals.Add(pair.Key,point);}
    }
    private static void Need(bool v){if(!v)throw new CryptographicException("Root journal refused");}
    private static byte[] Join(params byte[][] values){byte[] output=new byte[values.Sum(v=>v.Length)];int at=0;foreach(var v in values){v.CopyTo(output,at);at+=v.Length;}return output;}
    private static bool Same(byte[] a,byte[] b)=>CryptographicOperations.FixedTimeEquals(a,b);
    private static byte[] Read(FileStream f,int size){byte[] v=new byte[size];f.ReadExactly(v);return v;}
    private ManifestChain.Verified Step(byte[] raw,byte[]? transition,ManifestChain.Verified? current,long now){
        Need(raw.Length is >=364 and <=9751 && raw[4]==2);if(current is null){Need(transition is null);return ManifestChain.Genesis02(raw,trust,now);}
        if(transition is not null){Need(transition.Length==343);Need(approvals.TryGetValue(BinaryPrimitives.ReadInt64BigEndian(transition.AsSpan(29,8)),out var approved));return ManifestChain.Rotate02(transition,raw,current,approved!,now);}
        var value=ManifestChain.ContinueChain(raw,current,2,now);Need(current.Version<long.MaxValue && value.Version==current.Version+1);return value;
    }
    private sealed class Clock {
        private readonly FileStream file;private readonly byte[] header;public long Floor{get;private set;}
        public Clock(FileStream file,byte[] header,long now){this.file=file;this.header=header;byte[] value=Read(file,8);Need(Same(Read(file,32),SHA256.HashData(Join(header,value))));Floor=BinaryPrimitives.ReadInt64BigEndian(value);Need(Floor>=0 && Floor<=now);}
        public void Advance(long now){Need(now>=Floor);if(now>Floor){long at=file.Position;byte[] value=new byte[8];BinaryPrimitives.WriteInt64BigEndian(value,now);file.Position=header.Length;file.Write(Join(value,SHA256.HashData(Join(header,value))));file.Flush(true);file.Position=at;Floor=now;}}
    }
    private Snapshot Access(long now,Func<FileStream,long,ManifestChain.Verified?,Clock,Snapshot> action){
        Need(now>0 && !Directory.Exists(path));if(File.Exists(path))Need((File.GetAttributes(path)&FileAttributes.ReparsePoint)==0);
        FileStream? stream=null;bool created=false;for(int attempt=0;attempt<100 && stream is null;attempt++){
            try{stream=new FileStream(path,FileMode.CreateNew,FileAccess.ReadWrite,FileShare.None,4096,FileOptions.WriteThrough);created=true;}
            catch(IOException){try{stream=new FileStream(path,FileMode.Open,FileAccess.ReadWrite,FileShare.None,4096,FileOptions.WriteThrough);}catch(IOException)when(attempt<99){Thread.Sleep(50);}}
        }
        Need(stream is not null);using var file=stream!;if(created){byte[] initial=new byte[8];file.Write(Join(header,initial,SHA256.HashData(Join(header,initial))));file.Flush(true);}
        Need(file.Length>=header.Length+40 && file.Length<=3000000);file.Position=0;Need(Same(Read(file,header.Length),header));var clock=new Clock(file,header,now);ManifestChain.Verified? current=null;long revision=0,comparison=0;
        while(file.Position<file.Length){
            Need(revision<256 && file.Length-file.Position>=56);byte[] prefix=Read(file,24);long next=BinaryPrimitives.ReadInt64BigEndian(prefix),time=BinaryPrimitives.ReadInt64BigEndian(prefix.AsSpan(8));int transitionSize=BinaryPrimitives.ReadInt32BigEndian(prefix.AsSpan(16)),size=BinaryPrimitives.ReadInt32BigEndian(prefix.AsSpan(20));
            Need(next==revision+1 && time>=comparison && time<=clock.Floor && transitionSize is 0 or 343 && size is >=364 and <=9751 && file.Length-file.Position>=transitionSize+size+32);
            byte[] transition=Read(file,transitionSize),raw=Read(file,size);Need(Same(Read(file,32),SHA256.HashData(Join(prefix,transition,raw))));current=Step(raw,transitionSize==0?null:transition,current,time);revision=next;comparison=time;
        }
        return action(file,revision,current,clock);
    }
    public Snapshot Accept(byte[] manifest,byte[]? transition,long expectedRevision,long now){byte[] raw=(byte[])manifest.Clone();byte[]? change=transition is null?null:(byte[])transition.Clone();return Access(now,(file,revision,current,clock)=>{
        Need(expectedRevision==revision && revision<256);var value=Step(raw,change,current,now);byte[] entry=change??Array.Empty<byte>(),prefix=new byte[24];BinaryPrimitives.WriteInt64BigEndian(prefix,revision+1);BinaryPrimitives.WriteInt64BigEndian(prefix.AsSpan(8),now);BinaryPrimitives.WriteInt32BigEndian(prefix.AsSpan(16),entry.Length);BinaryPrimitives.WriteInt32BigEndian(prefix.AsSpan(20),raw.Length);byte[] record=Join(prefix,entry,raw);clock.Advance(now);file.Write(Join(record,SHA256.HashData(record)));file.Flush(true);return new Snapshot(revision+1,value);
    });}
    public Snapshot ReadSnapshot(long now)=>Access(now,(file,revision,current,clock)=>{var value=current is null?null:ManifestChain.ContinueChain(current.Bytes(),current,2,now);clock.Advance(now);return new Snapshot(revision,value);});
}

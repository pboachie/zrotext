using System;
using System.IO;
using System.Linq;
using System.Collections.Generic;
using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Threading;

namespace Zrotext.Candidate;

/// <summary>Trusted-path accepted history. Torn appends refuse; whole-file rollback is outside scope.</summary>
public sealed class OriginalReplyCheckpoint {
    private const int Capacity=64,Transactions=256,MaxBytes=16000000;
    public sealed class Snapshot {
        public long Revision{get;}public long ComparisonMs{get;}public IReadOnlyList<ManifestChain.Verified> History{get;}
        internal Snapshot(long revision,long comparison,IReadOnlyList<ManifestChain.Verified> history){Revision=revision;ComparisonMs=comparison;History=Array.AsReadOnly(history.ToArray());}
    }
    private sealed record Saved(long Comparison,byte[] Bytes);
    private sealed record State(long Revision,long Comparison,List<Saved> Rows);
    private readonly string path;private readonly byte[] header;private readonly ManifestChain.RootPin trust;
    private OriginalReplyCheckpoint(string path,byte[] pin,byte[] fingerprint,OriginalReplyReader.Scope scope){this.path=Path.GetFullPath(path);var root=(byte[])pin.Clone();var compared=(byte[])fingerprint.Clone();trust=ManifestChain.RootPin.Enroll(root,compared);Need(Same(root.AsSpan(5,16).ToArray(),scope.Account));header=Join(new byte[]{90,84,79,49},root,compared,scope.CheckpointBinding());}
    private static void Need(bool value){if(!value)throw new CryptographicException("Original history refused");}
    private static byte[] Join(params byte[][] values){int size=values.Sum(v=>v.Length);var output=new byte[size];int at=0;foreach(var v in values){v.CopyTo(output,at);at+=v.Length;}return output;}
    private static bool Same(byte[] a,byte[] b)=>CryptographicOperations.FixedTimeEquals(a,b);
    private static byte[] Long(long value){var b=new byte[8];BinaryPrimitives.WriteInt64BigEndian(b,value);return b;}
    private static byte[] Int(int value){var b=new byte[4];BinaryPrimitives.WriteInt32BigEndian(b,value);return b;}
    private static byte[] Read(Stream file,int count){var b=new byte[count];file.ReadExactly(b);return b;}
    private static List<Saved> Capture(IReadOnlyList<ManifestChain.Verified> history){Need(history.Count>=1 && history.Count<=Capacity);var rows=new List<Saved>();foreach(var m in history){Need(m.Profile==2 && m.Generation==1);rows.Add(new Saved(m.ComparisonMs,m.Bytes()));}return rows;}
    private IReadOnlyList<ManifestChain.Verified> Verify(List<Saved> rows,long now){
        Need(now>0 && rows.Count>=1 && rows.Count<=Capacity);var history=new List<ManifestChain.Verified>();ManifestChain.Verified? previous=null;
        foreach(var row in rows){Need(row.Comparison>0 && row.Comparison<=now && row.Bytes.Length>=364 && row.Bytes.Length<=9751);var m=previous is null?ManifestChain.Genesis02(row.Bytes,trust,row.Comparison):ManifestChain.ContinueChain(row.Bytes,previous,2,row.Comparison);Need(m.Generation==1 && m.Version==history.Count+1);history.Add(m);previous=m;}
        history[^1]=ManifestChain.ContinueChain(previous!.Bytes(),previous,2,now);return history.AsReadOnly();
    }
    private static byte[] Encode(State state){using var data=new MemoryStream();data.Write(Long(state.Revision));data.Write(Long(state.Comparison));data.Write(Int(state.Rows.Count));foreach(var row in state.Rows){data.Write(Long(row.Comparison));data.Write(Int(row.Bytes.Length));data.Write(row.Bytes);}return data.ToArray();}
    private State Decode(byte[] bytes){
        using var data=new MemoryStream(bytes,false);long revision=BinaryPrimitives.ReadInt64BigEndian(Read(data,8)),now=BinaryPrimitives.ReadInt64BigEndian(Read(data,8));int count=BinaryPrimitives.ReadInt32BigEndian(Read(data,4));Need(revision>=1 && revision<=Transactions && now>0 && count>=1 && count<=Capacity);var rows=new List<Saved>();
        for(int i=0;i<count;i++){long time=BinaryPrimitives.ReadInt64BigEndian(Read(data,8));int length=BinaryPrimitives.ReadInt32BigEndian(Read(data,4));Need(length>=364 && length<=9751 && length<=data.Length-data.Position);rows.Add(new Saved(time,Read(data,length)));}Need(data.Position==data.Length);Verify(rows,now);return new State(revision,now,rows);
    }
    private State Load(FileStream file){
        Need(file.Length>=header.Length+432 && file.Length<=MaxBytes);file.Position=0;Need(Same(Read(file,header.Length),header));State? state=null;
        while(file.Position<file.Length){Need(file.Length-file.Position>=4);var length=Read(file,4);int count=BinaryPrimitives.ReadInt32BigEndian(length);Need(count>=396 && count<=20+Capacity*(12+9751) && file.Length-file.Position>=count+32);var body=Read(file,count);Need(Same(Read(file,32),SHA256.HashData(Join(header,length,body))));var next=Decode(body);Need(next.Revision==(state is null?1:state.Revision+1));if(state is not null){Need(next.Comparison>=state.Comparison && next.Rows.Count>=state.Rows.Count);for(int i=0;i<state.Rows.Count;i++)Need(state.Rows[i].Comparison==next.Rows[i].Comparison && Same(state.Rows[i].Bytes,next.Rows[i].Bytes));}state=next;}
        Need(state is not null);return state!;
    }
    private void Append(FileStream file,State state){var raw=Encode(state);var length=Int(raw.Length);var record=Join(length,raw,SHA256.HashData(Join(header,length,raw)));Need(file.Length+record.Length<=MaxBytes);file.Position=file.Length;file.Write(record);file.Flush(true);}
    private Snapshot Access(Func<FileStream,State,Snapshot> action){
        Need((File.GetAttributes(path)&FileAttributes.ReparsePoint)==0);FileStream? file=null;
        for(int attempt=0;attempt<100 && file is null;attempt++){try{file=new FileStream(path,FileMode.Open,FileAccess.ReadWrite,FileShare.None);}catch(IOException)when(attempt<99){Thread.Sleep(50);}}
        using(file){Need(file is not null);return action(file!,Load(file!));}
    }
    public static OriginalReplyCheckpoint Create(string path,byte[] pin,byte[] fingerprint,OriginalReplyReader.Scope scope,IReadOnlyList<ManifestChain.Verified> history,long now){var result=new OriginalReplyCheckpoint(path,pin,fingerprint,scope);var rows=Capture(history);result.Verify(rows,now);using(var file=new FileStream(result.path,FileMode.CreateNew,FileAccess.ReadWrite,FileShare.None)){file.Write(result.header);result.Append(file,new State(1,now,rows));}return result;}
    public static OriginalReplyCheckpoint Open(string path,byte[] pin,byte[] fingerprint,OriginalReplyReader.Scope scope){var result=new OriginalReplyCheckpoint(path,pin,fingerprint,scope);result.Access((file,state)=>new Snapshot(state.Revision,state.Comparison,result.Verify(state.Rows,state.Comparison)));return result;}
    /// <summary>Read/reverify only. Accept to publish a durable comparison before effects.</summary>
    public Snapshot ReadSnapshot(OriginalReplyReader.Scope scope,long now){Need(Same(scope.CheckpointBinding(),header.AsSpan(header.Length-32).ToArray()));return Access((file,state)=>{Need(now>=state.Comparison);return new Snapshot(state.Revision,state.Comparison,Verify(state.Rows,now));});}
    /// <summary>Check immutable history/CAS and trusted freshness under exclusive ownership, then flush one transaction.</summary>
    public Snapshot Accept(OriginalReplyReader.Scope scope,IReadOnlyList<ManifestChain.Verified> history,long expectedRevision,long now,Func<ManifestChain.Verified,long,long> fence){
        Need(fence is not null && Same(scope.CheckpointBinding(),header.AsSpan(header.Length-32).ToArray()));var proposed=Capture(history);
        return Access((file,state)=>{Need(expectedRevision==state.Revision && state.Revision<Transactions && now>=state.Comparison && proposed.Count>=state.Rows.Count);Verify(proposed,now);for(int i=0;i<state.Rows.Count;i++){var old=state.Rows[i].Bytes;var next=proposed[i].Bytes;Need(Same(old.AsSpan(0,old.Length-64).ToArray(),next.AsSpan(0,next.Length-64).ToArray()));proposed[i]=state.Rows[i];}var before=Verify(proposed,now);long checkedAt=fence!(before[^1],now);Need(checkedAt>=now);var verified=Verify(proposed,checkedAt);var value=new State(state.Revision+1,checkedAt,proposed);Append(file,value);return new Snapshot(value.Revision,checkedAt,verified);});
    }
}

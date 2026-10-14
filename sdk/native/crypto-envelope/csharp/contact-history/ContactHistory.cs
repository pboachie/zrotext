using System.Buffers.Binary;
#pragma warning disable CS8618
using System.Security.Cryptography;
using System.Text;
namespace Zrotext.Candidate;
/// <summary>Application-owned contact local history with independently reverified signed root history.</summary>
public sealed class ContactHistory:IDisposable {
    const int Capacity=256,HistoryLimit=64,MaxBytes=16_000_000,OriginMax=512;
    static readonly SemaphoreSlim Permits=new(4,4);
    static void Need(bool value,string reason="refused"){if(!value)throw new InvalidOperationException($"Contact local history: {reason}");}
    static bool Same(byte[] a,byte[] b)=>a is not null && b is not null && a.Length==b.Length && CryptographicOperations.FixedTimeEquals(a,b);
    static bool Zero(byte[] b){foreach(var v in b)if(v!=0)return false;return true;}
    static byte[] Join(params byte[][] values){long size=0;foreach(var v in values)size+=v.LongLength;var output=new byte[size];long at=0;foreach(var v in values){Array.Copy(v,0,output,at,v.LongLength);at+=v.LongLength;}return output;}
    static byte[] BE32(int v){Span<byte> b=stackalloc byte[4];BinaryPrimitives.WriteInt32BigEndian(b,v);return b.ToArray();}
    static byte[] BE64(long v){Span<byte> b=stackalloc byte[8];BinaryPrimitives.WriteInt64BigEndian(b,v);return b.ToArray();}
    static long ReadBE64(BinaryReader reader)=>BinaryPrimitives.ReadInt64BigEndian(reader.ReadBytes(8));
    static byte[] Sha(byte[] b)=>SHA256.HashData(b);
    static long Number(byte[] b,int at){long v=BinaryPrimitives.ReadInt64BigEndian(b.AsSpan(at,8));Need(v>0,"corrupt");return v;}
    string Hex(byte[] b)=>Convert.ToHexString(b).ToLowerInvariant();

    public sealed record Slot(int Tag,long SealRevision,byte[] Digest);
    public sealed record Stamp(long Version,byte[] Digest,byte[] AnchorDigest,long Time);
    public sealed record Metadata(byte[] ContactId,long Revision,byte[] Digest,byte[] RequestId,byte[] RoutingDigest,Slot Name,Slot Notes,
        byte[] StatementDigest,long ManifestVersion,byte[] ManifestDigest,byte[] ReaderId,long ReaderGeneration,byte[] RootWriterId,
        long ComparisonMs,Stamp RootStamp);
    sealed record Saved(long Comparison,byte[] Bytes);
    sealed record State(List<Saved> History,List<Row> Rows);
    sealed record Row(byte[] ContactId,bool Accepted,Metadata? Metadata);
    public sealed class Token {
        internal ContactHistory Owner;internal byte[] Row;
        internal Token(ContactHistory owner,byte[] row){Owner=owner;Row=row;}
    }
    public sealed class LookupResult {
        internal LookupResult(Token? token,Metadata? metadata,string reason){this.token=token;this.metadata=metadata;Reason=reason;}
        public bool Accepted=>metadata is not null;
        public string Reason{get;}
        public Metadata? Metadata=>metadata;
        readonly Token? token;readonly Metadata? metadata;
        internal Token? TokenField=>token;
    }
    delegate object Action(FileStream file,State state,List<ManifestChain.Verified> history);

    readonly string path;readonly byte[] header;readonly int maximum;readonly bool reduction;
    readonly ManifestChain.RootPin trust;readonly byte[] account;readonly string origin;
    bool closed;readonly long expiry=Environment.TickCount64+1_800_000;
#pragma warning disable CS8618

    ContactHistory(string path,byte[] pin,byte[] fingerprint,byte[] expectedAccount,string origin,int maximumRecords,bool reduction){
        Need(pin is not null && pin.Length==94 && fingerprint is not null && fingerprint.Length==32);
        Need(expectedAccount is not null && expectedAccount.Length==16 && !Zero(expectedAccount));
        byte[] originBytes=origin is null?Array.Empty<byte>():Encoding.ASCII.GetBytes(origin);
        Need(originBytes.Length>=1 && originBytes.Length<=OriginMax && originBytes.All(b=>b>32&&b<127));
        Need(maximumRecords>=1 && maximumRecords<=Capacity);
        trust=ManifestChain.RootPin.Enroll((byte[])pin.Clone(),(byte[])fingerprint.Clone());
        this.path=Path.GetFullPath(path);maximum=maximumRecords;this.reduction=reduction;
        account=(byte[])expectedAccount.Clone();this.origin=origin??throw new InvalidOperationException("Contact local history: refused");
        header=Join(new byte[]{90,84,76,72,49},pin,fingerprint,expectedAccount,new byte[]{(byte)(originBytes.Length/256),(byte)(originBytes.Length%256)},originBytes,BE32(maximumRecords));
        Need(Permits.Wait(0),"storage unavailable");
    }

    static void WriteFull(FileStream file,byte[] bytes)=>file.Write(bytes,0,bytes.Length);
    static byte[] ReadFull(FileStream file,int count){var output=new byte[count];file.ReadExactly(output);return output;}
    byte[] RowBytes(Row r)=>r.Accepted?Join(r.ContactId,new byte[]{1},EncodeMetadata(r.Metadata!)):Join(r.ContactId,new byte[]{2});
    static byte[] EncodeMetadata(Metadata m)=>Join(
        BE64(m.Revision),m.Digest,m.RequestId,m.RoutingDigest,
        new byte[]{(byte)m.Name.Tag},BE64(m.Name.SealRevision),m.Name.Digest,
        new byte[]{(byte)m.Notes.Tag},BE64(m.Notes.SealRevision),m.Notes.Digest,
        m.StatementDigest,BE64(m.ManifestVersion),m.ManifestDigest,m.ReaderId,
        BE64(m.ReaderGeneration),m.RootWriterId,BE64(m.ComparisonMs),
        BE64(m.RootStamp.Version),m.RootStamp.Digest,m.RootStamp.AnchorDigest,BE64(m.RootStamp.Time));

    static byte[] Fixed(byte[] b,int n){Need(b is not null && b.Length==n && !Zero(b),"corrupt");return b;}
    static Slot ReadSlot(BinaryReader reader,long revision){
        int tag=reader.ReadByte();long seal=ReadBE64(reader);byte[] digest=reader.ReadBytes(32);
        Need((tag==0||tag==1)&&seal<=revision,"corrupt");
        Need(tag==0?seal==0&&Zero(digest):seal>0&&!Zero(digest),"corrupt");
        return new Slot(tag,seal,digest);
    }
    static BinaryReader Reader(byte[] body)=>new(new MemoryStream(body,false),Encoding.UTF8,false);
    static void WriteInt64BE(BinaryWriter writer,long v){Span<byte> b=stackalloc byte[8];BinaryPrimitives.WriteInt64BigEndian(b,v);writer.Write(b);}

    List<Saved> Capture(IReadOnlyList<ManifestChain.Verified> history){
        Need(history is not null && history.Count>=1 && history.Count<=HistoryLimit);
        var rows=new List<Saved>();
        foreach(var m in history){Need(m is not null && m.Profile==2 && m.Generation==1);rows.Add(new Saved(m.ComparisonMs,m.Bytes()));}
        return rows;
    }
    List<ManifestChain.Verified> VerifyHistory(List<Saved> rows){
        Need(rows.Count>=1 && rows.Count<=HistoryLimit);
        var history=new List<ManifestChain.Verified>();ManifestChain.Verified? previous=null;
        foreach(var row in rows){
            Need(row.Comparison>0 && row.Bytes.Length>=364 && row.Bytes.Length<=9751);
            var m=ManifestChain.OriginalAccepted02(row.Bytes,trust,previous,row.Comparison);
            Need(m.Generation==1 && m.Version==history.Count+1 && Same(m.Account(),account),"corrupt");
            history.Add(m);previous=m;
        }
        return history;
    }

    byte[] EncodeState(State value){
        using var memory=new MemoryStream();using var writer=new BinaryWriter(memory);
        writer.Write(value.History.Count);
        foreach(var m in value.History){WriteInt64BE(writer,m.Comparison);writer.Write(m.Bytes.Length);writer.Write(m.Bytes);}
        writer.Write(value.Rows.Count);
        foreach(var row in value.Rows)writer.Write(RowBytes(row));
        writer.Flush();return memory.ToArray();
    }
    State Decode(byte[] body,List<ManifestChain.Verified> history,List<Saved> saved){
        using var reader=Reader(body);
        int historyCount=reader.ReadInt32();Need(historyCount>=1 && historyCount<=HistoryLimit && historyCount==history.Count,"corrupt");
        for(int i=0;i<historyCount;i++){long when=ReadBE64(reader);int length=reader.ReadInt32();
            Need(when>0 && length>=364 && length<=9751,"corrupt");byte[] raw=reader.ReadBytes(length);
            Need(when==saved[i].Comparison && Same(raw,history[i].Bytes()),"corrupt");}
        int count=reader.ReadInt32();Need(count>=0 && count<=Capacity,"corrupt");
        var rows=new List<Row>();var seen=new HashSet<string>();
        for(int i=0;i<count;i++){
            byte[] contactId=reader.ReadBytes(16);Need(contactId.Length==16 && !Zero(contactId) && seen.Add(Hex(contactId)),"corrupt");
            int state=reader.ReadByte();
            if(state==2){rows.Add(new Row(contactId,false,null));continue;}
            Need(state==1,"corrupt");
            long revision=ReadBE64(reader);byte[] digest=Fixed(reader.ReadBytes(32),32),request=Fixed(reader.ReadBytes(16),16),routing=Fixed(reader.ReadBytes(32),32);
            Slot name=ReadSlot(reader,revision),notes=ReadSlot(reader,revision);
            byte[] statement=Fixed(reader.ReadBytes(32),32);long manifestVersion=ReadBE64(reader);byte[] manifest=Fixed(reader.ReadBytes(32),32),readerId=Fixed(reader.ReadBytes(32),32);
            long readerGeneration=ReadBE64(reader);byte[] writer=Fixed(reader.ReadBytes(32),32);long comparisonMs=ReadBE64(reader);
            long stampVersion=ReadBE64(reader);byte[] stampDigest=reader.ReadBytes(32),anchor=reader.ReadBytes(32);long stampTime=ReadBE64(reader);
            Need(revision>0 && manifestVersion>0 && readerGeneration>0 && comparisonMs>0 && stampVersion>0 && stampTime>0,"corrupt");
            rows.Add(new Row(contactId,true,new Metadata(contactId,revision,digest,request,routing,name,notes,statement,manifestVersion,manifest,readerId,readerGeneration,writer,comparisonMs,new Stamp(stampVersion,stampDigest,anchor,stampTime))));
        }
        Need(memory_fully_read(),"corrupt");
        return new State(saved,rows);
        bool memory_fully_read()=>reader.BaseStream.Position==reader.BaseStream.Length;
    }

    void VerifyRows(List<Row> rows,List<ManifestChain.Verified> history,List<Saved> saved){
        int accepted=0;
        foreach(var r in rows){
            if(!r.Accepted)continue;accepted++;var m=r.Metadata!;
            ManifestChain.Verified? bound=null;int at=-1;
            for(int i=0;i<history.Count;i++)if(history[i].Version==m.ManifestVersion && Same(history[i].Digest(),m.ManifestDigest)){bound=history[i];at=i;break;}
            Need(bound is not null && saved[at].Comparison<=m.ComparisonMs,"history_missing");
            byte[]? reader=null,writer=null;
            foreach(var k in bound!.KeyRecords()){
                long from=BinaryPrimitives.ReadInt64BigEndian(k.AsSpan(132,8)),until=BinaryPrimitives.ReadInt64BigEndian(k.AsSpan(140,8));
                if(k[0]==2 && Same(Part(k,1,32),m.ReaderId) && from<=m.ComparisonMs && m.ComparisonMs<until)reader=k;
                if(k[0]==6 && Same(Part(k,1,32),m.RootWriterId))writer=k;
            }
            Need(reader is not null && writer is not null,"history_missing");
            var head=history[^1];
            Need(head.Version>m.RootStamp.Version || head.Version==m.RootStamp.Version && Same(head.Digest(),m.RootStamp.Digest),"history_missing");
        }
        Need(accepted<=maximum,"corrupt");
    }
    static byte[] Part(byte[] b,int at,int count){var output=new byte[count];Array.Copy(b,at,output,0,count);return output;}

    void Evolve(State prior,State next){
        Need(next.History.Count>=prior.History.Count,"corrupt");
        for(int i=0;i<prior.History.Count;i++)Need(prior.History[i].Comparison==next.History[i].Comparison && Same(prior.History[i].Bytes,next.History[i].Bytes),"corrupt");
        var before=ByKey(prior.Rows);var after=ByKey(next.Rows);
        foreach(var entry in before){
            Need(after.TryGetValue(entry.Key,out var fresh) && fresh is not null,"corrupt");
            var old=entry.Value;
            if(!old.Accepted){Need(!fresh!.Accepted,"corrupt");continue;}
            if(!fresh!.Accepted)continue;
            Need(fresh.Metadata!.Revision>=old.Metadata!.Revision,"corrupt");
            if(fresh.Metadata.Revision==old.Metadata.Revision)Need(Same(RowBytes(old),RowBytes(fresh)),"corrupt");
        }
    }
    Dictionary<string,Row> ByKey(List<Row> rows)=>rows.ToDictionary(r=>Hex(r.ContactId));

    (State state,List<ManifestChain.Verified> history) Load(FileStream file){
        Need(file.Length>=header.Length+4+12+364+32+4 && file.Length<=MaxBytes,"corrupt");
        file.Seek(0,SeekOrigin.Begin);Need(Same(ReadFull(file,header.Length),header),"root_mismatch");
        State? state=null;List<ManifestChain.Verified>? history=null;
        while(file.Position<file.Length){
            Need(file.Length-file.Position>=4,"corrupt");int count=BinaryPrimitives.ReadInt32BigEndian(ReadFull(file,4));
            Need(count>=12+364 && count<=20+HistoryLimit*(12+9751)+Capacity*230 && file.Length-file.Position>=count+32,"corrupt");
            byte[] body=ReadFull(file,count);Need(Same(ReadFull(file,32),Sha(Join(header,BE32(count),body))),"corrupt");
            var saved=new List<Saved>();
            using(var reader=Reader(body)){
                int historyCount=reader.ReadInt32();Need(historyCount>=1 && historyCount<=HistoryLimit,"corrupt");
                for(int i=0;i<historyCount;i++){long when=ReadBE64(reader);int size=reader.ReadInt32();
                    Need(when>0 && size>=364 && size<=9751,"corrupt");saved.Add(new Saved(when,reader.ReadBytes(size)));}
            }
            history=VerifyHistory(saved);
            var next=Decode(body,history,saved);
            VerifyRows(next.Rows,history,saved);
            if(state is not null)Evolve(state,next);
            state=next;
        }
        Need(state is not null && history is not null,"unobserved");
        return (state,history);
    }

    void Append(FileStream file,State state){
        byte[] raw=EncodeState(state),record=Join(BE32(raw.Length),raw,Sha(Join(header,BE32(raw.Length),raw)));
        Need(file.Length+record.Length<=MaxBytes,"storage unavailable");
        file.Seek(0,SeekOrigin.End);WriteFull(file,record);file.Flush(true);
    }

    object Access(Action action){
        Need(!closed && Environment.TickCount64<expiry,"closed");
        using var file=new FileStream(path,FileMode.Open,FileAccess.ReadWrite,FileShare.None);
        var (state,history)=Load(file);
        return action(file,state,history);
    }

    Token TokenOf(Row r)=>new(this,RowBytes(r));
    byte[] ExpectedRow(Token t){Need(t is not null && ReferenceEquals(t.Owner,this),"invalid local token");return (byte[])t.Row.Clone();}

    public static ContactHistory Create(string path,byte[] pin,byte[] fingerprint,byte[] account,string origin,int maximumRecords,IReadOnlyList<ManifestChain.Verified> history,long now){
        var result=new ContactHistory(path,pin,fingerprint,account,origin,maximumRecords,false);
        try{
            Need(!File.Exists(result.path));
            var saved=result.Capture(history);result.VerifyHistory(saved);
            using(var file=new FileStream(result.path,FileMode.CreateNew,FileAccess.ReadWrite,FileShare.None)){
                WriteFull(file,result.header);result.Append(file,new State(saved,new List<Row>()));
            }
            return result;
        }catch{result.Dispose();throw;}
    }
    public static ContactHistory Open(string path,byte[] pin,byte[] fingerprint,byte[] account,string origin,int maximumRecords,bool reductionOnly=false){
        var result=new ContactHistory(path,pin,fingerprint,account,origin,maximumRecords,reductionOnly);
        try{
            Need(!reductionOnly || File.Exists(result.path),"unobserved");
            result.Access((file,state,history)=>null!);
            return result;
        }catch{result.Dispose();throw;}
    }

    public LookupResult Lookup(byte[] contactId){
        Need(contactId is not null && contactId.Length==16 && !Zero(contactId));
        return (LookupResult)Access((file,state,history)=>{
            Row? row=ByKey(state.Rows).TryGetValue(Hex(contactId),out var found)?found:null;
            if(row is null)return new LookupResult(null,null,"unobserved");
            var holder=TokenOf(row);
            if(!row.Accepted)return new LookupResult(holder,null,"local_stop");
            if(reduction)return new LookupResult(holder,null,"reduction_only");
            return new LookupResult(holder,row.Metadata,"available");
        });
    }

    static long IssuedOf(ContactField.Statement s){var b=s.Bytes();int n=BinaryPrimitives.ReadUInt16BigEndian(b.AsSpan(38,2));return BinaryPrimitives.ReadInt64BigEndian(b.AsSpan(225+n,8));}

    public LookupResult Accept(Token? expected,IReadOnlyList<ManifestChain.Verified> history,ContactField.Mutation.Transition transition,ContactField.Statement statement){
        Need(!reduction,"reduction_only");
        Need(transition is not null && statement is not null);
        Need(Same(transition.Mutation.Statement!.Bytes(),statement.Bytes()),"invalid statement");
        Need(Same(statement.Account!,account) && statement.Origin==origin,"root_mismatch");
        byte[] mutation=transition.Mutation.Bytes(),unsigned=Part(mutation,0,304);
        Need(mutation.Length==368 && Same(Part(unsigned,118,32),statement.Manifest!) && Number(unsigned,110)==statement.Version);
        byte[] digest=Sha(mutation),contactId=Part(unsigned,22,16),request=Part(unsigned,54,16),routing=Part(unsigned,182,32);
        long revision=Number(unsigned,46),issued=IssuedOf(statement);
        var nameSlot=new Slot((int)unsigned[222],Number(unsigned,223),Part(unsigned,231,32));
        var notesSlot=new Slot((int)unsigned[263],Number(unsigned,264),Part(unsigned,272,32));
        int operation=unsigned[5];byte[] previousDigest=Part(unsigned,70,32);
        byte[]? priorRow=expected is null?null:ExpectedRow(expected);
        var saved=Capture(history);
        return (LookupResult)Access((file,state,stored)=>{
            Need(saved.Count>=state.History.Count);
            for(int i=0;i<state.History.Count;i++)Need(state.History[i].Comparison==saved[i].Comparison && Same(state.History[i].Bytes,saved[i].Bytes),"history_missing");
            var chain=VerifyHistory(saved);
            ManifestChain.Verified? bound=null;int at=-1;
            for(int i=0;i<chain.Count;i++)if(chain[i].Version==statement.Version && Same(chain[i].Digest(),statement.Manifest!)){bound=chain[i];at=i;break;}
            Need(bound is not null && saved[at].Comparison<=issued,"history_missing");
            var metadata=new Metadata(contactId,revision,digest,request,routing,nameSlot,notesSlot,statement.Digest(),statement.Version,statement.Manifest!,statement.Reader!,statement.ReaderGeneration,statement.Writer!,issued,
                new Stamp(bound!.Version,bound.Digest(),Part(bound.Bytes(),53,32),saved[at].Comparison));
            Row? old=ByKey(state.Rows).TryGetValue(Hex(contactId),out var found)?found:null;
            if(old is null){
                Need(expected is null,"stale local CAS");
                Need((operation==1||operation==3) && revision==1,"cold update");
                Need(state.Rows.Count<maximum,"storage unavailable");
                var rows=new List<Row>(state.Rows){new Row(contactId,true,metadata)};
                var next=new State(saved,rows);VerifyRows(next.Rows,chain,saved);Append(file,next);
                return new LookupResult(new Token(this,RowBytes(new Row(contactId,true,metadata))),metadata,"available");
            }
            Need(priorRow is not null && Same(priorRow,RowBytes(old)),"stale local CAS");
            Need(old.Accepted,"local_stop");
            if(old.Metadata!.Revision==revision){
                var prior=new Metadata(contactId,revision,digest,request,routing,nameSlot,notesSlot,statement.Digest(),statement.Version,statement.Manifest!,statement.Reader!,statement.ReaderGeneration,statement.Writer!,issued,old.Metadata.RootStamp);
                Need(Same(RowBytes(old),RowBytes(new Row(contactId,true,prior))),"fork");
                return new LookupResult(TokenOf(old),old.Metadata,"available");
            }
            Need(operation==2 && old.Metadata.Revision<long.MaxValue && revision==old.Metadata.Revision+1,"fork");
            Need(Same(previousDigest,old.Metadata.Digest),"fork");
            Need(Same(routing,old.Metadata.RoutingDigest),"fork");
            Need(metadata.ManifestVersion>old.Metadata.ManifestVersion || metadata.ManifestVersion==old.Metadata.ManifestVersion && Same(metadata.ManifestDigest,old.Metadata.ManifestDigest),"fork");
            Need(metadata.ReaderGeneration>old.Metadata.ReaderGeneration || metadata.ReaderGeneration==old.Metadata.ReaderGeneration && Same(metadata.ReaderId,old.Metadata.ReaderId),"fork");
            var updated=new List<Row>();
            foreach(var row in state.Rows)updated.Add(Same(row.ContactId,contactId)?new Row(contactId,true,metadata):row);
            var final=new State(saved,updated);VerifyRows(final.Rows,chain,saved);Append(file,final);
            return new LookupResult(new Token(this,RowBytes(new Row(contactId,true,metadata))),metadata,"available");
        });
    }

    public LookupResult MarkUnavailable(Token expected){
        byte[] prior=ExpectedRow(expected);byte[] contact=Part(prior,0,16);
        return (LookupResult)Access((file,state,history)=>{
            Row? old=ByKey(state.Rows).TryGetValue(Hex(contact),out var found)?found:null;
            Need(old is not null && Same(prior,RowBytes(old!)),"stale local CAS");
            if(!old!.Accepted)return new LookupResult(TokenOf(old),null,"local_stop");
            var rows=new List<Row>();
            foreach(var row in state.Rows)rows.Add(Same(row.ContactId,contact)?new Row(contact,false,null):row);
            Append(file,new State(state.History,rows));
            return new LookupResult(new Token(this,Join(contact,new byte[]{2})),null,"local_stop");
        });
    }

    public void Dispose(){
        if(closed)return;closed=true;Permits.Release();
    }
}
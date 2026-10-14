package org.zrotext.candidate;

import java.io.*;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.channels.FileLock;
import java.nio.channels.OverlappingFileLockException;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.*;
import java.util.*;
import java.util.concurrent.Semaphore;
import java.util.concurrent.TimeUnit;

/** Application-owned contact local history with independently reverified signed root history. */
public final class ContactHistory {
    private static final int CAPACITY=256,MAX_BYTES=16000000,ORIGIN_MAX=512,HISTORY_LIMIT=64;
    private static final long LIFETIME_MS=TimeUnit.MINUTES.toMillis(30);
    private static final Semaphore PERMITS=new Semaphore(4);
    private static void need(boolean value)throws GeneralSecurityException{if(!value)throw new GeneralSecurityException("Contact local history refused");}
    private static void need(boolean value,String reason)throws GeneralSecurityException{if(!value)throw new GeneralSecurityException("Contact local history: "+reason);}
    private static byte[] part(byte[] b,int at,int count){return Arrays.copyOfRange(b,at,at+count);}
    private static boolean same(byte[] a,byte[] b){return a!=null && b!=null && a.length==b.length && MessageDigest.isEqual(a,b);}
    private static boolean zero(byte[] b){for(byte v:b)if(v!=0)return false;return true;}
    private static byte[] join(byte[]... values){int size=0;for(byte[] b:values)size+=b.length;byte[] out=new byte[size];int at=0;for(byte[] b:values){System.arraycopy(b,0,out,at,b.length);at+=b.length;}return out;}
    private static byte[] sha(byte[] b)throws GeneralSecurityException{return MessageDigest.getInstance("SHA-256").digest(b);}
    private static String hex(byte[] b){return HexFormat.of().formatHex(b);}
    private static long number(byte[] b,int at)throws GeneralSecurityException{long v=ByteBuffer.wrap(b,at,8).getLong();need(v>0);return v;}

    public record Slot(int tag,long sealRevision,byte[] digest){}
    public record Stamp(long version,byte[] digest,byte[] anchorDigest,long time){}
    public record Metadata(byte[] contactId,long revision,byte[] digest,byte[] requestId,byte[] routingDigest,Slot name,Slot notes,
        byte[] statementDigest,long manifestVersion,byte[] manifestDigest,byte[] readerId,long readerGeneration,byte[] rootWriterId,
        long comparisonMs,Stamp rootStamp){}
    private record Row(byte[] contactId,boolean accepted,Metadata metadata){}
    private record Saved(long comparison,byte[] bytes){}
    private record State(List<Saved> history,List<Row> rows){}
    public static final class Token{
        private final ContactHistory owner;private final byte[] row;
        private Token(ContactHistory owner,byte[] row){this.owner=owner;this.row=row;}
    }
    public static final class Lookup{
        private final Token token;private final Metadata metadata;private final String reason;
        private Lookup(Token token,Metadata metadata,String reason){this.token=token;this.metadata=metadata;this.reason=reason;}
        public boolean accepted(){return metadata!=null;}
        public String reason(){return reason;}
        public Metadata metadata(){return metadata;}
        public Token token(){return token;}
    }
    @FunctionalInterface private interface Action {Object run(FileChannel file,State state,List<ManifestChain.Verified> history)throws IOException,GeneralSecurityException;}

    private final Path path;private final byte[] header;private final int maximum;private final boolean reduction;
    private final ManifestChain.RootPin trust;private final byte[] account;private final String origin;
    private boolean closed;private final long expiry;

    private ContactHistory(Path path,byte[] pin,byte[] fingerprint,byte[] expectedAccount,String origin,int maximumRecords,boolean reduction,ManifestChain.RootPin enrolled)throws GeneralSecurityException{
        need(pin!=null && pin.length==94 && fingerprint!=null && fingerprint.length==32 && expectedAccount!=null && expectedAccount.length==16 && !zero(expectedAccount));
        need(origin!=null && origin.startsWith("https://"));
        byte[] originBytes=origin.getBytes(StandardCharsets.US_ASCII);
        need(originBytes.length>=1 && originBytes.length<=ORIGIN_MAX && maximumRecords>=1 && maximumRecords<=CAPACITY);
        for(byte v:originBytes)need(v>32 && v<127);
        need(new String(originBytes,StandardCharsets.US_ASCII).equals(origin));
        byte[] count=ByteBuffer.allocate(4).putInt(maximumRecords).array();
        this.path=path.toAbsolutePath();this.maximum=maximumRecords;this.reduction=reduction;this.expiry=System.currentTimeMillis()+LIFETIME_MS;this.closed=false;
        this.trust=enrolled;this.account=expectedAccount.clone();this.origin=origin;
        this.header=join(new byte[]{90,84,76,72,49},pin.clone(),fingerprint.clone(),expectedAccount.clone(),ByteBuffer.allocate(2).putShort((short)originBytes.length).array(),originBytes,count);
    }

    private static void writeFull(FileChannel file,byte[] bytes)throws IOException{var b=ByteBuffer.wrap(bytes);while(b.hasRemaining())file.write(b);}
    private static byte[] readFull(FileChannel file,int count)throws IOException{var out=ByteBuffer.allocate(count);while(out.hasRemaining())if(file.read(out)<0)throw new EOFException("Partial contact history");return out.array();}
    private static byte[] read(DataInputStream in,int n)throws IOException{byte[] out=new byte[n];in.readFully(out);return out;}

    private static List<Saved> capture(List<ManifestChain.Verified> history)throws GeneralSecurityException{
        need(history!=null && history.size()>=1 && history.size()<=HISTORY_LIMIT);var rows=new ArrayList<Saved>();
        for(var m:history){need(m!=null && m.profile()==2 && m.generation()==1 && m.version()>=1);rows.add(new Saved(m.comparisonMs(),m.bytes()));}
        return rows;
    }
    private List<ManifestChain.Verified> verifyHistory(List<Saved> rows)throws GeneralSecurityException{
        need(rows.size()>=1 && rows.size()<=HISTORY_LIMIT);var history=new ArrayList<ManifestChain.Verified>();ManifestChain.Verified previous=null;
        for(var row:rows){need(row.comparison()>0 && row.bytes().length>=364 && row.bytes().length<=9751);
            var m=ManifestChain.originalAccepted02(row.bytes(),trust,previous,row.comparison());need(m.generation()==1 && m.version()==history.size()+1 && same(m.account(),account),"corrupt");history.add(m);previous=m;}
        return history;
    }

    private static byte[] encode(State value)throws GeneralSecurityException{
        var bytes=new ByteArrayOutputStream();
        try(var data=new DataOutputStream(bytes)){
            data.writeInt(value.history().size());
            for(Saved m:value.history()){data.writeLong(m.comparison());data.writeInt(m.bytes().length);data.write(m.bytes());}
            data.writeInt(value.rows().size());
            for(Row r:value.rows()){
                data.write(r.contactId());data.writeByte(r.accepted()?1:2);
                if(!r.accepted())continue;
                Metadata m=r.metadata();
                data.writeLong(m.revision());data.write(m.digest());data.write(m.requestId());data.write(m.routingDigest());
                data.writeByte(m.name().tag());data.writeLong(m.name().sealRevision());data.write(m.name().digest());
                data.writeByte(m.notes().tag());data.writeLong(m.notes().sealRevision());data.write(m.notes().digest());
                data.write(m.statementDigest());data.writeLong(m.manifestVersion());data.write(m.manifestDigest());
                data.write(m.readerId());data.writeLong(m.readerGeneration());data.write(m.rootWriterId());data.writeLong(m.comparisonMs());
                data.writeLong(m.rootStamp().version());data.write(m.rootStamp().digest());data.write(m.rootStamp().anchorDigest());data.writeLong(m.rootStamp().time());
            }
        }catch(IOException failure){throw new GeneralSecurityException("Contact local history refused");}
        return bytes.toByteArray();
    }
    private static byte[] fixed(byte[] b,int n)throws GeneralSecurityException{need(b!=null && b.length==n && !zero(b),"corrupt");return b.clone();}
    private static Slot slot(DataInputStream in,long revision)throws GeneralSecurityException,IOException{
        int tag=in.read();long seal=in.readLong();byte[] digest=read(in,32);
        need(tag==0 || tag==1,"corrupt");need(seal>=0 && seal<=revision,"corrupt");
        need(tag==0?seal==0 && zero(digest):seal>0 && !zero(digest),"corrupt");
        return new Slot(tag,seal,digest);
    }
    private static State decode(byte[] body,List<ManifestChain.Verified> history,List<Saved> saved)throws GeneralSecurityException{
        try(var in=new DataInputStream(new ByteArrayInputStream(body))){
            int historyCount=in.readInt();need(historyCount>=1 && historyCount<=HISTORY_LIMIT && historyCount==history.size(),"corrupt");
            for(int i=0;i<historyCount;i++){long when=in.readLong();int length=in.readInt();
                need(when>0 && length>=364 && length<=9751 && length<=in.available(),"corrupt");byte[] raw=read(in,length);
                need(when==saved.get(i).comparison() && same(raw,history.get(i).bytes()),"corrupt");}
            int count=in.readInt();need(count>=0 && count<=CAPACITY,"corrupt");
            var rows=new ArrayList<Row>();var seen=new HashSet<String>();
            for(int i=0;i<count;i++){
                byte[] contactId=read(in,16);need(!zero(contactId) && seen.add(hex(contactId)),"corrupt");
                int state=in.read();
                if(state==2){rows.add(new Row(contactId,false,null));continue;}
                need(state==1,"corrupt");
                long revision=in.readLong();byte[] digest=fixed(read(in,32),32),request=fixed(read(in,16),16),routing=fixed(read(in,32),32);
                Slot name=slot(in,revision),notes=slot(in,revision);
                byte[] statement=fixed(read(in,32),32);long manifestVersion=in.readLong();byte[] manifest=fixed(read(in,32),32),reader=fixed(read(in,32),32);
                long readerGeneration=in.readLong();byte[] writer=fixed(read(in,32),32);long comparisonMs=in.readLong();
                long stampVersion=in.readLong();byte[] stampDigest=read(in,32),anchor=read(in,32);long stampTime=in.readLong();
                need(revision>0 && manifestVersion>0 && readerGeneration>0 && comparisonMs>0 && stampVersion>0 && stampTime>0,"corrupt");
                Metadata m=new Metadata(contactId,revision,digest,request,routing,name,notes,statement,manifestVersion,manifest,reader,readerGeneration,writer,comparisonMs,
                    new Stamp(stampVersion,stampDigest,anchor,stampTime));
                rows.add(new Row(contactId,true,m));
            }
            need(in.available()==0,"corrupt");
            return new State(saved,rows);
        }catch(IOException failure){throw new GeneralSecurityException("Contact local history: corrupt");}
    }

    /** Every accepted row must still bind to a manifest of the reverified history and the current head floor. */
    private static void verifyRows(List<Row> rows,List<ManifestChain.Verified> history,List<Saved> saved,int maximum)throws GeneralSecurityException{
        int accepted=0;
        for(Row r:rows){
            if(!r.accepted())continue;accepted++;Metadata m=r.metadata();
            ManifestChain.Verified bound=null;int at=-1;
            for(int i=0;i<history.size();i++)if(history.get(i).version()==m.manifestVersion() && same(history.get(i).digest(),m.manifestDigest())){bound=history.get(i);at=i;break;}
            need(bound!=null && saved.get(at).comparison()<=m.comparisonMs(),"history_missing");
            byte[] reader=null,writer=null;
            for(byte[] k:bound.keyRecords()){
                long from=ByteBuffer.wrap(k,132,8).getLong(),until=ByteBuffer.wrap(k,140,8).getLong();
                if(k[0]==2 && same(part(k,1,32),m.readerId()) && from<=m.comparisonMs() && m.comparisonMs()<until)reader=k;
                if(k[0]==6)writer=k;
            }
            need(reader!=null && writer!=null && same(part(writer,1,32),m.rootWriterId()),"history_missing");
            var head=history.get(history.size()-1);
            need(head.version()>m.rootStamp().version() || head.version()==m.rootStamp().version() && same(head.digest(),m.rootStamp().digest()),"history_missing");
        }
        need(accepted<=maximum,"corrupt");
    }

    /** Contacts never disappear, terminal states stay terminal and revisions never regress. */
    private static void evolve(State prior,State next)throws GeneralSecurityException{
        need(next.history().size()>=prior.history().size(),"corrupt");
        for(int i=0;i<prior.history().size();i++)need(prior.history().get(i).comparison()==next.history().get(i).comparison() && same(prior.history().get(i).bytes(),next.history().get(i).bytes()),"corrupt");
        var before=byKey(prior.rows());var after=byKey(next.rows());
        for(var entry:before.entrySet()){
            Row fresh=after.get(entry.getKey());need(fresh!=null,"corrupt");
            Row old=entry.getValue();
            if(!old.accepted()){need(!fresh.accepted(),"corrupt");continue;}
            if(!fresh.accepted())continue;
            need(fresh.metadata().revision()>=old.metadata().revision(),"corrupt");
            if(fresh.metadata().revision()==old.metadata().revision())need(same(rowBytes(old),rowBytes(fresh)),"corrupt");
        }
    }
    private static byte[] rowBytes(Row r)throws GeneralSecurityException{return encode(new State(List.of(),List.of(r)));}
    private static Map<String,Row> byKey(List<Row> rows){var out=new HashMap<String,Row>();for(Row r:rows)out.put(hex(r.contactId()),r);return out;}

    private record Loaded(State state,List<ManifestChain.Verified> history,List<Saved> saved){}
    private Loaded load(FileChannel file)throws IOException,GeneralSecurityException{
        need(file.size()>=header.length+4+12+364+32+4 && file.size()<=MAX_BYTES,"corrupt");file.position(0);
        need(same(readFull(file,header.length),header),"root_mismatch");
        State state=null;List<ManifestChain.Verified> history=null;
        while(file.position()<file.size()){
            need(file.size()-file.position()>=4,"corrupt");byte[] length=readFull(file,4);int count=ByteBuffer.wrap(length).getInt();
            need(count>=12+364 && count<=20+HISTORY_LIMIT*(12+9751)+CAPACITY*419 && file.size()-file.position()>=count+32,"corrupt");
            byte[] body=readFull(file,count);need(same(readFull(file,32),sha(join(header,length,body))),"corrupt");
            var saved=new ArrayList<Saved>();
            try(var in=new DataInputStream(new ByteArrayInputStream(body))){
                int historyCount=in.readInt();need(historyCount>=1 && historyCount<=HISTORY_LIMIT,"corrupt");
                for(int i=0;i<historyCount;i++){long when=in.readLong();int size=in.readInt();
                    need(when>0 && size>=364 && size<=9751 && size<=in.available(),"corrupt");saved.add(new Saved(when,read(in,size)));}
            }
            history=verifyHistory(saved);
            State next=decode(body,history,saved);
            verifyRows(next.rows(),history,saved,maximum);
            if(state!=null)evolve(state,next);
            state=next;
        }
        need(state!=null && history!=null,"unobserved");
        return new Loaded(state,history,state.history());
    }

    private void append(FileChannel file,State state)throws IOException,GeneralSecurityException{
        byte[] raw=encode(state),length=ByteBuffer.allocate(4).putInt(raw.length).array(),record=join(length,raw,sha(join(header,length,raw)));
        need(file.size()+record.length<=MAX_BYTES,"storage unavailable");file.position(file.size());writeFull(file,record);file.force(true);
    }

    private Object access(Action action)throws IOException,GeneralSecurityException,InterruptedException{
        need(!closed && System.currentTimeMillis()<expiry,"closed");
        try(var file=FileChannel.open(path,StandardOpenOption.READ,StandardOpenOption.WRITE,LinkOption.NOFOLLOW_LINKS)){
            FileLock acquired=null;
            for(int attempt=0;attempt<100 && acquired==null;attempt++){
                try{acquired=file.tryLock();}catch(OverlappingFileLockException busy){/* bounded local contention */}
                if(acquired==null)Thread.sleep(50);
            }
            need(acquired!=null,"storage unavailable");
            try(var lock=acquired){
                need(lock.isValid());
                Loaded loaded=load(file);
                return action.run(file,loaded.state(),loaded.history());
            }
        }
    }

    private Token token(Row r)throws GeneralSecurityException{
        need(!closed && System.currentTimeMillis()<expiry,"closed");
        return new Token(this,rowBytes(r));
    }
    private Row expected(Token t)throws GeneralSecurityException{
        // Tokens carry opaque full-row bytes; the CAS comparison uses them verbatim.
        need(t!=null && t.owner==this,"invalid local token");
        need(!closed && System.currentTimeMillis()<expiry,"closed");
        // Row bytes carry the state framing: [historyCount=0][rowCount=1][contactId][state]...
        need(t.row.length>=25,"invalid local token");
        return new Row(Arrays.copyOfRange(t.row,8,24),t.row[24]==1,null);
    }

    /** SHA-256 of the persisted file, for cross-language interchange checks. */
    public static String fileDigest(java.nio.file.Path path)throws java.io.IOException{try{return HexFormat.of().formatHex(java.security.MessageDigest.getInstance("SHA-256").digest(java.nio.file.Files.readAllBytes(path)));}catch(java.security.NoSuchAlgorithmException failure){throw new java.io.IOException(failure);}}

    /** Creates the file with the complete verified generation-one history and no rows. Missing state never initializes on open. */
    public static ContactHistory create(Path path,byte[] pin,byte[] fingerprint,byte[] account,String origin,int maximumRecords,List<ManifestChain.Verified> history,long now)throws IOException,GeneralSecurityException{
        need(PERMITS.tryAcquire(),"storage unavailable");
        boolean done=false;
        try{
        ManifestChain.RootPin enrolled=ManifestChain.RootPin.enroll(pin.clone(),fingerprint.clone());
        var result=new ContactHistory(path,pin,fingerprint,account,origin,maximumRecords,false,enrolled);
        var saved=capture(history);result.verifyHistory(saved);
        need(now>0 && saved.stream().allMatch(m->m.comparison()<=now || m.comparison()-now<=30000),"corrupt");
        try(var file=FileChannel.open(result.path,StandardOpenOption.CREATE_NEW,StandardOpenOption.READ,StandardOpenOption.WRITE,LinkOption.NOFOLLOW_LINKS);var lock=file.lock()){
            need(lock.isValid());writeFull(file,result.header);result.append(file,new State(saved,List.of()));
        }
        done=true;return result;
        }finally{if(!done)PERMITS.release();}
    }
    public static ContactHistory open(Path path,byte[] pin,byte[] fingerprint,byte[] account,String origin,int maximumRecords,boolean reductionOnly)throws IOException,GeneralSecurityException,InterruptedException{
        need(PERMITS.tryAcquire(),"storage unavailable");
        boolean done=false;
        try{
        ManifestChain.RootPin enrolled=ManifestChain.RootPin.enroll(pin.clone(),fingerprint.clone());
        var result=new ContactHistory(path,pin,fingerprint,account,origin,maximumRecords,reductionOnly,enrolled);
        need(!reductionOnly || java.nio.file.Files.exists(result.path),"unobserved");
        result.access((file,state,history)->null);
        done=true;return result;
        }finally{if(!done)PERMITS.release();}
    }

    /** Reverified lookup: accepted metadata, or unobserved/local_stop/reduction_only/history_missing/root_mismatch. */
    public Lookup lookup(byte[] contactId)throws IOException,GeneralSecurityException,InterruptedException{
        need(contactId!=null && contactId.length==16 && !zero(contactId));
        return (Lookup)access((file,state,history)->{
            Row r=byKey(state.rows()).get(hex(contactId));
            if(r==null)return new Lookup(null,null,"unobserved");
            Token t=token(r);
            if(!r.accepted())return new Lookup(t,null,"local_stop");
            if(reduction)return new Lookup(t,null,"reduction_only");
            return new Lookup(t,r.metadata(),"available");
        });
    }

    /** Exact CAS, replay tolerance and fork refusal against the reverified current row.
     * The supplied history must extend the stored signed root history by prefix. */
    public Lookup accept(Token expected,List<ManifestChain.Verified> history,ContactField.Mutation.Transition transition,ContactField.Statement statement)throws IOException,GeneralSecurityException,InterruptedException{
        need(!reduction,"reduction_only");
        need(transition!=null && statement!=null);
        var saved=capture(history);
        need(same(transition.mutation().statement().bytes(),statement.bytes()),"invalid statement");
        need(same(statement.accountField(),account) && statement.originField().equals(origin),"root_mismatch");
        final byte[] mutation=transition.mutation().bytes(),unsigned=part(mutation,0,304),digest=sha(mutation);
        need(mutation.length==368 && same(part(unsigned,118,32),statement.manifestField()) && number(unsigned,110)==statement.versionField());
        final byte[] contactId=part(unsigned,22,16),request=part(unsigned,54,16),routing=part(unsigned,182,32);
        final long revision=number(unsigned,46),manifestVersion=statement.versionField(),readerGeneration=statement.readerGenerationField(),comparisonMs=statement.issuedField();
        final Slot name=new Slot(unsigned[222],ByteBuffer.wrap(unsigned,223,8).getLong(),part(unsigned,231,32));
        final Slot notes=new Slot(unsigned[263],ByteBuffer.wrap(unsigned,264,8).getLong(),part(unsigned,272,32));
        final byte[] statementDigest=statement.digest(),manifestDigest=statement.manifestField(),readerId=statement.readerField(),rootWriterId=statement.writerField(),previousDigest=part(unsigned,70,32);
        final int operation=unsigned[5];
        return (Lookup)access((file,state,stored)->{
            var stateSaved=state.history();
            need(saved.size()>=stateSaved.size(),"history_missing");
            for(int i=0;i<stateSaved.size();i++)need(stateSaved.get(i).comparison()==saved.get(i).comparison() && same(stateSaved.get(i).bytes(),saved.get(i).bytes()),"history_missing");
            var nextSaved=saved;
            var chain=verifyHistory(nextSaved);
            ManifestChain.Verified bound=null;int at=-1;
            for(int i=0;i<chain.size();i++)if(chain.get(i).version()==manifestVersion && same(chain.get(i).digest(),manifestDigest)){bound=chain.get(i);at=i;break;}
            need(bound!=null && saved.get(at).comparison()<=comparisonMs,"history_missing");
            Metadata proposed=new Metadata(contactId,revision,digest,request,routing,name,notes,statementDigest,manifestVersion,manifestDigest,readerId,readerGeneration,rootWriterId,comparisonMs,
                new Stamp(bound.version(),bound.digest(),part(bound.bytes(),53,32),nextSaved.get(at).comparison()));
            Row old=byKey(state.rows()).get(hex(proposed.contactId()));
            Row priorRow=expected==null?null:expected(expected);
            need(priorRow==null || same(priorRow.contactId(),proposed.contactId()),"invalid local token");
            if(old==null){
                need(expected==null,"stale local CAS");
                need(operation==1 || operation==3,"cold update");need(proposed.revision()==1,"cold update");
                need(state.rows().size()<maximum,"storage unavailable");
                var rows=new ArrayList<>(state.rows());rows.add(new Row(proposed.contactId(),true,proposed));
                var next=new State(nextSaved,rows);verifyRows(next.rows(),chain,nextSaved,maximum);
                append(file,next);
                return new Lookup(token(new Row(proposed.contactId(),true,proposed)),proposed,"available");
            }
            need(same(rowBytes(old),priorRow==null?null:expected.row),"stale local CAS");
            need(old.accepted(),"local_stop");
            if(old.metadata().revision()==proposed.revision()){
                need(same(rowBytes(old),rowBytes(new Row(proposed.contactId(),true,withPriorStamp(proposed,old.metadata().rootStamp())))),"fork");
                return new Lookup(token(old),old.metadata(),"available");
            }
            need(operation==2 && old.metadata().revision()<Long.MAX_VALUE && proposed.revision()==old.metadata().revision()+1,"fork");
            need(same(previousDigest,old.metadata().digest()),"fork");
            need(same(proposed.routingDigest(),old.metadata().routingDigest()),"fork");
            need(proposed.manifestVersion()>old.metadata().manifestVersion() || proposed.manifestVersion()==old.metadata().manifestVersion() && same(proposed.manifestDigest(),old.metadata().manifestDigest()),"fork");
            need(proposed.readerGeneration()>old.metadata().readerGeneration() || proposed.readerGeneration()==old.metadata().readerGeneration() && same(proposed.readerId(),old.metadata().readerId()),"fork");
            var rows=new ArrayList<>(state.rows());
            for(int i=0;i<rows.size();i++)if(same(rows.get(i).contactId(),proposed.contactId()))rows.set(i,new Row(proposed.contactId(),true,proposed));
            var next=new State(nextSaved,rows);verifyRows(next.rows(),chain,nextSaved,maximum);
            append(file,next);
            return new Lookup(token(new Row(proposed.contactId(),true,proposed)),proposed,"available");
        });
    }
    private static Metadata withPriorStamp(Metadata m,Stamp stamp){return new Metadata(m.contactId(),m.revision(),m.digest(),m.requestId(),m.routingDigest(),m.name(),m.notes(),m.statementDigest(),m.manifestVersion(),m.manifestDigest(),m.readerId(),m.readerGeneration(),m.rootWriterId(),m.comparisonMs(),stamp);}

    /** Terminal local stop; exact CAS against the expected row. */
    public Lookup markUnavailable(Token expected)throws IOException,GeneralSecurityException,InterruptedException{
        Row prior=expected(expected);
        return (Lookup)access((file,state,history)->{
            Row old=byKey(state.rows()).get(hex(prior.contactId()));
            need(old!=null && same(rowBytes(old),expected.row),"stale local CAS");
            if(!old.accepted())return new Lookup(token(old),null,"local_stop");
            var rows=new ArrayList<>(state.rows());
            for(int i=0;i<rows.size();i++)if(same(rows.get(i).contactId(),prior.contactId()))rows.set(i,new Row(prior.contactId(),false,null));
            append(file,new State(state.history(),rows));
            return new Lookup(token(new Row(prior.contactId(),false,null)),null,"local_stop");
        });
    }

    public void close(){if(closed)return;closed=true;java.util.Arrays.fill(header,(byte)0);java.util.Arrays.fill(account,(byte)0);PERMITS.release();}
}

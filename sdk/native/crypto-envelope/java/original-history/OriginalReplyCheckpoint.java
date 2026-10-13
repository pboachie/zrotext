package org.zrotext.candidate;
import java.io.*;
import java.nio.*;
import java.nio.channels.*;
import java.nio.file.*;
import java.security.*;
import java.util.*;

/** Trusted-path accepted history. Torn appends refuse; whole-file rollback is not detected. */
public final class OriginalReplyCheckpoint {
    private static final int CAPACITY=64,TRANSACTIONS=256,MAX_BYTES=16000000;
    public record Snapshot(long revision,long comparisonMs,List<ManifestChain.Verified> history){public Snapshot{history=List.copyOf(history);}}
    private record Saved(long comparison,byte[] bytes){}
    private record State(long revision,long comparison,List<Saved> rows){}
    @FunctionalInterface public interface Fence {long check(ManifestChain.Verified current,long comparisonMs)throws GeneralSecurityException;}
    private final Path path;private final byte[] header;private final ManifestChain.RootPin trust;
    private OriginalReplyCheckpoint(Path path,byte[] pin,byte[] fingerprint,OriginalReplyReader.Scope scope)throws GeneralSecurityException{
        this.path=path.toAbsolutePath();byte[] root=pin.clone(),compared=fingerprint.clone();trust=ManifestChain.RootPin.enroll(root,compared);need(same(Arrays.copyOfRange(root,5,21),scope.checkpointAccount()));header=join(new byte[]{90,84,79,49},root,compared,scope.checkpointBinding());
    }
    private static void need(boolean value)throws GeneralSecurityException{if(!value)throw new GeneralSecurityException("Original history refused");}
    private static byte[] join(byte[]... values){int size=0;for(var v:values)size+=v.length;byte[] result=new byte[size];int at=0;for(var v:values){System.arraycopy(v,0,result,at,v.length);at+=v.length;}return result;}
    private static boolean same(byte[] a,byte[] b){return MessageDigest.isEqual(a,b);}
    private static byte[] sha(byte[] value)throws GeneralSecurityException{return MessageDigest.getInstance("SHA-256").digest(value);}
    private static byte[] read(FileChannel file,int count)throws IOException{var out=ByteBuffer.allocate(count);while(out.hasRemaining())if(file.read(out)<0)throw new EOFException("Partial original history");return out.array();}
    private static void write(FileChannel file,byte[] bytes)throws IOException{var b=ByteBuffer.wrap(bytes);while(b.hasRemaining())file.write(b);}
    private static List<Saved> capture(List<ManifestChain.Verified> history)throws GeneralSecurityException{
        need(history!=null && history.size()>=1 && history.size()<=CAPACITY);var rows=new ArrayList<Saved>();
        for(var m:history){need(m!=null && m.profile()==2 && m.generation()==1);rows.add(new Saved(m.comparisonMs(),m.bytes()));}return rows;
    }
    private List<ManifestChain.Verified> verify(List<Saved> rows,long now)throws GeneralSecurityException{
        need(now>0 && rows.size()>=1 && rows.size()<=CAPACITY);var history=new ArrayList<ManifestChain.Verified>();ManifestChain.Verified previous=null;
        for(var row:rows){need(row.comparison>0 && (row.comparison<=now || row.comparison-now<=30000) && row.bytes.length>=364 && row.bytes.length<=9751);var m=ManifestChain.originalAccepted02(row.bytes,trust,previous,row.comparison);need(m.generation()==1 && m.version()==history.size()+1);history.add(m);previous=m;}
        need(previous!=null);history.set(history.size()-1,ManifestChain.originalAccepted02(previous.bytes(),trust,previous,now));return List.copyOf(history);
    }
    private static boolean prefix(Saved old,Saved proposed){return same(Arrays.copyOf(old.bytes,old.bytes.length-64),Arrays.copyOf(proposed.bytes,proposed.bytes.length-64));}
    private byte[] encode(State value)throws IOException{
        var bytes=new ByteArrayOutputStream();try(var data=new DataOutputStream(bytes)){data.writeLong(value.revision);data.writeLong(value.comparison);data.writeInt(value.rows.size());for(var r:value.rows){data.writeLong(r.comparison);data.writeInt(r.bytes.length);data.write(r.bytes);}}return bytes.toByteArray();
    }
    private State decode(byte[] bytes)throws IOException,GeneralSecurityException{
        try(var in=new DataInputStream(new ByteArrayInputStream(bytes))){long revision=in.readLong(),now=in.readLong();int count=in.readInt();need(revision>=1 && revision<=TRANSACTIONS && now>0 && count>=1 && count<=CAPACITY);var rows=new ArrayList<Saved>();for(int i=0;i<count;i++){long when=in.readLong();int length=in.readInt();need(length>=364 && length<=9751 && length<=in.available());rows.add(new Saved(when,in.readNBytes(length)));}need(in.available()==0);verify(rows,now);return new State(revision,now,rows);}
    }
    private State load(FileChannel file)throws IOException,GeneralSecurityException{
        need(file.size()>=header.length+4+20+12+364+32 && file.size()<=MAX_BYTES);file.position(0);need(same(read(file,header.length),header));State state=null;
        while(file.position()<file.size()){
            need(file.size()-file.position()>=4);byte[] length=read(file,4);int count=ByteBuffer.wrap(length).getInt();need(count>=396 && count<=20+CAPACITY*(12+9751) && file.size()-file.position()>=count+32);byte[] body=read(file,count);need(same(read(file,32),sha(join(header,length,body))));State next=decode(body);
            need(next.revision==(state==null?1:state.revision+1));if(state!=null){need(next.comparison>=state.comparison && next.rows.size()>=state.rows.size());for(int i=0;i<state.rows.size();i++)need(state.rows.get(i).comparison==next.rows.get(i).comparison && same(state.rows.get(i).bytes,next.rows.get(i).bytes));}state=next;
        }
        need(state!=null);return state;
    }
    private void append(FileChannel file,State state)throws IOException,GeneralSecurityException{
        byte[] raw=encode(state),length=ByteBuffer.allocate(4).putInt(raw.length).array(),record=join(length,raw,sha(join(header,length,raw)));need(file.size()+record.length<=MAX_BYTES);file.position(file.size());write(file,record);file.force(true);
    }
    @FunctionalInterface private interface Action {Snapshot run(FileChannel file,State state)throws IOException,GeneralSecurityException;}
    private Snapshot access(Action action)throws IOException,GeneralSecurityException,InterruptedException{
        try(var file=FileChannel.open(path,StandardOpenOption.READ,StandardOpenOption.WRITE,LinkOption.NOFOLLOW_LINKS)){
            FileLock acquired=null;for(int attempt=0;attempt<100 && acquired==null;attempt++){try{acquired=file.tryLock();}catch(OverlappingFileLockException busy){/* bounded local contention */}if(acquired==null)Thread.sleep(50);}need(acquired!=null);
            try(var lock=acquired){need(lock.isValid());return action.run(file,load(file));}
        }
    }
    public static OriginalReplyCheckpoint create(Path path,byte[] pin,byte[] fingerprint,OriginalReplyReader.Scope scope,List<ManifestChain.Verified> history,long now)throws IOException,GeneralSecurityException{
        var result=new OriginalReplyCheckpoint(path,pin,fingerprint,scope);var rows=capture(history);result.verify(rows,now);
        try(var file=FileChannel.open(result.path,StandardOpenOption.CREATE_NEW,StandardOpenOption.READ,StandardOpenOption.WRITE,LinkOption.NOFOLLOW_LINKS);var lock=file.lock()){need(lock.isValid());write(file,result.header);result.append(file,new State(1,now,rows));}return result;
    }
    public static OriginalReplyCheckpoint open(Path path,byte[] pin,byte[] fingerprint,OriginalReplyReader.Scope scope)throws IOException,GeneralSecurityException,InterruptedException{
        var result=new OriginalReplyCheckpoint(path,pin,fingerprint,scope);result.access((file,state)->new Snapshot(state.revision,state.comparison,result.verify(state.rows,state.comparison)));return result;
    }
    /** Re-verifies without committing fresh time. Accept before returning plaintext or effects. */
    public Snapshot snapshot(OriginalReplyReader.Scope scope,long now)throws IOException,GeneralSecurityException,InterruptedException{
        need(same(scope.checkpointBinding(),Arrays.copyOfRange(header,header.length-32,header.length)));return access((file,state)->{need(now>=state.comparison);return new Snapshot(state.revision,state.comparison,verify(state.rows,now));});
    }
    /** Captures immutable history, checks CAS and trusted freshness under the exclusive lock, then flushes one transaction. */
    public Snapshot accept(OriginalReplyReader.Scope scope,List<ManifestChain.Verified> history,long expectedRevision,long now,Fence fence)throws IOException,GeneralSecurityException,InterruptedException{
        need(fence!=null && same(scope.checkpointBinding(),Arrays.copyOfRange(header,header.length-32,header.length)));var proposed=capture(history);
        return access((file,state)->{need(expectedRevision==state.revision && state.revision<TRANSACTIONS && now>=state.comparison && proposed.size()>=state.rows.size());verify(proposed,now);for(int i=0;i<state.rows.size();i++){need(prefix(state.rows.get(i),proposed.get(i)));proposed.set(i,state.rows.get(i));}var before=verify(proposed,now);long checked=fence.check(before.get(before.size()-1),now);need(checked>=now);var verified=verify(proposed,checked);var next=new State(state.revision+1,checked,proposed);append(file,next);return new Snapshot(next.revision,checked,verified);});
    }
}

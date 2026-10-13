package org.zrotext.candidate;
import java.io.*;
import java.nio.*;
import java.nio.channels.*;
import java.nio.file.*;
import java.security.*;
import java.util.*;

/** Bounded trusted-path history. Incomplete append refuses; no hostile-filesystem rollback claim. */
public final class RootJournal {
    public record Snapshot(long revision,ManifestChain.Verified manifest){}
    private final Path path;private final byte[] header;private final ManifestChain.RootPin trust;private final Map<Long,byte[]> approvals;
    public RootJournal(Path path,byte[] pin,byte[] fingerprint,Map<Long,byte[]> approvedRoots)throws GeneralSecurityException{
        need(approvedRoots.size()<=256);this.path=path.toAbsolutePath();byte[] captured=pin.clone(),compared=fingerprint.clone();trust=ManifestChain.RootPin.enroll(captured,compared);header=join(new byte[]{90,84,67,50},captured,compared);
        Map<Long,byte[]> values=new HashMap<>();for(var entry:approvedRoots.entrySet()){need(entry.getKey()>1 && entry.getValue().length==65);byte[] point=entry.getValue().clone();HpkeRecipient.point(point);values.put(entry.getKey(),point);}approvals=Map.copyOf(values);
    }
    private static void need(boolean value)throws GeneralSecurityException{if(!value)throw new GeneralSecurityException("Root journal refused");}
    private static byte[] join(byte[]... values){int n=0;for(var v:values)n+=v.length;byte[] out=new byte[n];int at=0;for(var v:values){System.arraycopy(v,0,out,at,v.length);at+=v.length;}return out;}
    private static byte[] sha(byte[] b)throws GeneralSecurityException{return MessageDigest.getInstance("SHA-256").digest(b);}
    private static boolean same(byte[] a,byte[] b){return MessageDigest.isEqual(a,b);}
    private static byte[] read(FileChannel file,int size)throws IOException{ByteBuffer b=ByteBuffer.allocate(size);while(b.hasRemaining())if(file.read(b)<0)throw new EOFException("Partial root journal");return b.array();}
    private static void write(FileChannel file,byte[] value)throws IOException{ByteBuffer b=ByteBuffer.wrap(value);while(b.hasRemaining())file.write(b);}
    private ManifestChain.Verified step(byte[] raw,byte[] transition,ManifestChain.Verified current,long now)throws GeneralSecurityException{
        need(raw.length>=364 && raw.length<=9751 && raw[4]==2);
        if(current==null){need(transition==null);return ManifestChain.genesis02(raw,trust,now);}
        if(transition!=null){need(transition.length==343);byte[] approved=approvals.get(ByteBuffer.wrap(transition,29,8).getLong());need(approved!=null);return ManifestChain.rotate02(transition,raw,current,approved,now);}
        var value=ManifestChain.continueChain(raw,current,2,now);need(current.version()<Long.MAX_VALUE && value.version()==current.version()+1);return value;
    }
    private final class Clock {
        private final FileChannel file;private long floor;
        private Clock(FileChannel file,long now)throws IOException,GeneralSecurityException{this.file=file;byte[] b=read(file,8);need(same(read(file,32),sha(join(header,b))));floor=ByteBuffer.wrap(b).getLong();need(floor>=0 && floor<=now);}
        private void advance(long now)throws IOException,GeneralSecurityException{need(now>=floor);if(now>floor){long at=file.position();byte[] value=ByteBuffer.allocate(8).putLong(now).array();file.position(header.length);write(file,join(value,sha(join(header,value))));file.force(true);file.position(at);floor=now;}}
    }
    @FunctionalInterface private interface Action {Snapshot run(FileChannel file,long revision,ManifestChain.Verified current,Clock clock)throws GeneralSecurityException,IOException;}
    private Snapshot access(long now,Action action)throws GeneralSecurityException,IOException,InterruptedException{
        need(now>0);FileChannel channel;boolean created;
        try{channel=FileChannel.open(path,StandardOpenOption.CREATE_NEW,StandardOpenOption.READ,StandardOpenOption.WRITE,LinkOption.NOFOLLOW_LINKS);created=true;}
        catch(FileAlreadyExistsException exists){channel=FileChannel.open(path,StandardOpenOption.READ,StandardOpenOption.WRITE,LinkOption.NOFOLLOW_LINKS);created=false;}
        try(var file=channel){FileLock acquired=null;for(int attempt=0;attempt<100 && acquired==null;attempt++){try{acquired=file.tryLock();}catch(OverlappingFileLockException busy){/* another local caller */}if(acquired==null)Thread.sleep(50);}need(acquired!=null);
            try(var lock=acquired){need(lock.isValid());if(created){byte[] initial=new byte[8];write(file,join(header,initial,sha(join(header,initial))));file.force(true);}need(file.size()>=header.length+40 && file.size()<=3000000);file.position(0);need(same(read(file,header.length),header));var clock=new Clock(file,now);
                ManifestChain.Verified current=null;long revision=0,comparison=0;
                while(file.position()<file.size()){
                    need(revision<256 && file.size()-file.position()>=56);byte[] prefix=read(file,24);var data=ByteBuffer.wrap(prefix);long next=data.getLong(),time=data.getLong();int transitionSize=data.getInt(),size=data.getInt();
                    need(next==revision+1 && time>=comparison && time<=clock.floor && (transitionSize==0 || transitionSize==343) && size>=364 && size<=9751 && file.size()-file.position()>=transitionSize+size+32);
                    byte[] transition=read(file,transitionSize),raw=read(file,size);need(same(read(file,32),sha(join(prefix,transition,raw))));current=step(raw,transitionSize==0?null:transition,current,time);revision=next;comparison=time;
                }
                return action.run(file,revision,current,clock);
            }
        }
    }
    public Snapshot accept(byte[] manifest,byte[] transition,long expectedRevision,long now)throws GeneralSecurityException,IOException,InterruptedException{
        byte[] raw=manifest.clone(),change=transition==null?null:transition.clone();return access(now,(file,revision,current,clock)->{
            need(expectedRevision==revision && revision<256);var value=step(raw,change,current,now);byte[] event=change==null?new byte[0]:change,prefix=ByteBuffer.allocate(24).putLong(revision+1).putLong(now).putInt(event.length).putInt(raw.length).array(),record=join(prefix,event,raw);
            clock.advance(now);write(file,join(record,sha(record)));file.force(true);return new Snapshot(revision+1,value);
        });
    }
    public Snapshot snapshot(long now)throws GeneralSecurityException,IOException,InterruptedException{return access(now,(file,revision,current,clock)->{var value=current==null?null:ManifestChain.continueChain(current.bytes(),current,2,now);clock.advance(now);return new Snapshot(revision,value);});}
}

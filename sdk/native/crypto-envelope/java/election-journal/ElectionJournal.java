package org.zrotext.candidate;
import java.io.*;
import java.nio.*;
import java.nio.channels.*;
import java.nio.file.*;
import java.security.*;
import java.util.*;

/** Bounded trusted-path history. Incomplete append refuses; no hostile-filesystem rollback claim. */
public final class ElectionJournal {
    public record Snapshot(long revision,ManifestChain.Verified manifest,Election03.Proof proof){}
    private record Selection(ManifestChain.Verified manifest,Election03.Proof proof){}
    /** Values must originate in independently authenticated application evidence. */
    public static final class Expectations {
        private final byte[] core,device,owner,digest;private final Map<String,Object> accepted;
        public Expectations(byte[] expectedCore,Map<String,?> acceptedRecord,byte[] devicePoint,byte[] ownerPoint)throws GeneralSecurityException{
            need(expectedCore.length==500 && devicePoint.length==65 && ownerPoint.length==65 && acceptedRecord.size()<=32);core=expectedCore.clone();device=devicePoint.clone();owner=ownerPoint.clone();HpkeRecipient.point(device);HpkeRecipient.point(owner);
            var values=new TreeMap<String,Object>();var encoded=new ArrayList<byte[]>();
            for(var entry:acceptedRecord.entrySet()){String key=entry.getKey();need(key!=null && key.matches("[A-Za-z][A-Za-z0-9]{0,63}"));byte[] name=key.getBytes(java.nio.charset.StandardCharsets.US_ASCII),value;Object item=entry.getValue();
                if(item instanceof byte[] bytes){need(bytes.length==16 || bytes.length==32);byte[] captured=bytes.clone();values.put(key,captured);value=join(new byte[]{0,(byte)captured.length},captured);}
                else{need(item instanceof Long || item instanceof Integer);long n=((Number)item).longValue();need(n>0);values.put(key,n);value=join(new byte[]{1},ByteBuffer.allocate(8).putLong(n).array());}
                encoded.add(join(new byte[]{(byte)name.length},name,value));
            }
            // Sorted framed entries make the externally supplied record binding deterministic.
            encoded.sort(Arrays::compareUnsigned);accepted=Collections.unmodifiableMap(values);digest=sha(join(core,device,owner,join(encoded.toArray(byte[][]::new))));
        }
    }
    private final Path path;private final byte[] header;private final ManifestChain.RootPin trust;private final Expectations expected;
    public ElectionJournal(Path path,byte[] pin,byte[] fingerprint,Expectations expectations)throws GeneralSecurityException{
        this.path=path.toAbsolutePath();byte[] captured=pin.clone(),compared=fingerprint.clone();trust=ManifestChain.RootPin.enroll(captured,compared);header=join(new byte[]{90,84,69,51},captured,compared);expected=expectations;
    }
    private static void need(boolean value)throws GeneralSecurityException{if(!value)throw new GeneralSecurityException("Election journal refused");}
    private static byte[] join(byte[]... values){int n=0;for(var v:values)n+=v.length;byte[] out=new byte[n];int at=0;for(var v:values){System.arraycopy(v,0,out,at,v.length);at+=v.length;}return out;}
    private static byte[] sha(byte[] b)throws GeneralSecurityException{return MessageDigest.getInstance("SHA-256").digest(b);}
    private static boolean same(byte[] a,byte[] b){return MessageDigest.isEqual(a,b);}
    private static byte[] read(FileChannel file,int size)throws IOException{ByteBuffer b=ByteBuffer.allocate(size);while(b.hasRemaining())if(file.read(b)<0)throw new EOFException("Partial root journal");return b.array();}
    private static void write(FileChannel file,byte[] value)throws IOException{ByteBuffer b=ByteBuffer.wrap(value);while(b.hasRemaining())file.write(b);}
    private Selection step(byte[] raw,byte[] election,Selection current,long now)throws GeneralSecurityException{
        need(raw.length>=364 && raw.length<=9753 && (raw[4]==2 || raw[4]==3));
        if(current==null){need(election==null && raw[4]==2);return new Selection(ManifestChain.genesis02(raw,trust,now),null);}
        if(election!=null){
            need(election.length==660 && expected!=null && current.manifest.profile()==2 && raw[4]==3 && current.proof==null && same(Arrays.copyOfRange(election,628,660),expected.digest));
            Object acceptedAt=expected.accepted.get("acceptedAtMs");need(acceptedAt instanceof Long && ((Long)acceptedAt)==now);
            var proof=Election03.verify(Arrays.copyOf(election,628),expected.core,expected.accepted,current.manifest,current.manifest.bytes(),raw,expected.device,expected.owner);return new Selection(proof.acceptedManifest(),proof);
        }
        need(raw[4]==current.manifest.profile());var value=ManifestChain.continueChain(raw,current.manifest,raw[4],now);need(current.manifest.version()<Long.MAX_VALUE && value.version()==current.manifest.version()+1);return new Selection(value,current.proof);
    }
    private final class Clock {
        private final FileChannel file;private long floor;
        private Clock(FileChannel file,long now)throws IOException,GeneralSecurityException{this.file=file;byte[] b=read(file,8);need(same(read(file,32),sha(join(header,b))));floor=ByteBuffer.wrap(b).getLong();need(floor>=0 && floor<=now);}
        private void advance(long now)throws IOException,GeneralSecurityException{need(now>=floor);if(now>floor){long at=file.position();byte[] value=ByteBuffer.allocate(8).putLong(now).array();file.position(header.length);write(file,join(value,sha(join(header,value))));file.force(true);file.position(at);floor=now;}}
    }
    @FunctionalInterface private interface Action {Snapshot run(FileChannel file,long revision,Selection current,Clock clock)throws GeneralSecurityException,IOException;}
    private Snapshot access(long now,Action action)throws GeneralSecurityException,IOException,InterruptedException{
        need(now>0);FileChannel channel;boolean created;
        try{channel=FileChannel.open(path,StandardOpenOption.CREATE_NEW,StandardOpenOption.READ,StandardOpenOption.WRITE,LinkOption.NOFOLLOW_LINKS);created=true;}
        catch(FileAlreadyExistsException exists){channel=FileChannel.open(path,StandardOpenOption.READ,StandardOpenOption.WRITE,LinkOption.NOFOLLOW_LINKS);created=false;}
        try(var file=channel){FileLock acquired=null;for(int attempt=0;attempt<100 && acquired==null;attempt++){try{acquired=file.tryLock();}catch(OverlappingFileLockException busy){/* another local caller */}if(acquired==null)Thread.sleep(50);}need(acquired!=null);
            try(var lock=acquired){need(lock.isValid());if(created){byte[] initial=new byte[8];write(file,join(header,initial,sha(join(header,initial))));file.force(true);}need(file.size()>=header.length+40 && file.size()<=3000000);file.position(0);need(same(read(file,header.length),header));var clock=new Clock(file,now);
                Selection current=null;long revision=0,comparison=0;
                while(file.position()<file.size()){
                    need(revision<256 && file.size()-file.position()>=56);byte[] prefix=read(file,24);var data=ByteBuffer.wrap(prefix);long next=data.getLong(),time=data.getLong();int transitionSize=data.getInt(),size=data.getInt();
                    need(next==revision+1 && time>=comparison && time<=clock.floor && (transitionSize==0 || transitionSize==660) && size>=364 && size<=9753 && file.size()-file.position()>=transitionSize+size+32);
                    byte[] transition=read(file,transitionSize),raw=read(file,size);need(same(read(file,32),sha(join(prefix,transition,raw))));current=step(raw,transitionSize==0?null:transition,current,time);revision=next;comparison=time;
                }
                return action.run(file,revision,current,clock);
            }
        }
    }
    public Snapshot accept(byte[] manifest,byte[] bundle,long expectedRevision,long now)throws GeneralSecurityException,IOException,InterruptedException{
        byte[] raw=manifest.clone(),change=bundle==null?null:bundle.clone();return access(now,(file,revision,current,clock)->{
            need(expectedRevision==revision && revision<256);need(change==null || change.length==628 && expected!=null);byte[] event=change==null?new byte[0]:join(change,expected.digest);var value=step(raw,change==null?null:event,current,now);byte[] prefix=ByteBuffer.allocate(24).putLong(revision+1).putLong(now).putInt(event.length).putInt(raw.length).array(),record=join(prefix,event,raw);
            clock.advance(now);write(file,join(record,sha(record)));file.force(true);return new Snapshot(revision+1,value.manifest,value.proof);
        });
    }
    public Snapshot snapshot(long now)throws GeneralSecurityException,IOException,InterruptedException{return access(now,(file,revision,current,clock)->{var value=current==null?null:ManifestChain.continueChain(current.manifest.bytes(),current.manifest,current.manifest.profile(),now);clock.advance(now);return new Snapshot(revision,value,current==null?null:current.proof);});}
}

package org.zrotext.candidate;
import com.google.gson.*;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.nio.channels.FileChannel;
import java.security.*;
import java.util.*;
import java.util.concurrent.Semaphore;
import java.util.concurrent.atomic.AtomicBoolean;
/** Test-only enrollment signing; never included in the runtime artifact inventory. */
final class ContactProtectedTest {
    private ContactProtectedTest(){}
    private static byte[] d(JsonObject f,String name){return Base64.getDecoder().decode(f.get(name).getAsString());}
    private static void set(JsonObject f,String name,byte[] bytes){f.addProperty(name,Base64.getEncoder().encodeToString(bytes));}
    private static byte[] join(byte[]... parts){int size=0;for(var b:parts)size+=b.length;byte[] out=new byte[size];int at=0;for(var b:parts){System.arraycopy(b,0,out,at,b.length);at+=b.length;}return out;}
    private static byte[] domain(String label){return (label+"\0").getBytes(StandardCharsets.US_ASCII);}
    private static byte[] sha(byte[] b)throws GeneralSecurityException{return MessageDigest.getInstance("SHA-256").digest(b);}
    private static void write(Path receipt,String alias,String state)throws Exception{
        var value=new JsonObject();value.addProperty("alias",alias);value.addProperty("state",state);
        try(var file=FileChannel.open(receipt,StandardOpenOption.CREATE,StandardOpenOption.WRITE,StandardOpenOption.TRUNCATE_EXISTING)){ByteBuffer b=ByteBuffer.wrap(value.toString().getBytes(StandardCharsets.UTF_8));while(b.hasRemaining())file.write(b);file.force(true);}
    }
    private static byte[] setup(ProtectedContactSigner key,String label,byte[] unsigned)throws Exception{
        var method=ProtectedContactSigner.class.getDeclaredMethod("signDigest",byte[].class);method.setAccessible(true);
        byte[] digest=sha(join(domain(label),ByteBuffer.allocate(4).putInt(unsigned.length).array(),unsigned));return join(unsigned,(byte[])method.invoke(key,(Object)digest));
    }
    static JsonObject run(JsonObject input,Path asset,Path receipt)throws Exception{
        return run(input,asset,receipt,false);
    }
    static JsonObject run(JsonObject input,Path asset,Path receipt,boolean mutation)throws Exception{
        JsonObject f=input.deepCopy();var parser=new ContactOrigin(asset);ProtectedContactSigner key=null,borrowed=null;String alias=null;byte[] point=null;int controls=0;
        try{
            key=ProtectedContactSigner.create(name->write(receipt,name,"pending"));alias=key.alias();point=key.publicPoint();
            byte[] rootId=sha(join(domain("ZTSE/key/v1"),new byte[]{1,1},point));byte[] pin=join(new byte[]{90,84,82,80,2},d(f,"account"),ByteBuffer.allocate(8).putLong(1).array(),point);
            set(f,"rootPin",pin);set(f,"fingerprint",sha(join(domain("ZTSE/root-pin/v2"),pin)));byte[] raw=d(f,"manifest"),first=Arrays.copyOf(raw,raw.length-64);System.arraycopy(point,0,first,85,65);
            for(int i=0;i<(first[150]&255);i++){int at=151+149*i;if(first[at]==6){System.arraycopy(rootId,0,first,at+1,32);System.arraycopy(point,0,first,at+33,65);}}
            set(f,"manifest",setup(key,"ZTSE/manifest/v2",first));byte[] next=first.clone();ByteBuffer.wrap(next,29,8).putLong(2);System.arraycopy(sha(first),0,next,53,32);set(f,"nextManifest",setup(key,"ZTSE/manifest/v2",next));
            for(String name:new String[]{"statement","nextStatement"}){raw=d(f,name);byte[] u=Arrays.copyOf(raw,raw.length-64);int at=40+Short.toUnsignedInt(ByteBuffer.wrap(u,38,2).getShort())+24;System.arraycopy(d(f,"fingerprint"),0,u,at,32);System.arraycopy(sha(name.equals("statement")?first:next),0,u,at+32,32);set(f,name,setup(key,"ZT/contact-reader/authorization/v1",u));}
            var trust=ManifestChain.RootPin.enroll(d(f,"rootPin"),d(f,"fingerprint"));var m=ManifestChain.genesis02(d(f,"manifest"),trust,10000);var successor=ManifestChain.continueChain(d(f,"nextManifest"),m,2,10000);
            var expected=new ContactField.Expected(d(f,"account"),f.get("origin").getAsString(),d(f,"fingerprint"),d(f,"contact"),d(f,"routing"),parser);JsonArray outputs=new JsonArray();ContactField.Statement selected=null;byte[] selectedUnsigned=null;
            for(String name:new String[]{"name","notes","replacement"}){
                String which=name.equals("replacement")?"nextStatement":"statement";var manifest=name.equals("replacement")?successor:m;var statement=ContactField.verifyStatement(d(f,which),manifest,d(f,"account"),f.get("origin").getAsString(),d(f,"fingerprint"),parser);
                raw=d(f,name);byte[] u=Arrays.copyOf(raw,raw.length-64);System.arraycopy(manifest.digest(),0,u,102,32);System.arraycopy(statement.digest(),0,u,134,32);System.arraycopy(rootId,0,u,214,32);
                var produced=ContactField.produceProtected(key,statement,expected,u,new AtomicBoolean());JsonObject output=new JsonObject();output.addProperty("statement",which);set(output,"bytes",produced.bytes());outputs.add(output);controls++;if(selected==null){selected=statement;selectedUnsigned=u;}
            }
            final var st=Objects.requireNonNull(selected);final byte[] u=Objects.requireNonNull(selectedUnsigned);borrowed=ProtectedContactSigner.open(alias,point);ContactField.produceProtected(borrowed,st,expected,u,new AtomicBoolean());controls++;borrowed.close();
            try{ContactField.produceProtected(borrowed,st,expected,u,new AtomicBoolean());throw new IllegalStateException("Closed signer accepted");}catch(GeneralSecurityException expectedFailure){controls++;}
            final var held=key;
            var admissionField=ContactField.class.getDeclaredField("ADMISSION");admissionField.setAccessible(true);Semaphore admission=(Semaphore)admissionField.get(null);
            AtomicBoolean[] cancelled=new AtomicBoolean[4],refused=new AtomicBoolean[4];Thread[] callers=new Thread[4];
            synchronized(held){
                for(int i=0;i<4;i++){final int at=i;cancelled[i]=new AtomicBoolean();refused[i]=new AtomicBoolean();callers[i]=new Thread(()->{try{ContactField.produceProtected(held,st,expected,u,cancelled[at]);}catch(GeneralSecurityException failure){refused[at].set(true);}});callers[i].start();}
                long admitted=System.nanoTime()+2_000_000_000L;while(admission.availablePermits()!=0 && System.nanoTime()<admitted)Thread.sleep(10);
                if(admission.availablePermits()!=0)throw new IllegalStateException("Four workers not admitted");
                Thread.sleep(200);for(var cancel:cancelled)cancel.set(true);
                for(int i=0;i<4;i++){callers[i].join(1000);if(callers[i].isAlive() || !refused[i].get())throw new IllegalStateException("Provider wait defeated cancellation");}
                if(admission.availablePermits()!=0)throw new IllegalStateException("Unsettled workers released admission");
                try{ContactField.produceProtected(held,st,expected,u,new AtomicBoolean());throw new IllegalStateException("Fifth worker admitted");}catch(GeneralSecurityException expectedFailure){controls++;}
            }
            long end=System.nanoTime()+2_000_000_000L;while(admission.availablePermits()!=4 && System.nanoTime()<end)Thread.sleep(10);if(admission.availablePermits()!=4)throw new IllegalStateException("Worker admission leaked");controls++;
            AtomicBoolean timedOut=new AtomicBoolean();long began=System.nanoTime();
            synchronized(held){Thread caller=new Thread(()->{try{ContactField.produceProtected(held,st,expected,u,new AtomicBoolean());}catch(GeneralSecurityException failure){timedOut.set(true);}});caller.start();caller.join(12000);double seconds=(System.nanoTime()-began)/1_000_000_000.0;if(caller.isAlive() || !timedOut.get() || seconds<9.5 || seconds>12 || admission.availablePermits()!=3)throw new IllegalStateException("Provider deadline/retained admission failed");}
            end=System.nanoTime()+2_000_000_000L;while(admission.availablePermits()!=4 && System.nanoTime()<end)Thread.sleep(10);if(admission.availablePermits()!=4)throw new IllegalStateException("Timed out worker did not settle");controls++;
            JsonObject result=new JsonObject();result.add("fixture",f);result.add("outputs",outputs);result.addProperty("controls",controls);if(mutation)result.add("mutation",ContactMutationProtectedTest.run(key,f,outputs,parser));return result;
        }finally{
            if(borrowed!=null)borrowed.close();if(key!=null){key.deleteCreated();if(point!=null){try(var reopened=ProtectedContactSigner.open(alias,point)){reopened.publicPoint();throw new IllegalStateException("Deleted key reopened");}catch(GeneralSecurityException expectedFailure){/* expected */}}write(receipt,alias,"owned_key_deleted");}
        }
    }
}

package org.zrotext.candidate;

import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicBoolean;

/** Historical signed integrity only; tokens confer no current permission or decryption authority. */
public final class ContactField {
    private ContactField(){}
    private static final BigInteger ORDER=new BigInteger("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551",16);
    private static final Semaphore ADMISSION=new Semaphore(4);
    private static final ExecutorService WORKERS=Executors.newFixedThreadPool(4,r->{Thread t=new Thread(r,"contact-field");t.setDaemon(true);return t;});
    static void need(boolean value)throws GeneralSecurityException{if(!value)throw new GeneralSecurityException("Contact historical integrity refused");}
    private static byte[] part(byte[] b,int at,int count){return Arrays.copyOfRange(b,at,at+count);}
    private static boolean same(byte[] a,byte[] b){return MessageDigest.isEqual(a,b);}
    private static boolean zero(byte[] b){for(byte v:b)if(v!=0)return false;return true;}
    private static byte[] fixed(byte[] b,int n)throws GeneralSecurityException{need(b!=null && b.length==n && !zero(b));return b.clone();}
    private static long number(byte[] b,int at)throws GeneralSecurityException{long v=ByteBuffer.wrap(b,at,8).getLong();need(v>0);return v;}
    private static byte[] domain(String s){return (s+"\0").getBytes(StandardCharsets.US_ASCII);}
    private static byte[] join(byte[]... values){int size=0;for(byte[] b:values)size+=b.length;byte[] out=new byte[size];int at=0;for(byte[] b:values){System.arraycopy(b,0,out,at,b.length);at+=b.length;}return out;}
    private static byte[] sha(byte[] b)throws GeneralSecurityException{return MessageDigest.getInstance("SHA-256").digest(b);}
    private static void signature(byte[] point,byte[] raw,String label,byte[] unsigned)throws GeneralSecurityException{
        need(raw.length==64);BigInteger r=new BigInteger(1,part(raw,0,32)),s=new BigInteger(1,part(raw,32,32));need(r.signum()>0 && r.compareTo(ORDER)<0 && s.signum()>0 && s.compareTo(ORDER.shiftRight(1))<=0);
        Signature v=Signature.getInstance("SHA256withECDSAinP1363Format");v.initVerify(HpkeRecipient.point(point));v.update(join(domain(label),ByteBuffer.allocate(4).putInt(unsigned.length).array(),unsigned));need(v.verify(raw));
    }
    public static final class Statement {
        private final byte[] bytes,account,fingerprint,manifest,reader,point,root,writer,digest;
        private final String origin;private final long version,readerGeneration;
        private Statement(byte[] bytes,byte[] account,byte[] fingerprint,byte[] manifest,byte[] reader,byte[] point,byte[] root,byte[] writer,String origin,long version,long generation)throws GeneralSecurityException{
            this.bytes=bytes.clone();this.account=account.clone();this.fingerprint=fingerprint.clone();this.manifest=manifest.clone();this.reader=reader.clone();this.point=point.clone();this.root=root.clone();this.writer=writer.clone();this.origin=origin;this.version=version;readerGeneration=generation;digest=sha(bytes);
        }
        public byte[] bytes(){return bytes.clone();}public byte[] digest(){return digest.clone();}
    }
    public static Statement verifyStatement(byte[] input,ManifestChain.Verified accepted,byte[] expectedAccount,String expectedOrigin,byte[] expectedFingerprint,ContactOrigin parser)throws GeneralSecurityException{
        need(input!=null && input.length>=314 && input.length<=817 && accepted!=null && accepted.profile()==2 && accepted.generation()==1);
        byte[] b=input.clone(),account=fixed(expectedAccount,16),fingerprint=fixed(expectedFingerprint,32);need(parser!=null && parser.accepts(expectedOrigin));
        need(same(part(b,0,6),new byte[]{90,84,75,65,1,3}));int n=Short.toUnsignedInt(ByteBuffer.wrap(b,38,2).getShort());need(n>=9 && n<=512 && b.length==305+n);
        String origin=new String(b,40,n,StandardCharsets.US_ASCII);need(parser.accepts(origin) && same(origin.getBytes(StandardCharsets.US_ASCII),part(b,40,n)) && origin.equals(expectedOrigin));
        int at=40+n;need(number(b,at)==1);long version=number(b,at+8),generation=number(b,at+16);at+=24;
        byte[] fp=fixed(part(b,at,32),32),md=fixed(part(b,at+32,32),32),reader=fixed(part(b,at+64,32),32),point=fixed(part(b,at+96,65),65);at+=161;
        long issued=number(b,at),until=number(b,at+8);need(until>issued && until-issued<=86400000);fixed(part(b,6,16),16);fixed(part(b,22,16),16);HpkeRecipient.point(point);
        need(same(reader,sha(join(domain("ZTSE/key/v1"),new byte[]{0,16},point))) && same(part(b,22,16),account) && same(accepted.account(),account) && version==accepted.version() && same(md,accepted.digest()) && issued>=accepted.issuedMs() && until<=accepted.expiresMs());
        byte[] selected=null,rootRecord=null;for(byte[] k:accepted.keyRecords())if(k[148]==1 && ByteBuffer.wrap(k,132,8).getLong()<=issued && issued<ByteBuffer.wrap(k,140,8).getLong()){
            if(k[0]==2 && same(part(k,1,32),reader))selected=k;if(k[0]==6)rootRecord=k;
        }
        need(selected!=null && rootRecord!=null && Short.toUnsignedInt(ByteBuffer.wrap(selected,130,2).getShort())==12 && ByteBuffer.wrap(rootRecord,130,2).getShort()==0 && same(part(selected,33,65),point) && until<=ByteBuffer.wrap(selected,140,8).getLong() && until<=ByteBuffer.wrap(rootRecord,140,8).getLong());
        byte[] root=part(rootRecord,33,65),pin=join(new byte[]{90,84,82,80,2},account,ByteBuffer.allocate(8).putLong(1).array(),root);
        need(same(fp,fingerprint) && same(fingerprint,sha(join(domain("ZTSE/root-pin/v2"),pin))));signature(root,part(b,b.length-64,64),"ZT/contact-reader/authorization/v1",part(b,0,b.length-64));
        return new Statement(b,account,fp,md,reader,point,root,part(rootRecord,1,32),origin,version,generation);
    }
    public static final class Verified {
        private final byte[] bytes,digest;
        private Verified(byte[] b)throws GeneralSecurityException{bytes=b.clone();digest=sha(b);}
        public byte[] bytes(){return bytes.clone();}public byte[] digest(){return digest.clone();}
    }
    public static final class Expected {
        private final byte[] account,fingerprint,contact,routing;private final String origin;
        public Expected(byte[] account,String origin,byte[] fingerprint,byte[] contact,byte[] routing,ContactOrigin parser)throws GeneralSecurityException{
            this.account=fixed(account,16);this.fingerprint=fixed(fingerprint,32);this.contact=fixed(contact,16);this.routing=fixed(routing,32);need(parser!=null && parser.accepts(origin));this.origin=origin;
        }
    }
    private static void bound(byte[] u,Statement s,Expected e)throws GeneralSecurityException{
        need(s!=null && e!=null && same(s.account,e.account) && same(s.fingerprint,e.fingerprint) && s.origin.equals(e.origin));
        need(same(part(u,6,16),s.account) && same(part(u,22,16),e.contact) && same(part(u,166,32),e.routing) && number(u,54)==s.version && number(u,62)==s.readerGeneration && same(part(u,70,32),s.reader) && same(part(u,102,32),s.manifest) && same(part(u,134,32),s.digest) && same(part(u,214,32),s.writer));
    }
    @FunctionalInterface interface Check {void run()throws GeneralSecurityException;}
    @FunctionalInterface private interface Signer {byte[] sign(byte[] unsigned,Check live)throws GeneralSecurityException;}
    /** Explicit software capability, not protected custody. Exact native output verifies against the enrolled root. */
    public static Verified produceSoftware(KeyPair pair,Statement statement,Expected expected,byte[] input,AtomicBoolean cancelled)throws GeneralSecurityException{
        Objects.requireNonNull(pair);return produce(statement,expected,input,cancelled,softwareSigner(pair,statement,"ZT/contact-field/commitment/v1"));
    }
    private static Signer softwareSigner(KeyPair pair,Statement statement,String label){return (u,live)->{need(same(pair.getPublic().getEncoded(),HpkeRecipient.point(statement.root).getEncoded()));Signature proof=Signature.getInstance("SHA256withECDSAinP1363Format");live.run();proof.initSign(pair.getPrivate());byte[] challenge=domain("ZROtext/software-contact-key-binding/v1");proof.update(challenge);byte[] binding=proof.sign();live.run();proof.initVerify(HpkeRecipient.point(statement.root));proof.update(challenge);need(proof.verify(binding));PrivateKey key=pair.getPrivate();byte[] transcript=join(domain(label),ByteBuffer.allocate(4).putInt(u.length).array(),u);try{Signature sign=Signature.getInstance("SHA256withECDSAinP1363Format");live.run();sign.initSign(key);sign.update(transcript);byte[] raw=sign.sign();need(raw.length==64);BigInteger s=new BigInteger(1,part(raw,32,32));if(s.compareTo(ORDER.shiftRight(1))>0){byte[] low=ORDER.subtract(s).toByteArray();Arrays.fill(raw,32,64,(byte)0);int count=Math.min(32,low.length);System.arraycopy(low,low.length-count,raw,64-count,count);}return raw;}finally{Arrays.fill(transcript,(byte)0);}};}

    public static Verified produceProtected(ProtectedContactSigner key,Statement statement,Expected expected,byte[] input,AtomicBoolean cancelled)throws GeneralSecurityException{
        need(key!=null && statement!=null);return produce(statement,expected,input,cancelled,(u,live)->{need(same(key.publicPoint(),statement.root));live.run();return key.signField(u,live);});
    }
    @FunctionalInterface private interface Result<T>{T verify(byte[] signed)throws GeneralSecurityException;}
    private static Verified produce(Statement statement,Expected expected,byte[] input,AtomicBoolean cancelled,Signer signer)throws GeneralSecurityException{
        byte[] captured=unsigned(input);try{bound(captured,statement,expected);}catch(GeneralSecurityException|RuntimeException e){Arrays.fill(captured,(byte)0);throw e;}
        return execute(captured,cancelled,signed->verify(signed,statement,expected.contact,expected.routing),signer);
    }
    private static <T> T execute(byte[] input,AtomicBoolean cancelled,Result<T> verifier,Signer signer)throws GeneralSecurityException{
        byte[] captured=input;boolean transferred=false;
        try{need(cancelled!=null && !cancelled.get() && ADMISSION.tryAcquire());
            long deadline=System.nanoTime()+TimeUnit.SECONDS.toNanos(10);Future<T> future;
            try{future=WORKERS.submit(()->{byte[] signature=null,signed=null;try{need(!cancelled.get() && System.nanoTime()<deadline);signature=signer.sign(captured,()->need(!cancelled.get() && System.nanoTime()<deadline));need(!cancelled.get() && System.nanoTime()<deadline);signed=join(captured,signature);T result=verifier.verify(signed);need(!cancelled.get() && System.nanoTime()<deadline);return result;}finally{Arrays.fill(captured,(byte)0);if(signature!=null)Arrays.fill(signature,(byte)0);if(signed!=null)Arrays.fill(signed,(byte)0);ADMISSION.release();}});transferred=true;}
            catch(RuntimeException failure){ADMISSION.release();throw failure;}
            for(;;){need(!cancelled.get() && System.nanoTime()<deadline);try{T result=future.get(10,TimeUnit.MILLISECONDS);need(!cancelled.get() && System.nanoTime()<deadline);return result;}catch(TimeoutException retry){/* No retry of signing; wait only. */}catch(InterruptedException interrupted){Thread.currentThread().interrupt();throw new GeneralSecurityException("Contact producer interrupted");}catch(ExecutionException failure){throw new GeneralSecurityException("Contact producer refused",failure.getCause());}}
        }finally{if(!transferred)Arrays.fill(captured,(byte)0);}
    }
    /** Signed historical mutation and genuine retained-field transition capability. */
    public static final class Mutation {
        private Mutation(){}
        private static long n(byte[] b,int at){return ByteBuffer.wrap(b,at,8).getLong();}
        static byte[] unsigned(byte[] input)throws GeneralSecurityException{
            need(input!=null && input.length==304);byte[] b=input.clone();need(same(part(b,0,5),new byte[]{90,84,67,77,1}));
            for(int at:new int[]{6,22,54})fixed(part(b,at,16),16);for(int at:new int[]{118,150,182})fixed(part(b,at,32),32);
            for(int at:new int[]{38,46,102,110,214})need(n(b,at)>=0);need(n(b,46)>0 && n(b,102)==1 && n(b,110)>0);
            if(b[5]==1 || b[5]==3){need(n(b,38)==0 && n(b,46)==1 && zero(part(b,70,32)));need(b[5]==1?n(b,214)==0:n(b,214)>0);}
            else{need(b[5]==2 && n(b,38)>0 && n(b,38)<Long.MAX_VALUE && n(b,46)==n(b,38)+1 && !zero(part(b,70,32)) && n(b,214)==0);}
            for(int at:new int[]{222,263}){long revision=n(b,at+1);need(revision>=0 && revision<=n(b,46));need(b[at]==0?revision==0 && zero(part(b,at+9,32)):b[at]==1 && revision>0 && !zero(part(b,at+9,32)));}return b;
        }
        private static void expected(Statement s,Expected e)throws GeneralSecurityException{need(s!=null && e!=null && same(s.account,e.account) && same(s.fingerprint,e.fingerprint) && s.origin.equals(e.origin));}
        private static void bound(byte[] b,Statement s,Expected e,long legacy)throws GeneralSecurityException{
            expected(s,e);need(legacy>=0 && n(b,214)==legacy && same(part(b,6,16),e.account) && same(part(b,22,16),e.contact) && same(part(b,182,32),e.routing) && n(b,110)==s.version && same(part(b,118,32),s.manifest) && same(part(b,150,32),s.digest));
        }
        public static final class Verified {
            private final byte[] bytes,digest;private final Statement statement;
            private Verified(byte[] b,Statement s)throws GeneralSecurityException{bytes=b.clone();digest=sha(b);statement=s;}
            public byte[] bytes(){return bytes.clone();}public byte[] digest(){return digest.clone();}public Statement statement(){return statement;}
        }
        public static final class Transition {
            private final Verified mutation;private final ContactField.Verified[] fields;
            private Transition(Verified m,ContactField.Verified[] f){mutation=m;fields=f.clone();}
            public Verified mutation(){return mutation;}public ContactField.Verified field(int kind)throws GeneralSecurityException{need(kind==1 || kind==2);return fields[kind-1];}
        }
        public static Verified verify(byte[] input,Statement statement,Expected e,long legacy)throws GeneralSecurityException{
            need(input!=null && input.length==368);byte[] b=input.clone(),u=unsigned(part(b,0,304));bound(u,statement,e,legacy);signature(statement.root,part(b,304,64),"ZT/contact-field/mutation/v1",u);return new Verified(b,statement);
        }
        private static ContactField.Verified[] fields(Transition previous,byte[] b,Statement s,List<ContactField.Verified> replacements)throws GeneralSecurityException{
            need(replacements!=null && replacements.size()<=2);ContactField.Verified[] supplied=new ContactField.Verified[2],out=new ContactField.Verified[2];
            for(ContactField.Verified f:replacements){need(f!=null);int kind=f.bytes[5];need((kind==1 || kind==2) && supplied[kind-1]==null);supplied[kind-1]=f;}
            if(previous!=null){Verified p=previous.mutation;Statement ps=p.statement;
                need(b[5]==2 && n(b,38)==n(p.bytes,46) && same(part(b,70,32),p.digest) && same(part(b,6,32),part(p.bytes,6,32)) && same(part(b,182,32),part(p.bytes,182,32)));
                need(s.origin.equals(ps.origin) && same(s.fingerprint,ps.fingerprint) && s.version>=ps.version && (s.version!=ps.version || same(s.manifest,ps.manifest)));
                need(s.readerGeneration>=ps.readerGeneration && (s.readerGeneration!=ps.readerGeneration || same(s.reader,ps.reader) && same(s.point,ps.point)));
            }else need(b[5]!=2);
            int used=0;for(int i=0;i<2;i++){int at=222+i*41;if(b[at]==0)continue;
                if(n(b,at+1)==n(b,46)){ContactField.Verified f=supplied[i];need(f!=null);byte[] v=f.bytes;
                    need(same(f.digest,part(b,at+9,32)) && n(v,38)==n(b,46) && same(part(v,198,16),part(b,54,16)) && same(part(v,6,32),part(b,6,32)) && n(v,46)==1);
                    need(n(v,54)==s.version && n(v,62)==s.readerGeneration && same(part(v,70,32),s.reader) && same(part(v,102,32),s.manifest) && same(part(v,134,32),s.digest) && same(part(v,166,32),part(b,182,32)) && same(part(v,214,32),s.writer));out[i]=f;used++;
                }else{need(previous!=null && same(part(b,at,41),part(previous.mutation.bytes,at,41)) && previous.fields[i]!=null);out[i]=previous.fields[i];}
            }need(used==replacements.size());return out;
        }
        public static Transition transition(Transition previous,Verified mutation,List<ContactField.Verified> replacements)throws GeneralSecurityException{need(mutation!=null);return new Transition(mutation,fields(previous,mutation.bytes,mutation.statement,replacements));}
        private static Transition produce(Statement s,Expected e,byte[] input,long legacy,Transition previous,Statement previousStatement,List<ContactField.Verified> replacements,AtomicBoolean cancelled,Signer signer)throws GeneralSecurityException{
            byte[] captured=unsigned(input);List<ContactField.Verified> owned;
            try{owned=List.copyOf(replacements);bound(captured,s,e,legacy);if(previous!=null){expected(previousStatement,e);need(same(previous.mutation.statement.bytes,previousStatement.bytes));}else need(previousStatement==null);fields(previous,captured,s,owned);}
            catch(GeneralSecurityException|RuntimeException failure){Arrays.fill(captured,(byte)0);throw failure;}
            return execute(captured,cancelled,signed->transition(previous,verify(signed,s,e,legacy),owned),signer);
        }
        public static Transition produceSoftware(KeyPair key,Statement s,Expected e,byte[] input,long legacy,Transition previous,Statement previousStatement,List<ContactField.Verified> replacements,AtomicBoolean cancelled)throws GeneralSecurityException{
            need(key!=null);return produce(s,e,input,legacy,previous,previousStatement,replacements,cancelled,softwareSigner(key,s,"ZT/contact-field/mutation/v1"));
        }
        public static Transition produceProtected(ProtectedContactSigner key,Statement s,Expected e,byte[] input,long legacy,Transition previous,Statement previousStatement,List<ContactField.Verified> replacements,AtomicBoolean cancelled)throws GeneralSecurityException{
            need(key!=null);return produce(s,e,input,legacy,previous,previousStatement,replacements,cancelled,(u,live)->{need(same(key.publicPoint(),s.root));live.run();return key.signMutation(u,live);});
        }
    }
    static byte[] unsigned(byte[] input)throws GeneralSecurityException{
        need(input!=null && input.length>=332 && input.length<=2379);byte[] b=input.clone();need(same(part(b,0,5),new byte[]{90,84,67,79,1}) && (b[5]==1 || b[5]==2));
        for(int at:new int[]{6,22,198})fixed(part(b,at,16),16);for(int at:new int[]{70,102,134,166,214})fixed(part(b,at,32),32);
        for(int at:new int[]{38,46,54,62})number(b,at);need(number(b,46)==1);HpkeRecipient.point(part(b,246,65));int n=ByteBuffer.wrap(b,311,4).getInt();need(n>=17 && n<=(b[5]==1?272:2064) && b.length==315+n);return b;
    }
    public static Verified verify(byte[] input,Statement statement,byte[] expectedContact,byte[] expectedRouting)throws GeneralSecurityException{
        need(input!=null && input.length>=396 && input.length<=2443 && statement!=null);byte[] b=input.clone(),u=unsigned(part(b,0,b.length-64));byte[] contact=fixed(expectedContact,16),routing=fixed(expectedRouting,32);
        need(same(part(u,6,16),statement.account) && same(part(u,22,16),contact) && same(part(u,166,32),routing) && number(u,54)==statement.version && number(u,62)==statement.readerGeneration && same(part(u,70,32),statement.reader) && same(part(u,102,32),statement.manifest) && same(part(u,134,32),statement.digest) && same(part(u,214,32),statement.writer));
        signature(statement.root,part(b,b.length-64,64),"ZT/contact-field/commitment/v1",u);return new Verified(b);
    }
}

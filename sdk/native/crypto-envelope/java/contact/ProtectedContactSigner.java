package org.zrotext.candidate;
import com.sun.jna.*;
import com.sun.jna.ptr.*;
import java.math.BigInteger;
import java.nio.*;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.util.*;

/** Locally qualified Windows PCP signer for historical contact fields and mutations only. */
public final class ProtectedContactSigner implements AutoCloseable {
    private static final String PROVIDER="Microsoft Platform Crypto Provider",PREFIX="zrotext-managed-java-contact-p256-";
    private static final int SILENT=0x40;
    private static final BigInteger ORDER=new BigInteger("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551",16);
    private final NativeLibrary api;
    private Pointer provider,key;private boolean qualified,created,closed;private String alias;
    @FunctionalInterface public interface PendingReceipt{void recordAndFlush(String alias)throws Exception;}
    private ProtectedContactSigner()throws GeneralSecurityException{
        need(System.getProperty("os.name").startsWith("Windows") && Native.POINTER_SIZE==8);
        var options=Map.<String,Object>of(Library.OPTION_OPEN_FLAGS,0x800);
        try{var kernel=NativeLibrary.getInstance("kernel32",options);char[] path=new char[32768];int size=kernel.getFunction("GetSystemDirectoryW").invokeInt(new Object[]{path,path.length});need(size>0 && size<path.length);api=NativeLibrary.getInstance(new String(path,0,size)+"\\ncrypt.dll",options);}
        catch(LinkageError e){throw new GeneralSecurityException("Native system library unavailable",e);}
        var out=new PointerByReference();check(call("NCryptOpenStorageProvider",out,new WString(PROVIDER),0));provider=out.getValue();
        try{need((property(provider,"Impl Type")&1)!=0);check(call("NCryptIsAlgSupported",provider,new WString("ECDSA_P256"),0));}catch(GeneralSecurityException e){close();throw e;}
    }
    private int call(String name,Object... args){return api.getFunction(name).invokeInt(args);}
    private static void need(boolean value)throws GeneralSecurityException{if(!value)throw new GeneralSecurityException("Protected signer refused");}
    private static void check(int status)throws GeneralSecurityException{if(status!=0)throw new GeneralSecurityException(String.format("Native signer refused (%08x)",status));}
    private int property(Pointer handle,String name)throws GeneralSecurityException{byte[] bytes=new byte[4];var size=new IntByReference();check(call("NCryptGetProperty",handle,new WString(name),bytes,4,size,0));need(size.getValue()==4);return ByteBuffer.wrap(bytes).order(ByteOrder.LITTLE_ENDIAN).getInt();}
    public static void probe()throws GeneralSecurityException{try(var probe=new ProtectedContactSigner()){need(probe.provider!=null);}}
    public static ProtectedContactSigner create(PendingReceipt receipt)throws Exception{
        Objects.requireNonNull(receipt);var value=new ProtectedContactSigner();
        try{value.alias=PREFIX+UUID.randomUUID();receipt.recordAndFlush(value.alias);var out=new PointerByReference();check(value.call("NCryptCreatePersistedKey",value.provider,out,new WString("ECDSA_P256"),new WString(value.alias),0,SILENT));value.key=out.getValue();value.created=true;
            check(value.call("NCryptSetProperty",value.key,new WString("Export Policy"),new byte[4],4,0));check(value.call("NCryptFinalizeKey",value.key,SILENT));value.qualify();return value;
        }catch(Exception e){try{if(value.created)value.deleteCreated();}catch(Exception cleanup){e.addSuppressed(cleanup);}finally{value.close();}throw e;}
    }
    public static ProtectedContactSigner open(String alias,byte[] expectedPublic)throws GeneralSecurityException{
        need(alias.startsWith(PREFIX));String suffix=alias.substring(PREFIX.length());try{need(UUID.fromString(suffix).toString().equals(suffix));}catch(IllegalArgumentException e){throw new GeneralSecurityException("Alias shape",e);}
        byte[] expected=expectedPublic.clone();HpkeRecipient.point(expected);var value=new ProtectedContactSigner();
        try{value.alias=alias;var out=new PointerByReference();check(value.call("NCryptOpenKey",value.provider,out,new WString(alias),0,SILENT));value.key=out.getValue();value.qualify();need(MessageDigest.isEqual(value.publicPoint(),expected));return value;}
        catch(GeneralSecurityException e){value.close();throw e;}
    }
    public synchronized String alias(){return alias;}
    private byte[] publicRaw()throws GeneralSecurityException{
        need(!closed && key!=null);byte[] blob=new byte[72];var size=new IntByReference();check(call("NCryptExportKey",key,null,new WString("ECCPUBLICBLOB"),null,blob,72,size,SILENT));
        var b=ByteBuffer.wrap(blob).order(ByteOrder.LITTLE_ENDIAN);need(size.getValue()==72 && b.getInt()==0x31534345 && b.getInt()==32);
        byte[] point=new byte[65];point[0]=4;System.arraycopy(blob,8,point,1,64);HpkeRecipient.point(point);return point;
    }
    public synchronized byte[] publicPoint()throws GeneralSecurityException{need(qualified && !closed);return publicRaw();}
    private byte[] signDigest(byte[] digest)throws GeneralSecurityException{
        need(!closed && digest.length==32);byte[] raw=new byte[64];var size=new IntByReference();check(call("NCryptSignHash",key,null,digest,32,raw,64,size,SILENT));need(size.getValue()==64);
        var r=new BigInteger(1,Arrays.copyOfRange(raw,0,32));var s=new BigInteger(1,Arrays.copyOfRange(raw,32,64));need(r.signum()>0 && r.compareTo(ORDER)<0 && s.signum()>0 && s.compareTo(ORDER)<0);
        if(s.compareTo(ORDER.shiftRight(1))>0){byte[] low=ORDER.subtract(s).toByteArray();int count=Math.min(32,low.length);Arrays.fill(raw,32,64,(byte)0);System.arraycopy(low,low.length-count,raw,64-count,count);}return raw;
    }
    private void qualify()throws GeneralSecurityException{
        need(property(key,"Export Policy")==0);int status=call("NCryptExportKey",key,null,new WString("ECCPRIVATEBLOB"),null,null,0,new IntByReference(),SILENT);need(status==0x80090010 || status==0x8009000a);
        byte[] challenge=new byte[32];new SecureRandom().nextBytes(challenge);byte[] signature=signDigest(challenge);var verifier=Signature.getInstance("NONEwithECDSAinP1363Format");verifier.initVerify(HpkeRecipient.point(publicRaw()));verifier.update(challenge);need(verifier.verify(signature));qualified=true;
    }
    synchronized byte[] signField(byte[] input,ContactField.Check live)throws GeneralSecurityException{
        return signContact(input,live,false);
    }
    synchronized byte[] signMutation(byte[] input,ContactField.Check live)throws GeneralSecurityException{
        return signContact(input,live,true);
    }
    private byte[] signContact(byte[] input,ContactField.Check live,boolean mutation)throws GeneralSecurityException{
        need(qualified && !closed);byte[] unsigned=mutation?ContactField.Mutation.unsigned(input):ContactField.unsigned(input);
        byte[] domain=(mutation?"ZT/contact-field/mutation/v1\0":"ZT/contact-field/commitment/v1\0").getBytes(StandardCharsets.US_ASCII),transcript=ByteBuffer.allocate(domain.length+4+unsigned.length).put(domain).putInt(unsigned.length).put(unsigned).array();
        try{live.run();byte[] signature=signDigest(MessageDigest.getInstance("SHA-256").digest(transcript));var verifier=Signature.getInstance("SHA256withECDSAinP1363Format");verifier.initVerify(HpkeRecipient.point(publicRaw()));verifier.update(transcript);need(verifier.verify(signature));return signature;}
        finally{Arrays.fill(unsigned,(byte)0);Arrays.fill(transcript,(byte)0);}
    }
    public synchronized void deleteCreated()throws GeneralSecurityException{need(created && !closed && key!=null);check(call("NCryptDeleteKey",key,0));key=null;created=qualified=false;close();}
    private void free(Pointer value){if(value!=null)call("NCryptFreeObject",value);}
    @Override public synchronized void close(){if(closed)return;closed=true;qualified=false;free(key);key=null;free(provider);provider=null;}
}

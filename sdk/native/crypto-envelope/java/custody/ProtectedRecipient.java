package org.zrotext.candidate;

import com.sun.jna.*;
import com.sun.jna.ptr.*;
import java.nio.*;
import java.security.*;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.util.*;
import javax.crypto.KeyAgreement;

/** Locally qualified Windows PCP recipient; no software fallback or remote attestation. */
public final class ProtectedRecipient implements HpkeRecipient.Recipient,HpkeRecipient.ContentRecipient,AutoCloseable {
    private static final String PROVIDER="Microsoft Platform Crypto Provider",PREFIX="zrotext-managed-java-p256-";
    private static final int SILENT=0x40;
    private final NativeLibrary api;
    private Pointer provider,key;
    private boolean qualified,created,closed;
    private String alias;
    @FunctionalInterface public interface PendingReceipt {void recordAndFlush(String alias)throws Exception;}
    private ProtectedRecipient()throws GeneralSecurityException{
        need(System.getProperty("os.name").startsWith("Windows") && Native.POINTER_SIZE==8);
        // Restrict both native system libraries to System32; do not trust PATH.
        var options=Map.<String,Object>of(Library.OPTION_OPEN_FLAGS,0x800);
        try{
            NativeLibrary kernel=NativeLibrary.getInstance("kernel32",options);
            char[] path=new char[32768];int size=kernel.getFunction("GetSystemDirectoryW").invokeInt(new Object[]{path,path.length});
            need(size>0 && size<path.length);api=NativeLibrary.getInstance(new String(path,0,size)+"\\ncrypt.dll",options);
        }catch(LinkageError e){throw new GeneralSecurityException("Native system library unavailable",e);}
        var out=new PointerByReference();check(call("NCryptOpenStorageProvider",out,new WString(PROVIDER),0));provider=out.getValue();
        try{need((property(provider,"Impl Type")&1)!=0);check(call("NCryptIsAlgSupported",provider,new WString("ECDH_P256"),0));}
        catch(GeneralSecurityException e){close();throw e;}
    }
    private int call(String name,Object... arguments){return api.getFunction(name).invokeInt(arguments);}
    private static void need(boolean value)throws GeneralSecurityException{if(!value)throw new GeneralSecurityException("Protected recipient refused");}
    private static void check(int status)throws GeneralSecurityException{if(status!=0)throw new GeneralSecurityException(String.format("Native custody refused (%08x)",status));}
    private int property(Pointer handle,String name)throws GeneralSecurityException{
        byte[] value=new byte[4];var size=new IntByReference();check(call("NCryptGetProperty",handle,new WString(name),value,4,size,0));need(size.getValue()==4);return ByteBuffer.wrap(value).order(ByteOrder.LITTLE_ENDIAN).getInt();
    }
    public static void probe()throws GeneralSecurityException{try(var probe=new ProtectedRecipient()){need(probe.provider!=null);}}
    public static ProtectedRecipient create(PendingReceipt receipt)throws Exception{
        Objects.requireNonNull(receipt);var value=new ProtectedRecipient();
        try{
            value.alias=PREFIX+UUID.randomUUID();receipt.recordAndFlush(value.alias);
            var out=new PointerByReference();check(value.call("NCryptCreatePersistedKey",value.provider,out,new WString("ECDH_P256"),new WString(value.alias),0,SILENT));value.key=out.getValue();value.created=true;
            check(value.call("NCryptSetProperty",value.key,new WString("Export Policy"),new byte[4],4,0));check(value.call("NCryptFinalizeKey",value.key,SILENT));value.qualify();return value;
        }catch(Exception e){try{if(value.created)value.deleteCreated();}catch(Exception cleanup){e.addSuppressed(cleanup);}finally{value.close();}throw e;}
    }
    public static ProtectedRecipient open(String alias,byte[] expectedPublic)throws GeneralSecurityException{
        need(alias.startsWith(PREFIX));String suffix=alias.substring(PREFIX.length());
        try{need(UUID.fromString(suffix).toString().equals(suffix));}catch(IllegalArgumentException e){throw new GeneralSecurityException("Alias shape",e);}
        byte[] expected=expectedPublic.clone();HpkeRecipient.point(expected);var value=new ProtectedRecipient();
        try{
            value.alias=alias;var out=new PointerByReference();check(value.call("NCryptOpenKey",value.provider,out,new WString(alias),0,SILENT));value.key=out.getValue();value.qualify();need(MessageDigest.isEqual(value.publicPoint(),expected));return value;
        }catch(GeneralSecurityException e){value.close();throw e;}
    }
    public synchronized String alias(){return alias;}
    private byte[] publicRaw()throws GeneralSecurityException{
        need(!closed && key!=null);byte[] blob=new byte[72];var size=new IntByReference();check(call("NCryptExportKey",key,null,new WString("ECCPUBLICBLOB"),null,blob,72,size,SILENT));
        var b=ByteBuffer.wrap(blob).order(ByteOrder.LITTLE_ENDIAN);need(size.getValue()==72 && b.getInt()==0x314b4345 && b.getInt()==32);
        byte[] point=new byte[65];point[0]=4;System.arraycopy(blob,8,point,1,64);HpkeRecipient.point(point);return point;
    }
    public synchronized byte[] publicPoint()throws GeneralSecurityException{need(qualified && !closed);return publicRaw();}
    private static byte[] point(ECPublicKey key){
        byte[] result=new byte[65];result[0]=4;byte[] x=key.getW().getAffineX().toByteArray(),y=key.getW().getAffineY().toByteArray();
        int nx=Math.min(x.length,32),ny=Math.min(y.length,32);System.arraycopy(x,x.length-nx,result,33-nx,nx);System.arraycopy(y,y.length-ny,result,65-ny,ny);return result;
    }
    private void qualify()throws GeneralSecurityException{
        need(property(key,"Export Policy")==0);int status=call("NCryptExportKey",key,null,new WString("ECCPRIVATEBLOB"),null,null,0,new IntByReference(),SILENT);need(status==0x80090010 || status==0x8009000a);
        byte[] publicPoint=publicRaw();var generator=KeyPairGenerator.getInstance("EC");generator.initialize(new ECGenParameterSpec("secp256r1"));var peer=generator.generateKeyPair();
        byte[] expected=null,actual=null;
        try{var agreement=KeyAgreement.getInstance("ECDH");agreement.init(peer.getPrivate());agreement.doPhase(HpkeRecipient.point(publicPoint),true);expected=agreement.generateSecret();actual=exchange(point((ECPublicKey)peer.getPublic()));need(expected.length==32 && MessageDigest.isEqual(expected,actual));qualified=true;}
        finally{if(expected!=null)Arrays.fill(expected,(byte)0);if(actual!=null)Arrays.fill(actual,(byte)0);}
    }
    private byte[] exchange(byte[] peer)throws GeneralSecurityException{
        need(!closed);HpkeRecipient.point(peer);byte[] blob=new byte[72];ByteBuffer.wrap(blob).order(ByteOrder.LITTLE_ENDIAN).putInt(0x314b4345).putInt(32);System.arraycopy(peer,1,blob,8,64);
        var imported=new PointerByReference();var agreementHandle=new PointerByReference();byte[] raw=new byte[32];boolean success=false;
        try{
            check(call("NCryptImportKey",provider,null,new WString("ECCPUBLICBLOB"),null,imported,blob,72,SILENT));check(call("NCryptSecretAgreement",key,imported.getValue(),agreementHandle,SILENT));
            var size=new IntByReference();check(call("NCryptDeriveKey",agreementHandle.getValue(),new WString("TRUNCATE"),null,raw,32,size,0));need(size.getValue()==32);
            for(int i=0;i<16;i++){byte t=raw[i];raw[i]=raw[31-i];raw[31-i]=t;}success=true;return raw;
        }finally{if(!success)Arrays.fill(raw,(byte)0);free(agreementHandle.getValue());free(imported.getValue());}
    }
    @Override public synchronized byte[] unwrap(byte[] publicPoint,byte[] enc,byte[] info,byte[] aad,byte[] ciphertext)throws GeneralSecurityException{
        need(qualified && !closed);byte[] pk=publicPoint.clone(),ephemeral=enc.clone(),context=info.clone(),authenticated=aad.clone(),encrypted=ciphertext.clone();
        need(context.length<=36864 && authenticated.length<=36864 && encrypted.length==48 && MessageDigest.isEqual(pk,publicRaw()));
        byte[] shared=exchange(ephemeral);try{return HpkeRecipient.openAgreement(shared,pk,ephemeral,context,authenticated,encrypted);}finally{Arrays.fill(shared,(byte)0);}
    }
    @Override public synchronized byte[] openContent(byte[] publicPoint,byte[] enc,byte[] info,byte[] aad,byte[] ciphertext)throws GeneralSecurityException{
        need(qualified && !closed);byte[] pk=publicPoint.clone(),ephemeral=enc.clone(),context=info.clone(),authenticated=aad.clone(),encrypted=ciphertext.clone();
        need(context.length<=36864 && authenticated.length<=36864 && encrypted.length>=17 && encrypted.length<=32784 && MessageDigest.isEqual(pk,publicRaw()));
        byte[] shared=exchange(ephemeral);try{return HpkeRecipient.openContentAgreement(shared,pk,ephemeral,context,authenticated,encrypted);}finally{Arrays.fill(shared,(byte)0);}
    }
    public synchronized void deleteCreated()throws GeneralSecurityException{need(created && !closed && key!=null);check(call("NCryptDeleteKey",key,0));key=null;created=false;qualified=false;close();}
    private void free(Pointer handle){if(handle!=null)call("NCryptFreeObject",handle);}
    @Override public synchronized void close(){if(closed)return;closed=true;qualified=false;free(key);key=null;free(provider);provider=null;}
}

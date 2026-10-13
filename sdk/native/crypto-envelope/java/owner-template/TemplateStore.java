package org.zrotext.candidate;
import java.nio.*;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.util.*;
/** Opaque request/receipt framing only. No owner credential, review ticket or send authority. */
public final class TemplateStore {
 private TemplateStore(){}
 public static final String CONTENT_TYPE="application/vnd.zrotext.workflow-template.v1";
 static void need(boolean b)throws GeneralSecurityException{if(!b)throw new GeneralSecurityException("Template contract refused");}
 static byte[] part(byte[] b,int at,int n){return Arrays.copyOfRange(b,at,at+n);}
 static long number(byte[] b,int at){return ByteBuffer.wrap(b,at,8).getLong();}
 static boolean same(byte[] a,byte[] b){return MessageDigest.isEqual(a,b);}
 static String hex(byte[] b){return HexFormat.of().formatHex(b);}
 static String uuid(byte[] b){String s=hex(b);return s.substring(0,8)+"-"+s.substring(8,12)+"-"+s.substring(12,16)+"-"+s.substring(16,20)+"-"+s.substring(20);}
 static EncryptedTemplate.Scope parse(byte[] input)throws GeneralSecurityException{
  need(input!=null && input.length>=308 && input.length<=33075 && input[222]==4 && ByteBuffer.wrap(input,287,4).getInt()==input.length-291);
  return new EncryptedTemplate.Scope(part(input,0,222));
 }
 public static final class SaveRequest {
  private final byte[] body;private final String request,digest;private final int expected;
  public SaveRequest(EncryptedTemplate.Scope scope,String requestId,int expectedRevision,byte[] envelope)throws GeneralSecurityException{
   need(requestId!=null && requestId.matches("[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}") && !requestId.replace("-", "").equals("0".repeat(32)) && expectedRevision>=0 && expectedRevision<=127);
   byte[] aad=scope.aad();need(number(aad,94)==expectedRevision+1 && envelope.length>=308 && envelope.length<=33075);byte[] copy=envelope.clone();need(same(part(copy,0,222),aad) && ByteBuffer.wrap(copy,287,4).getInt()==copy.length-291);
   body=copy;request=requestId;expected=expectedRevision;digest=hex(MessageDigest.getInstance("SHA-256").digest(copy));
  }
  public byte[] body(){return body.clone();}public String path(){return "/v1/owner/workflow/templates";}public int revision(){return expected+1;}public String encryptedDigest(){return digest;}
  public Map<String,String> headers(){return Map.of("content-type",CONTENT_TYPE,"idempotency-key",request,"x-zrotext-template-revision",Integer.toString(expected));}
  /** Exact canonical receipt acknowledges saving only, never dispatch. */
  public int receipt(byte[] wire)throws GeneralSecurityException{need(wire.length<=256 && same(wire,("{\"revision\":"+revision()+"}").getBytes(StandardCharsets.US_ASCII)));return revision();}
 }
}

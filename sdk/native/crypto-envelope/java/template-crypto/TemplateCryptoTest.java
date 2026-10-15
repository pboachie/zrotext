package org.zrotext.candidate;
import com.google.gson.*;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.*;
import java.util.*;
public final class TemplateCryptoTest {
 private TemplateCryptoTest(){}
 private static byte[] b(JsonObject p,String name){return Base64.getDecoder().decode(p.get(name).getAsString());}
 private static long n(JsonObject p,String name){return p.get(name).getAsLong();}
 private static void lengths()throws Exception {
  var generator=KeyPairGenerator.getInstance("EC");generator.initialize(new ECGenParameterSpec("secp256r1"));var key=generator.generateKeyPair();var publicKey=(java.security.interfaces.ECPublicKey)key.getPublic();
  byte[] point=new byte[65];point[0]=4;byte[] x=publicKey.getW().getAffineX().toByteArray(),y=publicKey.getW().getAffineY().toByteArray();int nx=Math.min(32,x.length),ny=Math.min(32,y.length);System.arraycopy(x,x.length-nx,point,33-nx,nx);System.arraycopy(y,y.length-ny,point,65-ny,ny);
  for(int size:new int[]{1,31,32,33,32768}){
   byte[] plain=new byte[size];Arrays.fill(plain,(byte)7);byte[] wrap=HpkeRecipient.sealContent(point,new byte[0],new byte[0],plain),enc=Arrays.copyOf(wrap,65),ct=Arrays.copyOfRange(wrap,65,wrap.length);
   if(!Arrays.equals(plain,HpkeRecipient.openContent(key.getPrivate(),point,enc,new byte[0],new byte[0],ct)))throw new AssertionError("Content boundary mismatch");
   boolean accepted=false;try{HpkeRecipient.open(key.getPrivate(),point,enc,new byte[0],new byte[0],ct);accepted=true;}catch(GeneralSecurityException expected){}
   if(accepted!=(size==32))throw new AssertionError("CEK boundary widened");
  }
  for(int size:new int[]{0,32769}){try{HpkeRecipient.sealContent(point,new byte[0],new byte[0],new byte[size]);throw new AssertionError("Content size accepted");}catch(GeneralSecurityException expected){}}
 }
 public static void run(ProtectedRecipient owner)throws Exception {
  lengths();
  var input=JsonParser.parseString(new String(System.in.readAllBytes(),StandardCharsets.UTF_8)).getAsJsonObject();var f=input.getAsJsonObject("Fixture");
  if(owner!=null && f.has("archiveScalar"))throw new AssertionError("Native scalar exposed");
  var pin=ManifestChain.RootPin.enroll(b(f,"rootPin"),b(f,"fingerprint"));var manifest=ManifestChain.genesis02(b(f,"manifest"),pin,10000);
  HpkeRecipient.ContentRecipient recipient=owner;
  if(recipient==null){var parameters=AlgorithmParameters.getInstance("EC");parameters.init(new ECGenParameterSpec("secp256r1"));recipient=HpkeRecipient.softwareContent(KeyFactory.getInstance("EC").generatePrivate(new ECPrivateKeySpec(new BigInteger(1,b(f,"archiveScalar")),parameters.getParameterSpec(ECParameterSpec.class))));}
  var results=new JsonArray();
  for(var entry:input.getAsJsonArray("Cases")){
   var c=entry.getAsJsonObject();var result=new JsonObject();result.addProperty("accepted",false);int[] calls={0};var times=c.getAsJsonArray("Clock");
   EncryptedTemplate.AuthoritySource source=()->{int at=calls[0]++;if(at>0 && c.get("FailFinal").getAsBoolean())throw new GeneralSecurityException("Synthetic revoked authority");return new EncryptedTemplate.Authority(manifest,times.get(Math.min(at,times.size()-1)).getAsLong());};
   var content=c.get("Mode").getAsString().equals("seal")?TemplateContent.parse(b(c,"Canonical")):null;
   try{
    var s=c.getAsJsonObject("Scope");var scope=EncryptedTemplate.Scope.capture(b(s,"accountId"),b(s,"deviceId"),b(s,"lineId"),b(s,"intervalId"),b(s,"templateId"),n(s,"bindingGeneration"),n(s,"revision"),n(s,"expiresMs"),n(s,"trustGeneration"),n(s,"manifestVersion"),b(s,"peerDigest"),b(s,"readerId"),b(s,"manifestDigest"));
    byte[] value=content!=null?EncryptedTemplate.seal(scope,content,source):EncryptedTemplate.open(scope,b(c,"Envelope"),recipient,source).canonical();
    result.addProperty("accepted",true);result.addProperty(content!=null?"envelope":"canonical",Base64.getEncoder().encodeToString(value));
   }catch(GeneralSecurityException expected){/* Only tested operation may refuse. */}
   result.addProperty("calls",calls[0]);results.add(result);
  }
  var output=new JsonObject();output.add("cases",results);System.out.write((output.toString()+"\n").getBytes(StandardCharsets.UTF_8));System.out.flush();
 }
}

package org.zrotext.consumer;
import org.zrotext.candidate.*;
import com.google.gson.*;
import java.nio.file.Path;
import java.security.*;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECPrivateKeySpec;
import java.math.BigInteger;
import java.util.*;
public final class ContactPackageTest {
    private ContactPackageTest(){}
    private static byte[] d(JsonObject f,String key){return Base64.getDecoder().decode(f.get(key).getAsString());}
    static PublicKey point(byte[] value)throws Exception{var parameters=AlgorithmParameters.getInstance("EC");parameters.init(new java.security.spec.ECGenParameterSpec("secp256r1"));var curve=parameters.getParameterSpec(java.security.spec.ECParameterSpec.class);return KeyFactory.getInstance("EC").generatePublic(new java.security.spec.ECPublicKeySpec(new java.security.spec.ECPoint(new BigInteger(1,Arrays.copyOfRange(value,1,33)),new BigInteger(1,Arrays.copyOfRange(value,33,65))),curve));}
    public static void main(String[] args)throws Exception{
        if(args.length>1 && args[1].equals("--probe")){try{ProtectedContactSigner.probe();}catch(GeneralSecurityException unavailable){System.exit(77);}return;}
        Session session=args.length>1 && args[1].equals("--hardware")?new Session(Path.of(args[2])):null;
        try{
        JsonElement input=JsonParser.parseString(new String(System.in.readAllBytes(),java.nio.charset.StandardCharsets.UTF_8));

        var parser=new ContactOrigin(Path.of(args[0]));JsonArray requests=input.getAsJsonArray(),results=new JsonArray();
        for(JsonElement element:requests){JsonObject result=new JsonObject();try{JsonObject request=element.getAsJsonObject();String operation=request.get("operation").getAsString();
            if(operation.equals("origin")){result.addProperty("accepted",parser.accepts(request.get("origin").getAsString()));results.add(result);continue;}
            JsonObject f=request.getAsJsonObject("fixture");String which=request.has("statement")?request.get("statement").getAsString():"statement";
            var pin=ManifestChain.RootPin.enroll(d(f,"rootPin"),d(f,"fingerprint"));var manifest=ManifestChain.genesis02(d(f,"manifest"),pin,10000);if(which.equals("nextStatement"))manifest=ManifestChain.continueChain(d(f,"nextManifest"),manifest,2,10000);
            var statement=ContactField.verifyStatement(d(f,which),manifest,d(f,"account"),f.get("origin").getAsString(),d(f,"fingerprint"),parser);
            if(operation.equals("statement")){result.addProperty("accepted",true);results.add(result);continue;}
            String field=request.has("field")?request.get("field").getAsString():"name";byte[] raw=d(f,field);ContactField.Verified verified;
            if(operation.equals("verify"))verified=ContactField.verify(raw,statement,d(f,"contact"),d(f,"routing"));
            else if(operation.equals("produce")){
                if(session!=null){verified=session.produce(f,statement,manifest,raw,request,parser);}
                else{
                byte[] scalar=request.has("scalar")?d(request,"scalar"):new byte[32];if(!request.has("scalar"))scalar[31]=7;
                ECPublicKey point=(ECPublicKey)point(manifest.rootPoint());PrivateKey key=KeyFactory.getInstance("EC").generatePrivate(new ECPrivateKeySpec(new BigInteger(1,scalar),point.getParams()));
                var expected=new ContactField.Expected(d(f,"account"),f.get("origin").getAsString(),d(f,"fingerprint"),d(f,"contact"),d(f,"routing"),parser);
                verified=ContactField.produceSoftware(new KeyPair(point,key),statement,expected,Arrays.copyOf(raw,raw.length-64),new java.util.concurrent.atomic.AtomicBoolean(request.has("cancel") && request.get("cancel").getAsBoolean()));}
            }else throw new IllegalArgumentException("Unknown probe mode");
            result.addProperty("accepted",true);result.addProperty("bytes",Base64.getEncoder().encodeToString(verified.bytes()));
        }catch(Exception error){result=new JsonObject();result.addProperty("accepted",false);}results.add(result);}
        if(session!=null && requests.size()>6 && requests.get(6).getAsJsonObject().get("operation").getAsString().equals("mutation-chain")){var last=new JsonObject();last.addProperty("accepted",true);last.add("value",ContactMutationPackageTest.run(session.key,requests.get(6).getAsJsonObject().getAsJsonObject("fixture"),results,parser));results.set(6,last);}
        System.out.println(results);
        }finally{if(session!=null)session.close();}
    }
    private static final class Session implements AutoCloseable{
        private ProtectedContactSigner key;private final Path receipt;private byte[] point;private String alias;
        private void record(String state)throws java.io.IOException{try(var file=java.nio.channels.FileChannel.open(receipt,java.nio.file.StandardOpenOption.CREATE,java.nio.file.StandardOpenOption.WRITE,java.nio.file.StandardOpenOption.TRUNCATE_EXISTING)){var b=java.nio.ByteBuffer.wrap(("{\"alias\":\""+alias+"\",\"state\":\""+state+"\"}").getBytes(java.nio.charset.StandardCharsets.UTF_8));while(b.hasRemaining())file.write(b);file.force(true);}}
        Session(Path receipt)throws Exception{this.receipt=receipt;try{key=ProtectedContactSigner.create(value->{alias=value;record("pending");});point=key.publicPoint();var identity=new JsonObject();identity.addProperty("alias",alias);identity.addProperty("public",Base64.getEncoder().encodeToString(point));System.out.println(identity);System.out.flush();}catch(Exception failure){if(key!=null)close();throw failure;}}
        ContactField.Verified produce(JsonObject f,ContactField.Statement statement,ManifestChain.Verified manifest,byte[] raw,JsonObject request,ContactOrigin parser)throws Exception{
            byte[] unsigned=Arrays.copyOf(raw,raw.length-64);System.arraycopy(manifest.digest(),0,unsigned,102,32);System.arraycopy(statement.digest(),0,unsigned,134,32);
            var hash=MessageDigest.getInstance("SHA-256");hash.update("ZTSE/key/v1\0".getBytes(java.nio.charset.StandardCharsets.US_ASCII));hash.update(new byte[]{1,1});System.arraycopy(hash.digest(point),0,unsigned,214,32);
            var expected=new ContactField.Expected(d(f,"account"),f.get("origin").getAsString(),d(f,"fingerprint"),d(f,"contact"),d(f,"routing"),parser);
            var borrowed=ProtectedContactSigner.open(alias,point);try{
                boolean refused=false;try{borrowed.deleteCreated();}catch(GeneralSecurityException failure){refused=true;}if(!refused)throw new IllegalStateException("Borrowed deletion accepted");
                if(request.has("closed") && request.get("closed").getAsBoolean())borrowed.close();
                return ContactField.produceProtected(borrowed,statement,expected,unsigned,new java.util.concurrent.atomic.AtomicBoolean(request.has("cancel") && request.get("cancel").getAsBoolean()));
            }finally{borrowed.close();}
        }
        public void close()throws GeneralSecurityException,java.io.IOException{key.deleteCreated();if(point!=null){boolean refused=false;try(var reopened=ProtectedContactSigner.open(alias,point)){reopened.publicPoint();}catch(GeneralSecurityException failure){refused=true;}if(!refused)throw new IllegalStateException("Deleted key reopened");}record("owned_key_deleted");System.out.println("{\"owned_key_deleted\":true}");System.out.flush();}
    }
}

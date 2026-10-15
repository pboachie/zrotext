package org.zrotext.candidate;
import com.google.gson.*;
import java.nio.file.Path;
import java.security.*;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECPrivateKeySpec;
import java.math.BigInteger;
import java.util.*;
public final class ContactTest {
    private ContactTest(){}
    private static byte[] d(JsonObject f,String key){return Base64.getDecoder().decode(f.get(key).getAsString());}
    public static void main(String[] args)throws Exception{
        JsonElement input=JsonParser.parseString(new String(System.in.readAllBytes(),java.nio.charset.StandardCharsets.UTF_8));
        if(args.length>1 && args[1].equals("--hardware")){System.out.println(ContactProtectedTest.run(input.getAsJsonObject(),Path.of(args[0]),Path.of(args[2])));return;}
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
                byte[] scalar=request.has("scalar")?d(request,"scalar"):new byte[32];if(!request.has("scalar"))scalar[31]=7;
                ECPublicKey point=(ECPublicKey)HpkeRecipient.point(manifest.rootPoint());PrivateKey key=KeyFactory.getInstance("EC").generatePrivate(new ECPrivateKeySpec(new BigInteger(1,scalar),point.getParams()));
                var expected=new ContactField.Expected(d(f,"account"),f.get("origin").getAsString(),d(f,"fingerprint"),d(f,"contact"),d(f,"routing"),parser);
                verified=ContactField.produceSoftware(new KeyPair(point,key),statement,expected,Arrays.copyOf(raw,raw.length-64),new java.util.concurrent.atomic.AtomicBoolean(request.has("cancel") && request.get("cancel").getAsBoolean()));
            }else throw new IllegalArgumentException("Unknown probe mode");
            result.addProperty("accepted",true);result.addProperty("bytes",Base64.getEncoder().encodeToString(verified.bytes()));
        }catch(Exception error){result=new JsonObject();result.addProperty("accepted",false);}results.add(result);}
        System.out.println(results);
    }
}

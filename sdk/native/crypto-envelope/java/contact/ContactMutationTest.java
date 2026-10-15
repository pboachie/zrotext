package org.zrotext.candidate;
import com.google.gson.*;
import java.nio.file.Path;
import java.security.*;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECPrivateKeySpec;
import java.math.BigInteger;
import java.util.*;
import java.util.concurrent.atomic.AtomicBoolean;
public final class ContactMutationTest {
    private ContactMutationTest(){}
    private static byte[] d(JsonObject f,String key){return Base64.getDecoder().decode(f.get(key).getAsString());}
    private static String option(JsonObject r,String key,String fallback){return r.has(key) && !r.get(key).isJsonNull()?r.get(key).getAsString():fallback;}
    private static long legacy(String name){return name.equals("converted")?7:0;}
    static final class Fixture {
        final JsonObject wire;final ContactField.Statement first,next;final ContactField.Expected expected;final byte[] root;
        final Map<String,ContactField.Verified> fields=new HashMap<>();
        Fixture(JsonObject f,ContactOrigin parser)throws Exception{
            wire=f;var pin=ManifestChain.RootPin.enroll(d(f,"rootPin"),d(f,"fingerprint"));var m=ManifestChain.genesis02(d(f,"manifest"),pin,10000);var n=ManifestChain.continueChain(d(f,"nextManifest"),m,2,10000);root=m.rootPoint();
            first=ContactField.verifyStatement(d(f,"statement"),m,d(f,"account"),f.get("origin").getAsString(),d(f,"fingerprint"),parser);next=ContactField.verifyStatement(d(f,"nextStatement"),n,d(f,"account"),f.get("origin").getAsString(),d(f,"fingerprint"),parser);
            expected=new ContactField.Expected(d(f,"account"),f.get("origin").getAsString(),d(f,"fingerprint"),d(f,"contact"),d(f,"routing"),parser);
            for(String name:List.of("name","notes","replacement"))fields.put(name,ContactField.verify(d(f,name),statement(name),d(f,"contact"),d(f,"routing")));
        }
        ContactField.Statement statement(String name){return List.of("update","clear","replacement","nextStatement").contains(name)?next:first;}
        List<ContactField.Verified> replacements(String name){return switch(name){case "create","converted"->List.of(fields.get("name"),fields.get("notes"));case "update"->List.of(fields.get("replacement"));default->List.of();};}
        ContactField.Mutation.Transition previous(String name)throws Exception{
            if(name.equals("none"))return null;if(!List.of("create","update").contains(name))throw new IllegalArgumentException("Unknown predecessor");
            var p=name.equals("update")?previous("create"):null;return ContactField.Mutation.transition(p,ContactField.Mutation.verify(d(wire,name),statement(name),expected,legacy(name)),replacements(name));
        }
        KeyPair key(byte[] scalar)throws Exception{ECPublicKey point=(ECPublicKey)HpkeRecipient.point(root);return new KeyPair(point,KeyFactory.getInstance("EC").generatePrivate(new ECPrivateKeySpec(new BigInteger(1,scalar),point.getParams())));}
    }
    public static void main(String[] args)throws Exception{
        if(args.length>1 && args[1].equals("--hardware")){JsonObject f=JsonParser.parseString(new String(System.in.readAllBytes(),java.nio.charset.StandardCharsets.UTF_8)).getAsJsonObject();System.out.println(ContactProtectedTest.run(f,Path.of(args[0]),Path.of(args[2]),true));return;}
        var parser=new ContactOrigin(Path.of(args[0]));JsonArray results=new JsonArray();
        for(JsonElement element:JsonParser.parseString(new String(System.in.readAllBytes(),java.nio.charset.StandardCharsets.UTF_8)).getAsJsonArray()){
            JsonObject out=new JsonObject();out.addProperty("accepted",false);out.addProperty("mutationVerified",false);
            try{JsonObject r=element.getAsJsonObject();Fixture x=new Fixture(r.getAsJsonObject("fixture"),parser);String op=r.get("operation").getAsString(),name=option(r,"mutation","create");byte[] scalar=new byte[32];scalar[31]=7;
                if(op.equals("produce-chain")){JsonObject generated=new JsonObject();ContactField.Mutation.Transition previous=null;ContactField.Statement ps=null;KeyPair key=x.key(scalar);
                    for(String which:List.of("create","update","clear","converted")){if(which.equals("converted")){previous=null;ps=null;}byte[] u=Arrays.copyOf(d(x.wire,which),304);if(previous!=null)System.arraycopy(previous.mutation().digest(),0,u,70,32);
                        previous=ContactField.Mutation.produceSoftware(key,x.statement(which),x.expected,u,legacy(which),previous,ps,x.replacements(which),new AtomicBoolean());ps=x.statement(which);generated.addProperty(which,Base64.getEncoder().encodeToString(previous.mutation().bytes()));}
                    out.addProperty("accepted",true);out.add("mutations",generated);results.add(out);continue;
                }
                var selected=x.statement(option(r,"statement",name));String prior=option(r,"previous",name.equals("update")?"create":name.equals("clear")?"update":"none");var previous=x.previous(prior);
                List<ContactField.Verified> fs=x.replacements(name);if(r.has("replacements")){fs=new ArrayList<>();for(JsonElement f:r.getAsJsonArray("replacements"))fs.add(x.fields.get(f.getAsString()));}
                long l=r.has("legacy")?r.get("legacy").getAsBigInteger().longValueExact():legacy(name);
                if(op.equals("produce")){var ps=previous==null?null:x.statement(prior);if(r.has("previousStatement")){String s=r.get("previousStatement").getAsString();ps=s.equals("none")?null:x.statement(s);}
                    if(r.has("scalar"))scalar=d(r,"scalar");byte[] raw=d(x.wire,name);if(raw.length!=368)throw new IllegalArgumentException("Mutation width");
                    var value=ContactField.Mutation.produceSoftware(x.key(scalar),selected,x.expected,Arrays.copyOf(raw,304),l,previous,ps,fs,new AtomicBoolean(r.has("cancel") && r.get("cancel").getAsBoolean()));out.addProperty("bytes",Base64.getEncoder().encodeToString(value.mutation().bytes()));
                }else{var m=ContactField.Mutation.verify(d(x.wire,name),selected,x.expected,l);out.addProperty("mutationVerified",true);
                    if(!op.equals("verify")){var value=ContactField.Mutation.transition(previous,m,fs);JsonObject retained=new JsonObject();for(int i=1;i<=2;i++){var f=value.field(i);if(f!=null)retained.addProperty(i==1?"name":"notes",Base64.getEncoder().encodeToString(f.bytes()));}out.add("fields",retained);}}
                out.addProperty("accepted",true);
            }catch(Exception error){/* Preserve independent mutation authentication on transition refusal. */}
            results.add(out);
        }System.out.println(results);
    }
}

package org.zrotext.candidate;
import com.google.gson.*;
import java.nio.charset.StandardCharsets;
import java.util.*;
public final class OwnerTemplateOpeningTest {
 private OwnerTemplateOpeningTest(){}
 static byte[] b(JsonObject p,String key){return Base64.getDecoder().decode(p.get(key).getAsString());}
 static long n(JsonObject p,String key,long fallback){return p.has(key)?p.get(key).getAsLong():fallback;}
 static OwnerTemplate.Binding binding(JsonObject o,boolean changed)throws Exception{byte[] device=b(o,"device");if(changed)device[0]^=1;return new OwnerTemplate.Binding(b(o,"account"),device,b(o,"line"),b(o,"interval"),b(o,"session"),n(o,"generation",0),o.get("peer").getAsString(),b(o,"phoneReader"),b(o,"archiveReader"));}
 static void run(ProtectedRecipient recipient)throws Exception{
  var p=JsonParser.parseString(new String(System.in.readAllBytes(),StandardCharsets.UTF_8)).getAsJsonObject();var f=p.getAsJsonObject("Fixture");if(recipient!=null && f.has("archiveScalar"))throw new AssertionError("Native scalar exposed");var pin=ManifestChain.RootPin.enroll(b(f,"rootPin"),b(f,"fingerprint"));var m=ManifestChain.genesis02(b(f,"manifest"),pin,10000);var binding=binding(f.getAsJsonObject("binding"),false);var other=binding(f.getAsJsonObject("binding"),true);OwnerTemplate[] supplied={null};int[] current={0},session={0};var results=new JsonArray();
  OwnerTemplate.CurrentSource source=()->{int at=++current[0];if(n(p,"ProviderCloseAt",0)==at && recipient!=null)recipient.close();if(n(p,"ClientCloseAt",0)==at && supplied[0]!=null)supplied[0].close();if(n(p,"CurrentFailAt",0)==at)throw new OwnerTemplate.Failure("synthetic");if(n(p,"CurrentSleepAt",0)==at)Thread.sleep(n(p,"SleepMS",0));String mode=p.get("Mode").getAsString();var times=p.getAsJsonArray("Now");return new OwnerTemplate.Current(mode.equals("binding")?other:binding,m,times.get(Math.min(at-1,times.size()-1)).getAsLong(),n(p,"ValidForMS",0),!mode.equals("owner-dead"),!mode.equals("consent-dead"),!mode.equals("inactive"));};
  OwnerTemplate.SessionSource credentials=()->{int at=++session[0];return new OwnerTemplate.Session(p.get(p.has("SessionOrigin")?"SessionOrigin":"Origin").getAsString(),p.get("Cookie").getAsString(),p.get("CSRF").getAsString()+(n(p,"SessionChangeAt",0)==at?"-changed":""));};
  long start=System.nanoTime();
  try(var client=new OwnerTemplate(p.get("Origin").getAsString(),binding,b(f.getAsJsonObject("scope"),"templateId"),source,credentials,p.get("Enabled").getAsBoolean(),n(p,"TimeoutMS",0),p.get("Roots").getAsString(),ignoredReview->{})){
   supplied[0]=client;
   if(p.has("SetupPending") && p.get("SetupPending").getAsBoolean()){
    byte[] wire=b(f,"envelope");var ticket=client.prepareSave(new EncryptedTemplate.Scope(Arrays.copyOf(wire,222)),"00000000-0000-0000-0000-000000000041",0,wire);
    try{client.commit(ticket);throw new AssertionError("Expected unknown");}catch(OwnerTemplate.Failure expected){if(!expected.unknown)throw expected;}current[0]=session[0]=0;
   }
   if(p.has("ClientInitiallyClosed"))supplied[0].close();
   var opening=new OwnerTemplateOpening(client,p.get("Origin").getAsString(),p.has("DedicatedMismatch")?other:binding,b(f.getAsJsonObject("scope"),"templateId"),source,credentials,p.get("Enabled").getAsBoolean(),n(p,"TimeoutMS",0),p.get("Roots").getAsString());
   byte[] scalar=recipient==null?b(f,"archiveScalar"):new byte[32];if(recipient!=null)scalar[31]=1;if(p.has("WrongKey") && p.get("WrongKey").getAsBoolean())scalar[31]^=1;
   var parameters=java.security.AlgorithmParameters.getInstance("EC");parameters.init(new java.security.spec.ECGenParameterSpec("secp256r1"));var spec=parameters.getParameterSpec(java.security.spec.ECParameterSpec.class);
   var key=java.security.KeyFactory.getInstance("EC").generatePrivate(new java.security.spec.ECPrivateKeySpec(new java.math.BigInteger(1,scalar),spec));
   byte[] publicPoint=null;for(var record:m.keyRecords())if(record[0]==2 && Arrays.equals(Arrays.copyOfRange(record,1,33),b(f.getAsJsonObject("binding"),"archiveReader")))publicPoint=Arrays.copyOfRange(record,33,98);
   for(int i=0;i<n(p,"Reads",1);i++){try{var value=recipient==null?opening.openLatestSoftware(key,publicPoint):opening.openLatest(recipient);var out=new JsonObject();out.addProperty("accepted",true);out.addProperty("digest",value.encryptedDigest());out.addProperty("ack",value.requestAcknowledged());out.addProperty("pending",value.matchesPending());out.addProperty("text",value.preview().text());out.add("segments",new Gson().toJsonTree(value.preview().estimate()));results.add(out);}catch(OwnerTemplate.Failure error){results.add(failure(error));}}
  }catch(OwnerTemplate.Failure error){for(int i=0;i<n(p,"Reads",1);i++)results.add(failure(error));}
  double elapsed=(System.nanoTime()-start)/1e9;Thread.sleep(n(p,"SettleMS",0));var output=new JsonObject();output.add("results",results);output.addProperty("elapsed",elapsed);output.addProperty("currentCalls",current[0]);output.addProperty("sessionCalls",session[0]);System.out.write((output.toString()+"\n").getBytes(StandardCharsets.UTF_8));
 }
 static JsonObject failure(OwnerTemplate.Failure e){var out=new JsonObject();out.addProperty("accepted",false);out.addProperty("code",e.code);out.addProperty("unknown",e.unknown);return out;}
}

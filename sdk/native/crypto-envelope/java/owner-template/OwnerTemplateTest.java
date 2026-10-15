package org.zrotext.candidate;
import com.google.gson.*;
import java.nio.charset.StandardCharsets;
import java.util.*;
public final class OwnerTemplateTest {
 private OwnerTemplateTest(){}
 static byte[] b(JsonObject p,String key){return Base64.getDecoder().decode(p.get(key).getAsString());}
 static long n(JsonObject p,String key,long fallback){return p.has(key)?p.get(key).getAsLong():fallback;}
 static OwnerTemplate.Binding binding(JsonObject o,boolean changed)throws Exception{byte[] device=b(o,"device");if(changed)device[0]^=1;return new OwnerTemplate.Binding(b(o,"account"),device,b(o,"line"),b(o,"interval"),b(o,"session"),n(o,"generation",0),o.get("peer").getAsString(),b(o,"phoneReader"),b(o,"archiveReader"));}
 static void store(byte[] envelope)throws Exception{
  var scope=new EncryptedTemplate.Scope(Arrays.copyOf(envelope,222));String id=UUID.randomUUID().toString();var request=new TemplateStore.SaveRequest(scope,id,0,envelope);if(request.revision()!=1 || !request.headers().get("idempotency-key").equals(id) || !Arrays.equals(request.body(),envelope) || !request.path().equals("/v1/owner/workflow/templates"))throw new AssertionError("Save framing mismatch");
  byte[] copy=request.body();copy[0]^=1;if(!Arrays.equals(request.body(),envelope))throw new AssertionError("Mutable stored request");
  if(request.receipt("{\"revision\":1}".getBytes(StandardCharsets.UTF_8))!=1)throw new AssertionError("Receipt mismatch");
  for(String invalid:List.of("{\"revision\":1} ","{\"revision\":1,\"revision\":1}","{\"revision\":2}","{\"revision\":1,\"sent\":true}","[]","{\"revision\":1.0}")){try{request.receipt(invalid.getBytes(StandardCharsets.UTF_8));throw new AssertionError("Invalid receipt accepted");}catch(java.security.GeneralSecurityException expected){}}
  for(int revision:new int[]{-1,1,128}){try{new TemplateStore.SaveRequest(scope,id,revision,envelope);throw new AssertionError("Invalid CAS accepted");}catch(java.security.GeneralSecurityException expected){}}
  try{new TemplateStore.SaveRequest(scope,"",0,envelope);throw new AssertionError("Empty identity accepted");}catch(java.security.GeneralSecurityException expected){}
 }
 public static void main(String[] ignored)throws Exception{
  var p=JsonParser.parseString(new String(System.in.readAllBytes(),StandardCharsets.UTF_8)).getAsJsonObject();var f=p.getAsJsonObject("Fixture");var pin=ManifestChain.RootPin.enroll(b(f,"rootPin"),b(f,"fingerprint"));var m=ManifestChain.genesis02(b(f,"manifest"),pin,10000);store(b(f,"envelope"));var binding=binding(f.getAsJsonObject("binding"),false);var other=binding(f.getAsJsonObject("binding"),true);int[] current={0},session={0};var results=new JsonArray();
  OwnerTemplate.CurrentSource source=()->{int at=++current[0];if(n(p,"CurrentFailAt",0)==at)throw new OwnerTemplate.Failure("synthetic");if(n(p,"CurrentSleepAt",0)==at)Thread.sleep(n(p,"SleepMS",0));String mode=p.get("Mode").getAsString();var times=p.getAsJsonArray("Now");return new OwnerTemplate.Current(mode.equals("binding")?other:binding,m,times.get(Math.min(at-1,times.size()-1)).getAsLong(),n(p,"ValidForMS",0),!mode.equals("owner-dead"),!mode.equals("consent-dead"),!mode.equals("inactive"));};
  OwnerTemplate.SessionSource credentials=()->{int at=++session[0];return new OwnerTemplate.Session(p.get(p.has("SessionOrigin")?"SessionOrigin":"Origin").getAsString(),p.get("Cookie").getAsString(),p.get("CSRF").getAsString()+(n(p,"SessionChangeAt",0)==at?"-changed":""));};
  if(p.has("Lifecycle")){OwnerTemplateLifecycleTest.run(p.get("Origin").getAsString(),binding,b(f.getAsJsonObject("scope"),"templateId"),credentials,p.get("Roots").getAsString());System.out.println("{\"lifecycle\":4}");return;}
  long start=System.nanoTime();
  try(var client=new OwnerTemplate(p.get("Origin").getAsString(),binding,b(f.getAsJsonObject("scope"),"templateId"),source,credentials,p.get("Enabled").getAsBoolean(),n(p,"TimeoutMS",0),p.get("Roots").getAsString())){
   for(int i=0;i<n(p,"Reads",1);i++){try{var value=client.readLatest();var out=new JsonObject();out.addProperty("accepted",true);out.addProperty("digest",value.encryptedDigest());out.addProperty("ack",value.requestAcknowledged());out.addProperty("pending",value.matchesPending());results.add(out);}catch(OwnerTemplate.Failure error){results.add(failure(error));}}
  }catch(OwnerTemplate.Failure error){for(int i=0;i<n(p,"Reads",1);i++)results.add(failure(error));}
  double elapsed=(System.nanoTime()-start)/1e9;Thread.sleep(n(p,"SettleMS",0));var output=new JsonObject();output.add("results",results);output.addProperty("elapsed",elapsed);output.addProperty("currentCalls",current[0]);output.addProperty("sessionCalls",session[0]);System.out.write((output.toString()+"\n").getBytes(StandardCharsets.UTF_8));
 }
 static JsonObject failure(OwnerTemplate.Failure e){var out=new JsonObject();out.addProperty("accepted",false);out.addProperty("code",e.code);out.addProperty("unknown",e.unknown);return out;}
}

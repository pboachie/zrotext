package org.zrotext.candidate;
import com.google.gson.*;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.*;
public final class OwnerTemplateSaveTest {
 private OwnerTemplateSaveTest(){}
 static byte[] b(JsonObject o,String key){return OwnerTemplateTest.b(o,key);}
 static long n(JsonObject o,String key,long fallback){return OwnerTemplateTest.n(o,key,fallback);}
 public static void main(String[] ignored)throws Exception{
  var p=JsonParser.parseString(new String(System.in.readAllBytes(),StandardCharsets.UTF_8)).getAsJsonObject();var f=p.getAsJsonObject("Fixture");var pin=ManifestChain.RootPin.enroll(b(f,"rootPin"),b(f,"fingerprint"));var manifest=ManifestChain.genesis02(b(f,"manifest"),pin,10000);var binding=OwnerTemplateTest.binding(f.getAsJsonObject("binding"),false);var other=OwnerTemplateTest.binding(f.getAsJsonObject("binding"),true);
  var currents=new AtomicInteger();var sessions=new AtomicInteger();var reviews=new AtomicInteger();var currentEntered=new CountDownLatch(1);var currentRelease=new CountDownLatch(1);var reviewEntered=new CountDownLatch(1);var reviewRelease=new CountDownLatch(1);
  var operations=p.getAsJsonArray("Ops");boolean race=false;for(var op:operations)if(op.getAsString().equals("race-prepare"))race=true;final boolean racing=race;
  OwnerTemplate.CurrentSource current=()->{int at=currents.incrementAndGet();if(n(p,"CurrentBlockAt",0)==at){currentEntered.countDown();if(!currentRelease.await(10,TimeUnit.SECONDS))throw new AssertionError("Current release missing");}if(n(p,"CurrentFailAt",0)==at)throw new OwnerTemplate.Failure("synthetic");if(n(p,"CurrentSleepAt",0)==at)Thread.sleep(n(p,"SleepMS",0));String mode=p.get("Mode").getAsString();var times=p.getAsJsonArray("Now");return new OwnerTemplate.Current(mode.equals("binding")?other:binding,manifest,times.get(Math.min(at-1,times.size()-1)).getAsLong(),n(p,"ValidForMS",0),!mode.equals("owner-dead"),!mode.equals("consent-dead"),!mode.equals("inactive"));};
  OwnerTemplate.SessionSource session=()->{int at=sessions.incrementAndGet();return new OwnerTemplate.Session(p.get(p.has("SessionOrigin")?"SessionOrigin":"Origin").getAsString(),p.get("Cookie").getAsString(),p.get("CSRF").getAsString()+(n(p,"SessionChangeAt",0)==at?"-changed":""));};
  OwnerTemplate.Reviewer review=value->{int at=reviews.incrementAndGet();if(racing && at==1){reviewEntered.countDown();if(!reviewRelease.await(10,TimeUnit.SECONDS))throw new AssertionError("Review release missing");}Thread.sleep(n(p,"ReviewSleepMS",0));if(p.has("ReviewFail") && p.get("ReviewFail").getAsBoolean())throw new Exception("Synthetic review refusal");};
  byte[] wire=p.has("Envelope")?b(p,"Envelope"):b(f,"envelope");var scope=new EncryptedTemplate.Scope(Arrays.copyOf(wire,222));String request=p.get("RequestID").getAsString();int expected=p.get("Expected").getAsInt();var results=new JsonArray();double elapsed;
  var client=new OwnerTemplate(p.get("Origin").getAsString(),binding,b(f.getAsJsonObject("scope"),"templateId"),current,session,p.get("Enabled").getAsBoolean(),n(p,"TimeoutMS",0),p.get("Roots").getAsString(),review);try{
   long start=System.nanoTime();OwnerTemplate.Ticket ticket=null;int i=0;
   for(var operation:operations){if(p.has("DelayMS") && i<p.getAsJsonArray("DelayMS").size())Thread.sleep(p.getAsJsonArray("DelayMS").get(i).getAsLong());i++;String op=operation.getAsString();var row=new JsonObject();row.addProperty("accepted",false);row.addProperty("unknown",false);row.addProperty("ack",false);row.addProperty("matches",false);
    try{switch(op){
     case "prepare" -> ticket=client.prepareSave(scope,request,expected,wire);
     case "race-prepare" -> {var first=new FutureTask<>(()->client.prepareSave(scope,request,expected,wire));new Thread(first).start();try{if(!reviewEntered.await(3,TimeUnit.SECONDS))throw new AssertionError("Review not entered");try{client.prepareSave(scope,request,expected,wire);throw new AssertionError("Concurrent prepare accepted");}catch(OwnerTemplate.Failure error){if(!error.code.equals("busy"))throw error;}}finally{reviewRelease.countDown();}ticket=first.get(5,TimeUnit.SECONDS);}
     case "close-commit" -> {var selected=ticket;var attempt=new FutureTask<OwnerTemplate.Failure>(()->{try{client.commit(selected);return null;}catch(OwnerTemplate.Failure error){return error;}});new Thread(attempt).start();try{if(!currentEntered.await(3,TimeUnit.SECONDS))throw new AssertionError("Current not entered");client.close();}finally{currentRelease.countDown();}var error=attempt.get(5,TimeUnit.SECONDS);if(error==null)throw new AssertionError("Closed commit acknowledged");throw error;}
     case "commit","retry" -> {var ack=op.equals("commit")?client.commit(ticket):client.retryUnknown(ticket);row.addProperty("ack",true);row.addProperty("digest",ack.identity().encryptedDigest());}
     case "read","verify" -> {var snapshot=op.equals("read")?client.readLatest():client.verifyUnknown(ticket);row.addProperty("matches",snapshot.matchesPending());row.addProperty("ack",snapshot.requestAcknowledged());row.addProperty("digest",snapshot.encryptedDigest());}
     case "mutate" -> wire[wire.length-1]^=1;
     case "close" -> client.close();
     default -> throw new AssertionError("Unknown operation");
    }row.addProperty("accepted",true);}catch(OwnerTemplate.Failure error){row.addProperty("unknown",error.unknown);row.addProperty("code",error.code);}
    var pending=client.pending();row.addProperty("pending",pending!=null);if(pending!=null){row.addProperty("pendingID",pending.requestId());row.addProperty("pendingDigest",pending.encryptedDigest());}results.add(row);
   }
   elapsed=(System.nanoTime()-start)/1e9;
  }finally{client.close();reviewRelease.countDown();currentRelease.countDown();}
  Thread.sleep(n(p,"SettleMS",0));var output=new JsonObject();output.add("results",results);output.addProperty("elapsed",elapsed);output.addProperty("currentCalls",currents.get());output.addProperty("sessionCalls",sessions.get());output.addProperty("reviewCalls",reviews.get());System.out.write((output.toString()+"\n").getBytes(StandardCharsets.UTF_8));
 }
}

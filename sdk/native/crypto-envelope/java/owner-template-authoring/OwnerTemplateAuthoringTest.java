package org.zrotext.candidate;
import com.google.gson.*;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.concurrent.*;
public final class OwnerTemplateAuthoringTest {
 private OwnerTemplateAuthoringTest(){}
 static byte[] b(JsonObject o,String key){return Base64.getDecoder().decode(o.get(key).getAsString());}
 static long n(JsonObject p,String key,long fallback){return p.has(key)?p.get(key).getAsLong():fallback;}
 static boolean yes(JsonObject p,String key){return p.has(key) && p.get(key).getAsBoolean();}
 public static void main(String[] args)throws Exception{
  var p=JsonParser.parseString(new String(System.in.readAllBytes(),StandardCharsets.UTF_8)).getAsJsonObject();var f=p.getAsJsonObject("Fixture");var pin=ManifestChain.RootPin.enroll(b(f,"rootPin"),b(f,"fingerprint"));var m=ManifestChain.genesis02(b(f,"manifest"),pin,10000);var o=f.getAsJsonObject("binding");var binding=new OwnerTemplate.Binding(b(o,"account"),b(o,"device"),b(o,"line"),b(o,"interval"),b(o,"session"),n(o,"generation",0),o.get("peer").getAsString(),b(o,"phoneReader"),b(o,"archiveReader"));
  int[] currents={0},sessions={0},reviewed={0},metadata={0};OwnerTemplate[] client={null};var entered=new CountDownLatch(1);var release=new CountDownLatch(1);
  OwnerTemplate.CurrentSource current=()->{int at=++currents[0];if(n(p,"ClientCloseAt",0)==at && client[0]!=null)client[0].close();if(n(p,"CurrentSleepAt",0)==at)Thread.sleep(n(p,"SleepMS",0));if(n(p,"CurrentFailAt",0)==at)throw new OwnerTemplate.Failure("synthetic");var times=p.getAsJsonArray("Now");return new OwnerTemplate.Current(binding,m,times.get(Math.min(at-1,times.size()-1)).getAsLong(),n(p,"ValidForMS",0),!(yes(p,"OwnerLost") && reviewed[0]>0),true,true);};
  OwnerTemplate.SessionSource session=()->{int at=++sessions[0];return new OwnerTemplate.Session(p.get("Origin").getAsString(),p.get("Cookie").getAsString(),p.get("CSRF").getAsString()+((n(p,"SessionChangeAt",0)==at || yes(p,"CSRFChanged") && reviewed[0]>0)?"-changed":""));};
  OwnerTemplate.DraftSource draft=()->new OwnerTemplate.DraftState(1+(reviewed[0]>0 && yes(p,"EpochChanged")?1:0),1+(reviewed[0]>0 && yes(p,"RevisionChanged")?1:0),yes(p,"CustodyLive") && !(reviewed[0]>0 && yes(p,"CustodyLost")));
  OwnerTemplate.DraftReviewer review=value->{reviewed[0]++;if(yes(p,"ReviewBlock")){entered.countDown();if(!release.await(10,TimeUnit.SECONDS))throw new AssertionError("Review release timeout");}Thread.sleep(n(p,"ReviewSleepMS",0));return yes(p,"Decision");};
  try(var author=new OwnerTemplate.Authoring(p.get("Origin").getAsString(),binding,b(f.getAsJsonObject("scope"),"templateId"),current,session,ignored->metadata[0]++,draft,review,yes(p,"Enabled"),n(p,"TimeoutMS",0),p.get("Roots").getAsString())){
   client[0]=author.client();byte[] wire=b(f,"envelope");var scope=new EncryptedTemplate.Scope(Arrays.copyOf(wire,222));TemplateContent content=null;var values=new HashMap<String,String>();p.getAsJsonObject("Values").entrySet().forEach(e->values.put(e.getKey(),e.getValue().getAsString()));try{content=new TemplateContent(p.get("Template").getAsString(),values);}catch(TemplateContent.Failure expected){}
   final TemplateContent captured=content;OwnerTemplate.Ticket[] ticket={null};if(yes(p,"PriorSaved") || yes(p,"PriorUnknown")){ticket[0]=client[0].prepareSave(scope,"00000000-0000-0000-0000-000000000041",0,wire);if(yes(p,"PriorUnknown"))try{client[0].commit(ticket[0]);throw new AssertionError("Expected unknown");}catch(OwnerTemplate.Failure expected){if(!expected.unknown)throw expected;}}var results=new ArrayList<Boolean>();long start=System.nanoTime();Runnable prepare=()->{try{var next=author.prepare("00000000-0000-0000-0000-000000000041",0,scope,captured,1,1);ticket[0]=next;results.add(true);}catch(OwnerTemplate.Failure expected){results.add(false);}};
   if(yes(p,"ReviewBlock")){var worker=new Thread(prepare);worker.start();if(!entered.await(10,TimeUnit.SECONDS))throw new AssertionError("Review entry timeout");try{if(yes(p,"ForeignReview"))ticket[0]=client[0].prepareSave(scope,"00000000-0000-0000-0000-000000000041",0,wire);else{author.prepare("00000000-0000-0000-0000-000000000041",0,scope,captured,1,1);throw new AssertionError("Concurrent author accepted");}}catch(OwnerTemplate.Failure expected){if(!expected.code.equals("busy"))throw expected;}finally{release.countDown();}worker.join();}else for(int i=0;i<n(p,"Repeat",1);i++)prepare.run();
   double elapsed=(System.nanoTime()-start)/1e9;Thread.sleep(n(p,"DelayMS",0));boolean ack=false,fresh=false,read=false;if(yes(p,"Commit") && ticket[0]!=null)try{if(yes(p,"PriorUnknown"))client[0].retryUnknown(ticket[0]);else client[0].commit(ticket[0]);ack=true;}catch(OwnerTemplate.Failure expected){}
   if(yes(p,"ProbeExpired")){try{client[0].prepareSave(scope,"00000000-0000-0000-0000-000000000042",0,wire);fresh=true;}catch(OwnerTemplate.Failure expected){}try{client[0].readLatest();read=true;}catch(OwnerTemplate.Failure expected){}}
   Thread.sleep(n(p,"SettleMS",0));System.out.println(new Gson().toJson(Map.of("accepted",results,"ack",ack,"fresh",fresh,"read",read,"reviewed",reviewed[0],"metadata",metadata[0],"currentCalls",currents[0],"elapsed",elapsed)));
  }
 }
}

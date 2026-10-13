package org.zrotext.candidate;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.*;
final class OwnerTemplateLifecycleTest {
 private OwnerTemplateLifecycleTest(){}
 static void run(String origin,OwnerTemplate.Binding binding,byte[] template,OwnerTemplate.SessionSource sessions,String roots)throws Exception{
  var entered=new CountDownLatch(8);var release=new CountDownLatch(1);var clients=new ArrayList<OwnerTemplate>();var threads=new ArrayList<Thread>();var unexpected=new AtomicReference<Throwable>();
  OwnerTemplate.CurrentSource blocked=()->{entered.countDown();if(!release.await(10,TimeUnit.SECONDS))throw new AssertionError("Callback release missing");throw new OwnerTemplate.Failure("synthetic");};
  try{
   for(int i=0;i<8;i++)clients.add(new OwnerTemplate(origin,binding,template,blocked,sessions,true,10000,roots));
   for(var client:clients){var t=new Thread(()->{try{client.readLatest();unexpected.set(new AssertionError("Closed client returned snapshot"));}catch(OwnerTemplate.Failure expected){}catch(Throwable error){unexpected.set(error);}});threads.add(t);t.start();}
   if(!entered.await(8,TimeUnit.SECONDS))throw new AssertionError("Workers did not enter callbacks");
   expect(clients.get(0),"busy");for(var client:clients)client.close();
   for(var t:threads){t.join(2000);if(t.isAlive())throw new AssertionError("Close did not settle foreground");}
   if(unexpected.get()!=null)throw new AssertionError(unexpected.get());
   var recovered=new AtomicBoolean();
   try(var ninth=new OwnerTemplate(origin,binding,template,()->{recovered.set(true);throw new OwnerTemplate.Failure("synthetic");},sessions,true,10000,roots)){
    expect(ninth,"capacity");release.countDown();long until=System.nanoTime()+TimeUnit.SECONDS.toNanos(3);
    for(;;){try{ninth.readLatest();throw new AssertionError("Unexpected snapshot");}catch(OwnerTemplate.Failure error){if((error.code.equals("owner_changed") || error.code.equals("closed")) && recovered.get())break;if(!error.code.equals("capacity") || System.nanoTime()>until)throw error;Thread.sleep(5);}}
   }
  }finally{release.countDown();for(var client:clients)client.close();for(var t:threads)t.join(2000);}
 }
 private static void expect(OwnerTemplate client,String code)throws Exception{try{client.readLatest();throw new AssertionError("Expected "+code);}catch(OwnerTemplate.Failure error){if(!error.code.equals(code))throw error;}}
}

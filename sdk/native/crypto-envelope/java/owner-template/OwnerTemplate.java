package org.zrotext.candidate;
import java.nio.*;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.util.*;
import java.util.concurrent.*;
/** Cold opaque current template loading. No decryption, save acknowledgement or send authority. */
public final class OwnerTemplate implements AutoCloseable {
 public static final class Failure extends Exception {
  private static final long serialVersionUID=1L;public final String code;public final boolean unknown;
  public Failure(String code){this(code,false);}public Failure(String code,boolean unknown){super("Owner template "+code);this.code=code;this.unknown=unknown;}
 }
 private static void need(boolean b)throws Failure{if(!b)throw new Failure("invalid_request");}
 private static byte[] bytes(byte[] b,int size)throws Failure{need(b!=null && b.length==size);byte[] out=b.clone();need(!Arrays.equals(out,new byte[size]));return out;}
 public static final class Binding {
  private final byte[][] ids,readers;private final long generation;private final String peer;
  public Binding(byte[] account,byte[] device,byte[] line,byte[] interval,byte[] session,long generation,String peer,byte[] phoneReader,byte[] archiveReader)throws Failure{
   ids=new byte[][]{bytes(account,16),bytes(device,16),bytes(line,16),bytes(interval,16),bytes(session,16)};readers=new byte[][]{bytes(phoneReader,32),bytes(archiveReader,32)};need(generation>0 && peer!=null && peer.matches("\\+[1-9][0-9]{1,14}"));this.generation=generation;this.peer=peer;
  }
  private boolean same(Binding b){return b!=null && generation==b.generation && peer.equals(b.peer) && Arrays.deepEquals(ids,b.ids) && Arrays.deepEquals(readers,b.readers);}
 }
 public record Current(Binding binding,ManifestChain.Verified manifest,long nowMs,long validForMs,boolean ownerLive,boolean consentLive,boolean active){}
 public record Session(String origin,String cookie,String csrf){@Override public String toString(){return "OwnerTemplate.Session[redacted]";}}
 public interface CurrentSource{Current current()throws Exception;}
 public interface SessionSource{Session current()throws Exception;}
 public static final class Snapshot {
  private final EncryptedTemplate.Scope scope;private final byte[] wire;private final String digest;
  private Snapshot(EncryptedTemplate.Scope scope,byte[] wire,String digest){this.scope=scope;this.wire=wire.clone();this.digest=digest;}
  public EncryptedTemplate.Scope scope(){return scope;}public byte[] envelope(){return wire.clone();}public String encryptedDigest(){return digest;}public boolean requestAcknowledged(){return false;}public boolean matchesPending(){return false;}
 }
 private static final Semaphore ADMISSION=new Semaphore(8);
 private static final ExecutorService WORKERS=Executors.newFixedThreadPool(8,r->{var t=new Thread(r,"zrotext-owner-template");t.setDaemon(true);return t;});
 private final Object lock=new Object();private final String origin,path;private final Binding binding;private final byte[] template;private final CurrentSource source;private final SessionSource sessions;private final long timeout;private final OwnerTemplateTransport transport;
 private boolean closed,busy;private long now,head;private ManifestChain.Verified prior;private String headDigest;
 private static final class Work {long deadline;boolean done;Snapshot result;Failure error;Work(long deadline){this.deadline=deadline;}}
 public OwnerTemplate(String origin,Binding binding,byte[] template,CurrentSource source,SessionSource sessions,boolean enabled,long timeoutMs,String additionalRootsPem)throws Failure{
  try{var u=new java.net.URI(origin);need(u.getScheme().equals("https") && u.getHost()!=null && u.getHost().equals(u.getHost().toLowerCase(Locale.ROOT)) && u.getRawPath().isEmpty() && u.getRawUserInfo()==null && u.getQuery()==null && u.getFragment()==null);need(binding!=null && source!=null && sessions!=null && timeoutMs>=1 && timeoutMs<=10000);
   this.origin=origin;this.binding=binding;this.template=bytes(template,16);this.source=source;this.sessions=sessions;timeout=timeoutMs;closed=!enabled;path="/v1/owner/workflow/templates/"+TemplateStore.uuid(this.template);transport=new OwnerTemplateTransport(origin,timeoutMs,additionalRootsPem);
  }catch(Exception error){throw new Failure("invalid_request");}
 }
 @Override public void close(){synchronized(lock){closed=true;lock.notifyAll();}transport.close();}
 private void live(Work w)throws Failure{synchronized(lock){if(closed)throw new Failure("closed");if(System.nanoTime()>=w.deadline){closed=true;lock.notifyAll();transport.close();throw new Failure("deadline");}}}
 private long remaining(Work w)throws Failure{live(w);synchronized(lock){return Math.max(1,TimeUnit.NANOSECONDS.toMillis(w.deadline-System.nanoTime()));}}
 public Snapshot readLatest()throws Failure{
  final Work w;synchronized(lock){if(closed)throw new Failure("closed");if(busy)throw new Failure("busy");if(!ADMISSION.tryAcquire())throw new Failure("capacity");busy=true;w=new Work(System.nanoTime()+TimeUnit.MILLISECONDS.toNanos(timeout));}
  try{WORKERS.execute(()->{try{var result=read(w);synchronized(lock){w.result=result;}}catch(Exception error){synchronized(lock){w.error=error instanceof Failure f?f:new Failure("read_refused");}}finally{synchronized(lock){w.done=true;busy=false;lock.notifyAll();}ADMISSION.release();}});}catch(RuntimeException error){synchronized(lock){busy=false;}ADMISSION.release();throw new Failure("capacity");}
  synchronized(lock){for(;;){live(w);if(w.done){if(w.error!=null)throw w.error;return w.result;}try{TimeUnit.NANOSECONDS.timedWait(lock,Math.max(1,w.deadline-System.nanoTime()));}catch(InterruptedException error){Thread.currentThread().interrupt();close();throw new Failure("closed");}}}
 }
 private Session credentials(Work w)throws Exception{
  live(w);var s=sessions.current();live(w);need(s!=null && origin.equals(s.origin()) && s.cookie()!=null && s.cookie().length()>=1 && s.cookie().length()<=4096 && s.cookie().contains("=") && s.cookie().matches("[ -~]+") && s.csrf()!=null && s.csrf().length()>=1 && s.csrf().length()<=256 && s.csrf().matches("[!-~]+"));return s;
 }
 private static boolean active(byte[] k,long at,int permission){return k[148]==1 && TemplateStore.number(k,132)<=at && at<TemplateStore.number(k,140) && (Short.toUnsignedInt(ByteBuffer.wrap(k,130,2).getShort())&permission)!=0;}
 private void authorize(Work w,EncryptedTemplate.Scope scope,Session session)throws Exception{
  try{live(w);long start=System.nanoTime();var a=source.current();live(w);need(a!=null && binding.same(a.binding()) && a.ownerLive() && a.consentLive() && a.active() && a.nowMs()>0 && a.nowMs()>=now && a.validForMs()>0 && a.validForMs()<=60000 && a.manifest()!=null && a.manifest().profile()==2);
   var m=ManifestChain.continueChain(a.manifest().bytes(),a.manifest(),2,a.nowMs());need(TemplateStore.same(m.account(),binding.ids[0]));if(prior!=null)need(TemplateStore.same(m.rootPoint(),prior.rootPoint()) && TemplateStore.same(m.enrolledRootPoint(),prior.enrolledRootPoint()) && m.generation()==prior.generation() && m.version()>=prior.version() && (m.version()!=prior.version() || TemplateStore.same(m.digest(),prior.digest())));
   byte[] reader=null,phone=null;for(var k:m.keyRecords()){if(k[0]==2 && TemplateStore.same(TemplateStore.part(k,1,32),binding.readers[1]) && active(k,a.nowMs(),8))reader=k;if(k[0]==4 && TemplateStore.same(TemplateStore.part(k,98,16),binding.ids[1]) && TemplateStore.same(TemplateStore.part(k,114,16),binding.ids[2]) && active(k,a.nowMs(),2) && ByteBuffer.wrap(k,130,2).getShort()==2)phone=k;}
   need(reader!=null && phone!=null);long expiry=Math.min(TemplateStore.number(m.bytes(),45),Math.min(TemplateStore.number(reader,140),TemplateStore.number(phone,140)));
   if(scope!=null){var aad=scope.aad();for(int i=0;i<4;i++)need(TemplateStore.same(TemplateStore.part(aad,6+16*i,16),binding.ids[i]));need(TemplateStore.same(TemplateStore.part(aad,70,16),template) && TemplateStore.number(aad,86)==binding.generation && TemplateStore.same(TemplateStore.part(aad,158,32),binding.readers[1]) && TemplateStore.number(aad,110)==m.generation() && TemplateStore.number(aad,118)==m.version() && TemplateStore.same(TemplateStore.part(aad,190,32),m.digest()) && TemplateStore.same(TemplateStore.part(aad,126,32),MessageDigest.getInstance("SHA-256").digest(binding.peer.getBytes(StandardCharsets.UTF_8))));long expires=TemplateStore.number(aad,102);need(expires>a.nowMs() && expires-a.nowMs()<=30L*86400000);expiry=Math.min(expiry,expires);}
   long duration=Math.min(a.validForMs(),expiry-a.nowMs());need(duration>0);synchronized(lock){w.deadline=Math.min(w.deadline,start+TimeUnit.MILLISECONDS.toNanos(duration));lock.notifyAll();}need(credentials(w).equals(session));live(w);prior=m;now=a.nowMs();
  }catch(Exception error){close();throw new Failure("owner_changed");}
 }
 private Snapshot read(Work w)throws Exception{
  var session=credentials(w);authorize(w,null,session);if(!credentials(w).equals(session)){close();throw new Failure("owner_changed");}
  byte[] wire;try{wire=transport.get(path,session,remaining(w));}catch(Failure error){if(error.code.equals("owner_changed"))close();throw error;}
  live(w);var scope=TemplateStore.parse(wire);long revision=TemplateStore.number(scope.aad(),94);need(revision>=head);authorize(w,scope,session);HpkeRecipient.point(TemplateStore.part(wire,222,65));String digest=TemplateStore.hex(MessageDigest.getInstance("SHA-256").digest(wire));authorize(w,scope,session);need(revision!=head || digest.equals(headDigest));live(w);head=revision;headDigest=digest;return new Snapshot(scope,wire,digest);
 }
}

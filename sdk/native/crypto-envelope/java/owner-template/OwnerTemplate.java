package org.zrotext.candidate;
import java.nio.*;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.util.*;
import java.util.concurrent.*;
/** Opaque template loading and explicit reviewed persistence. No decryption or send authority. */
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
  private final EncryptedTemplate.Scope scope;private final byte[] wire;private final String digest;private final boolean matches;
  private Snapshot(EncryptedTemplate.Scope scope,byte[] wire,String digest){this(scope,wire,digest,false);}
  private Snapshot(EncryptedTemplate.Scope scope,byte[] wire,String digest,boolean matches){this.scope=scope;this.wire=wire.clone();this.digest=digest;this.matches=matches;}
  public EncryptedTemplate.Scope scope(){return scope;}public byte[] envelope(){return wire.clone();}public String encryptedDigest(){return digest;}public boolean requestAcknowledged(){return false;}public boolean matchesPending(){return matches;}
 }
 private static final Semaphore ADMISSION=new Semaphore(8);
 private static final ExecutorService WORKERS=Executors.newFixedThreadPool(8,r->{var t=new Thread(r,"zrotext-owner-template");t.setDaemon(true);return t;});
 private final Object lock=new Object();private final String origin,path;private final Binding binding;private final byte[] template;private final CurrentSource source;private final SessionSource sessions;private final long timeout;private final OwnerTemplateTransport transport;
 private final Reviewer review;private Saved saved;private Pending pending;
 private boolean closed,busy;private long lifetimeDeadline=Long.MAX_VALUE;private long now,head;private ManifestChain.Verified prior;private String headDigest;
 private static final class Work {long deadline;boolean done,foreground,released;Object result;Failure error;Runnable finish;Work(long deadline){this.deadline=deadline;}}
 public OwnerTemplate(String origin,Binding binding,byte[] template,CurrentSource source,SessionSource sessions,boolean enabled,long timeoutMs,String additionalRootsPem)throws Failure{this(origin,binding,template,source,sessions,enabled,timeoutMs,additionalRootsPem,null);}
 public OwnerTemplate(String origin,Binding binding,byte[] template,CurrentSource source,SessionSource sessions,boolean enabled,long timeoutMs,String additionalRootsPem,Reviewer review)throws Failure{
  try{var u=new java.net.URI(origin);need(u.getScheme().equals("https") && u.getHost()!=null && u.getHost().equals(u.getHost().toLowerCase(Locale.ROOT)) && u.getRawPath().isEmpty() && u.getRawUserInfo()==null && u.getQuery()==null && u.getFragment()==null);need(binding!=null && source!=null && sessions!=null && timeoutMs>=1 && timeoutMs<=10000);
   this.review=review;this.origin=origin;this.binding=binding;this.template=bytes(template,16);this.source=source;this.sessions=sessions;timeout=timeoutMs;closed=!enabled;path="/v1/owner/workflow/templates/"+TemplateStore.uuid(this.template);transport=new OwnerTemplateTransport(origin,timeoutMs,additionalRootsPem);
  }catch(Exception error){throw new Failure("invalid_request");}
 }
 @Override public void close(){synchronized(lock){closed=true;if(!busy)saved=null;lock.notifyAll();}transport.close();}
 private void live(Work w)throws Failure{synchronized(lock){if(closed)throw classify(new Failure("closed"));if(System.nanoTime()>=w.deadline){closed=true;lock.notifyAll();transport.close();throw classify(new Failure("deadline"));}}}
 private long remaining(Work w)throws Failure{live(w);synchronized(lock){return Math.max(1,TimeUnit.NANOSECONDS.toMillis(w.deadline-System.nanoTime()));}}
 private interface Operation{Object run(Work work)throws Exception;}
 private Failure classify(Exception error){if(error instanceof Failure f && Set.of("invalid_request","pending_write","busy","capacity").contains(f.code))return f;if(pending!=null)return new Failure("response_unknown",true);return error instanceof Failure f?f:new Failure("read_refused");}
 private void releaseWork(Work w){if(w.done && w.foreground && !w.released){w.released=true;busy=false;if(closed)saved=null;ADMISSION.release();lock.notifyAll();}}
 private Object execute(Operation op)throws Failure{
  final Work w;synchronized(lock){if(busy)throw new Failure("busy");if(closed)throw classify(new Failure("closed"));if(!ADMISSION.tryAcquire())throw new Failure("capacity");busy=true;w=new Work(Math.min(lifetimeDeadline,System.nanoTime()+TimeUnit.MILLISECONDS.toNanos(timeout)));}
  try{WORKERS.execute(()->{try{var result=op.run(w);synchronized(lock){w.result=result;}}catch(Exception error){synchronized(lock){w.error=classify(error);}}finally{synchronized(lock){w.done=true;releaseWork(w);lock.notifyAll();}}});}catch(RuntimeException error){synchronized(lock){busy=false;}ADMISSION.release();throw new Failure("capacity");}
  try{synchronized(lock){for(;;){live(w);if(w.done){if(w.error!=null)throw w.error;if(w.finish!=null)w.finish.run();return w.result;}try{TimeUnit.NANOSECONDS.timedWait(lock,Math.max(1,w.deadline-System.nanoTime()));}catch(InterruptedException error){Thread.currentThread().interrupt();close();throw classify(new Failure("closed"));}}}}
  finally{synchronized(lock){w.foreground=true;releaseWork(w);}}
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
 private Snapshot read(Work w,Session expected)throws Exception{
  var session=credentials(w);if(expected!=null && !session.equals(expected)){close();throw new Failure("owner_changed");}authorize(w,null,session);if(!credentials(w).equals(session)){close();throw new Failure("owner_changed");}
  byte[] wire;try{wire=transport.get(path,session,remaining(w));}catch(Failure error){if(error.code.equals("owner_changed"))close();throw error;}
  live(w);var scope=TemplateStore.parse(wire);long revision=TemplateStore.number(scope.aad(),94);need(revision>=head);authorize(w,scope,session);HpkeRecipient.point(TemplateStore.part(wire,222,65));String digest=TemplateStore.hex(MessageDigest.getInstance("SHA-256").digest(wire));authorize(w,scope,session);need(revision!=head || digest.equals(headDigest));live(w);head=revision;headDigest=digest;return new Snapshot(scope,wire,digest);
 }
 /** Immutable local preview only; no persistence or send authority. Strings cannot guarantee erasure. */
 public record OpenedPreview(TemplateContent.Preview preview,long revision,String encryptedDigest,boolean matchesPending){public boolean requestAcknowledged(){return false;}}
 static final class Opening implements AutoCloseable {
  private final OwnerTemplate client,guard;
  Opening(OwnerTemplate client,String origin,Binding binding,byte[] template,CurrentSource current,SessionSource session,boolean enabled,long timeoutMs,String roots)throws Failure{
   if(client==null)throw new Failure("invalid_request");
   try{need(client.origin.equals(origin) && client.binding.same(binding) && Arrays.equals(client.template,template));guard=new OwnerTemplate(origin,binding,template,current,session,enabled,timeoutMs,roots);this.client=client;if(!enabled)close();}
   catch(Exception error){client.close();throw new Failure("invalid_request");}
  }
  @Override public void close(){guard.close();client.close();}
  interface PointSource{byte[] point()throws Exception;}
  private void clientLive()throws Failure{synchronized(client.lock){if(client.closed)throw new Failure("closed");}}
  OpenedPreview open(PointSource point,HpkeRecipient.ContentRecipient recipient)throws Failure{
   try{var result=(OpenedPreview)guard.execute(w->{byte[] wire=null;try{
    guard.live(w);clientLive();byte[] pk=point.point().clone();HpkeRecipient.point(pk);var session=guard.credentials(w);guard.authorize(w,null,session);
    byte[] selected=null;for(var k:guard.prior.keyRecords())if(k[0]==2 && Arrays.equals(TemplateStore.part(k,1,32),guard.binding.readers[1]))selected=TemplateStore.part(k,33,65);need(Arrays.equals(pk,selected));
    var snapshot=client.readLatest();guard.live(w);clientLive();var scope=snapshot.scope();wire=snapshot.envelope();guard.authorize(w,scope,session);
    var authority=new EncryptedTemplate.Authority(guard.prior,guard.now);var content=EncryptedTemplate.open(scope,wire,recipient,()->authority);
    clientLive();guard.live(w);need(Arrays.equals(pk,point.point()));guard.authorize(w,scope,session);var preview=content.preview();guard.authorize(w,scope,session);clientLive();need(Arrays.equals(pk,point.point()));guard.live(w);
    return new OpenedPreview(preview,TemplateStore.number(scope.aad(),94),snapshot.encryptedDigest(),snapshot.matchesPending());
   }catch(Exception error){close();throw error;}finally{if(wire!=null)Arrays.fill(wire,(byte)0);}});clientLive();return result;
   }catch(Exception error){close();throw error instanceof Failure f?f:new Failure("refused");}
  }
  OpenedPreview openLatestSoftware(PrivateKey key,byte[] publicPoint)throws Failure{
   need(key!=null && publicPoint!=null);byte[] pk=publicPoint.clone();return open(()->{
    var publicKey=HpkeRecipient.point(pk);var proof=Signature.getInstance("SHA256withECDSA");byte[] domain="ZT/template-opening/key-binding/v1\0".getBytes(StandardCharsets.US_ASCII);
    proof.initSign(key);proof.update(domain);proof.update(pk);byte[] signature=proof.sign();proof.initVerify(publicKey);proof.update(domain);proof.update(pk);need(proof.verify(signature));return pk.clone();
   },HpkeRecipient.softwareContent(key));
  }
 }
 /** Independently maintained host lease; custodyLive does not qualify a protected provider. */
 public record DraftState(long epoch,long revision,boolean custodyLive){}
 public record DraftReview(String requestId,int expectedRevision,EncryptedTemplate.Scope scope,long epoch,long draftRevision,TemplateContent content,TemplateContent.Preview preview){}
 public interface DraftSource{DraftState current()throws Exception;}
 public interface DraftReviewer{boolean consume(DraftReview review)throws Exception;}
 /** One immutable reviewed draft lifetime. Never commits or sends automatically. */
 public static final class Authoring implements AutoCloseable {
  private static final ScheduledExecutorService TIMERS=Executors.newSingleThreadScheduledExecutor(r->{var t=new Thread(r,"zrotext-template-expiry");t.setDaemon(true);return t;});
  private final OwnerTemplate client,guard;private final DraftSource draft;private final DraftReviewer review;private boolean used;private volatile ScheduledFuture<?> timer;
  public Authoring(String origin,Binding binding,byte[] template,CurrentSource current,SessionSource session,Reviewer ciphertextReview,DraftSource draft,DraftReviewer review,boolean enabled,long timeoutMs,String roots)throws Failure{
   need(draft!=null && review!=null && ciphertextReview!=null);this.draft=draft;this.review=review;client=new OwnerTemplate(origin,binding,template,current,session,enabled,timeoutMs,roots,ciphertextReview);
   try{guard=new OwnerTemplate(origin,binding,template,current,session,enabled,timeoutMs,roots);}catch(Exception error){client.close();throw new Failure("invalid_request");}
  }
  public OwnerTemplate client(){return client;}
  @Override public void close(){guard.close();client.close();var scheduled=timer;if(scheduled!=null)scheduled.cancel(false);}
  public void invalidate(){close();}
  private void abort(Ticket owned){guard.close();synchronized(client.lock){if((client.saved!=null && client.saved.ticket!=owned) || (client.busy && owned==null))return;client.close();}}
  private void draft(Work w,long epoch,long revision)throws Exception{guard.live(w);var d=draft.current();guard.live(w);if(d==null || d.epoch()!=epoch || d.revision()!=revision || !d.custodyLive())throw new Failure("draft_changed");}
  private void current(Work w,EncryptedTemplate.Scope scope,Session session,long epoch,long revision)throws Exception{draft(w,epoch,revision);guard.authorize(w,scope,session);draft(w,epoch,revision);if(!guard.credentials(w).equals(session))throw new Failure("owner_changed");guard.live(w);}
  public Ticket prepare(String requestId,int expectedRevision,EncryptedTemplate.Scope scope,TemplateContent content,long epoch,long draftRevision)throws Failure{
   byte[] canonical=null;final TemplateContent captured;
   try{need(content!=null && scope!=null);canonical=content.canonical();need(canonical.length<=32768);captured=TemplateContent.parse(canonical);}catch(Exception error){throw new Failure("invalid_draft");}finally{if(canonical!=null)Arrays.fill(canonical,(byte)0);}
   try{var ticket=(Ticket)guard.execute(w->{synchronized(client.lock){if(used || client.saved!=null || client.pending!=null)throw new Failure("pending_draft");}byte[] wire=null;Ticket owned=null;
    try{need(epoch>0 && draftRevision>0 && expectedRevision>=0 && expectedRevision<128 && TemplateStore.number(scope.aad(),94)==expectedRevision+1L && requestId!=null && requestId.matches("[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}"));
     var session=guard.credentials(w);var preview=captured.preview();current(w,scope,session,epoch,draftRevision);if(!review.consume(new DraftReview(requestId,expectedRevision,scope,epoch,draftRevision,captured,preview)))throw new Failure("review_declined");
     current(w,scope,session,epoch,draftRevision);var authority=new EncryptedTemplate.Authority(guard.prior,guard.now);wire=EncryptedTemplate.seal(scope,captured,()->authority);current(w,scope,session,epoch,draftRevision);
     var prepared=client.prepareSave(scope,requestId,expectedRevision,wire);owned=prepared;current(w,scope,session,epoch,draftRevision);
     synchronized(client.lock){if(client.closed || client.saved==null || client.saved.ticket!=prepared)throw new Failure("closed");client.saved.deadline=Math.min(client.saved.deadline,w.deadline);client.lifetimeDeadline=Math.min(client.lifetimeDeadline,w.deadline);}
     w.finish=()->{used=true;timer=TIMERS.schedule(this::close,Math.max(0,w.deadline-System.nanoTime()),TimeUnit.NANOSECONDS);};return prepared;
    }catch(Exception error){if(error instanceof Failure f && Set.of("pending_write","busy").contains(f.code))throw new Failure("pending_draft");abort(owned);throw error;}finally{if(wire!=null)Arrays.fill(wire,(byte)0);}
   });synchronized(client.lock){if(client.closed)throw new Failure("closed");}return ticket;
   }catch(Failure error){if(!Set.of("busy","capacity","pending_draft").contains(error.code))abort(null);throw error;}
  }
 }
 public record Review(String requestId,int expectedRevision,EncryptedTemplate.Scope scope,String encryptedDigest){}
 public record Pending(String requestId,String templateId,int revision,String encryptedDigest){}
 public record Acknowledgement(Pending identity){public String state(){return "acknowledged_saved_revision";}}
 public interface Reviewer{void consume(Review review)throws Exception;}
 public static final class Ticket{private Ticket(){}}
 private static final class Saved{
  final Ticket ticket=new Ticket();final TemplateStore.SaveRequest request;final String requestId;final EncryptedTemplate.Scope scope;final Session session;long deadline;int attempts,verifies;boolean unknown;
  Saved(TemplateStore.SaveRequest request,String requestId,EncryptedTemplate.Scope scope,Session session,long deadline){this.request=request;this.requestId=requestId;this.scope=scope;this.session=session;this.deadline=deadline;}
 }
 public Pending pending(){synchronized(lock){return pending;}}
 private Pending identity(Saved r){return new Pending(r.requestId,TemplateStore.uuid(TemplateStore.part(r.scope.aad(),70,16)),r.request.revision(),r.request.encryptedDigest());}
 private void forget(Saved r){if(saved==r){saved=null;pending=null;}}
 private void savedDeadline(Saved r,Work w)throws Failure{synchronized(lock){w.deadline=Math.min(w.deadline,r.deadline);r.deadline=w.deadline;lock.notifyAll();}live(w);}
 private Saved ticket(Ticket t,Work w)throws Failure{var r=saved;if(r==null || t==null || r.ticket!=t)throw new Failure("invalid_request");savedDeadline(r,w);return r;}
 public Ticket prepareSave(EncryptedTemplate.Scope scope,String requestId,int expectedRevision,byte[] envelope)throws Failure{
  need(envelope!=null && envelope.length>=308 && envelope.length<=33075 && scope!=null);byte[] wire=envelope.clone();
  return (Ticket)execute(w->{if(saved!=null || pending!=null)throw new Failure("pending_write");need(review!=null);Saved owned=null;
   try{var request=new TemplateStore.SaveRequest(scope,requestId,expectedRevision,wire);TemplateStore.parse(wire);var session=credentials(w);owned=new Saved(request,requestId,scope,session,w.deadline);saved=owned;
    authorize(w,scope,session);savedDeadline(owned,w);HpkeRecipient.point(TemplateStore.part(wire,222,65));review.consume(new Review(requestId,expectedRevision,scope,request.encryptedDigest()));authorize(w,scope,session);savedDeadline(owned,w);return owned.ticket;
   }catch(Exception error){if(owned!=null)synchronized(lock){forget(owned);}throw error instanceof Failure f?f:new Failure("invalid_request");}
  });
 }
 public Acknowledgement commit(Ticket ticket)throws Failure{return postSaved(ticket,false);}
 public Acknowledgement retryUnknown(Ticket ticket)throws Failure{return postSaved(ticket,true);}
 private Acknowledgement postSaved(Ticket t,boolean retry)throws Failure{
  return (Acknowledgement)execute(w->{var r=ticket(t,w);if(retry?!r.unknown:r.attempts!=0)throw new Failure("invalid_request");if(r.attempts>=3)throw new Failure("attempts_exhausted",r.unknown);
   authorize(w,r.scope,r.session);savedDeadline(r,w);synchronized(lock){r.attempts++;r.unknown=true;pending=identity(r);}
   if(!credentials(w).equals(r.session)){close();throw new Failure("owner_changed");}
   byte[] body;try{body=transport.post(r.request,r.session,remaining(w));}catch(Failure error){if(error.code.equals("owner_changed"))close();throw error;}r.request.receipt(body);
   authorize(w,r.scope,r.session);savedDeadline(r,w);int revision=r.request.revision();String digest=r.request.encryptedDigest();if(revision==head && !digest.equals(headDigest))throw new Failure("response_unknown",true);
   var ack=new Acknowledgement(identity(r));w.finish=()->{if(revision>=head){head=revision;headDigest=digest;}forget(r);};return ack;
  });
 }
 public Snapshot readLatest()throws Failure{return latestSaved(null,false);}
 public Snapshot verifyUnknown(Ticket ticket)throws Failure{return latestSaved(ticket,true);}
 private Snapshot latestSaved(Ticket t,boolean verify)throws Failure{
  return (Snapshot)execute(w->{var r=verify?ticket(t,w):saved;if(verify && !r.unknown)throw new Failure("invalid_request");
   if(r!=null){savedDeadline(r,w);if(r.unknown){if(r.verifies>=3)throw new Failure("attempts_exhausted",true);r.verifies++;}}
   var snapshot=read(w,r==null?null:r.session);if(r!=null){savedDeadline(r,w);snapshot=new Snapshot(snapshot.scope(),snapshot.envelope(),snapshot.encryptedDigest(),Arrays.equals(snapshot.envelope(),r.request.body()));}return snapshot;
  });
 }

}

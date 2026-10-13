namespace Zrotext.Candidate;
public sealed partial class OwnerTemplate {
 public sealed record Review(string RequestId,int ExpectedRevision,EncryptedTemplate.Scope Scope,string EncryptedDigest);
 public sealed record PendingIdentity(string RequestId,string TemplateId,int Revision,string EncryptedDigest);
 public sealed record Acknowledgement(PendingIdentity Identity){public string State=>"acknowledged_saved_revision";}
 public sealed class Ticket{internal Ticket(){}}
 private sealed class Saved(TemplateStore.SaveRequest request,string requestId,EncryptedTemplate.Scope scope,Session session,long deadline){
  internal readonly Ticket Ticket=new();internal readonly TemplateStore.SaveRequest Request=request;internal readonly string RequestId=requestId;internal readonly EncryptedTemplate.Scope Scope=scope;internal readonly Session Session=session;internal long Deadline=deadline;internal int Attempts,Verifies;internal bool Unknown;
 }
 public PendingIdentity? Pending(){lock(gate){return pending;}}
 private static PendingIdentity Identity(Saved r)=>new(r.RequestId,TemplateStore.Uuid(r.Scope.Aad()[70..86]),r.Request.Revision,r.Request.EncryptedDigest);
 private void Forget(Saved r){if(ReferenceEquals(saved,r)){saved=null;pending=null;}}
 private void SavedDeadline(Saved r,Work w){lock(gate){w.Deadline=Math.Min(w.Deadline,r.Deadline);r.Deadline=w.Deadline;Monitor.PulseAll(gate);}Live(w);}
 private Saved GetTicket(Ticket? ticket,Work w){var r=saved;if(r is null || ticket is null || !ReferenceEquals(r.Ticket,ticket))throw new Failure("invalid_request");SavedDeadline(r,w);return r;}
 public Ticket PrepareSave(EncryptedTemplate.Scope scope,string requestId,int expectedRevision,byte[] envelope){
  Need(envelope.Length>=308 && envelope.Length<=33075);byte[] wire=(byte[])envelope.Clone();
  return (Ticket)Execute(w=>{if(saved is not null || pending is not null)throw new Failure("pending_write");Need(review is not null);Saved? owned=null;
   try{var request=new TemplateStore.SaveRequest(scope,requestId,expectedRevision,wire);TemplateStore.Parse(wire);var session=Credentials(w);owned=new(request,requestId,scope,session,w.Deadline);saved=owned;
    Authorize(w,scope,session);SavedDeadline(owned,w);using var point=HpkeRecipient.Point(wire[222..287]);review!(new Review(requestId,expectedRevision,scope,request.EncryptedDigest));Authorize(w,scope,session);SavedDeadline(owned,w);return owned.Ticket;
   }catch(Exception error){if(owned is not null)lock(gate){Forget(owned);}throw error as Failure??new Failure("invalid_request");}
  });
 }
 public Acknowledgement Commit(Ticket? ticket)=>PostSaved(ticket,false);
 public Acknowledgement RetryUnknown(Ticket? ticket)=>PostSaved(ticket,true);
 private Acknowledgement PostSaved(Ticket? ticket,bool retry){
  return (Acknowledgement)Execute(w=>{var r=GetTicket(ticket,w);if(retry?!r.Unknown:r.Attempts!=0)throw new Failure("invalid_request");if(r.Attempts>=3)throw new Failure("attempts_exhausted",r.Unknown);
   Authorize(w,r.Scope,r.Session);SavedDeadline(r,w);lock(gate){r.Attempts++;r.Unknown=true;pending=Identity(r);}
   if(Credentials(w)!=r.Session){Dispose();throw new Failure("owner_changed");}
   byte[] body;try{body=transport.Post(r.Request,r.Session,Remaining(w));}catch(Failure error){if(error.Code=="owner_changed")Dispose();throw;}r.Request.Receipt(body);
   Authorize(w,r.Scope,r.Session);SavedDeadline(r,w);int revision=r.Request.Revision;string digest=r.Request.EncryptedDigest;if(revision==head && digest!=headDigest)throw new Failure("response_unknown",true);
   var ack=new Acknowledgement(Identity(r));w.Finish=()=>{if(revision>=head){head=revision;headDigest=digest;}Forget(r);};return ack;
  });
 }
 public Snapshot ReadLatest()=>LatestSaved(null,false);
 public Snapshot VerifyUnknown(Ticket? ticket)=>LatestSaved(ticket,true);
 private Snapshot LatestSaved(Ticket? ticket,bool verify){
  return (Snapshot)Execute(w=>{var r=verify?GetTicket(ticket,w):saved;if(verify && !r!.Unknown)throw new Failure("invalid_request");
   if(r is not null){SavedDeadline(r,w);if(r.Unknown){if(r.Verifies>=3)throw new Failure("attempts_exhausted",true);r.Verifies++;}}
   var snapshot=Read(w,r?.Session);if(r is not null){SavedDeadline(r,w);snapshot=new Snapshot(snapshot.Scope,snapshot.Envelope(),snapshot.EncryptedDigest,snapshot.Envelope().SequenceEqual(r.Request.Body()));}return snapshot;
  });
 }
}

using System.Security.Cryptography;
using System.Text.RegularExpressions;
using System.Diagnostics;
namespace Zrotext.Candidate;
public sealed partial class OwnerTemplate {
 /// <summary>Host lease only; CustodyLive does not qualify a protected provider.</summary>
 public sealed record DraftState(long Epoch,long Revision,bool CustodyLive);
 public sealed record DraftReview(string RequestId,int ExpectedRevision,EncryptedTemplate.Scope Scope,long Epoch,long DraftRevision,TemplateContent Content,TemplateContent.PreviewResult Preview);
 /// <summary>One reviewed immutable draft lifetime. Never commits or sends automatically.</summary>
 public sealed class Authoring:IDisposable {
  private readonly OwnerTemplate client,guard;private readonly Func<DraftState> draft;private readonly Func<DraftReview,bool> review;private bool used;private Timer? timer;
  public Authoring(string origin,Binding binding,byte[] template,Func<Current> current,Func<Session> session,Action<Review> ciphertextReview,Func<DraftState> draft,Func<DraftReview,bool> review,bool enabled=false,int timeoutMs=10000,string additionalRootsPem=""){
   Need(draft is not null && review is not null && ciphertextReview is not null);this.draft=draft!;this.review=review!;client=new(origin,binding,template,current,session,enabled,timeoutMs,additionalRootsPem,ciphertextReview);
   try{guard=new(origin,binding,template,current,session,enabled,timeoutMs,additionalRootsPem);}catch{client.Dispose();throw new Failure("invalid_request");}
  }
  public OwnerTemplate Client=>client;
  public void Dispose(){guard.Dispose();client.Dispose();timer?.Dispose();}
  public void Invalidate()=>Dispose();
  private void Abort(Ticket? owned){guard.Dispose();lock(client.gate){if((client.saved is not null && !ReferenceEquals(client.saved.Ticket,owned)) || (client.busy && owned is null))return;client.Dispose();}}
  private void CheckDraft(Work w,long epoch,long revision){guard.Live(w);var d=draft();guard.Live(w);if(d is null || d.Epoch!=epoch || d.Revision!=revision || !d.CustodyLive)throw new Failure("draft_changed");}
  private void CheckCurrent(Work w,EncryptedTemplate.Scope scope,Session session,long epoch,long revision){CheckDraft(w,epoch,revision);guard.Authorize(w,scope,session);CheckDraft(w,epoch,revision);if(guard.Credentials(w)!=session)throw new Failure("owner_changed");guard.Live(w);}
  public Ticket Prepare(string requestId,int expectedRevision,EncryptedTemplate.Scope scope,TemplateContent content,long epoch,long draftRevision){
   byte[]? canonical=null;TemplateContent captured;try{Need(content is not null && scope is not null);canonical=content!.Canonical();Need(canonical.Length<=32768);captured=TemplateContent.Parse(canonical);}catch{throw new Failure("invalid_draft");}finally{if(canonical is not null)CryptographicOperations.ZeroMemory(canonical);}
   try{var ticket=(Ticket)guard.Execute(w=>{lock(client.gate){if(used || client.saved is not null || client.pending is not null)throw new Failure("pending_draft");}byte[]? wire=null;Ticket? owned=null;
    try{Need(epoch>0 && draftRevision>0 && expectedRevision>=0 && expectedRevision<128 && TemplateStore.Number(scope.Aad(),94)==expectedRevision+1L && requestId is not null && Regex.IsMatch(requestId,@"\A[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}\z"));
     var session=guard.Credentials(w);var preview=captured.Preview();CheckCurrent(w,scope,session,epoch,draftRevision);if(!review(new(requestId!,expectedRevision,scope,epoch,draftRevision,captured,preview)))throw new Failure("review_declined");
     CheckCurrent(w,scope,session,epoch,draftRevision);var authority=new EncryptedTemplate.Authority(guard.prior!,guard.now);wire=EncryptedTemplate.Seal(scope,captured,()=>authority);CheckCurrent(w,scope,session,epoch,draftRevision);
     var prepared=client.PrepareSave(scope,requestId!,expectedRevision,wire);owned=prepared;CheckCurrent(w,scope,session,epoch,draftRevision);
     lock(client.gate){if(client.closed || client.saved is null || !ReferenceEquals(client.saved.Ticket,prepared))throw new Failure("closed");client.saved.Deadline=Math.Min(client.saved.Deadline,w.Deadline);client.lifetimeDeadline=Math.Min(client.lifetimeDeadline,w.Deadline);}
     w.Finish=()=>{used=true;timer=new Timer(_=>Dispose(),null,TimeSpan.FromSeconds(Math.Max(0,w.Deadline-Tick())/(double)Stopwatch.Frequency),Timeout.InfiniteTimeSpan);};return prepared;
    }catch(Failure e) when(e.Code=="pending_write" || e.Code=="busy"){throw new Failure("pending_draft");}catch{Abort(owned);throw;}finally{if(wire is not null)CryptographicOperations.ZeroMemory(wire);}
   });lock(client.gate){if(client.closed)throw new Failure("closed");}return ticket;
   }catch(Failure error){if(!new[]{"busy","capacity","pending_draft"}.Contains(error.Code))Abort(null);throw;}
  }
 }
}

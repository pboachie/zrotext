using System.Security.Cryptography;
namespace Zrotext.Candidate;
public sealed partial class OwnerTemplate {
 /// <summary>Local preview only, never persistence or sending authority. Immutable strings cannot guarantee erasure.</summary>
 public sealed record OpenedPreview(TemplateContent.PreviewResult Preview,long Revision,string EncryptedDigest,bool MatchesPending){public bool RequestAcknowledged=>false;}
 /// <summary>Owns its dedicated client's close lifecycle, never the caller's key deletion.</summary>
 public sealed class Opening:IDisposable {
  private readonly OwnerTemplate client,guard;
  public Opening(OwnerTemplate client,string origin,Binding binding,byte[] template,Func<Current> current,Func<Session> session,bool enabled=false,int timeoutMs=10000,string additionalRootsPem=""){
   try{Need(client is not null && client.origin==origin && client.binding.Same(binding) && client.template.SequenceEqual(template));guard=new(origin,binding,template,current,session,enabled,timeoutMs,additionalRootsPem);this.client=client!;if(!enabled)Dispose();}catch{client?.Dispose();throw new Failure("invalid_request");}
  }
  public void Dispose(){guard.Dispose();client.Dispose();}
  public void Invalidate()=>Dispose();
  private void ClientLive(){lock(client.gate){if(client.closed)throw new Failure("closed");}}
  private OpenedPreview Open(Func<byte[]> point,HpkeRecipient.IContentRecipient recipient){
   try{var result=(OpenedPreview)guard.Execute(w=>{byte[]? wire=null;try{
    guard.Live(w);ClientLive();var pk=(byte[])point().Clone();using var valid=HpkeRecipient.Point(pk);var session=guard.Credentials(w);guard.Authorize(w,null,session);
    var selected=guard.prior!.KeyRecords().FirstOrDefault(k=>k[0]==2 && k[1..33].SequenceEqual(guard.binding.Readers[1]));Need(selected is not null && selected[33..98].SequenceEqual(pk));
    var snapshot=client.ReadLatest();guard.Live(w);ClientLive();var scope=snapshot.Scope;wire=snapshot.Envelope();guard.Authorize(w,scope,session);
    var authority=new EncryptedTemplate.Authority(guard.prior!,guard.now);var content=EncryptedTemplate.Open(scope,wire,recipient,()=>authority);
    ClientLive();guard.Live(w);Need(pk.SequenceEqual(point()));guard.Authorize(w,scope,session);var preview=content.Preview();guard.Authorize(w,scope,session);ClientLive();Need(pk.SequenceEqual(point()));guard.Live(w);
    return new OpenedPreview(preview,TemplateStore.Number(scope.Aad(),94),snapshot.EncryptedDigest,snapshot.MatchesPending);
   }catch{Dispose();throw;}finally{if(wire is not null)CryptographicOperations.ZeroMemory(wire);}});ClientLive();return result;
   }catch(Exception error){Dispose();throw error as Failure??new Failure("refused");}
  }
  public OpenedPreview OpenLatest(ProtectedRecipient recipient)=>Open(recipient.PublicPoint,recipient);
  /// <summary>Explicit software custody; no protected-key claim.</summary>
  public OpenedPreview OpenLatestSoftware(ECDiffieHellman key)=>Open(()=>{var p=key.ExportParameters(false);return new byte[]{4}.Concat(p.Q.X!).Concat(p.Q.Y!).ToArray();},HpkeRecipient.SoftwareContent(key));
 }
}

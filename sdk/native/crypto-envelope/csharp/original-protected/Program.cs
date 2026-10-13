using System.Security.Cryptography;
using System.Text;
using Zrotext.Candidate;
if(args.Length==1 && args[0]=="--probe"){try{ProtectedRecipient.Probe();}catch(Exception e)when(e is CryptographicException or PlatformNotSupportedException){return 77;}return 0;}
if(args.Length!=1)throw new ArgumentException("Pending receipt required");string receipt=args[0];ProtectedRecipient? owner=null;int checks=0;
void Refuse(Action action){try{action();}catch(Exception e)when(e is CryptographicException or ArgumentException){checks++;return;}throw new Exception("Expected refusal");}
try{
    owner=ProtectedRecipient.Create(alias=>{using var stream=new FileStream(receipt,FileMode.CreateNew,FileAccess.Write,FileShare.None,4096,FileOptions.WriteThrough);stream.Write(Encoding.UTF8.GetBytes(alias+"\n"));stream.Flush(true);});Console.WriteLine(Convert.ToHexString(owner.PublicPoint()));Console.Out.Flush();
    var f=new Dictionary<string,byte[]>();string? line;while((line=Console.ReadLine()) is not null){var v=line.Split('\t');f[v[0]]=Convert.FromHexString(v[1]);}if(f.ContainsKey("originalScalar"))throw new Exception("Native scalar present");
    var prior=ManifestChain.Genesis02(f["predecessor"],ManifestChain.RootPin.Enroll(f["rootPin"],f["fingerprint"]),10000);var active=ManifestChain.ContinueChain(f["activation"],prior,2,10000);var successor=ManifestChain.ContinueChain(f["successor"],active,2,10000);var revoked=ManifestChain.ContinueChain(f["revoked"],active,2,10000);
    var scope=new OriginalReplyReader.Scope(f["account"],f["device"],f["line"],f["interval"],f["connector"],f["readGrant"],f["originalReader"],"+12");var selection=OriginalReplyReader.VerifySelection(f["selection"],f["approval"],f["installation"],active,10000,scope);string expected=Encoding.UTF8.GetString(f["text"]);
    OriginalReplyReader.Authority Authority(ManifestChain.Verified m)=>new(scope,"1",10000,20000,m);
    string Open(ProtectedRecipient key,Func<OriginalReplyReader.Authority> source)=>key.OpenOriginalReply02(f["inbound"],f["event"],active,selection,scope,source);
    foreach(var current in new[]{active,successor}){int count=0;if(Open(owner,()=>{count++;return Authority(current);})!=expected || count!=2)throw new Exception("Native opening");checks++;}
    string name=owner.Alias;var point=owner.PublicPoint();var reopened=ProtectedRecipient.Open(name,point);
    using(reopened){if(Open(reopened,()=>Authority(active))!=expected)throw new Exception("Reopened");checks++;Refuse(reopened.DeleteCreated);}
    Refuse(()=>Open(reopened,()=>Authority(active)));Refuse(()=>Open(owner,()=>Authority(revoked)));
    int calls=0;Refuse(()=>Open(owner,()=>++calls==1?Authority(active):Authority(active) with{Revision="2"}));if(calls!=2)throw new Exception("Final check");
    using var wrong=ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);var q=wrong.ExportParameters(false).Q;var bad=new byte[65];bad[0]=4;q.X!.CopyTo(bad,1);q.Y!.CopyTo(bad,33);Refuse(()=>{using var ignored=ProtectedRecipient.Open(name,bad);});
    owner.DeleteCreated();owner=null;File.Delete(receipt);Refuse(()=>{using var ignored=ProtectedRecipient.Open(name,point);});Console.WriteLine($"QUALIFIED: C# protected original reply {checks} controls passed");return 0;
}finally{if(owner is not null){owner.DeleteCreated();File.Delete(receipt);owner.Dispose();}}

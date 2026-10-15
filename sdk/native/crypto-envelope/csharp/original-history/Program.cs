using System.Security.Cryptography;
using System.Text;
using Zrotext.Candidate;
string mode=args[0],path=args[1];var f=new Dictionary<string,byte[]>();string? line;while((line=Console.ReadLine()) is not null){var v=line.Split('\t');f[v[0]]=Convert.FromHexString(v[1]);}
var scope=new OriginalReplyReader.Scope(f["account"],f["device"],f["line"],f["interval"],f["connector"],f["readGrant"],f["originalReader"],"+12");
var prior=ManifestChain.Genesis02(f["predecessor"],ManifestChain.RootPin.Enroll(f["rootPin"],f["fingerprint"]),10000);var active=ManifestChain.ContinueChain(f["activation"],prior,2,10000);var successor=ManifestChain.ContinueChain(f["successor"],active,2,10000);var revoked=ManifestChain.ContinueChain(f["revoked"],active,2,10000);var history=new[]{prior,active,successor};int checks=0;
void Refuse(Action action){try{action();}catch(Exception e)when(e is CryptographicException or IOException or ArgumentException){checks++;return;}throw new Exception("Expected history refusal");}
OriginalReplyCheckpoint Open(string? target=null,OriginalReplyReader.Scope? s=null)=>OriginalReplyCheckpoint.Open(target??path,f["rootPin"],f["fingerprint"],s??scope);
if(mode=="--partial"){using var file=new FileStream(path,FileMode.Append,FileAccess.Write,FileShare.None);file.Write(new byte[]{0,0});file.Flush(true);Environment.Exit(19);}
if(mode=="--advance"){var journal=Open();try{journal.Accept(scope,history,3,10006,(m,n)=>n);Console.WriteLine("CAS won");}catch(CryptographicException){return 3;}return 0;}
if(mode=="--verify"){if(Open().ReadSnapshot(scope,10006).Revision!=4)throw new Exception("Child CAS state");Console.WriteLine("Restart CAS verified");return 0;}
if(mode=="--refused"){Refuse(()=>Open());Console.WriteLine("Interrupted append refused");return 0;}
Refuse(()=>Open());var j=OriginalReplyCheckpoint.Create(path,f["rootPin"],f["fingerprint"],scope,new[]{prior,active},10000);Refuse(()=>OriginalReplyCheckpoint.Create(path,f["rootPin"],f["fingerprint"],scope,new[]{prior,active},10000));
var wrong=(byte[])f["readGrant"].Clone();wrong[0]^=1;var wrongScope=new OriginalReplyReader.Scope(f["account"],f["device"],f["line"],f["interval"],f["connector"],wrong,f["originalReader"],"+12");Refuse(()=>Open(path,wrongScope));Refuse(()=>j.ReadSnapshot(scope,9999));Refuse(()=>j.ReadSnapshot(scope,long.MaxValue));
var read=j.ReadSnapshot(scope,10001);if(read.Revision!=1 || read.ComparisonMs!=10000)throw new Exception("Snapshot mutated floor");checks++;
Refuse(()=>j.Accept(scope,history,0,10001,(m,n)=>throw new Exception("CAS before fence")));Refuse(()=>j.Accept(scope,history,1,10001,(m,n)=>throw new CryptographicException("Fence refused")));Refuse(()=>j.Accept(scope,history,1,10001,(m,n)=>9999));Refuse(()=>j.Accept(scope,history,1,10001,(m,n)=>long.MaxValue));
if(j.ReadSnapshot(scope,10000).Revision!=1)throw new Exception("Failed fence committed");checks++;
var next=j.Accept(scope,history,1,10002,(m,n)=>10003);if(next.Revision!=2 || next.ComparisonMs!=10003)throw new Exception("Advance");checks++;
Refuse(()=>j.ReadSnapshot(scope,10002));Refuse(()=>j.Accept(scope,new[]{prior,active,revoked},2,10003,(m,n)=>n));Refuse(()=>j.Accept(scope,new[]{prior,active},2,10003,(m,n)=>n));
var reopened=Open();var restored=reopened.ReadSnapshot(scope,10004).History;var selection=OriginalReplyReader.VerifySelection(f["selection"],f["approval"],f["installation"],restored[1],10000,scope);
using var key=ECDiffieHellman.Create(new ECParameters{Curve=ECCurve.NamedCurves.nistP256,D=f["originalScalar"]});var committed=reopened.Accept(scope,history,2,10004,(m,n)=>10005);
string plain=OriginalReplyReader.OpenSoftware(f["inbound"],f["event"],restored[1],selection,scope,key,()=>new OriginalReplyReader.Authority(scope,"1",10005,20000,committed.History[2]));if(plain!=Encoding.UTF8.GetString(f["text"]))throw new Exception("Restored opening");checks++;
var bytes=File.ReadAllBytes(path);string bad=path+".bad";foreach(int at in new[]{0,4,98,130,161,162,166,174,182,bytes.Length-33,bytes.Length-1}){var copy=(byte[])bytes.Clone();copy[at]^=1;File.WriteAllBytes(bad,copy);Refuse(()=>Open(bad));}File.Delete(bad);Refuse(()=>reopened.ReadSnapshot(scope,10004));Console.WriteLine($"C# original history {checks} controls passed");return 0;

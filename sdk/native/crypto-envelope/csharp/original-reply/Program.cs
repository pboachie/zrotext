using System;
using System.Collections.Generic;
using System.Numerics;
using System.Security.Cryptography;
using System.Text;
using Zrotext.Candidate;

var f=new Dictionary<string,byte[]>();string? line;while((line=Console.ReadLine()) is not null){var v=line.Split('\t');f[v[0]]=Convert.FromHexString(v[1]);}
var prior=ManifestChain.Genesis02(f["predecessor"],ManifestChain.RootPin.Enroll(f["rootPin"],f["fingerprint"]),10000);
var active=ManifestChain.ContinueChain(f["activation"],prior,2,10000);var successor=ManifestChain.ContinueChain(f["successor"],active,2,10000);var revoked=ManifestChain.ContinueChain(f["revoked"],active,2,10000);
var scope=new OriginalReplyReader.Scope(f["account"],f["device"],f["line"],f["interval"],f["connector"],f["readGrant"],f["originalReader"],"+12");
var raw=f["selection"];var approval=f["approval"];var installation=f["installation"];var selection=OriginalReplyReader.VerifySelection(raw,approval,installation,active,10000,scope);int checks=0;
void Refuse(Action action){try{action();}catch(Exception e)when(e is CryptographicException or ArgumentException){checks++;return;}throw new Exception("Expected refusal");}
byte[] High(byte[] input){var b=(byte[])input.Clone();var order=new BigInteger(Convert.FromHexString("FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551"),true,true);var s=(order-new BigInteger(b.AsSpan(32,32),true,true)).ToByteArray(true,true);Array.Clear(b,32,32);s.CopyTo(b,64-s.Length);return b;}
for(int i=0;i<raw.Length;i++){var bad=(byte[])raw.Clone();bad[i]^=1;Refuse(()=>OriginalReplyReader.VerifySelection(bad,approval,installation,active,10000,scope));}
Refuse(()=>OriginalReplyReader.VerifySelection(raw,High(approval),installation,active,10000,scope));Refuse(()=>OriginalReplyReader.VerifySelection(raw,approval,High(installation),active,10000,scope));
foreach(long when in new long[]{0,20000,long.MaxValue})Refuse(()=>OriginalReplyReader.VerifySelection(raw,approval,installation,active,when,scope));
Refuse(()=>OriginalReplyReader.VerifySelection(raw,approval,installation,prior,10000,scope));
var wrong=(byte[])f["connector"].Clone();wrong[0]^=1;var wrongScope=new OriginalReplyReader.Scope(f["account"],f["device"],f["line"],f["interval"],wrong,f["readGrant"],f["originalReader"],"+12");Refuse(()=>OriginalReplyReader.VerifySelection(raw,approval,installation,active,10000,wrongScope));
using var recipient=ECDiffieHellman.Create(new ECParameters{Curve=ECCurve.NamedCurves.nistP256,D=f["originalScalar"]});string text=Encoding.UTF8.GetString(f["text"]);
OriginalReplyReader.Authority Authority(ManifestChain.Verified m)=>new(scope,"1",10000,20000,m);
foreach(var current in new[]{active,successor}){int calls=0;string value=OriginalReplyReader.OpenSoftware(f["inbound"],f["event"],active,selection,scope,recipient,()=>{calls++;return Authority(current);});if(value!=text || calls!=2)throw new Exception("Open");checks++;}
foreach(var after in new[]{Authority(active) with{Revision="2"},Authority(active) with{NowMs=9999},Authority(active) with{NowMs=20000},Authority(active) with{ExpiresMs=10000},Authority(active) with{Scope=wrongScope},Authority(successor),Authority(revoked)}){int calls=0;Refuse(()=>OriginalReplyReader.OpenSoftware(f["inbound"],f["event"],active,selection,scope,recipient,()=>++calls==1?Authority(active):after));if(calls!=2)throw new Exception("Final callback missing");}
foreach(string name in new[]{"archiveOnly","inbound"}){int calls=0;Refuse(()=>OriginalReplyReader.OpenSoftware(f[name],f["event"],active,selection,scope,recipient,()=>{calls++;return Authority(name=="inbound"?revoked:active);}));if(calls!=1)throw new Exception("Early refusal");}
var badEvent=(byte[])f["event"].Clone();badEvent[0]^=1;Refuse(()=>OriginalReplyReader.OpenSoftware(f["inbound"],badEvent,active,selection,scope,recipient,()=>throw new Exception("Wrong event called source")));
using var wrongKey=ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);Refuse(()=>OriginalReplyReader.OpenSoftware(f["inbound"],f["event"],active,selection,scope,wrongKey,()=>Authority(active)));
raw[0]^=1;approval[0]^=1;installation[0]^=1;f["account"][0]^=1;if(OriginalReplyReader.OpenSoftware(f["inbound"],f["event"],active,selection,scope,recipient,()=>Authority(active))!=text)throw new Exception("Aliased proof");
Console.WriteLine($"C# original replies: {checks} controls passed");

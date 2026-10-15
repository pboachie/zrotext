using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace Zrotext.Candidate;

public sealed partial class OriginalCurrentClient
{
    /// <summary>Immutable canonical binding; its digest grants no permission.</summary>
    public sealed class WorkflowAction
    {
        private static readonly string[] Names=["account_id","action_id","authority_generation","commitment","content_digest","content_ref","content_version","expires_at","line_id","not_before","purpose_id","recipient_id","revision","routine_id","timezone","window_id"];
        private static readonly HashSet<string> Numbers=["authority_generation","content_version","expires_at","not_before","revision"];
        private readonly string canonical;private readonly JsonElement fields;
        private WorkflowAction(string canonical,JsonElement fields){this.canonical=canonical;this.fields=fields.Clone();}
        private static string Quote(string value)
        {
            var b=new StringBuilder("\"");foreach(char c in value)switch(c){
                case '"':b.Append("\\\"");break;case '\\':b.Append("\\\\");break;case '\b':b.Append("\\b");break;case '\t':b.Append("\\t");break;case '\n':b.Append("\\n");break;case '\f':b.Append("\\f");break;case '\r':b.Append("\\r");break;
                default:if(c<32 || c==127)b.Append("\\u").Append(((int)c).ToString("x4",CultureInfo.InvariantCulture));else b.Append(c);break;
            }return b.Append('"').ToString();
        }
        public static WorkflowAction Parse(string raw)
        {
            try {
                Need(raw.Length<=4096);using var doc=JsonDocument.Parse(raw,new JsonDocumentOptions{MaxDepth=4});var fields=Exact(doc.RootElement,Names);var b=new StringBuilder("{");
                foreach(string name in Names){if(b.Length>1)b.Append(',');b.Append(Quote(name)).Append(':');var v=fields.GetProperty(name);
                    if(Numbers.Contains(name)){Need(v.ValueKind==JsonValueKind.Number);double n=v.GetDouble();Need(double.IsFinite(n) && n==Math.Truncate(n) && n>=(name=="not_before"?0:1) && n<=9007199254740991L);b.Append(((long)n).ToString(CultureInfo.InvariantCulture));}
                    else{string value=Text(v);Need(value.Length>=1 && value.Length<=128 && value.All(c=>c<=127));b.Append(Quote(value));}
                }
                b.Append('}');using var normalized=JsonDocument.Parse(b.ToString());var f=normalized.RootElement;
                Need(System.Text.RegularExpressions.Regex.IsMatch(Text(f.GetProperty("content_digest")),"\\A[0-9a-f]{64}\\z") && f.GetProperty("not_before").GetInt64()<f.GetProperty("expires_at").GetInt64() && Text(f.GetProperty("commitment")) is "informational" or "sensitive");
                return new WorkflowAction(b.ToString(),f);
            } catch {throw new OriginalHttp.Failure();}
        }
        public string Canonical=>canonical;
        public string Digest=>Convert.ToHexString(SHA256.HashData(Encoding.ASCII.GetBytes(canonical))).ToLowerInvariant();
        internal string Value(string name)=>Text(fields.GetProperty(name));
        internal long Revision=>fields.GetProperty("revision").GetInt64();
        internal void Production(){foreach(string name in new[]{"account_id","action_id","line_id","recipient_id","purpose_id","content_ref","routine_id"}){string s=Value(name);Need(System.Text.RegularExpressions.Regex.IsMatch(s,"\\A[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\\z") && s!="00000000-0000-0000-0000-000000000000");}Need(Revision<=128);}
    }
    public sealed class ProposalIntent
    {
        private readonly byte[] record;public WorkflowAction Descriptor {get;}
        internal ProposalIntent(object permit,byte[] record,WorkflowAction descriptor){Need(ReferenceEquals(permit,Permit));this.record=(byte[])record.Clone();Descriptor=descriptor;}
        public byte[] Bytes()=>(byte[])record.Clone();
    }
    public sealed class ProposalResult
    {
        private readonly byte[] eventId,consumption,active;
        public byte[] Event=>(byte[])eventId.Clone();public byte[] Consumption=>(byte[])consumption.Clone();public byte[] ActiveRequest=>(byte[])active.Clone();
        public Verified Authority {get;}public WorkflowAction? Action {get;}
        internal ProposalResult(object permit,byte[] eventId,byte[] consumption,byte[] active,Verified authority,WorkflowAction? action){Need(ReferenceEquals(permit,Permit));this.eventId=(byte[])eventId.Clone();this.consumption=(byte[])consumption.Clone();this.active=(byte[])active.Clone();Authority=authority;Action=action;}
    }
    // No network or persistence. Caller must sync these bytes before an effect.
    public ProposalIntent PrepareProposal(byte[] eventId,byte[] request,byte[] active,WorkflowAction descriptor)
    {
        try{descriptor.Production();var prefix=PrepareOwnerReview(eventId,request,OwnerId(active)).Bytes();var json=Encoding.ASCII.GetBytes(descriptor.Canonical);var raw=new byte[151+json.Length];prefix.CopyTo(raw,0);raw[3]=80;json.CopyTo(raw,151);return RestoreProposal(raw);}catch{throw new OriginalHttp.Failure();}
    }
    public ProposalIntent RestoreProposal(byte[] input)
    {
        try{
            var raw=(byte[])input.Clone();Need(raw.Length>151 && raw.Length<=4096 && raw.AsSpan(0,5).SequenceEqual(new byte[]{90,84,79,80,1}) && raw[134]==1);var prefix=raw[..151];prefix[3]=82;RestoreOwnerReview(prefix);
            var json=raw[151..];var descriptor=WorkflowAction.Parse(new UTF8Encoding(false,true).GetString(json));descriptor.Production();Need(Same(json,Encoding.ASCII.GetBytes(descriptor.Canonical)) && descriptor.Value("account_id")==OwnerUuid(scope.Account) && descriptor.Value("line_id")==OwnerUuid(scope.Line));return new ProposalIntent(Permit,raw,descriptor);
        }catch{throw new OriginalHttp.Failure();}
    }
    public Task<ProposalResult> ConsumeProposalAsync(string credential,string output,ProposalIntent intent,Func<long> clock,CancellationToken cancellation=default)=>ProposalAsync(credential,output,intent,clock,true,cancellation);
    public Task<ProposalResult> StatusProposalAsync(string credential,ProposalIntent intent,Func<long> clock,CancellationToken cancellation=default)=>ProposalAsync(credential,null,intent,clock,false,cancellation);
    private async Task<ProposalResult> ProposalAsync(string credential,string? output,ProposalIntent intent,Func<long> clock,bool effect,CancellationToken cancellation)
    {
        bool acquired=false,dispatched=false;
        try{
            Need(clock is not null);var owned=RestoreProposal(intent.Bytes());var descriptor=owned.Descriptor;var raw=owned.Bytes();if(effect)OriginalHttp.OutputCredential(output!);Need(gate.Wait(0));acquired=true;
            var before=await CurrentLockedAsync(credential,clock!,cancellation).ConfigureAwait(false);var eventId=raw[102..118];var request=raw[118..134];var active=raw[135..151];
            var req=effect?new OriginalHttp.Request("consume",before.Authority.Manifest.Version,EventId:OwnerUuid(eventId),RequestId:OwnerUuid(request),ActiveRequestId:OwnerUuid(active)):new OriginalHttp.Request("status",before.Authority.Manifest.Version,ConsumptionId:OwnerUuid(request));
            var wire=effect?await transport.ExchangeProposalAsync(credential,output!,req,descriptor.Canonical,cancellation).ConfigureAwait(false):await transport.ExchangeAsync(credential,req,cancellation).ConfigureAwait(false);dispatched=effect;
            using var json=JsonDocument.Parse(wire.UntrustedJson,new JsonDocumentOptions{MaxDepth=64});var r=Exact(json.RootElement,"event_id","consumption_id","disposition","active_request_id","action");Need(Text(r.GetProperty("event_id"))==OwnerUuid(eventId) && Text(r.GetProperty("consumption_id"))==OwnerUuid(request) && Text(r.GetProperty("active_request_id"))==OwnerUuid(active));
            WorkflowAction? action=null;
            if(Text(r.GetProperty("disposition"))=="owner_review")Need(r.GetProperty("action").ValueKind==JsonValueKind.Null);
            else{Need(Text(r.GetProperty("disposition"))=="proposal");var a=Exact(r.GetProperty("action"),"account_id","action_id","revision","binding_digest");Need(Text(a.GetProperty("account_id"))==descriptor.Value("account_id") && Text(a.GetProperty("action_id"))==descriptor.Value("action_id") && Integer(a.GetProperty("revision"))==descriptor.Revision && Text(a.GetProperty("binding_digest"))==descriptor.Digest);action=descriptor;}
            var after=await CurrentLockedAsync(credential,clock!,cancellation).ConfigureAwait(false);return new ProposalResult(Permit,eventId,request,active,after,action);
        }catch(OriginalHttp.Failure error){throw new OriginalHttp.Failure(dispatched || error.Unknown);}
        catch{throw new OriginalHttp.Failure(dispatched);}
        finally{if(acquired)gate.Release();}
    }
}

using System.Text.Json;
using System.Text.RegularExpressions;

namespace Zrotext.Candidate;

public sealed partial class OriginalCurrentClient
{
    public sealed record PageCursor(string EventId,long AcceptedAtMs);
    public sealed record EventMetadata(string EventId,long AcceptedAtMs,long ObservedAtMs,long HistoricalManifestVersion,long ActivationManifestVersion,string Disposition,IReadOnlyList<string> ActiveRequestIds);
    public sealed class Page
    {
        public IReadOnlyList<EventMetadata> Events { get; }
        public PageCursor? Next { get; }
        public Verified Authority { get; }
        internal Page(object permit,List<EventMetadata> events,PageCursor? next,Verified authority)
        {
            Need(ReferenceEquals(permit,Permit));Events=events.AsReadOnly();Next=next;Authority=authority;
        }
    }
    private static string PageId(string text)
    {
        Need(Regex.IsMatch(text,"\\A[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\\z") && text!="00000000-0000-0000-0000-000000000000");return text;
    }
    private static PageCursor Cursor(string id,long time)=>new(PageId(id),Positive(time));
    // Discovery metadata only, never permission to consume or propose an action.
    public async Task<Page> PageAsync(string credential,PageCursor? cursor,int limit,Func<long> clock,CancellationToken cancellation=default)
    {
        bool acquired=false;
        try
        {
            Need(limit is >=1 and <=32 && clock is not null);var after=cursor is null?null:Cursor(cursor.EventId,cursor.AcceptedAtMs);
            Need(gate.Wait(0));acquired=true;var saved=SavedAt(clock!);var latest=saved.History[^1];
            var wire=await transport.ExchangeAsync(credential,new OriginalHttp.Request("page",latest.Version,Limit:limit,PageCursor:after is null?null:new OriginalHttp.Cursor(after.EventId,after.AcceptedAtMs)),cancellation).ConfigureAwait(false);
            using var json=JsonDocument.Parse(wire.UntrustedJson,new JsonDocumentOptions { MaxDepth=64 });var r=Exact(json.RootElement,"events","next","proof");
            var rows=r.GetProperty("events");Need(rows.ValueKind==JsonValueKind.Array && rows.GetArrayLength()<=limit);var events=new List<EventMetadata>();var ids=new HashSet<string>();
            foreach(var row in rows.EnumerateArray())
            {
                var e=Exact(row,"event_id","accepted_at_ms","observed_at_ms","historical_manifest_version","activation_manifest_version","disposition","active_request_ids");
                string id=PageId(Text(e.GetProperty("event_id")));Need(ids.Add(id));
                long accepted=Integer(e.GetProperty("accepted_at_ms")),observed=Integer(e.GetProperty("observed_at_ms")),historical=Integer(e.GetProperty("historical_manifest_version")),activation=Integer(e.GetProperty("activation_manifest_version"));
                Need(after is null || accepted>after.AcceptedAtMs || (accepted==after.AcceptedAtMs && string.CompareOrdinal(id,after.EventId)>0));after=Cursor(id,accepted);
                string disposition=Text(e.GetProperty("disposition"));Need(disposition is "unassociated" or "owner_review" or "request_available");
                var requests=e.GetProperty("active_request_ids");Need(requests.ValueKind==JsonValueKind.Array && requests.GetArrayLength()<=8);var unique=new HashSet<string>();var captured=new List<string>();
                foreach(var request in requests.EnumerateArray()){string rid=PageId(Text(request));Need(unique.Add(rid));captured.Add(rid);}
                events.Add(new(id,accepted,observed,historical,activation,disposition,captured.AsReadOnly()));
            }
            PageCursor? next=null;
            if(r.GetProperty("next").ValueKind==JsonValueKind.Null)Need(events.Count<limit);
            else{var c=Exact(r.GetProperty("next"),"event_id","accepted_at_ms");next=Cursor(Text(c.GetProperty("event_id")),Integer(c.GetProperty("accepted_at_ms")));Need(events.Count==limit && next==after);}
            return new Page(Permit,events,next,AcceptProof(r.GetProperty("proof"),saved,latest,clock!,cancellation));
        }
        catch { throw new OriginalHttp.Failure(); }
        finally { if(acquired)gate.Release(); }
    }
}

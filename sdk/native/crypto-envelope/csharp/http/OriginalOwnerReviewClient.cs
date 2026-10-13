using System.Text.Json;

namespace Zrotext.Candidate;

public sealed partial class OriginalCurrentClient
{
    public sealed class OwnerReviewIntent
    {
        private readonly byte[] record;
        internal OwnerReviewIntent(object permit,byte[] record){Need(ReferenceEquals(permit,Permit));this.record=(byte[])record.Clone();}
        public byte[] Bytes()=>(byte[])record.Clone();
    }
    public sealed class OwnerReviewResult
    {
        private readonly byte[] eventId,consumption;
        private readonly byte[]? active;
        public byte[] Event=>(byte[])eventId.Clone();
        public byte[] Consumption=>(byte[])consumption.Clone();
        public byte[]? ActiveRequest=>active is null?null:(byte[])active.Clone();
        public Verified Authority { get; }
        internal OwnerReviewResult(object permit,byte[] eventId,byte[] consumption,byte[]? active,Verified authority)
        {Need(ReferenceEquals(permit,Permit));this.eventId=(byte[])eventId.Clone();this.consumption=(byte[])consumption.Clone();this.active=active is null?null:(byte[])active.Clone();Authority=authority;}
    }
    private static byte[] OwnerId(byte[] value){Need(value.Length==16);var owned=(byte[])value.Clone();Need(owned.Any(b=>b!=0));return owned;}
    private static string OwnerUuid(byte[] bytes){string h=Convert.ToHexString(bytes).ToLowerInvariant();return $"{h[..8]}-{h[8..12]}-{h[12..16]}-{h[16..20]}-{h[20..]}";}
    // No network or persistence. Caller must sync these bytes before effect dispatch.
    public OwnerReviewIntent PrepareOwnerReview(byte[] eventId,byte[] request,byte[]? activeRequest=null)
    {
        try {
            eventId=OwnerId(eventId);request=OwnerId(request);var active=activeRequest is null?null:OwnerId(activeRequest);
            var raw=new byte[151];new byte[]{90,84,79,82,1}.CopyTo(raw,0);root.Point.CopyTo(raw,5);scope.CheckpointBinding().CopyTo(raw,70);eventId.CopyTo(raw,102);request.CopyTo(raw,118);
            if(active is not null){raw[134]=1;active.CopyTo(raw,135);}return RestoreOwnerReview(raw);
        } catch {throw new OriginalHttp.Failure();}
    }
    public OwnerReviewIntent RestoreOwnerReview(byte[] input)
    {
        try {
            var raw=(byte[])input.Clone();Need(raw.Length==151 && raw.AsSpan(0,5).SequenceEqual(new byte[]{90,84,79,82,1}) && Same(raw[5..70],root.Point) && Same(raw[70..102],scope.CheckpointBinding()));
            OwnerId(raw[102..118]);OwnerId(raw[118..134]);Need(raw[134]<=1 && (raw[134]==0)==raw[135..].All(b=>b==0));return new OwnerReviewIntent(Permit,raw);
        } catch {throw new OriginalHttp.Failure();}
    }
    public Task<OwnerReviewResult> ConsumeOwnerReviewAsync(string credential,OwnerReviewIntent intent,Func<long> clock,CancellationToken cancellation=default)=>OwnerReviewAsync(credential,intent,clock,true,cancellation);
    // Status never consumes; unavailable never establishes absence of an earlier effect.
    public Task<OwnerReviewResult> StatusOwnerReviewAsync(string credential,OwnerReviewIntent intent,Func<long> clock,CancellationToken cancellation=default)=>OwnerReviewAsync(credential,intent,clock,false,cancellation);
    private async Task<OwnerReviewResult> OwnerReviewAsync(string credential,OwnerReviewIntent intent,Func<long> clock,bool effect,CancellationToken cancellation)
    {
        bool acquired=false,dispatched=false;
        try {
            Need(clock is not null);byte[] owned=RestoreOwnerReview(intent.Bytes()).Bytes();Need(gate.Wait(0));acquired=true;
            var before=await CurrentLockedAsync(credential,clock!,cancellation).ConfigureAwait(false);byte[] eventId=owned[102..118],request=owned[118..134];byte[]? active=owned[134]==1?owned[135..]:null;
            var req=effect?new OriginalHttp.Request("consume",before.Authority.Manifest.Version,EventId:OwnerUuid(eventId),RequestId:OwnerUuid(request),ActiveRequestId:active is null?null:OwnerUuid(active)):new OriginalHttp.Request("status",before.Authority.Manifest.Version,ConsumptionId:OwnerUuid(request));
            var wire=await transport.ExchangeAsync(credential,req,cancellation).ConfigureAwait(false);dispatched=effect;
            using var json=JsonDocument.Parse(wire.UntrustedJson,new JsonDocumentOptions { MaxDepth=64 });var r=Exact(json.RootElement,"event_id","consumption_id","disposition","active_request_id","action");
            Need(Text(r.GetProperty("event_id"))==OwnerUuid(eventId) && Text(r.GetProperty("consumption_id"))==OwnerUuid(request) && Text(r.GetProperty("disposition"))=="owner_review" && r.GetProperty("action").ValueKind==JsonValueKind.Null);
            Need(active is null?r.GetProperty("active_request_id").ValueKind==JsonValueKind.Null:Text(r.GetProperty("active_request_id"))==OwnerUuid(active));
            var after=await CurrentLockedAsync(credential,clock!,cancellation).ConfigureAwait(false);return new OwnerReviewResult(Permit,eventId,request,active,after);
        } catch(OriginalHttp.Failure error){throw new OriginalHttp.Failure(dispatched || error.Unknown);}
        catch {throw new OriginalHttp.Failure(dispatched);}
        finally {if(acquired)gate.Release();}
    }
}

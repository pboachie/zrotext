using System.Security.Cryptography;
using System.Text.Json;

namespace Zrotext.Candidate;

public sealed partial class OriginalCurrentClient
{
    public sealed class Read
    {
        private readonly byte[] eventId, digest;
        public string Plaintext { get; }
        public byte[] Event => (byte[])eventId.Clone();
        public byte[] EnvelopeDigest => (byte[])digest.Clone();
        public long AcceptedManifestVersion { get; }
        public OriginalReplyReader.Authority Authority { get; }
        internal Read(object permit, string plaintext, byte[] eventId, byte[] digest, long baseline, OriginalReplyReader.Authority authority)
        {
            Need(ReferenceEquals(permit, Permit)); Plaintext=plaintext; this.eventId=(byte[])eventId.Clone(); this.digest=(byte[])digest.Clone(); AcceptedManifestVersion=baseline; Authority=authority;
        }
    }
    private delegate string Open(byte[] envelope, byte[] eventId, ManifestChain.Verified historical, OriginalReplyReader.Selection selection, Func<OriginalReplyReader.Authority> source);
    public Task<Read> ReadSoftwareAsync(string credential, byte[] eventId, ECDiffieHellman recipient, Func<long> clock, long baseline=0, CancellationToken cancellation=default)
        => ReadAsync(credential,eventId,clock,baseline,(e,id,h,s,source)=>OriginalReplyReader.OpenSoftware(e,id,h,s,scope,recipient,source),cancellation);
    public Task<Read> ReadProtectedAsync(string credential, byte[] eventId, ProtectedRecipient recipient, Func<long> clock, long baseline=0, CancellationToken cancellation=default)
        => ReadAsync(credential,eventId,clock,baseline,(e,id,h,s,source)=>recipient.OpenOriginalReply02(e,id,h,s,scope,source),cancellation);
    private static byte[] Encoded(JsonElement value, int maximum)
    {
        string text=Text(value); Need(text.Length<=((maximum+2)/3)*4); byte[] bytes=Convert.FromBase64String(text);
        Need(bytes.Length<=maximum && Convert.ToBase64String(bytes)==text); return bytes;
    }
    private async Task<Read> ReadAsync(string credential, byte[] eventId, Func<long> clock, long baseline, Open open, CancellationToken cancellation)
    {
        bool acquired=false;
        try
        {
            Need(clock is not null && gate.Wait(0)); acquired=true;
            Need(eventId.Length==16 && eventId.Any(b=>b!=0) && baseline>=0 && baseline<=Safe); eventId=(byte[])eventId.Clone();
            var saved=SavedAt(clock!); var latest=saved.History[^1];
            var first=saved.History.FirstOrDefault(m=>latest.Version-m.Version<32 && (baseline==0 || m.Version==baseline)); Need(first is not null);
            string hex=Convert.ToHexString(eventId).ToLowerInvariant(); string eventText=$"{hex[..8]}-{hex[8..12]}-{hex[12..16]}-{hex[16..20]}-{hex[20..]}";
            var wire=await transport.ExchangeAsync(credential,new OriginalHttp.Request("read",first!.Version,EventId:eventText),cancellation).ConfigureAwait(false);
            using var json=JsonDocument.Parse(wire.UntrustedJson,new JsonDocumentOptions { MaxDepth=64 });
            var r=Exact(json.RootElement,"event_id","accepted_at_ms","envelope_b64","historical_manifest_version","statement_b64","approval_signature_b64","installation_signature_b64","activation_manifest_version","proof");
            Need(Text(r.GetProperty("event_id"))==eventText); var initial=AcceptProof(r.GetProperty("proof"),saved,first,clock!,cancellation);
            var snap=checkpoint.ReadSnapshot(scope,last); if(snap.Revision!=revision){failed=true;Need(false);}
            long hv=Integer(r.GetProperty("historical_manifest_version")),av=Integer(r.GetProperty("activation_manifest_version")),accepted=Integer(r.GetProperty("accepted_at_ms"));
            Need(hv>=first.Version && accepted<=last+30000);
            var historical=snap.History.FirstOrDefault(m=>m.Version==hv); var activation=snap.History.FirstOrDefault(m=>m.Version==av); Need(historical is not null && activation is not null);
            activation=At(activation!.Bytes(),activation,accepted);
            var selection=OriginalReplyReader.VerifySelection(Encoded(r.GetProperty("statement_b64"),1536),Encoded(r.GetProperty("approval_signature_b64"),64),Encoded(r.GetProperty("installation_signature_b64"),64),activation,accepted,scope);
            byte[] envelope=Encoded(r.GetProperty("envelope_b64"),34082); var authority=initial.Authority; bool once=true;
            OriginalReplyReader.Authority Source()
            {
                cancellation.ThrowIfCancellationRequested();
                if(once)once=false;
                else authority=CurrentLockedAsync(credential,clock!,cancellation).GetAwaiter().GetResult().Authority;
                return authority;
            }
            string plaintext=open(envelope,eventId,historical!,selection,Source);
            cancellation.ThrowIfCancellationRequested(); return new Read(Permit,plaintext,eventId,SHA256.HashData(envelope),first.Version,authority);
        }
        catch { throw new OriginalHttp.Failure(); }
        finally { if(acquired)gate.Release(); }
    }
}

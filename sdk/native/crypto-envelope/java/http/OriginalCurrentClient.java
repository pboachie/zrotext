package org.zrotext.candidate;
import com.google.gson.*;
import java.security.*;
import java.util.*;
import java.util.concurrent.locks.ReentrantLock;
import java.util.function.LongSupplier;

/** Verified current snapshot after durable advancement; not perpetual authorization. */
public final class OriginalCurrentClient {
    public static final class Verified {
        private final OriginalReplyReader.Authority authority;
        private Verified(OriginalReplyReader.Authority authority){this.authority=authority;}
        public OriginalReplyReader.Authority authority(){return authority;}
    }
    private static final long SAFE=9007199254740991L;
    private static final String[] FIELDS={"account_id","interval_id","device_id","line_id","connector_id","read_grant_id","reader_id","root_generation","authority_revision","expires_at_ms","observed_at_ms","current_manifest_version","current_manifest_digest","manifest_chain"};
    private final OriginalHttp transport;
    private final OriginalReplyCheckpoint checkpoint;
    private final OriginalReplyReader.Scope scope;
    private final ManifestChain.RootPin root;
    private final ReentrantLock lock=new ReentrantLock();
    private long revision,last;
    private boolean failed;
    private static void need(boolean ok)throws OriginalHttp.Failure{if(!ok)throw new OriginalHttp.Failure(false);}
    private static long positive(long n)throws OriginalHttp.Failure{need(n>0 && n<=SAFE);return n;}
    private static long integer(JsonElement value)throws OriginalHttp.Failure{
        need(value!=null && value.isJsonPrimitive() && value.getAsJsonPrimitive().isNumber());
        String text=value.getAsString();need(text.matches("[1-9][0-9]{0,15}"));
        try{return positive(Long.parseLong(text));}catch(NumberFormatException error){throw new OriginalHttp.Failure(false);}
    }
    private static String string(JsonElement value)throws OriginalHttp.Failure{need(value!=null && value.isJsonPrimitive() && value.getAsJsonPrimitive().isString());return value.getAsString();}
    private static JsonObject object(JsonElement value,String... fields)throws OriginalHttp.Failure{
        need(value!=null && value.isJsonObject());JsonObject out=value.getAsJsonObject();need(out.keySet().equals(Set.of(fields)));return out;
    }
    private static boolean same(byte[] a,byte[] b){return MessageDigest.isEqual(a,b);}
    private static void uuid(JsonElement value,byte[] expected)throws OriginalHttp.Failure{
        String s=string(value);need(s.matches("[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}") && same(HexFormat.of().parseHex(s.replace("-","")),expected));
    }
    private ManifestChain.Verified at(byte[] input,ManifestChain.Verified prior,long time)throws GeneralSecurityException{return ManifestChain.originalAccepted02(input,root,prior,time);}
    public OriginalCurrentClient(OriginalHttp transport,OriginalReplyCheckpoint checkpoint,byte[] pin,byte[] fingerprint,OriginalReplyReader.Scope scope,long now)throws OriginalHttp.Failure{
        try{
            need(transport!=null && checkpoint!=null && scope!=null);positive(now);this.transport=transport;this.checkpoint=checkpoint;this.scope=scope;root=ManifestChain.RootPin.enroll(pin,fingerprint);
            var saved=checkpoint.snapshot(scope,now);var first=saved.history().get(0);at(first.bytes(),null,first.comparisonMs());revision=saved.revision();last=now;
        }catch(Exception error){throw new OriginalHttp.Failure(false);}
    }
    private long sample(LongSupplier clock)throws OriginalHttp.Failure{long now=positive(clock.getAsLong());need(now>=last);last=now;return now;}
    private static void fresh(long now,long observed,long expires)throws OriginalHttp.Failure{need(now<expires && now<=observed+30000 && observed<=now+30000);}
    public Verified current(String credential,LongSupplier clock)throws OriginalHttp.Failure{
        boolean acquired=false;
        try{
            need(clock!=null && !lock.isHeldByCurrentThread() && lock.tryLock());acquired=true;need(!failed);return currentLocked(credential,clock);
        }catch(Exception error){if(error instanceof InterruptedException)Thread.currentThread().interrupt();throw new OriginalHttp.Failure(false);}
        finally{if(acquired)lock.unlock();}
    }
    private Verified currentLocked(String credential,LongSupplier clock)throws Exception {
        need(!failed);var saved=savedAt(clock);var latest=saved.history().get(saved.history().size()-1);
        var wire=transport.exchange(credential,new OriginalHttp.Request("current",latest.version(),null,null,null,null,null,null));
        return acceptProof(JsonParser.parseString(wire.untrustedJson()),saved,latest,clock);
    }
    private OriginalReplyCheckpoint.Snapshot savedAt(LongSupplier clock)throws Exception{
        need(!failed);var saved=checkpoint.snapshot(scope,sample(clock));if(saved.revision()!=revision){failed=true;need(false);}return saved;
    }
    private Verified acceptProof(JsonElement value,OriginalReplyCheckpoint.Snapshot saved,ManifestChain.Verified first,LongSupplier clock)throws Exception {
            var p=object(value,FIELDS);long now=sample(clock);long observed=integer(p.get("observed_at_ms")),expires=integer(p.get("expires_at_ms"));fresh(now,observed,expires);
            byte[][] expected=scope.proofFields();String[] names={"account_id","device_id","line_id","interval_id","connector_id","read_grant_id"};
            for(int i=0;i<names.length;i++)uuid(p.get(names[i]),expected[i]);
            need(string(p.get("reader_id")).equals(HexFormat.of().formatHex(expected[6])) && integer(p.get("authority_revision"))==1);
            need(p.get("manifest_chain").isJsonArray());var chain=p.getAsJsonArray("manifest_chain");need(chain.size()>=1 && chain.size()<=32);
            var latest=saved.history().get(saved.history().size()-1);var history=new ArrayList<>(saved.history());var previous=first;
            for(int i=0;i<chain.size();i++){
                var entry=object(chain.get(i),"version","accepted_at_ms","manifest_b64");long version=integer(entry.get("version")),accepted=integer(entry.get("accepted_at_ms"));
                need(accepted<=now+30000 && version==(i==0?first.version():previous.version()+1));String encoded=string(entry.get("manifest_b64"));need(encoded.length()<=13004);
                byte[] bytes=Base64.getDecoder().decode(encoded);need(bytes.length<=9751 && Base64.getEncoder().encodeToString(bytes).equals(encoded));var current=at(bytes,previous,accepted);
                need(current.version()==version && current.generation()==latest.generation() && same(current.rootPoint(),latest.rootPoint()));
                var cached=saved.history().stream().filter(m->m.version()==version).findFirst();
                if(cached.isPresent())need(same(current.digest(),cached.get().digest()));else{need(version>latest.version());history.add(current);}previous=current;
            }
            need(previous.version()>=latest.version() && integer(p.get("current_manifest_version"))==previous.version() && integer(p.get("root_generation"))==latest.generation() && string(p.get("current_manifest_digest")).equals(HexFormat.of().formatHex(previous.digest())) && history.size()<=64);
            now=sample(clock);fresh(now,observed,expires);at(previous.bytes(),previous,now);
            OriginalReplyCheckpoint.Fence fence=(manifest,floor)->{
                try{long time=sample(clock);need(time>=floor);fresh(time,observed,expires);at(manifest.bytes(),manifest,time);return time;}
                catch(OriginalHttp.Failure error){throw new GeneralSecurityException("Original current refused");}
            };
            failed=true;var committed=checkpoint.accept(scope,history,revision,now,fence);long after=sample(clock);need(after>=committed.comparisonMs());fresh(after,observed,expires);
            var current=committed.history().get(committed.history().size()-1);at(current.bytes(),current,after);
            if(after>committed.comparisonMs())committed=checkpoint.accept(scope,committed.history(),committed.revision(),after,fence);
            revision=committed.revision();last=committed.comparisonMs();failed=false;current=committed.history().get(committed.history().size()-1);
            return new Verified(new OriginalReplyReader.Authority(scope,"1",last,expires,current));
    }

    public static final class Read {
        private final String plaintext;
        private final byte[] event,digest;
        private final long baseline;
        private final OriginalReplyReader.Authority authority;
        private Read(String text,byte[] event,byte[] digest,long baseline,OriginalReplyReader.Authority authority){this.plaintext=text;this.event=event.clone();this.digest=digest.clone();this.baseline=baseline;this.authority=authority;}
        public String plaintext(){return plaintext;}
        public byte[] event(){return event.clone();}
        public byte[] envelopeDigest(){return digest.clone();}
        public long acceptedManifestVersion(){return baseline;}
        public OriginalReplyReader.Authority authority(){return authority;}
    }
    private static byte[] encoded(JsonElement value,int maximum)throws OriginalHttp.Failure{
        String text=string(value);need(text.length()<=((maximum+2)/3)*4);byte[] out=Base64.getDecoder().decode(text);
        need(out.length<=maximum && Base64.getEncoder().encodeToString(out).equals(text));return out;
    }
    public Read readSoftware(String credential,byte[] event,PrivateKey recipient,LongSupplier clock,long baseline)throws OriginalHttp.Failure{
        return readWithRecipient(credential,event,HpkeRecipient.software(recipient),clock,baseline);
    }
    /** Injected recipients are trusted application code, not a custody claim. */
    public Read readWithRecipient(String credential,byte[] event,HpkeRecipient.Recipient recipient,LongSupplier clock,long baseline)throws OriginalHttp.Failure{
        boolean acquired=false;
        try{
            need(clock!=null && recipient!=null && !lock.isHeldByCurrentThread() && lock.tryLock());acquired=true;
            need(event!=null && event.length==16 && !same(event,new byte[16]) && baseline>=0 && baseline<=SAFE);event=event.clone();
            var saved=savedAt(clock);var latest=saved.history().get(saved.history().size()-1);
            var first=saved.history().stream().filter(m->latest.version()-m.version()<32 && (baseline==0 || baseline==m.version())).findFirst().orElseThrow();
            String hex=HexFormat.of().formatHex(event),eventText=hex.substring(0,8)+"-"+hex.substring(8,12)+"-"+hex.substring(12,16)+"-"+hex.substring(16,20)+"-"+hex.substring(20);
            var wire=transport.exchange(credential,new OriginalHttp.Request("read",first.version(),eventText,null,null,null,null,null));
            var r=object(JsonParser.parseString(wire.untrustedJson()),"event_id","accepted_at_ms","envelope_b64","historical_manifest_version","statement_b64","approval_signature_b64","installation_signature_b64","activation_manifest_version","proof");
            need(string(r.get("event_id")).equals(eventText));var initial=acceptProof(r.get("proof"),saved,first,clock);
            var snap=checkpoint.snapshot(scope,last);if(snap.revision()!=revision){failed=true;need(false);}
            long hv=integer(r.get("historical_manifest_version")),av=integer(r.get("activation_manifest_version")),accepted=integer(r.get("accepted_at_ms"));need(hv>=first.version() && accepted<=last+30000);
            var historical=snap.history().stream().filter(m->m.version()==hv).findFirst().orElseThrow();
            var activation=snap.history().stream().filter(m->m.version()==av).findFirst().orElseThrow();activation=at(activation.bytes(),activation,accepted);
            var selection=OriginalReplyReader.verifySelection(encoded(r.get("statement_b64"),1536),encoded(r.get("approval_signature_b64"),64),encoded(r.get("installation_signature_b64"),64),activation,accepted,scope);
            byte[] envelope=encoded(r.get("envelope_b64"),34082);OriginalReplyReader.Authority[] authority={initial.authority()};boolean[] once={true};
            OriginalReplyReader.AuthoritySource source=()->{
                if(once[0])once[0]=false;
                else try{authority[0]=currentLocked(credential,clock).authority();}catch(Exception error){if(error instanceof InterruptedException)Thread.currentThread().interrupt();throw new GeneralSecurityException("Original read refused");}
                return authority[0];
            };
            String plain=OriginalReplyReader.openWithRecipient(envelope,event,historical,selection,scope,recipient,source);
            return new Read(plain,event,MessageDigest.getInstance("SHA-256").digest(envelope),first.version(),authority[0]);
        }catch(Exception error){if(error instanceof InterruptedException)Thread.currentThread().interrupt();throw new OriginalHttp.Failure(false);}
        finally{if(acquired)lock.unlock();}
    }

    public record PageCursor(String eventId,long acceptedAtMs) {}
    public record EventMetadata(String eventId,long acceptedAtMs,long observedAtMs,long historicalManifestVersion,long activationManifestVersion,String disposition,List<String> activeRequestIds) {
        public EventMetadata { activeRequestIds=List.copyOf(activeRequestIds); }
    }
    public static final class Page {
        private final List<EventMetadata> events;private final PageCursor next;private final Verified authority;
        private Page(List<EventMetadata> events,PageCursor next,Verified authority){this.events=List.copyOf(events);this.next=next;this.authority=authority;}
        public List<EventMetadata> events(){return events;}
        public PageCursor next(){return next;}
        public Verified authority(){return authority;}
    }
    private static String pageId(JsonElement value)throws OriginalHttp.Failure{
        String text=string(value);need(text.matches("[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}") && !text.equals("00000000-0000-0000-0000-000000000000"));return text;
    }
    private static PageCursor pageCursor(String id,long time)throws OriginalHttp.Failure{return new PageCursor(pageId(new JsonPrimitive(id)),positive(time));}
    /** Discovery metadata only; no consumption or workflow authority. */
    public Page page(String credential,PageCursor cursor,int limit,LongSupplier clock)throws OriginalHttp.Failure{
        boolean acquired=false;
        try{
            need(limit>=1 && limit<=32 && clock!=null);PageCursor after=cursor==null?null:pageCursor(cursor.eventId(),cursor.acceptedAtMs());
            need(!lock.isHeldByCurrentThread() && lock.tryLock());acquired=true;var saved=savedAt(clock);var latest=saved.history().get(saved.history().size()-1);
            var wire=transport.exchange(credential,new OriginalHttp.Request("page",latest.version(),null,null,limit,after==null?null:new OriginalHttp.Cursor(after.eventId(),after.acceptedAtMs()),null,null));
            var r=object(JsonParser.parseString(wire.untrustedJson()),"events","next","proof");need(r.get("events").isJsonArray());var rows=r.getAsJsonArray("events");need(rows.size()<=limit);
            var events=new ArrayList<EventMetadata>();var ids=new HashSet<String>();
            for(var row:rows){
                var e=object(row,"event_id","accepted_at_ms","observed_at_ms","historical_manifest_version","activation_manifest_version","disposition","active_request_ids");
                String id=pageId(e.get("event_id"));need(ids.add(id));long accepted=integer(e.get("accepted_at_ms")),observed=integer(e.get("observed_at_ms")),historical=integer(e.get("historical_manifest_version")),activation=integer(e.get("activation_manifest_version"));
                var current=pageCursor(id,accepted);need(after==null || accepted>after.acceptedAtMs() || accepted==after.acceptedAtMs() && id.compareTo(after.eventId())>0);after=current;
                String disposition=string(e.get("disposition"));need(Set.of("unassociated","owner_review","request_available").contains(disposition));
                need(e.get("active_request_ids").isJsonArray());var requests=e.getAsJsonArray("active_request_ids");need(requests.size()<=8);var unique=new HashSet<String>();var captured=new ArrayList<String>();
                for(var request:requests){String rid=pageId(request);need(unique.add(rid));captured.add(rid);}
                events.add(new EventMetadata(id,accepted,observed,historical,activation,disposition,captured));
            }
            PageCursor next=null;
            if(r.get("next").isJsonNull())need(events.size()<limit);
            else{var c=object(r.get("next"),"event_id","accepted_at_ms");next=pageCursor(pageId(c.get("event_id")),integer(c.get("accepted_at_ms")));need(events.size()==limit && next.equals(after));}
            return new Page(events,next,acceptProof(r.get("proof"),saved,latest,clock));
        }catch(Exception error){if(error instanceof InterruptedException)Thread.currentThread().interrupt();throw new OriginalHttp.Failure(false);}
        finally{if(acquired)lock.unlock();}
    }

}

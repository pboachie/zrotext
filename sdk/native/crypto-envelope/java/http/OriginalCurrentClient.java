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
            need(clock!=null && !lock.isHeldByCurrentThread() && lock.tryLock());acquired=true;need(!failed);long now=sample(clock);
            var saved=checkpoint.snapshot(scope,now);if(saved.revision()!=revision){failed=true;need(false);}
            var latest=saved.history().get(saved.history().size()-1);
            var wire=transport.exchange(credential,new OriginalHttp.Request("current",latest.version(),null,null,null,null,null,null));
            var p=object(JsonParser.parseString(wire.untrustedJson()),FIELDS);now=sample(clock);long observed=integer(p.get("observed_at_ms")),expires=integer(p.get("expires_at_ms"));fresh(now,observed,expires);
            byte[][] expected=scope.proofFields();String[] names={"account_id","device_id","line_id","interval_id","connector_id","read_grant_id"};
            for(int i=0;i<names.length;i++)uuid(p.get(names[i]),expected[i]);
            need(string(p.get("reader_id")).equals(HexFormat.of().formatHex(expected[6])) && integer(p.get("authority_revision"))==1);
            need(p.get("manifest_chain").isJsonArray());var chain=p.getAsJsonArray("manifest_chain");need(chain.size()>=1 && chain.size()<=32);
            var history=new ArrayList<>(saved.history());var previous=latest;
            for(int i=0;i<chain.size();i++){
                var entry=object(chain.get(i),"version","accepted_at_ms","manifest_b64");long version=integer(entry.get("version")),accepted=integer(entry.get("accepted_at_ms"));
                need(accepted<=now+30000 && version==(i==0?latest.version():previous.version()+1));String encoded=string(entry.get("manifest_b64"));need(encoded.length()<=13004);
                byte[] bytes=Base64.getDecoder().decode(encoded);need(bytes.length<=9751 && Base64.getEncoder().encodeToString(bytes).equals(encoded));var current=at(bytes,previous,accepted);
                need(current.version()==version && current.generation()==latest.generation() && same(current.rootPoint(),latest.rootPoint()));
                if(i==0)need(same(current.digest(),latest.digest()));else history.add(current);previous=current;
            }
            need(integer(p.get("current_manifest_version"))==previous.version() && integer(p.get("root_generation"))==latest.generation() && string(p.get("current_manifest_digest")).equals(HexFormat.of().formatHex(previous.digest())) && history.size()<=64);
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
        }catch(Exception error){if(error instanceof InterruptedException)Thread.currentThread().interrupt();throw new OriginalHttp.Failure(false);}
        finally{if(acquired)lock.unlock();}
    }
}

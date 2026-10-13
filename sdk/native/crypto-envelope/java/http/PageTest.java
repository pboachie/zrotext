package org.zrotext.candidate;
import com.google.gson.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.*;
import java.util.function.*;

public final class PageTest {
    private PageTest() {}
    public static void main(String[] args)throws Exception {
        JsonObject input=JsonParser.parseString(new String(System.in.readAllBytes(),StandardCharsets.UTF_8)).getAsJsonObject(),f=input.getAsJsonObject("Fixture");
        Function<String,byte[]> b=name->Base64.getDecoder().decode(f.get(name).getAsString());
        var root=ManifestChain.RootPin.enroll(b.apply("rootPin"),b.apply("fingerprint"));
        var prior=ManifestChain.genesis02(b.apply("predecessor"),root,10000);var active=ManifestChain.continueChain(b.apply("activation"),prior,2,10000);
        var scope=new OriginalReplyReader.Scope(b.apply("account"),b.apply("device"),b.apply("line"),b.apply("interval"),b.apply("connector"),b.apply("readGrant"),b.apply("originalReader"),"+12");
        Path folder=Files.createTempDirectory("zrotext-managed-current-"),path=folder.resolve("history.dat");
        try {
            var checkpoint=OriginalReplyCheckpoint.create(path,b.apply("rootPin"),b.apply("fingerprint"),scope,List.of(prior,active),10000);
            var transport=new OriginalHttp(input.get("Origin").getAsString(),1000,input.get("Roots").getAsString());
            var client=new OriginalCurrentClient(transport,checkpoint,b.apply("rootPin"),b.apply("fingerprint"),scope,10000);
            int[] index={0};JsonArray times=input.getAsJsonArray("Clock");
            LongSupplier clock=()->{
                try {
                    if(index[0]==0){
                        try{client.current(input.get("Grant").getAsString(),()->10000);throw new AssertionError("Reentrant current accepted");}
                        catch(OriginalHttp.Failure expected){/* Must fail before another request. */}
                    }
                    long time=times.get(Math.min(index[0],times.size()-1)).getAsLong();index[0]++;return time;
                }catch(Exception error){throw new IllegalStateException("Fixture clock setup refused");}
            };
            OriginalCurrentClient.PageCursor cursor=null;
            if(!input.get("Cursor").isJsonNull()){
                var c=input.getAsJsonObject("Cursor");byte[] id=new byte[16];for(int i=0;i<16;i++)id[i]=c.getAsJsonArray("Event").get(i).getAsByte();String h=HexFormat.of().formatHex(id);cursor=new OriginalCurrentClient.PageCursor(h.substring(0,8)+"-"+h.substring(8,12)+"-"+h.substring(12,16)+"-"+h.substring(16,20)+"-"+h.substring(20),c.get("AcceptedAt").getAsLong());
            }
            JsonObject result=new JsonObject();result.addProperty("ok",false);
            try{
                var value=client.page(input.get("Grant").getAsString(),cursor,input.get("Limit").getAsInt(),clock);result.addProperty("ok",true);result.addProperty("now",value.authority().authority().nowMs());result.addProperty("version",value.authority().authority().manifest().version());
                var events=new JsonArray();for(var row:value.events()){var r=new JsonObject();r.addProperty("event",row.eventId().replace("-",""));r.addProperty("at",row.acceptedAtMs());r.addProperty("observed",row.observedAtMs());r.addProperty("historical",row.historicalManifestVersion());r.addProperty("activation",row.activationManifestVersion());r.addProperty("disposition",row.disposition());var ids=new JsonArray();for(var id:row.activeRequestIds())ids.add(id.replace("-",""));r.add("requests",ids);events.add(r);}result.add("events",events);
                if(value.next()==null)result.add("next",JsonNull.INSTANCE);else{var c=new JsonObject();c.addProperty("event",value.next().eventId().replace("-",""));c.addProperty("at",value.next().acceptedAtMs());result.add("next",c);}
            }catch(OriginalHttp.Failure expected){/* Only operation under test may refuse. */}
            var reopened=OriginalReplyCheckpoint.open(path,b.apply("rootPin"),b.apply("fingerprint"),scope);var saved=reopened.snapshot(scope,50000);
            result.addProperty("revision",saved.revision());result.addProperty("floor",saved.comparisonMs());result.addProperty("history",saved.history().size());result.addProperty("rollback_refused",false);
            try{reopened.snapshot(scope,saved.comparisonMs()-1);}catch(java.security.GeneralSecurityException expected){result.addProperty("rollback_refused",true);}
            System.out.println(result);
        }finally{Files.deleteIfExists(path);Files.deleteIfExists(folder);}
    }
}

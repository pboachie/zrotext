package org.zrotext.candidate;
import com.google.gson.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.*;
import java.util.function.*;

public final class CurrentTest {
    private CurrentTest() {}
    public static void main(String[] args)throws Exception {
        JsonObject input=JsonParser.parseString(new String(System.in.readAllBytes(),StandardCharsets.UTF_8)).getAsJsonObject(),f=input.getAsJsonObject("Fixture");
        Function<String,byte[]> b=name->Base64.getDecoder().decode(f.get(name).getAsString());
        var root=ManifestChain.RootPin.enroll(b.apply("rootPin"),b.apply("fingerprint"));
        var prior=ManifestChain.genesis02(b.apply("predecessor"),root,10000);var active=ManifestChain.continueChain(b.apply("activation"),prior,2,10000);
        var scope=new OriginalReplyReader.Scope(b.apply("account"),b.apply("device"),b.apply("line"),b.apply("interval"),b.apply("connector"),b.apply("readGrant"),b.apply("originalReader"),"+12");
        Path folder=Files.createTempDirectory("zrotext-managed-current-"),path=folder.resolve("history.dat");
        try {
            var checkpoint=OriginalReplyCheckpoint.create(path,b.apply("rootPin"),b.apply("fingerprint"),scope,List.of(prior,active),10000);
            // This suite checks signed-proof fences; HttpTest covers transport deadlines.
            // Leave room for a cold JVM and TLS handshake on a shared CI runner.
            var transport=new OriginalHttp(input.get("Origin").getAsString(),4000,input.get("Roots").getAsString());
            var client=new OriginalCurrentClient(transport,checkpoint,b.apply("rootPin"),b.apply("fingerprint"),scope,10000);
            int[] index={0};JsonArray times=input.getAsJsonArray("Clock");
            LongSupplier clock=()->{
                try {
                    if(index[0]==0){
                        try{client.current(input.get("Grant").getAsString(),()->10000);throw new AssertionError("Reentrant current accepted");}
                        catch(OriginalHttp.Failure expected){/* Must fail before another request. */}
                    }
                    if(input.get("Conflict").getAsBoolean() && index[0]==2){
                        var other=OriginalReplyCheckpoint.open(path,b.apply("rootPin"),b.apply("fingerprint"),scope);var old=other.snapshot(scope,10000);other.accept(scope,old.history(),old.revision(),10000,(m,n)->n);
                    }
                    long time=times.get(Math.min(index[0],times.size()-1)).getAsLong();index[0]++;return time;
                }catch(Exception error){throw new IllegalStateException("Fixture clock setup refused");}
            };
            JsonObject result=new JsonObject();result.addProperty("ok",false);
            try{var value=client.current(input.get("Grant").getAsString(),clock).authority();result.addProperty("ok",true);result.addProperty("now",value.nowMs());result.addProperty("version",value.manifest().version());}
            catch(OriginalHttp.Failure expected){/* Only operation under test may refuse. */}
            if(input.get("Retry").getAsBoolean()){
                try{client.current(input.get("Grant").getAsString(),()->10000);result.addProperty("stale_refused",false);}
                catch(OriginalHttp.Failure expected){result.addProperty("stale_refused",true);}
            }
            var reopened=OriginalReplyCheckpoint.open(path,b.apply("rootPin"),b.apply("fingerprint"),scope);var saved=reopened.snapshot(scope,50000);
            result.addProperty("revision",saved.revision());result.addProperty("floor",saved.comparisonMs());result.addProperty("history",saved.history().size());result.addProperty("rollback_refused",false);
            try{reopened.snapshot(scope,saved.comparisonMs()-1);}catch(java.security.GeneralSecurityException expected){result.addProperty("rollback_refused",true);}
            System.out.println(result);
        }finally{Files.deleteIfExists(path);Files.deleteIfExists(folder);}
    }
}

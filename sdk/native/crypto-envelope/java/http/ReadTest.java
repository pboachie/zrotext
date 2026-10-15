package org.zrotext.candidate;
import com.google.gson.*;
import java.security.*;
import java.security.spec.*;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.*;
import java.util.function.*;

public final class ReadTest {
    private ReadTest() {}
    public static void main(String[] args)throws Exception {
        run(null);
    }
    public static void run(HpkeRecipient.Recipient nativeRecipient)throws Exception {
        JsonObject input=JsonParser.parseString(new String(System.in.readAllBytes(),StandardCharsets.UTF_8)).getAsJsonObject(),f=input.getAsJsonObject("Fixture");
        Function<String,byte[]> b=name->Base64.getDecoder().decode(f.get(name).getAsString());
        var root=ManifestChain.RootPin.enroll(b.apply("rootPin"),b.apply("fingerprint"));
        var prior=ManifestChain.genesis02(b.apply("predecessor"),root,10000);var active=ManifestChain.continueChain(b.apply("activation"),prior,2,10000);
        var scope=new OriginalReplyReader.Scope(b.apply("account"),b.apply("device"),b.apply("line"),b.apply("interval"),b.apply("connector"),b.apply("readGrant"),b.apply("originalReader"),"+12");
        Path folder=Files.createTempDirectory("zrotext-managed-current-"),path=folder.resolve("history.dat");
        try {
            var checkpoint=OriginalReplyCheckpoint.create(path,b.apply("rootPin"),b.apply("fingerprint"),scope,List.of(prior,active),10000);
            var transport=new OriginalHttp(input.get("Origin").getAsString(),4000,input.get("Roots").getAsString());
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
            if(nativeRecipient!=null && f.has("originalScalar"))throw new AssertionError("Native scalar exposed");
            var parameters=AlgorithmParameters.getInstance("EC");parameters.init(new ECGenParameterSpec("secp256r1"));
            var recipient=nativeRecipient!=null ? nativeRecipient : HpkeRecipient.software(KeyFactory.getInstance("EC").generatePrivate(new ECPrivateKeySpec(new BigInteger(1,b.apply("originalScalar")),parameters.getParameterSpec(ECParameterSpec.class))));
            JsonObject result=new JsonObject();result.addProperty("ok",false);
            try{var value=client.readWithRecipient(input.get("Grant").getAsString(),b.apply("event"),recipient,clock,input.get("Baseline").getAsLong());result.addProperty("ok",true);result.addProperty("plaintext",value.plaintext());result.addProperty("digest",HexFormat.of().formatHex(value.envelopeDigest()));result.addProperty("baseline",value.acceptedManifestVersion());result.addProperty("version",value.authority().manifest().version());}
            catch(OriginalHttp.Failure expected){/* Only operation under test may refuse. */}
            var reopened=OriginalReplyCheckpoint.open(path,b.apply("rootPin"),b.apply("fingerprint"),scope);var saved=reopened.snapshot(scope,50000);
            result.addProperty("revision",saved.revision());result.addProperty("floor",saved.comparisonMs());result.addProperty("history",saved.history().size());result.addProperty("rollback_refused",false);
            try{reopened.snapshot(scope,saved.comparisonMs()-1);}catch(java.security.GeneralSecurityException expected){result.addProperty("rollback_refused",true);}
            System.out.write((result.toString()+"\n").getBytes(StandardCharsets.UTF_8));
        }finally{Files.deleteIfExists(path);Files.deleteIfExists(folder);}
    }
}

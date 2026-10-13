package org.zrotext.candidate;
import com.google.gson.*;
import java.nio.*;
import java.nio.channels.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.*;
import java.util.function.*;
public final class ProposalTest {
    private ProposalTest(){}
    public static void main(String[] args)throws Exception {
        var input=JsonParser.parseString(new String(System.in.readAllBytes(),StandardCharsets.UTF_8)).getAsJsonObject();if(input.has("Canonical")){var out=new JsonObject();try{var a=OriginalCurrentClient.WorkflowAction.parse(input.get("Canonical").getAsString());out.addProperty("ok",true);out.addProperty("canonical",a.canonical());out.addProperty("digest",a.digest());}catch(OriginalHttp.Failure error){out.addProperty("ok",false);}System.out.println(out);return;}var f=input.getAsJsonObject("Fixture");Function<String,byte[]> b=n->Base64.getDecoder().decode(f.get(n).getAsString());
        var root=ManifestChain.RootPin.enroll(b.apply("rootPin"),b.apply("fingerprint"));var prior=ManifestChain.genesis02(b.apply("predecessor"),root,10000);var active=ManifestChain.continueChain(b.apply("activation"),prior,2,10000);
        var scope=new OriginalReplyReader.Scope(b.apply("account"),b.apply("device"),b.apply("line"),b.apply("interval"),b.apply("connector"),b.apply("readGrant"),b.apply("originalReader"),"+12");
        var path=Path.of(input.get("Directory").getAsString(),"reply.db");var file=path.resolveSibling("intent.bin");
        var checkpoint=input.get("Resume").getAsBoolean()?OriginalReplyCheckpoint.open(path,b.apply("rootPin"),b.apply("fingerprint"),scope):OriginalReplyCheckpoint.create(path,b.apply("rootPin"),b.apply("fingerprint"),scope,List.of(prior,active),10000);
        var transport=new OriginalHttp(input.get("Origin").getAsString(),1000,input.get("Roots").getAsString());var client=new OriginalCurrentClient(transport,checkpoint,b.apply("rootPin"),b.apply("fingerprint"),scope,10000);var result=new JsonObject();result.addProperty("ok",false);result.addProperty("unknown",false);
        try {
            if(!input.get("Resume").getAsBoolean()){
                byte[] request=new byte[16],selected=new byte[16];request[15]=(byte)(input.get("Invalid").getAsBoolean()?0:1);selected[15]=2;
                var prepared=client.prepareProposal(b.apply("event"),request,selected,OriginalCurrentClient.WorkflowAction.parse(input.get("Descriptor").toString()));byte[] raw=prepared.bytes(),snapshot=prepared.bytes();raw[0]^=1;if(!Arrays.equals(prepared.bytes(),snapshot))throw new AssertionError("Intent alias");
                try(var stream=FileChannel.open(file,StandardOpenOption.CREATE_NEW,StandardOpenOption.WRITE)){var bytes=ByteBuffer.wrap(snapshot);while(bytes.hasRemaining())stream.write(bytes);stream.force(true);}
            }
            byte[] raw=Files.readAllBytes(file);int corrupt=input.get("Corrupt").getAsInt();if(corrupt>=0)raw[corrupt]^=1;else if(corrupt==-2)raw=Arrays.copyOf(raw,raw.length-1);
            var intent=client.restoreProposal(raw);result.addProperty("record",HexFormat.of().formatHex(intent.bytes()));int[] index={0};var times=input.getAsJsonArray("Clock");
            LongSupplier clock=()->{if(index[0]==0){try{client.current(input.get("Grant").getAsString(),()->10000);throw new AssertionError("Reentrant current accepted");}catch(OriginalHttp.Failure expected){/* No extra request. */}}return times.get(Math.min(index[0]++,times.size()-1)).getAsLong();};
            var value=input.get("Status").getAsBoolean()?client.statusProposal(input.get("Grant").getAsString(),intent,clock):client.consumeProposal(input.get("Grant").getAsString(),input.get("Output").getAsString(),intent,clock);
            result.addProperty("proposal",value.action()!=null);result.addProperty("ok",true);result.addProperty("event",HexFormat.of().formatHex(value.event()));result.addProperty("consumption",HexFormat.of().formatHex(value.consumption()));if(value.activeRequest()==null)result.add("active",JsonNull.INSTANCE);else result.addProperty("active",HexFormat.of().formatHex(value.activeRequest()));result.addProperty("now",value.authority().authority().nowMs());
        }catch(OriginalHttp.Failure error){result.addProperty("unknown",error.unknown);result.addProperty("error",error.getMessage());}
        var saved=checkpoint.snapshot(scope,50000);result.addProperty("revision",saved.revision());result.addProperty("floor",saved.comparisonMs());System.out.println(result);
    }
}

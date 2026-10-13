package org.zrotext.candidate;
import com.google.gson.*;
import java.nio.charset.StandardCharsets;
import java.util.*;
public final class TemplateTest {
    private TemplateTest(){}
    public static void main(String[] args)throws Exception {
        var request=JsonParser.parseString(new String(System.in.readAllBytes(),StandardCharsets.UTF_8)).getAsJsonObject();var result=new JsonObject();var cases=new JsonArray();var gson=new Gson();
        for(var row:request.getAsJsonArray("cases")){var out=new JsonObject();try{
            var content=TemplateContent.parse(Base64.getDecoder().decode(row.getAsJsonObject().get("raw").getAsString()));byte[] before=content.canonical(),copy=content.canonical();copy[0]^=1;if(!Arrays.equals(before,content.canonical()))throw new AssertionError("Canonical alias");content.values().put("changed","local");if(content.values().containsKey("changed"))throw new AssertionError("Values alias");
            out.addProperty("accepted",true);out.addProperty("canonical",Base64.getEncoder().encodeToString(content.canonical()));out.addProperty("digest",content.digest());try{out.add("preview",gson.toJsonTree(content.preview()));}catch(TemplateContent.Failure expected){out.add("preview",JsonNull.INSTANCE);}
        }catch(TemplateContent.Failure expected){out.addProperty("accepted",false);}cases.add(out);}
        var segments=new JsonArray();for(var row:request.getAsJsonArray("segments")){try{var text=new StringBuilder();for(var unit:row.getAsJsonObject().getAsJsonArray("units")){int n=unit.getAsInt();if(n<0 || n>65535)throw new TemplateContent.Failure();text.append((char)n);}segments.add(gson.toJsonTree(TemplateContent.estimate(text.toString())));}catch(TemplateContent.Failure expected){segments.add(JsonNull.INSTANCE);}}
        result.add("cases",cases);result.add("segments",segments);System.out.write(result.toString().getBytes(StandardCharsets.UTF_8));
    }
}

package org.zrotext.candidate;
import com.google.gson.*;
import java.nio.*;
import java.nio.charset.*;
import java.security.*;
import java.util.*;
import java.util.regex.*;

/** Pure local content, never save, encryption, approval or send authority. */
public final class TemplateContent {
    public static final class Failure extends Exception {
        private static final long serialVersionUID=1L;
        public Failure(){super("Invalid template content or preview");}
    }
    public record Estimate(String encoding,int parts,int perPart,int length,boolean empty){}
    public record Preview(String text,Estimate estimate){}
    private static final Pattern VARIABLE_PATTERN=Pattern.compile("\\{\\{([A-Za-z_][A-Za-z0-9_]{0,31})\\}\\}");
    private static final String GSM="@\u00a3$\u00a5\u00e8\u00e9\u00f9\u00ec\u00f2\u00c7\n\u00d8\u00f8\r\u00c5\u00e5\u0394_\u03a6\u0393\u039b\u03a9\u03a0\u03a8\u03a3\u0398\u039e\u00c6\u00e6\u00df\u00c9 !\"#\u00a4%&'()*+,-./0123456789:;<=>?\u00a1ABCDEFGHIJKLMNOPQRSTUVWXYZ\u00c4\u00d6\u00d1\u00dc\u00a7\u00bfabcdefghijklmnopqrstuvwxyz\u00e4\u00f6\u00f1\u00fc\u00e0";
    private static final String EXT="\f^{}\\[~]|\u20ac";
    private final String template;private final SortedMap<String,String> values;private final byte[] canonical;
    private static void need(boolean value)throws Failure{if(!value)throw new Failure();}
    private static boolean key(String value){return value!=null && value.matches("[A-Za-z_][A-Za-z0-9_]{0,31}") && !Set.of("__proto__","prototype","constructor").contains(value);}
    private static void bounded(String s,int max)throws Failure{
        need(s!=null && s.length()<=max);for(int i=0;i<s.length();i++){char c=s.charAt(i);if(Character.isHighSurrogate(c)){need(++i<s.length() && Character.isLowSurrogate(s.charAt(i)));}else need(!Character.isLowSurrogate(c));}
    }
    private static String quote(String s){
        var out=new StringBuilder("\"");for(int i=0;i<s.length();i++){char c=s.charAt(i);switch(c){
            case '"'->out.append("\\\"");case '\\'->out.append("\\\\");case '\b'->out.append("\\b");case '\t'->out.append("\\t");case '\n'->out.append("\\n");case '\f'->out.append("\\f");case '\r'->out.append("\\r");default->{if(c<32)out.append(String.format(Locale.ROOT,"\\u%04x",(int)c));else out.append(c);}
        }}return out.append('"').toString();
    }
    public TemplateContent(String template,Map<String,String> input)throws Failure{
        try{
            bounded(template,4096);need(input!=null && input.size()<=32);var owned=new TreeMap<String,String>(input);need(owned.size()<=32);int total=0;
            Matcher matcher=VARIABLE_PATTERN.matcher(template);int offset=0;while(matcher.find()){String literal=template.substring(offset,matcher.start());need(literal.indexOf('{')<0 && literal.indexOf('}')<0 && key(matcher.group(1)));offset=matcher.end();}String tail=template.substring(offset);need(tail.indexOf('{')<0 && tail.indexOf('}')<0);
            for(var entry:owned.entrySet()){need(key(entry.getKey()));bounded(entry.getValue(),512);total+=entry.getKey().length()+1+entry.getValue().length()+(total>0?1:0);need(total<=4096);}
            this.template=template;this.values=Collections.unmodifiableSortedMap(owned);var json=new StringBuilder("{\"v\":1,\"template\":").append(quote(template)).append(",\"values\":{");int i=0;
            for(var entry:owned.entrySet()){if(i++>0)json.append(',');json.append(quote(entry.getKey())).append(':').append(quote(entry.getValue()));}canonical=json.append("}}").toString().getBytes(StandardCharsets.UTF_8);
        }catch(Exception error){throw new Failure();}
    }
    public static TemplateContent parse(byte[] bytes)throws Failure{
        try{
            need(bytes!=null && bytes.length<=65536);byte[] raw=bytes.clone();String text=StandardCharsets.UTF_8.newDecoder().onMalformedInput(CodingErrorAction.REPORT).onUnmappableCharacter(CodingErrorAction.REPORT).decode(ByteBuffer.wrap(raw)).toString();
            var reader=new com.google.gson.stream.JsonReader(new java.io.StringReader(text));reader.setStrictness(Strictness.STRICT);reader.beginObject();var seen=new HashSet<String>();String template=null;Map<String,String> values=null;
            while(reader.hasNext()){String name=reader.nextName();need(seen.add(name));switch(name){
                case "v"->{need(reader.peek()==com.google.gson.stream.JsonToken.NUMBER && reader.nextString().equals("1"));}
                case "template"->{need(reader.peek()==com.google.gson.stream.JsonToken.STRING);template=reader.nextString();}
                case "values"->{reader.beginObject();values=new TreeMap<>();while(reader.hasNext()){String key=reader.nextName();need(!values.containsKey(key) && reader.peek()==com.google.gson.stream.JsonToken.STRING);values.put(key,reader.nextString());need(values.size()<=32);}reader.endObject();}
                default->throw new Failure();
            }}reader.endObject();need(reader.peek()==com.google.gson.stream.JsonToken.END_DOCUMENT && seen.equals(Set.of("v","template","values")));reader.close();
            var content=new TemplateContent(template,values);need(Arrays.equals(raw,content.canonical));return content;
        }catch(Exception error){throw new Failure();}
    }
    public byte[] canonical(){return canonical.clone();}
    public Map<String,String> values(){return new TreeMap<>(values);}
    public String digest(){try{return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(canonical));}catch(GeneralSecurityException error){throw new IllegalStateException(error);}}
    public static Estimate estimate(String text)throws Failure{
        bounded(text,918);boolean gsm=true;int septets=0;for(int i=0;i<text.length();){int c=text.codePointAt(i);i+=Character.charCount(c);need(c>=32 || c==10 || c==13 || c==12);if(EXT.indexOf(c)>=0)septets+=2;else if(GSM.indexOf(c)>=0)septets++;else gsm=false;}
        int length=gsm?septets:text.length(),perPart=gsm?(length<=160?160:153):(length<=70?70:67),parts=Math.max(1,(length+perPart-1)/perPart);need(parts<=6);return new Estimate(gsm?"gsm":"ucs2",parts,perPart,length,text.isEmpty());
    }
    public Preview preview()throws Failure{
        var out=new StringBuilder();Matcher matcher=VARIABLE_PATTERN.matcher(template);int offset=0;while(matcher.find()){String value=values.get(matcher.group(1));need(value!=null);need(out.length()+matcher.start()-offset+value.length()<=8192);out.append(template,offset,matcher.start()).append(value);offset=matcher.end();}need(out.length()+template.length()-offset<=8192);out.append(template.substring(offset));String text=out.toString();return new Preview(text,estimate(text));
    }
}

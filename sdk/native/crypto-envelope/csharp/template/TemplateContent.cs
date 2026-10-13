using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Text.RegularExpressions;
namespace Zrotext.Candidate;

/// <summary>Pure local content, never save, encryption, approval or send authority.</summary>
public sealed class TemplateContent
{
    public sealed class Failure : Exception {public Failure():base("Invalid template content or preview") {}}
    public sealed record Estimate([property:JsonPropertyName("encoding")]string Encoding,[property:JsonPropertyName("parts")]int Parts,[property:JsonPropertyName("perPart")]int PerPart,[property:JsonPropertyName("length")]int Length,[property:JsonPropertyName("empty")]bool Empty);
    public sealed record PreviewResult([property:JsonPropertyName("text")]string Text,[property:JsonPropertyName("estimate")]Estimate Estimate);
    private static readonly Regex VariablePattern=new("\\{\\{([A-Za-z_][A-Za-z0-9_]{0,31})\\}\\}",RegexOptions.CultureInvariant);
    private const string Gsm="@\u00a3$\u00a5\u00e8\u00e9\u00f9\u00ec\u00f2\u00c7\n\u00d8\u00f8\r\u00c5\u00e5\u0394_\u03a6\u0393\u039b\u03a9\u03a0\u03a8\u03a3\u0398\u039e\u00c6\u00e6\u00df\u00c9 !\"#\u00a4%&'()*+,-./0123456789:;<=>?\u00a1ABCDEFGHIJKLMNOPQRSTUVWXYZ\u00c4\u00d6\u00d1\u00dc\u00a7\u00bfabcdefghijklmnopqrstuvwxyz\u00e4\u00f6\u00f1\u00fc\u00e0";
    private const string Extension="\f^{}\\[~]|\u20ac";
    private readonly string template;private readonly SortedDictionary<string,string> values;private readonly byte[] canonical;
    private static void Need(bool value){if(!value)throw new Failure();}
    private static bool Key(string s)=>Regex.IsMatch(s,"\\A[A-Za-z_][A-Za-z0-9_]{0,31}\\z",RegexOptions.CultureInvariant) && s is not "__proto__" and not "prototype" and not "constructor";
    private static void Bounded(string s,int max){Need(s is not null && s.Length<=max);for(int i=0;i<s!.Length;i++){char c=s[i];if(char.IsHighSurrogate(c))Need(++i<s.Length && char.IsLowSurrogate(s[i]));else Need(!char.IsLowSurrogate(c));}}
    private static string Quote(string s){var b=new StringBuilder("\"");foreach(char c in s)switch(c){case '"':b.Append("\\\"");break;case '\\':b.Append("\\\\");break;case '\b':b.Append("\\b");break;case '\t':b.Append("\\t");break;case '\n':b.Append("\\n");break;case '\f':b.Append("\\f");break;case '\r':b.Append("\\r");break;default:if(c<32)b.Append("\\u").Append(((int)c).ToString("x4",CultureInfo.InvariantCulture));else b.Append(c);break;}return b.Append('"').ToString();}
    public TemplateContent(string template,IReadOnlyDictionary<string,string> input)
    {
        try{
            Bounded(template,4096);Need(input is not null && input.Count<=32);var owned=new SortedDictionary<string,string>(StringComparer.Ordinal);foreach(var pair in input!)owned.Add(pair.Key,pair.Value);Need(owned.Count<=32);
            int offset=0;foreach(Match match in VariablePattern.Matches(template)){string literal=template[offset..match.Index];Need(!literal.Contains('{') && !literal.Contains('}') && Key(match.Groups[1].Value));offset=match.Index+match.Length;}string tail=template[offset..];Need(!tail.Contains('{') && !tail.Contains('}'));
            int total=0;foreach(var pair in owned){Need(Key(pair.Key));Bounded(pair.Value,512);total+=pair.Key.Length+1+pair.Value.Length+(total>0?1:0);Need(total<=4096);}
            this.template=template;values=owned;var json=new StringBuilder("{\"v\":1,\"template\":").Append(Quote(template)).Append(",\"values\":{");int i=0;foreach(var pair in owned){if(i++>0)json.Append(',');json.Append(Quote(pair.Key)).Append(':').Append(Quote(pair.Value));}canonical=Encoding.UTF8.GetBytes(json.Append("}}").ToString());
        }catch{throw new Failure();}
    }
    public static TemplateContent Parse(byte[] input)
    {
        try{
            Need(input.Length<=65536);var raw=(byte[])input.Clone();using var doc=JsonDocument.Parse(raw,new JsonDocumentOptions{MaxDepth=4});var root=doc.RootElement;Need(root.ValueKind==JsonValueKind.Object);var names=root.EnumerateObject().Select(p=>p.Name).ToArray();Need(names.Length==3 && names.ToHashSet().SetEquals(new[]{"v","template","values"}) && root.GetProperty("v").GetInt32()==1);
            var fields=root.GetProperty("values");Need(fields.ValueKind==JsonValueKind.Object);var map=new Dictionary<string,string>(StringComparer.Ordinal);foreach(var field in fields.EnumerateObject()){Need(field.Value.ValueKind==JsonValueKind.String);map.Add(field.Name,field.Value.GetString()!);}Need(root.GetProperty("template").ValueKind==JsonValueKind.String);
            var content=new TemplateContent(root.GetProperty("template").GetString()!,map);Need(raw.SequenceEqual(content.canonical));return content;
        }catch{throw new Failure();}
    }
    public byte[] Canonical()=>(byte[])canonical.Clone();
    public string Digest=>Convert.ToHexString(SHA256.HashData(canonical)).ToLowerInvariant();
    public Dictionary<string,string> Values()=>new(values,StringComparer.Ordinal);
    public static Estimate EstimateSegments(string text)
    {
        Bounded(text,918);bool gsm=true;int septets=0;foreach(var rune in text.EnumerateRunes()){int c=rune.Value;Need(c>=32 || c is 10 or 13 or 12);if(c<=65535 && Extension.Contains((char)c))septets+=2;else if(c<=65535 && Gsm.Contains((char)c))septets++;else gsm=false;}
        int length=gsm?septets:text.Length,perPart=gsm?(length<=160?160:153):(length<=70?70:67),parts=Math.Max(1,(length+perPart-1)/perPart);Need(parts<=6);return new Estimate(gsm?"gsm":"ucs2",parts,perPart,length,text.Length==0);
    }
    public PreviewResult Preview()
    {
        try{var b=new StringBuilder();int offset=0;foreach(Match match in VariablePattern.Matches(template)){string value=values[match.Groups[1].Value];Need(b.Length+match.Index-offset+value.Length<=8192);b.Append(template,offset,match.Index-offset).Append(value);offset=match.Index+match.Length;}Need(b.Length+template.Length-offset<=8192);b.Append(template[offset..]);string text=b.ToString();return new PreviewResult(text,EstimateSegments(text));}catch{throw new Failure();}
    }
}

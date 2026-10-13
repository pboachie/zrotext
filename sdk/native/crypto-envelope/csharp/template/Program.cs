using System.Text.Json;
using Zrotext.Candidate;
using var request=JsonDocument.Parse(Console.In.ReadToEnd());var cases=new List<object>();
foreach(var row in request.RootElement.GetProperty("cases").EnumerateArray()){
    try{var content=TemplateContent.Parse(Convert.FromBase64String(row.GetProperty("raw").GetString()!));var before=content.Canonical();var changed=content.Canonical();changed[0]^=1;if(!before.SequenceEqual(content.Canonical()))throw new Exception("Canonical alias");content.Values()["changed"]="local";if(content.Values().ContainsKey("changed"))throw new Exception("Values alias");TemplateContent.PreviewResult? preview;try{preview=content.Preview();}catch(TemplateContent.Failure){preview=null;}cases.Add(new{accepted=true,canonical=Convert.ToBase64String(content.Canonical()),digest=content.Digest,preview});}
    catch(TemplateContent.Failure){cases.Add(new{accepted=false});}
}
var segments=new List<TemplateContent.Estimate?>();foreach(var row in request.RootElement.GetProperty("segments").EnumerateArray()){
    try{var chars=row.GetProperty("units").EnumerateArray().Select(v=>{int n=v.GetInt32();if(n<0 || n>65535)throw new TemplateContent.Failure();return (char)n;}).ToArray();segments.Add(TemplateContent.EstimateSegments(new string(chars)));}catch(TemplateContent.Failure){segments.Add(null);}
}
Console.WriteLine(JsonSerializer.Serialize(new{cases,segments}));

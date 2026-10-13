#nullable enable
using System;
using System.Collections.Generic;
using System.Text.Json.Nodes;
using System.Threading;
using Tungsten.Runtime;
using Zrotext.Sdk;

var input = JsonNode.Parse(Console.In.ReadToEnd())!.AsObject();
var auth = new Dictionary<string, Credential>();
if (input["auth"]!.GetValue<bool>()) {
    auth["ownerSession"] = Credential.Parts(new Dictionary<string, string> {
        ["__Host-zrotext_session"] = "synthetic-session", ["__Host-zrotext_csrf"] = "synthetic-csrf", ["origin"] = "https://example.test" });
    auth["bearerAuth"] = Credential.Secret("synthetic-bearer");
    auth["workflowCredential"] = Credential.Secret("ztw_synthetic");
}
IDispatch client = new ZrotextClient(new ClientOptions {
    BaseUrl = input["base"]!.GetValue<string>(), Auth = auth, Timeout = TimeSpan.FromMilliseconds(1500),
    ValidateResponses = ValidateResponses.Strict });
var call = new CallOptions { IdempotencyKey = input["key"]?.GetValue<string>() };
if (input["confirm"]?.GetValue<bool>() == true) {
    var preview = await client.PreviewOperationAsync(input["operation"]!.GetValue<string>(), input["args"]!.AsObject(), call);
    if (preview is Result<PreviewResult>.Err failed) { Console.WriteLine(failed.Diagnostic.ToJson().ToJsonString()); return; }
    call = call with { Confirm = Confirm.Token(preview.Unwrap().ConfirmationToken!) };
}
var result = await client.InvokeAsync(input["operation"]!.GetValue<string>(), input["args"]!.AsObject(), call, CancellationToken.None);
Console.WriteLine(result is Result<JsonNode?>.Err error ? error.Diagnostic.ToJson().ToJsonString() : "{\"ok\":true}");

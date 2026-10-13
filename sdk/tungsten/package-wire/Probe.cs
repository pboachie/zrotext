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
var client = new ZrotextClient(new ClientOptions {
    BaseUrl = input["base"]!.GetValue<string>(), Auth = auth, Timeout = TimeSpan.FromMilliseconds(1500),
    ValidateResponses = ValidateResponses.Strict });
var call = new CallOptions { IdempotencyKey = input["key"]?.GetValue<string>() };
if (input["pages"]?.GetValue<bool>() == true) {
    var output = new JsonArray();
    var request = PublicOwnerMessagesResource.ListRequest.FromJson(input["args"], new Decoder(true));
    await foreach (var pageResult in client.Public.OwnerMessages.ListPagesAsync(request, call)) {
        if (pageResult is Result<Page<Zrotext.Sdk.Models.Public.OwnerMessageView>>.Err failed) {
            output.Add(new JsonObject { ["category"] = failed.Diagnostic.ToJson()["category"]!.DeepClone() });
        } else {
            var page = pageResult.Unwrap();
            var ids = new JsonArray();
            foreach (var item in page.Items) ids.Add(item.MessageId);
            output.Add(new JsonObject { ["ids"] = ids, ["cursor"] = page.Next?.DeepClone() });
        }
        if (output.Count >= input["limit"]!.GetValue<int>()) break;
    }
    Console.WriteLine(new JsonObject { ["pages"] = output }.ToJsonString());
    return;
}
IDispatch dispatch = client;
if (input["confirm"]?.GetValue<bool>() == true) {
    var preview = await dispatch.PreviewOperationAsync(input["operation"]!.GetValue<string>(), input["args"]!.AsObject(), call);
    if (preview is Result<PreviewResult>.Err failed) { Console.WriteLine(failed.Diagnostic.ToJson().ToJsonString()); return; }
    call = call with { Confirm = Confirm.Token(preview.Unwrap().ConfirmationToken!) };
}
var result = await dispatch.InvokeAsync(input["operation"]!.GetValue<string>(), input["args"]!.AsObject(), call, CancellationToken.None);
Console.WriteLine(result is Result<JsonNode?>.Err error ? error.Diagnostic.ToJson().ToJsonString() : "{\"ok\":true}");

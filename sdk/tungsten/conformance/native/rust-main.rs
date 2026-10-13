use serde_json::{Value, json};
use std::io::{self, Read};
use tungsten_runtime::{
    CallOptions, ClientOptions, Confirm, Credential, Dispatch, ValidateResponses,
};
use zrotext_sdk::ZrotextClient;
#[tokio::main]
async fn main() {
    let mut input = String::new();
    io::stdin().read_to_string(&mut input).unwrap();
    let v: Value = serde_json::from_str(&input).unwrap();
    let mut options = ClientOptions {
        base_url: Some(v["base"].as_str().unwrap().to_owned()),
        validate_responses: ValidateResponses::Strict,
        ..Default::default()
    };
    if let Some(token) = v["token"].as_str() {
        options
            .auth
            .insert("bearerAuth".into(), Credential::Secret(token.into()));
    }
    let client = ZrotextClient::new(options).unwrap();
    let op = v["operation"].as_str().unwrap();
    let args = v["args"].clone();
    let mut opts = CallOptions {
        idempotency_key: v["key"].as_str().map(str::to_owned),
        ..Default::default()
    };
    if v["confirm"] == true {
        let preview = client
            .preview(op, args.clone(), opts.clone())
            .await
            .unwrap();
        opts.confirm = Some(Confirm::Token(preview.value.confirmation_token.unwrap()));
    }
    let output = match client.invoke(op, args, opts).await {
        Ok(r) => json!({"ok":true,"value":r.value,"attempts":r.meta.attempts}),
        Err(e) => json!({"ok":false,"category":e.category,"attempts":e.trace.attempts}),
    };
    println!("{}", output);
}

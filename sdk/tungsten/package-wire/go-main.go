package main

import (
	"context"
	"encoding/json"
	"errors"
	tungsten "github.com/pboachie/tungsten/runtimes/go"
	zrotext "github.com/pboachie/zrotext/sdk/tungsten/generated/go"
	"os"
	"time"
)

func main() {
	var v struct {
		Base      string
		Token     string
		Operation string
		Args      any
		Key       string
		Confirm   bool
		TimeoutMs int
	}
	if err := json.NewDecoder(os.Stdin).Decode(&v); err != nil {
		panic(err)
	}
	options := tungsten.ClientOptions{BaseURL: v.Base, ValidateResponses: tungsten.ValidateStrict}
	if v.Token != "" {
		options.Auth = tungsten.AuthConfig{"bearerAuth": tungsten.Secret(v.Token)}
	}
	client, err := zrotext.New(options)
	if err != nil {
		panic(err)
	}
	opts := tungsten.CallOptions{IdempotencyKey: v.Key}
	if v.TimeoutMs > 0 {
		opts.Timeout = time.Duration(v.TimeoutMs) * time.Millisecond
	}
	if v.Confirm {
		p, err := client.PreviewOperation(context.Background(), v.Operation, v.Args, opts)
		if err != nil {
			panic(err)
		}
		opts.Confirm = tungsten.ConfirmToken(p.Value.ConfirmationToken)
	}
	r, err := client.Invoke(context.Background(), v.Operation, v.Args, opts)
	output := map[string]any{}
	if err != nil {
		var e *tungsten.Error
		if !errors.As(err, &e) {
			panic(err)
		}
		output["ok"] = false
		output["category"] = e.Diagnostic.Category
		output["attempts"] = e.Diagnostic.Attempts
	} else {
		output["ok"] = true
		output["value"] = r.Value
		output["attempts"] = r.Meta.Attempts
	}
	if err := json.NewEncoder(os.Stdout).Encode(output); err != nil {
		panic(err)
	}
}

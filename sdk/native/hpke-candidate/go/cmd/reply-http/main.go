package main

import (
	"context"
	"encoding/json"
	"errors"
	h "github.com/pboachie/zrotext/sdk/native/hpke-candidate/go"
	"os"
	"time"
)

func main() {
	var input struct {
		Origin  string
		Roots   string
		Grant   string
		Method  string
		Invalid string
		Timeout uint64
	}
	if json.NewDecoder(os.Stdin).Decode(&input) != nil {
		panic("fixture shape")
	}
	start := time.Now()
	state := "unavailable"
	client, e := h.NewOriginalHTTP(input.Origin, time.Duration(input.Timeout)*time.Millisecond, []byte(input.Roots))
	if e == nil {
		id := "11111111-1111-4111-8111-111111111111"
		request := h.OriginalHTTPRequest{Method: input.Method, AcceptedManifestVersion: 1}
		switch input.Method {
		case "page":
			request.Limit = 20
		case "read":
			request.EventID = id
		case "status":
			request.ConsumptionID = id
		case "consume":
			request.EventID = id
			request.RequestID = id
		}
		if input.Invalid == "version" {
			request.AcceptedManifestVersion = 0
		}
		if input.Invalid == "uuid" {
			request.EventID = "invalid"
		}
		_, e = client.Exchange(context.Background(), input.Grant, request)
		if e == nil {
			state = "untrusted"
		} else {
			var failure h.OriginalHTTPError
			if !errors.As(e, &failure) {
				panic("unredacted error")
			}
			if failure.Unknown {
				state = "unknown"
			}
			if e.Error() != "original reply unavailable" && e.Error() != "original reply outcome unknown" {
				panic("error disclosure")
			}
		}
	}
	json.NewEncoder(os.Stdout).Encode(map[string]any{"state": state, "elapsed": time.Since(start).Seconds()})
}

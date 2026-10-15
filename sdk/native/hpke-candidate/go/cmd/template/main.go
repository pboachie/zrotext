package main

import (
	"encoding/base64"
	"encoding/json"
	h "github.com/pboachie/zrotext/sdk/native/hpke-candidate/go"
	"os"
	"unicode/utf16"
)

func main() {
	var input struct {
		Cases    []struct{ Raw string }
		Segments []struct{ Units []uint16 }
	}
	if json.NewDecoder(os.Stdin).Decode(&input) != nil {
		panic("fixture malformed")
	}
	cases := []any{}
	for _, c := range input.Cases {
		result := map[string]any{"accepted": false}
		raw, e := base64.StdEncoding.DecodeString(c.Raw)
		if e != nil {
			panic("fixture base64")
		}
		content, e := h.ParseTemplateContent(raw)
		if e == nil {
			result["accepted"] = true
			result["canonical"] = base64.StdEncoding.EncodeToString(content.Canonical())
			result["digest"] = content.Digest()
			result["preview"] = nil
			text, estimate, e := content.Preview()
			if e == nil {
				result["preview"] = map[string]any{"text": text, "estimate": estimate}
			}
			copy := content.Canonical()
			copy[0] ^= 1
			values := content.Values()
			values["injected"] = "changed"
			if base64.StdEncoding.EncodeToString(content.Canonical()) != result["canonical"] || len(content.Values()) == len(values) {
				panic("owned content aliases caller")
			}
		}
		cases = append(cases, result)
	}
	segments := []any{}
	for _, s := range input.Segments {
		valid := true
		for i := 0; i < len(s.Units); i++ {
			u := s.Units[i]
			if u >= 0xd800 && u <= 0xdbff {
				if i+1 >= len(s.Units) || s.Units[i+1] < 0xdc00 || s.Units[i+1] > 0xdfff {
					valid = false
					break
				}
				i++
			} else if u >= 0xdc00 && u <= 0xdfff {
				valid = false
				break
			}
		}
		var result any
		if valid {
			estimate, e := h.EstimateSegments(string(utf16.Decode(s.Units)))
			if e == nil {
				result = estimate
			}
		}
		segments = append(segments, result)
	}
	json.NewEncoder(os.Stdout).Encode(map[string]any{"cases": cases, "segments": segments})
}

package hpke

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"unicode/utf8"
)

var ErrTemplate = errors.New("invalid template content or preview")

type TemplateContent struct {
	template  string
	values    map[string]string
	canonical []byte
}

func units(s string) (int, bool) {
	if !utf8.ValidString(s) {
		return 0, false
	}
	n := 0
	for _, r := range s {
		n++
		if r > 0xffff {
			n++
		}
	}
	return n, true
}
func bounded(s string, max int) bool { n, ok := units(s); return ok && n <= max }
func templateKey(s string) bool {
	if len(s) < 1 || len(s) > 32 || s == "__proto__" || s == "prototype" || s == "constructor" {
		return false
	}
	for i, c := range []byte(s) {
		if !(c == '_' || c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || i > 0 && c >= '0' && c <= '9') {
			return false
		}
	}
	return true
}
func templateTokens(s string, visit func(string, string) error) error {
	offset := 0
	for i := 0; i < len(s); {
		if s[i] == '}' {
			return ErrTemplate
		}
		if s[i] != '{' {
			i++
			continue
		}
		if !strings.HasPrefix(s[i:], "{{") {
			return ErrTemplate
		}
		end := strings.Index(s[i+2:], "}}")
		if end < 0 {
			return ErrTemplate
		}
		end += i + 2
		name := s[i+2 : end]
		if !templateKey(name) {
			return ErrTemplate
		}
		if visit != nil {
			if e := visit(s[offset:i], name); e != nil {
				return e
			}
		}
		i = end + 2
		offset = i
	}
	if visit != nil {
		return visit(s[offset:], "")
	}
	return nil
}
func templateQuote(s string) string {
	var b strings.Builder
	b.WriteByte('"')
	for _, r := range s {
		switch r {
		case '"':
			b.WriteString(`\"`)
		case '\\':
			b.WriteString(`\\`)
		case '\b':
			b.WriteString(`\b`)
		case '\f':
			b.WriteString(`\f`)
		case '\n':
			b.WriteString(`\n`)
		case '\r':
			b.WriteString(`\r`)
		case '\t':
			b.WriteString(`\t`)
		default:
			if r < 32 {
				b.WriteString(fmt.Sprintf(`\u%04x`, r))
			} else {
				b.WriteRune(r)
			}
		}
	}
	b.WriteByte('"')
	return b.String()
}

// NewTemplateContent snapshots validated strings. No save, encryption or send occurs.
func NewTemplateContent(template string, values map[string]string) (*TemplateContent, error) {
	if !bounded(template, 4096) || values == nil || len(values) > 32 || templateTokens(template, nil) != nil {
		return nil, ErrTemplate
	}
	owned := map[string]string{}
	keys := make([]string, 0, len(values))
	for k := range values {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	total := 0
	for _, k := range keys {
		v := values[k]
		if !templateKey(k) || !bounded(v, 512) {
			return nil, ErrTemplate
		}
		n, _ := units(v)
		if total > 0 {
			total++
		}
		total += len(k) + 1 + n
		if total > 4096 {
			return nil, ErrTemplate
		}
		owned[k] = v
	}
	var b strings.Builder
	b.WriteString(`{"v":1,"template":`)
	b.WriteString(templateQuote(template))
	b.WriteString(`,"values":{`)
	for i, k := range keys {
		if i > 0 {
			b.WriteByte(',')
		}
		b.WriteString(templateQuote(k))
		b.WriteByte(':')
		b.WriteString(templateQuote(owned[k]))
	}
	b.WriteString(`}}`)
	raw := []byte(b.String())
	return &TemplateContent{template, owned, raw}, nil
}

// ParseTemplateContent accepts only the exact canonical UTF-8 stored content.
func ParseTemplateContent(raw []byte) (*TemplateContent, error) {
	if len(raw) > 65536 || !utf8.Valid(raw) {
		return nil, ErrTemplate
	}
	r, e := replyObject(raw, "v", "template", "values")
	if e != nil || string(r["v"]) != "1" {
		return nil, ErrTemplate
	}
	var t string
	var values map[string]string
	if json.Unmarshal(r["template"], &t) != nil || json.Unmarshal(r["values"], &values) != nil {
		return nil, ErrTemplate
	}
	out, e := NewTemplateContent(t, values)
	if e != nil || !bytes.Equal(raw, out.canonical) {
		return nil, ErrTemplate
	}
	return out, nil
}
func (c *TemplateContent) Canonical() []byte {
	if c == nil {
		return nil
	}
	return append([]byte(nil), c.canonical...)
}
func (c *TemplateContent) Digest() string {
	if c == nil {
		return ""
	}
	s := sha256.Sum256(c.canonical)
	return hex.EncodeToString(s[:])
}
func (c *TemplateContent) Values() map[string]string {
	out := map[string]string{}
	if c != nil {
		for k, v := range c.values {
			out[k] = v
		}
	}
	return out
}

type SegmentEstimate struct {
	Encoding string `json:"encoding"`
	Parts    int    `json:"parts"`
	PerPart  int    `json:"perPart"`
	Length   int    `json:"length"`
	Empty    bool   `json:"empty"`
}

const gsmDefault = "@\u00a3$\u00a5\u00e8\u00e9\u00f9\u00ec\u00f2\u00c7\n\u00d8\u00f8\r\u00c5\u00e5\u0394_\u03a6\u0393\u039b\u03a9\u03a0\u03a8\u03a3\u0398\u039e\u00c6\u00e6\u00df\u00c9 !\"#\u00a4%&'()*+,-./0123456789:;<=>?\u00a1ABCDEFGHIJKLMNOPQRSTUVWXYZ\u00c4\u00d6\u00d1\u00dc\u00a7\u00bfabcdefghijklmnopqrstuvwxyz\u00e4\u00f6\u00f1\u00fc\u00e0"
const gsmExtension = "\f^{}\\[~]|\u20ac"

// EstimateSegments is a bounded local estimate, never carrier/billing authority.
func EstimateSegments(text string) (SegmentEstimate, error) {
	out := SegmentEstimate{Encoding: "gsm", Parts: 1, PerPart: 160, Empty: text == ""}
	length, ok := units(text)
	if !ok {
		return out, ErrTemplate
	}
	septets := 0
	for _, r := range text {
		if r < 32 && r != '\n' && r != '\r' && r != '\f' {
			return out, ErrTemplate
		}
		if strings.ContainsRune(gsmExtension, r) {
			septets += 2
		} else if strings.ContainsRune(gsmDefault, r) {
			septets++
		} else {
			out.Encoding = "ucs2"
		}
	}
	if out.Encoding == "gsm" {
		out.Length = septets
		if septets > 160 {
			out.PerPart = 153
		}
	} else {
		out.Length = length
		out.PerPart = 70
		if length > 70 {
			out.PerPart = 67
		}
	}
	if out.Length > out.PerPart {
		out.Parts = (out.Length + out.PerPart - 1) / out.PerPart
	}
	if out.Parts > 6 {
		return out, ErrTemplate
	}
	return out, nil
}
func (c *TemplateContent) Preview() (string, SegmentEstimate, error) {
	if c == nil {
		return "", SegmentEstimate{}, ErrTemplate
	}
	var b strings.Builder
	n := 0
	e := templateTokens(c.template, func(prefix, name string) error {
		piece := prefix
		if name != "" {
			v, ok := c.values[name]
			if !ok {
				return ErrTemplate
			}
			piece += v
		}
		m, _ := units(piece)
		n += m
		if n > 8192 {
			return ErrTemplate
		}
		b.WriteString(piece)
		return nil
	})
	if e != nil {
		return "", SegmentEstimate{}, e
	}
	text := b.String()
	estimate, e := EstimateSegments(text)
	if e != nil {
		return "", SegmentEstimate{}, e
	}
	return text, estimate, nil
}

// Package decoder implements cicada's encoding/decoding operations (base64, hex,
// url, html, jwt) and the auto-detection helper. Go port of decoder/codec.py.
package decoder

import (
	"encoding/base64"
	"encoding/hex"
	"html"
	"net/url"
	"strings"
)

// isPrintable reports whether at least `threshold` of s is printable (ASCII 0x20–0x7e
// plus the whitespace controls), matching codec.is_printable.
func isPrintable(s string, threshold float64) bool {
	if len(s) == 0 {
		return false
	}
	n := 0
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c >= 0x20 && c <= 0x7e) || c == '\t' || c == '\n' || c == '\r' || c == '\v' || c == '\f' {
			n++
		}
	}
	return float64(n)/float64(len(s)) >= threshold
}

func Base64Encode(data string) string {
	return base64.StdEncoding.EncodeToString([]byte(data))
}

// Base64Decode pads the input as codec.py does, and returns "" on failure.
func Base64Decode(data string) string {
	if m := len(data) % 4; m != 0 {
		data += strings.Repeat("=", 4-m)
	}
	b, err := base64.StdEncoding.DecodeString(data)
	if err != nil {
		return ""
	}
	return string(b)
}

func URLEncode(data string) string { return url.QueryEscape(data) }

func URLDecode(data string) string {
	s, err := url.QueryUnescape(data)
	if err != nil {
		return ""
	}
	return s
}

func HexEncode(data string) string { return hex.EncodeToString([]byte(data)) }

func HexDecode(data string) string {
	b, err := hex.DecodeString(data)
	if err != nil {
		return ""
	}
	return string(b)
}

func HTMLEncode(data string) string { return html.EscapeString(data) }
func HTMLDecode(data string) string { return html.UnescapeString(data) }

// JWTDecode splits a token and base64url-decodes its header and payload segments.
func JWTDecode(token string) map[string]string {
	parts := strings.Split(token, ".")
	if len(parts) < 2 {
		return nil
	}
	b64url := strings.NewReplacer("-", "+", "_", "/")
	header := Base64Decode(b64url.Replace(parts[0]))
	payload := Base64Decode(b64url.Replace(parts[1]))
	if header == "" || payload == "" {
		return nil
	}
	return map[string]string{"header": header, "payload": payload}
}

// Result is one successful decoding from AutoDecode.
type Result struct {
	Method  string
	Decoded string
}

// AutoDecode tries every decoding and returns the ones that look printable and
// differ from the input, matching codec.auto_decode.
func AutoDecode(data string) []Result {
	var out []Result

	if b := Base64Decode(data); b != "" && b != data && isPrintable(b, 0.85) {
		out = append(out, Result{"base64", b})
	}
	if h := HexDecode(data); h != "" && h != data && isPrintable(h, 0.85) {
		out = append(out, Result{"hex", h})
	}
	if u := URLDecode(data); u != "" && u != data && isPrintable(u, 0.85) {
		out = append(out, Result{"url", u})
	}
	if hm := HTMLDecode(data); hm != "" && hm != data && isPrintable(hm, 0.85) {
		out = append(out, Result{"html", hm})
	}
	if strings.Count(data, ".") == 2 && strings.HasPrefix(data, "eyJ") {
		if j := JWTDecode(data); len(j) > 0 {
			out = append(out, Result{"jwt", "header: " + j["header"] + "\npayload: " + j["payload"]})
		}
	}
	return out
}
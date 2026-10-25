package decoder

import (
	"strings"
	"testing"
)

func TestBase64RoundTrip(t *testing.T) {
	cases := []string{"hello", "", "a", "hello world 123!@#"}
	for _, c := range cases {
		got := Base64Decode(Base64Encode(c))
		if got != c {
			t.Errorf("base64 roundtrip %q -> %q", c, got)
		}
	}
}

func TestHexRoundTrip(t *testing.T) {
	cases := []string{"hello", "a", "cafebabe", "hello\x00world"}
	for _, c := range cases {
		got := HexDecode(HexEncode(c))
		if got != c {
			t.Errorf("hex roundtrip %q -> %q", c, got)
		}
	}
}

func TestURLRoundTrip(t *testing.T) {
	cases := []string{"hello world", "x/y?z=1&a=b", "100% sure"}
	for _, c := range cases {
		got := URLDecode(URLEncode(c))
		if got != c {
			t.Errorf("url roundtrip %q -> %q", c, got)
		}
	}
}

func TestBase64Known(t *testing.T) {
	if got := Base64Decode("aGVsbG8="); got != "hello" {
		t.Errorf("Base64Decode(aGVsbG8=) = %q, want hello", got)
	}
	if got := Base64Encode("test"); got != "dGVzdA==" {
		t.Errorf("Base64Encode(test) = %q, want dGVzdA==", got)
	}
	// unpadded input must still decode (padding is added)
	if got := Base64Decode("aGVsbG8"); got != "hello" {
		t.Errorf("Base64Decode(aGVsbG8) = %q, want hello", got)
	}
}

func TestJWTDecode(t *testing.T) {
	// header {"alg":"none"} payload {"sub":"123"} — base64url
	token := "eyJhbGciOiJub25lIn0.eyJzdWIiOiIxMjMifQ.sig"
	j := JWTDecode(token)
	if j == nil {
		t.Fatal("JWTDecode returned nil")
	}
	if !strings.Contains(j["header"], `"alg"`) || !strings.Contains(j["payload"], `"sub"`) {
		t.Errorf("unexpected JWT decode: %#v", j)
	}
}

func TestAutoDecodeBase64(t *testing.T) {
	out := AutoDecode("aGVsbG8=")
	found := false
	for _, r := range out {
		if r.Method == "base64" && r.Decoded == "hello" {
			found = true
		}
	}
	if !found {
		t.Errorf("AutoDecode(aGVsbG8=) did not find base64->hello: %#v", out)
	}
}

func TestAutoDecodeHex(t *testing.T) {
	out := AutoDecode("68656c6c6f")
	found := false
	for _, r := range out {
		if r.Method == "hex" && r.Decoded == "hello" {
			found = true
		}
	}
	if !found {
		t.Errorf("AutoDecode(68656c6c6f) did not find hex->hello: %#v", out)
	}
}
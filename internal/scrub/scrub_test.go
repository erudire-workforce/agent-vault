package scrub

import (
	"bytes"
	"encoding/base64"
	"net/http"
	"strings"
	"testing"
)

const secret = "SENTINEL-SCRUB-0001~?&=/+ tok>>>?"

func TestForms(t *testing.T) {
	sc := New(secret)
	for _, f := range forms(secret) {
		in := "before " + f + " after"
		if got := sc.String(in); strings.Contains(got, f) || !strings.Contains(got, Redacted) {
			t.Errorf("form %q not scrubbed: %q", f, got)
		}
	}
}

// A secret embedded at any byte offset inside a larger base64 value
// (Basic auth, "Bearer <tok>") must still be found.
func TestEmbeddedBase64AllAlignments(t *testing.T) {
	sc := New(secret)
	for _, prefix := range []string{"", "a", "ab", "abc", "Bearer ", "user:"} {
		for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.URLEncoding} {
			blob := enc.EncodeToString([]byte(prefix + secret + "-trailer"))
			got := sc.String(blob)
			if !strings.Contains(got, Redacted) {
				t.Errorf("prefix %q: secret not found in %q", prefix, blob)
			}
			if dec, err := enc.DecodeString(strings.ReplaceAll(got, Redacted, "")); err == nil && strings.Contains(string(dec), "SENTINEL-SCRUB") {
				t.Errorf("prefix %q: decodable remainder still carries the secret", prefix)
			}
		}
	}
}

// Every split point of the stream must yield the same output as one pass.
func TestWriterChunkBoundaries(t *testing.T) {
	sc := New(secret)
	in := []byte("x" + secret + "yy" + base64.StdEncoding.EncodeToString([]byte(secret)) + "z" + secret)
	want := sc.Bytes(in)
	if bytes.Contains(want, []byte(secret)) {
		t.Fatal("one-pass scrub left the secret")
	}
	for cut := 0; cut <= len(in); cut++ {
		for cut2 := cut; cut2 <= len(in); cut2 += 7 {
			var out bytes.Buffer
			w := sc.NewWriter(&out, nil)
			_, _ = w.Write(in[:cut])
			_, _ = w.Write(in[cut:cut2])
			_, _ = w.Write(in[cut2:])
			_ = w.Close()
			if !bytes.Equal(out.Bytes(), want) {
				t.Fatalf("cut %d/%d: got %q want %q", cut, cut2, out.Bytes(), want)
			}
		}
	}
}

func TestHeaderAndShortSecrets(t *testing.T) {
	sc := New(secret, "ab", "")
	h := http.Header{}
	h.Set("X-Echo", "tok="+secret)
	h.Set("X-Plain", "abab")
	sc.Header(h)
	if strings.Contains(h.Get("X-Echo"), secret) {
		t.Fatal("header value not scrubbed")
	}
	if h.Get("X-Plain") != "abab" {
		t.Fatal("a two-character secret must not be scrubbed (would redact unrelated bytes)")
	}
	if New().String("abc") != "abc" || New("").String("abc") != "abc" {
		t.Fatal("empty scrubber changed input")
	}
}

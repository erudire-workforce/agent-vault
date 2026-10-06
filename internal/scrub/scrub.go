// Package scrub removes echoes of injected credentials from data leaving
// Agent Vault: proxied response headers and bodies, log lines and
// request-log entries.
//
// An upstream that rejects a token often reflects it back ("invalid token
// abc..."), sometimes encoded. The proxy must not hand the agent the very
// secret it brokers, so every occurrence of an injected value is replaced
// with [REDACTED] in each of the encodings an upstream plausibly uses:
// raw, standard and URL-safe base64 (padded, unpadded, and at every byte
// alignment so a value embedded in a larger base64 blob is still found),
// percent-encoded (query and path forms), JSON-string-escaped and
// lower/upper-case hex.
package scrub

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
)

// Redacted replaces every match.
const Redacted = "[REDACTED]"

// minSecretLen is the shortest injected value that is scrubbed. Shorter
// values would redact unrelated bytes everywhere (a one-character
// credential matches half the body); real credentials are far longer.
const minSecretLen = 4

// minAlignedLen is the shortest alignment-shifted base64 core that is
// scrubbed. The shifted forms drop up to two characters at each end, so
// short ones become generic and are skipped.
const minAlignedLen = 8

// Scrubber holds the patterns derived from a set of secrets. A nil or
// empty Scrubber is a no-op.
type Scrubber struct {
	patterns [][]byte // longest first
	maxLen   int
	byFirst  map[byte][][]byte
}

// New builds a Scrubber for secrets. Empty and very short values are
// ignored (see minSecretLen).
func New(secrets ...string) *Scrubber {
	set := map[string]bool{}
	add := func(s string, min int) {
		if len(s) >= min {
			set[s] = true
		}
	}
	for _, s := range secrets {
		if len(s) < minSecretLen {
			continue
		}
		for _, f := range forms(s) {
			add(f, minSecretLen)
		}
		for _, f := range alignedBase64Cores(s) {
			add(f, minAlignedLen)
		}
	}
	if len(set) == 0 {
		return &Scrubber{}
	}
	sc := &Scrubber{byFirst: map[byte][][]byte{}}
	for p := range set {
		sc.patterns = append(sc.patterns, []byte(p))
	}
	sort.Slice(sc.patterns, func(i, j int) bool {
		if len(sc.patterns[i]) != len(sc.patterns[j]) {
			return len(sc.patterns[i]) > len(sc.patterns[j])
		}
		return bytes.Compare(sc.patterns[i], sc.patterns[j]) < 0
	})
	for _, p := range sc.patterns {
		sc.byFirst[p[0]] = append(sc.byFirst[p[0]], p)
		if len(p) > sc.maxLen {
			sc.maxLen = len(p)
		}
	}
	return sc
}

// forms returns the whole-value encodings of s.
func forms(s string) []string {
	b := []byte(s)
	out := []string{
		s,
		base64.StdEncoding.EncodeToString(b),
		base64.RawStdEncoding.EncodeToString(b),
		base64.URLEncoding.EncodeToString(b),
		base64.RawURLEncoding.EncodeToString(b),
		url.QueryEscape(s),
		url.PathEscape(s),
		strings.ReplaceAll(url.QueryEscape(s), "+", "%20"),
		hex.EncodeToString(b),
		strings.ToUpper(hex.EncodeToString(b)),
	}
	// Lower-case percent-encoding (%2f rather than %2F).
	for _, f := range []string{url.QueryEscape(s), url.PathEscape(s)} {
		out = append(out, lowerPercent(f))
	}
	// JSON string escaping, with and without HTML escaping (Go's encoder
	// writes > for '>' by default).
	var jsonForms []string
	if j, err := json.Marshal(s); err == nil && len(j) >= 2 {
		jsonForms = append(jsonForms, string(j[1:len(j)-1]))
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if enc.Encode(s) == nil {
		j := bytes.TrimRight(buf.Bytes(), "\n")
		if len(j) >= 2 {
			jsonForms = append(jsonForms, string(j[1:len(j)-1]))
		}
	}
	out = append(out, jsonForms...)
	// Some JSON encoders (PHP's default, several Java ones) also escape '/'
	// as "\/"; add that variant of every JSON form.
	for _, f := range jsonForms {
		if strings.Contains(f, "/") {
			out = append(out, strings.ReplaceAll(f, "/", `\/`))
		}
	}
	return out
}

func lowerPercent(s string) string {
	b := []byte(s)
	for i := 0; i+2 < len(b); i++ {
		if b[i] == '%' {
			b[i+1] = toLowerHex(b[i+1])
			b[i+2] = toLowerHex(b[i+2])
		}
	}
	return string(b)
}

func toLowerHex(c byte) byte {
	if c >= 'A' && c <= 'F' {
		return c + ('a' - 'A')
	}
	return c
}

// alignedBase64Cores returns, for each base64 alphabet and each of the
// three byte alignments, the run of characters that depends only on s.
// That run appears verbatim whenever s is embedded at that alignment in
// any larger base64-encoded value (for example "Basic base64(user:pass)").
func alignedBase64Cores(s string) []string {
	var out []string
	for _, enc := range []*base64.Encoding{base64.RawStdEncoding, base64.RawURLEncoding} {
		for k := 0; k < 3; k++ {
			buf := make([]byte, k+len(s))
			copy(buf[k:], s)
			full := enc.EncodeToString(buf)
			start := (8*k + 5) / 6        // first char made only of s bits
			end := (8 * (k + len(s))) / 6 // chars fully covered by input bits
			if end-start >= minAlignedLen && end <= len(full) {
				out = append(out, full[start:end])
			}
		}
	}
	return out
}

// Empty reports whether the Scrubber has nothing to remove.
func (sc *Scrubber) Empty() bool { return sc == nil || len(sc.patterns) == 0 }

// Bytes returns b with every pattern replaced.
func (sc *Scrubber) Bytes(b []byte) []byte {
	if sc.Empty() {
		return b
	}
	out, _ := sc.process(b, true)
	return out
}

// String returns s with every pattern replaced.
func (sc *Scrubber) String(s string) string {
	if sc.Empty() {
		return s
	}
	return string(sc.Bytes([]byte(s)))
}

// Contains reports whether b holds any pattern.
func (sc *Scrubber) Contains(b []byte) bool {
	if sc.Empty() {
		return false
	}
	for _, p := range sc.patterns {
		if bytes.Contains(b, p) {
			return true
		}
	}
	return false
}

// Header scrubs every value in h in place. A header whose name carries a
// pattern is dropped.
func (sc *Scrubber) Header(h http.Header) {
	if sc.Empty() {
		return
	}
	for k, vv := range h {
		if sc.Contains([]byte(k)) {
			delete(h, k)
			continue
		}
		for i, v := range vv {
			vv[i] = sc.String(v)
		}
	}
}

// process scans buf left to right. When final is false it stops before
// the last maxLen-1 bytes (a match there could continue in the next
// chunk) and returns that unprocessed tail. Any match that starts before
// the stop point lies wholly inside buf, so chunk boundaries never hide
// an occurrence.
func (sc *Scrubber) process(buf []byte, final bool) (out, tail []byte) {
	stop := len(buf)
	if !final {
		stop = len(buf) - (sc.maxLen - 1)
		if stop < 0 {
			stop = 0
		}
	}
	var o bytes.Buffer
	o.Grow(len(buf))
	i := 0
	for i < stop {
		cands := sc.byFirst[buf[i]]
		matched := 0
		for _, p := range cands {
			if bytes.HasPrefix(buf[i:], p) {
				matched = len(p)
				break
			}
		}
		if matched > 0 {
			o.WriteString(Redacted)
			i += matched
			continue
		}
		o.WriteByte(buf[i])
		i++
	}
	return o.Bytes(), buf[i:]
}

// Writer streams scrubbed bytes to an underlying writer. It holds back at
// most maxLen-1 bytes between writes; Close flushes them.
type Writer struct {
	sc    *Scrubber
	w     io.Writer
	carry []byte
	flush func()
}

// NewWriter wraps w. flush, when non-nil, is called after each write that
// emitted bytes (for streaming responses).
func (sc *Scrubber) NewWriter(w io.Writer, flush func()) *Writer {
	return &Writer{sc: sc, w: w, flush: flush}
}

// Write scrubs p (joined with the held-back tail) and forwards the part
// that can no longer be the start of a match spanning into later data.
func (sw *Writer) Write(p []byte) (int, error) {
	if sw.sc.Empty() {
		n, err := sw.w.Write(p)
		if n > 0 && sw.flush != nil {
			sw.flush()
		}
		return n, err
	}
	buf := make([]byte, 0, len(sw.carry)+len(p))
	buf = append(buf, sw.carry...)
	buf = append(buf, p...)
	out, tail := sw.sc.process(buf, false)
	sw.carry = append([]byte(nil), tail...)
	if len(out) > 0 {
		if _, err := sw.w.Write(out); err != nil {
			return 0, err
		}
		if sw.flush != nil {
			sw.flush()
		}
	}
	return len(p), nil
}

// Close scrubs and writes the held-back tail. It does not close the
// underlying writer.
func (sw *Writer) Close() error {
	if sw.sc.Empty() || len(sw.carry) == 0 {
		return nil
	}
	out, _ := sw.sc.process(sw.carry, true)
	sw.carry = nil
	if _, err := sw.w.Write(out); err != nil {
		return err
	}
	if sw.flush != nil {
		sw.flush()
	}
	return nil
}

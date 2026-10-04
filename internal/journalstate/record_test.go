package journalstate

import (
	"bytes"
	"strings"
	"testing"
)

func TestStrictCanonicalMetadata(t *testing.T) {
	r := diskRecord{Version: Version, SenderBinding: strings.Repeat("a", 64)}
	raw, e := encodeRecord(r)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = decodeRecord(raw); e != nil {
		t.Fatal(e)
	}
	cases := map[string][]byte{
		"empty": nil, "oversized": bytes.Repeat([]byte(" "), MaxStateBytes+1), "unknown": append(append([]byte{}, raw[:len(raw)-1]...), []byte(`,"body":"synthetic"}`)...),
		"missing": bytes.Replace(raw, []byte(`,"sequence":0`), nil, 1), "null-scalar": bytes.Replace(raw, []byte(`"sequence":0`), []byte(`"sequence":null`), 1),
		"string-sequence": bytes.Replace(raw, []byte(`"sequence":0`), []byte(`"sequence":"0"`), 1), "number-alias": bytes.Replace(raw, []byte(`"sequence":0`), []byte(`"sequence":0.0`), 1),
		"case-fold": bytes.Replace(raw, []byte(`"sequence"`), []byte(`"Sequence"`), 1), "duplicate": bytes.Replace(raw, []byte(`"sequence":0`), []byte(`"sequence":0,"sequence":0`), 1),
		"trailing": append(append([]byte{}, raw...), []byte(`{}`)...), "whitespace": append(append([]byte{}, raw...), '\n'), "future-version": bytes.Replace(raw, []byte(Version), []byte("tracebolt.journal-consumption.v2"), 1),
		"negative": bytes.Replace(raw, []byte(`"sequence":0`), []byte(`"sequence":-1`), 1), "zero-metadata": bytes.Replace(raw, []byte(`"queryId":""`), []byte(`"queryId":"journal_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"`), 1),
		"positive-missing-metadata": bytes.Replace(raw, []byte(`"sequence":0`), []byte(`"sequence":1`), 1),
	}
	for name, b := range cases {
		t.Run(name, func(t *testing.T) {
			if _, e := decodeRecord(b); e != ErrCorrupt {
				t.Fatalf("got %v", e)
			}
		})
	}
	r.Sequence = ^uint64(0)
	r.QueryID = "journal_" + strings.Repeat("b", 32)
	r.QueryDigest = "sha256:" + strings.Repeat("c", 64)
	r.PolicyDigest = "sha256:" + strings.Repeat("d", 64)
	r.ExpiresAt = "2026-10-04T12:15:00Z"
	raw, _ = encodeRecord(r)
	if _, e = decodeRecord(raw); e != nil {
		t.Fatal("server uint64 sequence rejected", e)
	}
	for _, expiry := range []string{"2026-10-04T12:15:00+00:00", "2026-10-04T12:15:00.000Z", "2026-10-04T12:15:00+01:00", "1970-01-01T00:00:00Z", "no-time"} {
		r.ExpiresAt = expiry
		b, _ := encodeRecord(r)
		if _, e = decodeRecord(b); e != ErrCorrupt {
			t.Fatal("noncanonical expiry accepted")
		}
	}
}
func FuzzDecodeRecord(f *testing.F) {
	b, _ := encodeRecord(diskRecord{Version: Version, SenderBinding: strings.Repeat("a", 64)})
	f.Add(b)
	f.Add([]byte(`null`))
	f.Add([]byte(`{}`))
	f.Fuzz(func(t *testing.T, raw []byte) {
		r, e := decodeRecord(raw)
		if e == nil {
			canonical, e := encodeRecord(r)
			if e != nil || !bytes.Equal(raw, canonical) || len(raw) > MaxStateBytes {
				t.Fatal("accepted noncanonical record")
			}
		}
	})
}

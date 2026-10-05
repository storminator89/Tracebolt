package linuxcvefeed

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"localrmm/internal/linuxcve"
	"net/http"
	"strings"
	"testing"
	"time"
)

func gzipFixture(t *testing.T, raw []byte) []byte {
	t.Helper()
	var out bytes.Buffer
	w := gzip.NewWriter(&out)
	w.Name = "synthetic-fixture.json"
	if _, err := w.Write(raw); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return out.Bytes()
}

func gzipResponse(data []byte) *http.Response {
	return &http.Response{StatusCode: http.StatusOK, Header: http.Header{"Content-Type": {"application/json"}, "Content-Encoding": {"gzip"}}, Body: io.NopCloser(bytes.NewReader(data)), ContentLength: int64(len(data))}
}

func testDigest(raw []byte) string {
	h := sha256.Sum256(raw)
	return hex.EncodeToString(h[:])
}

func TestOfficialGzipPreservesExactBytesAndProvenance(t *testing.T) {
	raw := []byte(" \t\r\n" + debianFixture("1.2-3") + "\n")
	compressed := gzipFixture(t, raw)
	c := fetchCache(func(*http.Request) (*http.Response, error) { return gzipResponse(compressed), nil })
	candidate, err := c.FetchDebian(context.Background(), testNow)
	if err != nil {
		t.Fatal(err)
	}
	var envelope cacheEnvelope
	if err := json.Unmarshal(candidate.encoded, &envelope); err != nil {
		t.Fatal(err)
	}
	if envelope.Kind != officialGzipKind || !bytes.Equal(envelope.Data, compressed) || envelope.SHA256 != testDigest(compressed) || envelope.DecodedSHA256 != testDigest(raw) || envelope.PayloadSHA256 != testDigest(bytes.TrimSpace(raw)) {
		t.Fatal("compressed/exact-decoded/payload identity was changed")
	}
	at := testNow.Add(72 * time.Hour)
	restored, err := restore(context.Background(), candidate.encoded, linuxcve.DebianProvider, at)
	if err != nil {
		t.Fatal(err)
	}
	before, after := candidate.Metadata(testNow), restored.Metadata(at)
	if after.Trust != "https_origin_only" || after.Coverage != "official_feed_records" || after.SHA256 != before.SHA256 || !after.FetchedAt.Equal(before.FetchedAt) || !after.ExpiresAt.Equal(before.ExpiresAt) || after.Freshness != "stale" || !after.ValidatedAt.Equal(at) {
		t.Fatal("compressed restart changed hash, trust, coverage or original age")
	}
}

func TestGzipRejectsCorruptionTruncationAndAdditionalMembers(t *testing.T) {
	raw := []byte(debianFixture("1.2-3"))
	good := gzipFixture(t, raw)
	for _, tc := range []struct {
		name string
		edit func([]byte) []byte
	}{
		{"header", func(b []byte) []byte { b[0] = 0; return b }},
		{"truncated header", func(b []byte) []byte { return b[:5] }},
		{"truncated deflate", func(b []byte) []byte { return b[:len(b)/2] }},
		{"truncated trailer", func(b []byte) []byte { return b[:len(b)-1] }},
		{"CRC", func(b []byte) []byte { b[len(b)-8] ^= 1; return b }},
		{"ISIZE small", func(b []byte) []byte { binary.LittleEndian.PutUint32(b[len(b)-4:], 1); return b }},
		{"ISIZE huge", func(b []byte) []byte { binary.LittleEndian.PutUint32(b[len(b)-4:], ^uint32(0)); return b }},
		{"trailing text", func(b []byte) []byte { return append(b, "secret trailing text"...) }},
		{"trailing padding", func(b []byte) []byte { return append(b, 0) }},
		{"second member", func(b []byte) []byte { return append(b, good...) }},
		{"empty second member", func(b []byte) []byte { return append(b, gzipFixture(t, nil)...) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			bad := tc.edit(append([]byte(nil), good...))
			c := fetchCache(func(*http.Request) (*http.Response, error) { return gzipResponse(bad), nil })
			if candidate, err := c.FetchDebian(context.Background(), testNow); candidate != nil || !errors.Is(err, ErrResponse) || strings.Contains(err.Error(), "secret") {
				t.Fatalf("malformed gzip admitted or error leaked details: %v", err)
			}
		})
	}
}

func TestGzipDecodedBoundAndCompleteEOFVerification(t *testing.T) {
	const max = 1024
	good := gzipFixture(t, bytes.Repeat([]byte{' '}, max))
	if raw, err := decodeOfficialGzip(context.Background(), good, max); err != nil || len(raw) != max {
		t.Fatalf("exact decoded limit: len=%d err=%v", len(raw), err)
	}
	badCRC := append([]byte(nil), good...)
	badCRC[len(badCRC)-8] ^= 1
	if raw, err := decodeOfficialGzip(context.Background(), badCRC, max); raw != nil || !errors.Is(err, ErrResponse) {
		t.Fatalf("exact decoded limit bypassed CRC: %v", err)
	}
	bomb := gzipFixture(t, bytes.Repeat([]byte{' '}, max*128))
	for _, data := range [][]byte{good, bomb} {
		raw, err := decodeOfficialGzip(context.Background(), data, max-1)
		var limit *responseLimitError
		if raw != nil || !errors.As(err, &limit) || !errors.Is(err, linuxcve.ErrLimit) || !errors.Is(err, ErrResponse) || limit.layer != responseLimitDecoded || limit.reason != responseLimitRead || limit.observedBytes != max || limit.maxBytes != max-1 || limit.declaredLength != -1 {
			t.Fatalf("missing decoded bound diagnostic: %v", err)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := decodeOfficialGzip(ctx, good, max); !errors.Is(err, linuxcve.ErrCanceled) {
		t.Fatal(err)
	}
}

func TestGzipSuccessfulTransportStillRejectsInvalidJSON(t *testing.T) {
	for _, raw := range []string{"{", "{}", debianFixture("1.2-3") + "{}", `{"fixture-source":{},"fixture-source":{}}`} {
		c := fetchCache(func(*http.Request) (*http.Response, error) { return gzipResponse(gzipFixture(t, []byte(raw))), nil })
		if candidate, err := c.FetchDebian(context.Background(), testNow); candidate != nil || !errors.Is(err, ErrParse) || smokeFailureStage(err) != "PARSER_FAILED" {
			t.Fatalf("invalid decompressed JSON lost parser failure: %v", err)
		}
	}
}

func TestFetchOnlyAcceptsOneExplicitSupportedEncoding(t *testing.T) {
	for _, values := range [][]string{{"br"}, {"deflate"}, {"gzip, identity"}, {"gzip", "gzip"}, {"identity", "gzip"}} {
		c := fetchCache(func(*http.Request) (*http.Response, error) {
			r := response(debianFixture("1.2-3"))
			r.Header["Content-Encoding"] = values
			return r, nil
		})
		if _, err := c.FetchDebian(context.Background(), testNow); !errors.Is(err, ErrResponse) {
			t.Fatalf("unsupported or ambiguous encoding accepted: %v", values)
		}
	}
	c := fetchCache(func(*http.Request) (*http.Response, error) {
		r := response(debianFixture("1.2-3"))
		r.Header.Set("Content-Encoding", "identity")
		return r, nil
	})
	if _, err := c.FetchDebian(context.Background(), testNow); err != nil {
		t.Fatalf("explicit identity rejected: %v", err)
	}
}

type countingBody struct {
	remaining int64
	read      int64
	closed    bool
}

func (r *countingBody) Read(p []byte) (int, error) {
	if r.remaining == 0 {
		return 0, io.EOF
	}
	n := len(p)
	if int64(n) > r.remaining {
		n = int(r.remaining)
	}
	clear(p[:n])
	r.remaining -= int64(n)
	r.read += int64(n)
	return n, nil
}
func (r *countingBody) Close() error { r.closed = true; return nil }

func TestOfficialResponseCapsAndLayers(t *testing.T) {
	for _, tc := range []struct {
		name     string
		encoding string
		declared int64
		max      int64
		layer    responseLimitLayer
		read     int64
	}{
		{"identity declared", "identity", MaxOfficialFeedBytes + 1, MaxOfficialFeedBytes, responseLimitDecoded, 0},
		{"gzip declared", "gzip", MaxFeedBytes + 1, MaxFeedBytes, responseLimitCompressed, 0},
		{"gzip unknown", "gzip", -1, MaxFeedBytes, responseLimitCompressed, MaxFeedBytes + 1},
		{"gzip underreported", "gzip", 2, MaxFeedBytes, responseLimitCompressed, MaxFeedBytes + 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			body := &countingBody{remaining: tc.max + 100}
			c := fetchCache(func(*http.Request) (*http.Response, error) {
				r := response("")
				r.Header.Set("Content-Encoding", tc.encoding)
				r.ContentLength, r.Body = tc.declared, body
				return r, nil
			})
			_, err := c.FetchDebian(context.Background(), testNow)
			var limit *responseLimitError
			if !errors.As(err, &limit) || limit.layer != tc.layer || limit.maxBytes != tc.max || limit.observedBytes != tc.read || body.read != tc.read || !body.closed {
				t.Fatalf("wrong limit/count or body not closed: diagnostic=%+v read=%d closed=%t", limit, body.read, body.closed)
			}
		})
	}
	if responseLimitDecoded.String() != "decoded_json" || responseLimitCompressed.String() != "compressed_wire" || responseLimitLayer(255).String() != "unknown" {
		t.Fatal("limit layer is not a closed enum")
	}
}

func TestLocalCompressionRetainsStoredByteBound(t *testing.T) {
	raw := []byte(debianFixture("1.2-3"))
	compressed, err := compressOfficial(context.Background(), raw, MaxFeedBytes)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := compressOfficial(context.Background(), raw, int64(len(compressed)-1)); !errors.Is(err, linuxcve.ErrLimit) {
		t.Fatalf("local compression exceeded stored budget: %v", err)
	}
	if got, err := compressOfficial(context.Background(), raw, int64(len(compressed))); err != nil || !bytes.Equal(got, compressed) {
		t.Fatalf("exact stored budget rejected: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := compressOfficial(ctx, raw, MaxFeedBytes); !errors.Is(err, linuxcve.ErrCanceled) {
		t.Fatal(err)
	}
}

func TestLegacyOfficialCacheKeepsOriginalFormatHashAgeAndTrust(t *testing.T) {
	raw := []byte(" \n" + debianFixture("1.2-3") + "\n")
	// Spell out the prior writer's structure: it has no decodedSha256 field.
	legacy := struct {
		SchemaVersion string    `json:"schemaVersion"`
		Provider      string    `json:"provider"`
		Kind          string    `json:"kind"`
		FetchedAt     time.Time `json:"fetchedAt"`
		SHA256        string    `json:"sha256"`
		PayloadSHA256 string    `json:"payloadSha256"`
		Data          []byte    `json:"data"`
	}{cacheSchema, linuxcve.DebianProvider, officialKind, testNow, testDigest(raw), testDigest(bytes.TrimSpace(raw)), raw}
	encoded, err := json.Marshal(legacy)
	if err != nil {
		t.Fatal(err)
	}
	s, err := restore(context.Background(), encoded, linuxcve.DebianProvider, testNow.Add(72*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	m := s.Metadata(testNow.Add(72 * time.Hour))
	if m.SHA256 != legacy.PayloadSHA256 || m.Trust != "https_origin_only" || m.Coverage != "official_feed_records" || !m.FetchedAt.Equal(testNow) || m.Freshness != "stale" {
		t.Fatal("legacy cache provenance changed")
	}
}

func TestCompressedCacheRejectsHashCorruptionAndWrongKind(t *testing.T) {
	compressed := gzipFixture(t, []byte(debianFixture("1.2-3")))
	c := fetchCache(func(*http.Request) (*http.Response, error) { return gzipResponse(compressed), nil })
	candidate, err := c.FetchDebian(context.Background(), testNow)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name string
		edit func(*cacheEnvelope)
	}{
		{"stored hash", func(e *cacheEnvelope) { e.SHA256 = strings.Repeat("0", 64) }},
		{"decoded hash", func(e *cacheEnvelope) { e.DecodedSHA256 = strings.Repeat("0", 64) }},
		{"missing decoded hash", func(e *cacheEnvelope) { e.DecodedSHA256 = "" }},
		{"payload hash", func(e *cacheEnvelope) { e.PayloadSHA256 = strings.Repeat("0", 64) }},
		{"CRC with matching stored hash", func(e *cacheEnvelope) { e.Data[len(e.Data)-8] ^= 1; e.SHA256 = testDigest(e.Data) }},
		{"truncation with matching stored hash", func(e *cacheEnvelope) { e.Data = e.Data[:len(e.Data)-1]; e.SHA256 = testDigest(e.Data) }},
		{"second member with matching stored hash", func(e *cacheEnvelope) { e.Data = append(e.Data, compressed...); e.SHA256 = testDigest(e.Data) }},
		{"legacy kind", func(e *cacheEnvelope) { e.Kind = officialKind }},
		{"import kind", func(e *cacheEnvelope) { e.Kind = importKind }},
		{"wrong provider", func(e *cacheEnvelope) { e.Provider = linuxcve.UbuntuProvider }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var e cacheEnvelope
			if err := json.Unmarshal(candidate.encoded, &e); err != nil {
				t.Fatal(err)
			}
			tc.edit(&e)
			encoded, err := json.Marshal(e)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := restore(context.Background(), encoded, e.Provider, testNow); err == nil {
				t.Fatal("malformed or mislabeled compressed cache accepted")
			}
		})
	}
}

func TestManualImportBudgetAndCacheFormatRemainUnchanged(t *testing.T) {
	if linuxcve.MaxBundleBytes != 32<<20 || MaxFeedBytes != (32<<20)-1024 || MaxOfficialFeedBytes != (96<<20)-1024 || MaxCacheBytes != ((32<<20)+2)/3*4+4096 {
		t.Fatal("manual, stored, decoded or cache byte boundary changed unexpectedly")
	}
	c := &Cache{}
	body := &countingBody{remaining: linuxcve.MaxBundleBytes + 100}
	if _, err := c.PrepareImport(context.Background(), body, testNow); !errors.Is(err, linuxcve.ErrLimit) || body.read != linuxcve.MaxBundleBytes+1 {
		t.Fatalf("manual importer budget changed: %v read=%d", err, body.read)
	}
	original := importFixture(t, linuxcve.DebianProvider, testNow, debianFixture("1.2-3"))
	candidate, err := c.PrepareImport(context.Background(), bytes.NewReader(original), testNow)
	if err != nil {
		t.Fatal(err)
	}
	var e cacheEnvelope
	if json.Unmarshal(candidate.encoded, &e) != nil || e.Kind != importKind || !bytes.Equal(e.Data, original) || e.DecodedSHA256 != "" || bytes.Contains(candidate.encoded, []byte("decodedSha256")) || e.SHA256 != testDigest(original) || candidate.Metadata(testNow).Trust != "operator_imported_unverified" {
		t.Fatal("manual cache format or trust changed")
	}
}

func TestDownloadedGzipCancellationIsLocalParserFailure(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := decodeDownloadedOfficialGzip(ctx, gzipFixture(t, []byte(debianFixture("1.2-3"))), MaxOfficialFeedBytes)
	if !errors.Is(err, ErrParse) || !errors.Is(err, linuxcve.ErrCanceled) || smokeFailureStage(err) != "PARSER_FAILED" {
		t.Fatal("completed download followed by decode cancellation was mislabeled", err)
	}
}

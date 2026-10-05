package linuxcvefeed

import (
	"bytes"
	"context"
	"crypto/sha256"
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

var testNow = time.Date(2026, 10, 5, 7, 0, 0, 0, time.UTC)

func debianFixture(fixed string) string {
	return `{"fixture-source":{"CVE-2025-99999":{"description":"Synthetic adapter test only","releases":{"trixie":{"status":"resolved","fixed_version":"` + fixed + `"}}}}}`
}

func importFixture(t *testing.T, provider string, at time.Time, payload string) []byte {
	t.Helper()
	raw, err := json.Marshal(struct {
		SchemaVersion string          `json:"schemaVersion"`
		Provider      string          `json:"provider"`
		FetchedAt     time.Time       `json:"fetchedAt"`
		Payload       json.RawMessage `json:"payload"`
	}{linuxcve.BundleSchemaVersion, provider, at, json.RawMessage(payload)})
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) { return f(req) }

func response(raw string) *http.Response {
	return &http.Response{StatusCode: http.StatusOK, Header: http.Header{"Content-Type": {"application/json"}}, Body: io.NopCloser(strings.NewReader(raw)), ContentLength: int64(len(raw))}
}

func fetchCache(rt roundTripFunc) *Cache {
	c := &Cache{client: newHTTPClient()}
	c.client.Transport = rt
	return c
}

func TestFixedFetchContainsNoHostInventoryOrAmbientCredentials(t *testing.T) {
	t.Setenv("HTTPS_PROXY", "http://proxy.invalid:4444")
	t.Setenv("HTTP_PROXY", "http://proxy.invalid:4444")
	calls := 0
	raw := " \n" + debianFixture("1.2-3") + "\n"
	c := fetchCache(func(r *http.Request) (*http.Response, error) {
		calls++
		if r.Method != "GET" || r.URL.String() != DebianURL || r.URL.RawQuery != "" || r.URL.User != nil || r.Body != nil || r.Host != "security-tracker.debian.org" {
			t.Fatalf("unexpected request shape: %s %s", r.Method, r.URL)
		}
		if len(r.Header) != 3 || r.Header.Get("User-Agent") != "Tracebolt-CVE-Feed/1" || r.Header.Get("Accept") != "application/json" || r.Header.Get("Accept-Encoding") != "identity" {
			t.Fatalf("unexpected request headers: %v", r.Header)
		}
		if _, ok := r.Context().Deadline(); !ok {
			t.Fatal("missing bounded deadline")
		}
		return response(raw), nil
	})
	candidate, err := c.FetchDebian(context.Background(), testNow)
	if err != nil {
		t.Fatal(err)
	}
	if calls != 1 {
		t.Fatalf("requests=%d", calls)
	}
	m := candidate.Metadata(testNow)
	if m.Trust != "https_origin_only" || m.Coverage != "official_feed_records" || m.Provider != linuxcve.DebianProvider || m.RecordCount != 1 {
		t.Fatalf("bad metadata: %+v", m)
	}
	var envelope cacheEnvelope
	if json.Unmarshal(candidate.encoded, &envelope) != nil || string(envelope.Data) != raw {
		t.Fatal("cache changed original bytes")
	}
	h := sha256.Sum256([]byte(raw))
	if envelope.SHA256 != hex.EncodeToString(h[:]) {
		t.Fatal("raw hash missing")
	}
	transport := newHTTPClient().Transport.(*http.Transport)
	if transport.Proxy != nil || !transport.DisableCompression || transport.TLSClientConfig.InsecureSkipVerify || transport.TLSHandshakeTimeout <= 0 || transport.ResponseHeaderTimeout <= 0 || transport.MaxResponseHeaderBytes <= 0 {
		t.Fatal("unsafe transport defaults")
	}
}

func TestFetchRejectsRedirectWithoutFollowing(t *testing.T) {
	calls := 0
	c := fetchCache(func(r *http.Request) (*http.Response, error) {
		calls++
		return &http.Response{StatusCode: 302, Header: http.Header{"Location": {"https://attacker.invalid/feed"}}, Body: io.NopCloser(strings.NewReader(""))}, nil
	})
	if _, err := c.FetchDebian(context.Background(), testNow); !errors.Is(err, ErrResponse) {
		t.Fatalf("got %v", err)
	}
	if calls != 1 {
		t.Fatalf("redirect followed: %d requests", calls)
	}
}

func TestFetchRejectsResponseAndParseFailures(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*http.Response)
		want   error
	}{
		{"partial", func(r *http.Response) { r.StatusCode = 206 }, ErrResponse},
		{"not modified", func(r *http.Response) { r.StatusCode = 304 }, ErrResponse},
		{"html", func(r *http.Response) { r.Header.Set("Content-Type", "text/html") }, ErrResponse},
		{"missing type", func(r *http.Response) { r.Header.Del("Content-Type") }, ErrResponse},
		{"compressed", func(r *http.Response) { r.Header.Set("Content-Encoding", "gzip") }, ErrResponse},
		{"implicit decompress", func(r *http.Response) { r.Uncompressed = true }, ErrResponse},
		{"oversized declared", func(r *http.Response) { r.ContentLength = MaxFeedBytes + 1 }, linuxcve.ErrLimit},
		{"short body", func(r *http.Response) { r.ContentLength++ }, ErrResponse},
		{"invalid json", func(r *http.Response) { r.Body = io.NopCloser(strings.NewReader("{")); r.ContentLength = 1 }, linuxcve.ErrInvalid},
		{"empty target", func(r *http.Response) { r.Body = io.NopCloser(strings.NewReader("{}")); r.ContentLength = 2 }, linuxcve.ErrInvalid},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := fetchCache(func(*http.Request) (*http.Response, error) {
				r := response(debianFixture("1.2-3"))
				tt.mutate(r)
				return r, nil
			})
			if _, err := c.FetchDebian(context.Background(), testNow); !errors.Is(err, tt.want) {
				t.Fatalf("got %v, want %v", err, tt.want)
			} else if errors.Is(tt.want, linuxcve.ErrInvalid) && !errors.Is(err, ErrParse) {
				t.Fatalf("parser failure lost its stage: %v", err)
			}
		})
	}
}

func TestFetchCancellationAndSanitizedNetworkError(t *testing.T) {
	c := fetchCache(func(*http.Request) (*http.Response, error) {
		return nil, errors.New("sensitive transport implementation detail")
	})
	if _, err := c.FetchDebian(context.Background(), testNow); !errors.Is(err, ErrFetch) || strings.Contains(err.Error(), "sensitive") {
		t.Fatalf("unexpected error: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := c.FetchDebian(ctx, testNow); !errors.Is(err, linuxcve.ErrCanceled) {
		t.Fatalf("got %v", err)
	}
	c = fetchCache(func(r *http.Request) (*http.Response, error) { <-r.Context().Done(); return nil, r.Context().Err() })
	ctx, cancel = context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	if _, err := c.FetchDebian(ctx, testNow); !errors.Is(err, linuxcve.ErrCanceled) {
		t.Fatalf("got %v", err)
	}
}

func TestBoundedReader(t *testing.T) {
	if _, err := readBounded(context.Background(), strings.NewReader("12345"), 4); !errors.Is(err, linuxcve.ErrLimit) {
		t.Fatal(err)
	}
	if raw, err := readBounded(context.Background(), strings.NewReader("1234"), 4); err != nil || string(raw) != "1234" {
		t.Fatalf("%q %v", raw, err)
	}
}

func TestManualImportCannotClaimOfficialTransport(t *testing.T) {
	c := &Cache{}
	raw := importFixture(t, linuxcve.DebianProvider, testNow, debianFixture("1.2-3"))
	candidate, err := c.PrepareImport(context.Background(), bytes.NewReader(raw), testNow)
	if err != nil {
		t.Fatal(err)
	}
	if candidate.Metadata(testNow).Trust != "operator_imported_unverified" {
		t.Fatal("import fabricated official origin")
	}
	var body map[string]any
	if json.Unmarshal(raw, &body) != nil {
		t.Fatal("fixture")
	}
	body["trust"] = "https_origin_only"
	raw, _ = json.Marshal(body)
	if _, err = c.PrepareImport(context.Background(), bytes.NewReader(raw), testNow); !errors.Is(err, linuxcve.ErrInvalid) {
		t.Fatalf("got %v", err)
	}
}

func TestRestoreDetectsEnvelopeCorruption(t *testing.T) {
	c := &Cache{}
	candidate, err := c.PrepareImport(context.Background(), bytes.NewReader(importFixture(t, linuxcve.DebianProvider, testNow, debianFixture("1.2-3"))), testNow)
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name  string
		alter func([]byte) []byte
	}{
		{"truncated", func(b []byte) []byte { return b[:len(b)-1] }},
		{"trailing", func(b []byte) []byte { return append(b, []byte(`{}`)...) }},
		{"duplicate key", func(b []byte) []byte { return append([]byte(`{"kind":"operator_import",`), b[1:]...) }},
		{"hash", func(b []byte) []byte {
			var e cacheEnvelope
			_ = json.Unmarshal(b, &e)
			e.SHA256 = strings.Repeat("0", 64)
			out, _ := json.Marshal(e)
			return out
		}},
		{"payload hash", func(b []byte) []byte {
			var e cacheEnvelope
			_ = json.Unmarshal(b, &e)
			e.PayloadSHA256 = strings.Repeat("0", 64)
			out, _ := json.Marshal(e)
			return out
		}},
		{"provider", func(b []byte) []byte {
			var e cacheEnvelope
			_ = json.Unmarshal(b, &e)
			e.Provider = linuxcve.UbuntuProvider
			out, _ := json.Marshal(e)
			return out
		}},
		{"kind", func(b []byte) []byte {
			var e cacheEnvelope
			_ = json.Unmarshal(b, &e)
			e.Kind = "fake"
			out, _ := json.Marshal(e)
			return out
		}},
		{"timestamp", func(b []byte) []byte {
			var e cacheEnvelope
			_ = json.Unmarshal(b, &e)
			e.FetchedAt = e.FetchedAt.Add(time.Hour)
			out, _ := json.Marshal(e)
			return out
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			raw := tt.alter(append([]byte(nil), candidate.encoded...))
			if _, err := restore(context.Background(), raw, linuxcve.DebianProvider, testNow); err == nil {
				t.Fatal("corrupt cache accepted")
			}
		})
	}
}
